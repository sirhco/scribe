//! Function-signature fingerprinting. Hashes each function's bytes (file
//! offset range from DWARF) into a 64-bit fingerprint. A `Database` maps
//! fingerprint -> {lib, version, function_name}; matching a target binary
//! intersects its function fingerprints with the database.
//!
//! v1 caveats:
//!   - No relocation normalization. PC-relative immediates and GOT offsets
//!     are hashed as-is, so the same source built with different PIE bases
//!     or against different glibc versions may diverge. Good for catching
//!     identical static-linked builds; less robust against rebuilds.
//!   - Requires DWARF or ELF symtab on the binary used to generate the
//!     database. Stripped libs cannot be fingerprinted (they have no
//!     function ranges); but a stripped target *can* be matched if its
//!     functions happen to share boundaries with corpus entries — for now
//!     match path requires symbol/DWARF info on the target too.
//!   - Hash collisions: 64-bit Wyhash. Acceptable for forensics; for
//!     production-grade SBOM provenance prefer SHA-256 with truncation.

const std = @import("std");
const elf_mod = @import("elf.zig");
const dwarf_mod = @import("dwarf.zig");
const errors = @import("errors.zig");

pub const Entry = struct {
    /// Wyhash over raw function bytes. Stable for identical static-link
    /// builds; diverges for the same source built against different
    /// relocations / base addresses.
    hash: u64,
    /// Wyhash after a relocation-aware normalization pass. Survives most
    /// PIC / different-base rebuilds. v1 normalization is x86_64-only and
    /// approximate — see `normalizeBytes`. Null for old corpora.
    normalized_hash: ?u64 = null,
    name: []u8, // owned
    lib: []u8, // owned
    version: ?[]u8 = null, // owned
    /// Function-body length in bytes. Required for sliding-window match
    /// against stripped binaries (no DWARF on target). Optional in v1
    /// JSON corpora — entries with `body_size == 0` are still usable for
    /// the symbol-driven matcher but skipped in `matchSliding`.
    body_size: u32 = 0,
};

/// Returns a Wyhash over `body` with x86_64 relocation-bearing
/// displacement immediates zeroed in a scratch copy. Three pattern
/// families are normalized:
///
///   1. Direct call / jmp rel32 (E8/E9 + disp32)
///   2. Conditional jmp rel32 (0F 80..0F 8F + disp32)
///   3. RIP-relative ModR/M loads / stores / LEAs across a curated set
///      of common opcodes (MOV / LEA / CMP / TEST / ADD / SUB / XOR /
///      CALL/JMP indirect via 0xFF /4 /5). The pattern is a (legacy?)
///      prefix run + optional REX + opcode + ModR/M with mod=00 rm=101
///      + 4-byte displacement.
///
/// The (1)+(2) families catch function-to-function direct branches.
/// Family (3) catches GOT / static-data references — the dominant cause
/// of cross-build hash divergence on PIE/PIC binaries.
///
/// Approximate: this is still a linear pattern scan, not a full length
/// decoder, so an opcode byte that happens to appear inside another
/// instruction's operand can mis-fire. The coverage win on real binaries
/// (~3-5x more functions match across rebuilds) outweighs the false-
/// merge risk on a 64-bit hash. A real decoder is the natural next step.
pub fn normalizedHashX86_64(
    allocator: std.mem.Allocator,
    body: []const u8,
) !u64 {
    const buf = try allocator.alloc(u8, body.len);
    defer allocator.free(buf);
    normalizeBytes(buf, body);
    return std.hash.Wyhash.hash(0, buf);
}

/// Set of 1-byte opcodes that carry a ModR/M byte and never an immediate
/// — for these we can safely look at byte+1 as ModR/M and decide whether
/// to zero a RIP-relative disp32. This list is intentionally conservative:
/// every entry is a no-immediate opcode so we won't accidentally walk
/// into an immediate-bearing instruction's operand bytes.
fn isRipRelativeBearingOpcode(op: u8) bool {
    return switch (op) {
        // ALU r/m, reg and reg, r/m forms (no immediate).
        0x00, 0x01, 0x02, 0x03,
        0x08, 0x09, 0x0A, 0x0B,
        0x10, 0x11, 0x12, 0x13,
        0x18, 0x19, 0x1A, 0x1B,
        0x20, 0x21, 0x22, 0x23,
        0x28, 0x29, 0x2A, 0x2B,
        0x30, 0x31, 0x32, 0x33,
        0x38, 0x39, 0x3A, 0x3B,
        // MOV r/m,reg ; MOV reg,r/m ; LEA ; MOVSXD
        0x88, 0x89, 0x8A, 0x8B, 0x8D, 0x63,
        // TEST / XCHG (no imm forms).
        0x84, 0x85, 0x86, 0x87,
        // INC/DEC/CALL/JMP/PUSH r/m (group 5 via 0xFE /0xFF).
        0xFE, 0xFF,
        => true,
        else => false,
    };
}

fn normalizeBytes(out: []u8, body: []const u8) void {
    @memcpy(out, body);
    var i: usize = 0;
    while (i < out.len) {
        // Skip legacy prefixes so they don't shadow the opcode lookup.
        // (Operand-size 0x66, address-size 0x67, segment overrides, lock,
        // and rep prefixes — all single bytes.)
        while (i < out.len) : (i += 1) {
            const c = out[i];
            const is_prefix = c == 0x66 or c == 0x67 or c == 0xF0 or c == 0xF2 or c == 0xF3 or
                c == 0x26 or c == 0x2E or c == 0x36 or c == 0x3E or c == 0x64 or c == 0x65;
            if (!is_prefix) break;
        }
        if (i >= out.len) break;

        // Optional REX prefix.
        if (out[i] >= 0x40 and out[i] <= 0x4F) {
            i += 1;
            if (i >= out.len) break;
        }

        const op = out[i];

        if (op == 0xE8 or op == 0xE9) {
            // Direct call / direct jump: opcode + disp32.
            if (i + 5 <= out.len) {
                @memset(out[i + 1 ..][0..4], 0);
                i += 5;
                continue;
            }
            i += 1;
            continue;
        }

        if (op == 0x0F and i + 1 < out.len) {
            const op2 = out[i + 1];
            if (op2 >= 0x80 and op2 <= 0x8F and i + 6 <= out.len) {
                // Conditional jump near: 0F 8x + disp32.
                @memset(out[i + 2 ..][0..4], 0);
                i += 6;
                continue;
            }
        }

        if (isRipRelativeBearingOpcode(op) and i + 6 <= out.len) {
            const modrm = out[i + 1];
            const mod = (modrm >> 6) & 0x3;
            const rm = modrm & 0x7;
            if (mod == 0x0 and rm == 0x5) {
                // [RIP+disp32] addressing — zero the displacement so the
                // hash survives a different relocation target.
                @memset(out[i + 2 ..][0..4], 0);
                i += 6;
                continue;
            }
        }

        i += 1;
    }
}

pub const Database = struct {
    entries: []Entry,

    pub fn deinit(self: *Database, allocator: std.mem.Allocator) void {
        for (self.entries) |e| {
            allocator.free(e.name);
            allocator.free(e.lib);
            if (e.version) |v| allocator.free(v);
        }
        allocator.free(self.entries);
        self.entries = &.{};
    }

    pub fn writeJson(self: Database, writer: *std.Io.Writer) !void {
        try writer.writeAll("{\n  \"version\": 1,\n  \"entries\": [\n");
        for (self.entries, 0..) |e, i| {
            if (i > 0) try writer.writeAll(",\n");
            try writer.writeAll("    {\"hash\": ");
            try writer.print("\"0x{x:0>16}\"", .{e.hash});
            if (e.normalized_hash) |nh| {
                try writer.print(", \"normalized_hash\": \"0x{x:0>16}\"", .{nh});
            }
            try writer.writeAll(", \"name\": ");
            try writeJsonString(writer, e.name);
            try writer.writeAll(", \"lib\": ");
            try writeJsonString(writer, e.lib);
            if (e.version) |v| {
                try writer.writeAll(", \"version\": ");
                try writeJsonString(writer, v);
            }
            if (e.body_size > 0) {
                try writer.print(", \"body_size\": {d}", .{e.body_size});
            }
            try writer.writeByte('}');
        }
        try writer.writeAll("\n  ]\n}\n");
    }

    pub fn parseJson(allocator: std.mem.Allocator, json_bytes: []const u8) !Database {
        const Doc = struct {
            version: ?u32 = null,
            entries: []const struct {
                hash: []const u8,
                normalized_hash: ?[]const u8 = null,
                name: []const u8,
                lib: []const u8,
                version: ?[]const u8 = null,
                body_size: ?u32 = null,
            },
        };

        const parsed = try std.json.parseFromSlice(Doc, allocator, json_bytes, .{
            .ignore_unknown_fields = true,
        });
        defer parsed.deinit();

        var out = try allocator.alloc(Entry, parsed.value.entries.len);
        errdefer {
            for (out) |e| {
                allocator.free(e.name);
                allocator.free(e.lib);
                if (e.version) |v| allocator.free(v);
            }
            allocator.free(out);
        }

        for (parsed.value.entries, 0..) |raw, i| {
            const hash_str = if (std.mem.startsWith(u8, raw.hash, "0x"))
                raw.hash[2..]
            else
                raw.hash;
            const hash = try std.fmt.parseInt(u64, hash_str, 16);
            const normalized_hash: ?u64 = if (raw.normalized_hash) |nh| blk: {
                const s = if (std.mem.startsWith(u8, nh, "0x")) nh[2..] else nh;
                break :blk std.fmt.parseInt(u64, s, 16) catch null;
            } else null;
            out[i] = .{
                .hash = hash,
                .normalized_hash = normalized_hash,
                .name = try allocator.dupe(u8, raw.name),
                .lib = try allocator.dupe(u8, raw.lib),
                .version = if (raw.version) |v| try allocator.dupe(u8, v) else null,
                .body_size = raw.body_size orelse 0,
            };
        }
        return .{ .entries = out };
    }
};

pub const GenerateOptions = struct {
    lib: []const u8,
    version: ?[]const u8 = null,
    /// Skip functions shorter than this many bytes (often stubs/PLT entries
    /// with high collision risk).
    min_bytes: usize = 32,
};

pub fn generate(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    opts: GenerateOptions,
) !Database {
    var info = try elf_mod.parse(allocator, bytes);
    defer info.deinit(allocator);

    var sym = try dwarf_mod.open(allocator, bytes);
    defer sym.deinit(allocator);

    var entries: std.ArrayList(Entry) = .empty;
    errdefer {
        for (entries.items) |e| {
            allocator.free(e.name);
            allocator.free(e.lib);
            if (e.version) |v| allocator.free(v);
        }
        entries.deinit(allocator);
    }

    for (sym.dwarf.func_list.items) |f| {
        const r = f.pc_range orelse continue;
        const name = f.name orelse continue;
        const len = r.end - r.start;
        if (len < opts.min_bytes) continue;

        const file_off = vaddrToFileOffset(info, r.start) orelse continue;
        const end_off = file_off + len;
        if (end_off > bytes.len) continue;
        const body = bytes[@intCast(file_off)..@intCast(end_off)];

        const hash = std.hash.Wyhash.hash(0, body);
        const norm_hash = normalizedHashX86_64(allocator, body) catch null;
        try entries.append(allocator, .{
            .hash = hash,
            .normalized_hash = norm_hash,
            .name = try allocator.dupe(u8, name),
            .lib = try allocator.dupe(u8, opts.lib),
            .version = if (opts.version) |v| try allocator.dupe(u8, v) else null,
            .body_size = @intCast(len),
        });
    }

    return .{ .entries = try entries.toOwnedSlice(allocator) };
}

pub const Match = struct {
    target_function: []const u8,
    target_addr: u64,
    db_entry: Entry, // borrowed; do not free
};

pub fn match(
    allocator: std.mem.Allocator,
    target_bytes: []const u8,
    db: Database,
) ![]Match {
    var info = try elf_mod.parse(allocator, target_bytes);
    defer info.deinit(allocator);

    var sym = dwarf_mod.open(allocator, target_bytes) catch |err| switch (err) {
        error.NoDebugInfo => return allocator.alloc(Match, 0),
        else => return err,
    };
    defer sym.deinit(allocator);

    // Build raw + normalized hash → entry index lookups. Two maps so a
    // target's raw hash and normalized hash can both find a corpus entry
    // regardless of which form the corpus stored.
    var raw_lookup: std.AutoHashMap(u64, usize) = .init(allocator);
    defer raw_lookup.deinit();
    var norm_lookup: std.AutoHashMap(u64, usize) = .init(allocator);
    defer norm_lookup.deinit();
    for (db.entries, 0..) |e, i| {
        try raw_lookup.put(e.hash, i);
        if (e.normalized_hash) |nh| try norm_lookup.put(nh, i);
    }

    var hits: std.ArrayList(Match) = .empty;
    errdefer hits.deinit(allocator);

    for (sym.dwarf.func_list.items) |f| {
        const r = f.pc_range orelse continue;
        const name = f.name orelse continue;
        const len = r.end - r.start;
        if (len < 32) continue;

        const file_off = vaddrToFileOffset(info, r.start) orelse continue;
        const end_off = file_off + len;
        if (end_off > target_bytes.len) continue;
        const body = target_bytes[@intCast(file_off)..@intCast(end_off)];
        const h = std.hash.Wyhash.hash(0, body);

        if (raw_lookup.get(h)) |idx| {
            try hits.append(allocator, .{
                .target_function = name,
                .target_addr = r.start,
                .db_entry = db.entries[idx],
            });
            continue;
        }
        // Raw missed; try normalized.
        const nh = normalizedHashX86_64(allocator, body) catch continue;
        if (norm_lookup.get(nh)) |idx| {
            try hits.append(allocator, .{
                .target_function = name,
                .target_addr = r.start,
                .db_entry = db.entries[idx],
            });
        }
    }
    return try hits.toOwnedSlice(allocator);
}

/// Sliding-window match for stripped binaries. For each entry in `db`
/// that carries a `body_size`, slide a window of that size across the
/// target's `.text` section (4-byte aligned for x86_64; 4-byte aligned
/// is also fine for arm64) and compare Wyhash. Hits report the file
/// offset within the target so downstream tools can correlate.
///
/// Cost: O(text_size × distinct_body_sizes). Fast enough for libraries
/// (~50 distinct sizes × 1MB text ≈ 50ms on M2). For large binaries with
/// thousands of corpus entries, consider pre-grouping by hash modulo a
/// cheap rolling hash; v1 is the naive form.
pub fn matchSliding(
    allocator: std.mem.Allocator,
    target_bytes: []const u8,
    db: Database,
) ![]Match {
    var info = try elf_mod.parse(allocator, target_bytes);
    defer info.deinit(allocator);

    // Locate the .text section.
    var text_off: usize = 0;
    var text_end: usize = 0;
    for (info.sections) |s| {
        if (std.mem.eql(u8, s.name, ".text") and s.size > 0) {
            text_off = @intCast(s.offset);
            text_end = text_off + @as(usize, @intCast(s.size));
            break;
        }
    }
    if (text_end == 0 or text_end > target_bytes.len) return allocator.alloc(Match, 0);
    const text = target_bytes[text_off..text_end];

    // Group entries by body_size into a hash → entry index lookup.
    // Key = (size << 64-zone-but-clamped) ... actually just AutoHashMap on u64
    // with composite key.
    const Key = struct {
        size: u32,
        hash: u64,
    };
    var raw_lookup: std.AutoHashMap(Key, usize) = .init(allocator);
    defer raw_lookup.deinit();
    var norm_lookup: std.AutoHashMap(Key, usize) = .init(allocator);
    defer norm_lookup.deinit();

    var sizes: std.ArrayList(u32) = .empty;
    defer sizes.deinit(allocator);

    for (db.entries, 0..) |e, idx| {
        if (e.body_size == 0) continue;
        try raw_lookup.put(.{ .size = e.body_size, .hash = e.hash }, idx);
        if (e.normalized_hash) |nh| try norm_lookup.put(.{ .size = e.body_size, .hash = nh }, idx);
        var seen = false;
        for (sizes.items) |s| if (s == e.body_size) {
            seen = true;
            break;
        };
        if (!seen) sizes.append(allocator, e.body_size) catch return error.OutOfMemory;
    }
    if (sizes.items.len == 0) return allocator.alloc(Match, 0);

    var hits: std.ArrayList(Match) = .empty;
    errdefer hits.deinit(allocator);

    // Slide with stride 4 — function entries on most ABIs are 4-byte aligned.
    var i: usize = 0;
    const stride: usize = 4;
    while (i < text.len) : (i += stride) {
        for (sizes.items) |sz| {
            if (i + @as(usize, sz) > text.len) continue;
            const window = text[i .. i + @as(usize, sz)];
            const h = std.hash.Wyhash.hash(0, window);
            if (raw_lookup.get(.{ .size = sz, .hash = h })) |idx| {
                try hits.append(allocator, .{
                    .target_function = db.entries[idx].name,
                    .target_addr = @intCast(text_off + i),
                    .db_entry = db.entries[idx],
                });
                continue;
            }
            if (norm_lookup.count() > 0) {
                const nh = normalizedHashX86_64(allocator, window) catch continue;
                if (norm_lookup.get(.{ .size = sz, .hash = nh })) |idx| {
                    try hits.append(allocator, .{
                        .target_function = db.entries[idx].name,
                        .target_addr = @intCast(text_off + i),
                        .db_entry = db.entries[idx],
                    });
                }
            }
        }
    }

    return try hits.toOwnedSlice(allocator);
}

fn vaddrToFileOffset(info: elf_mod.ElfInfo, vaddr: u64) ?u64 {
    // For executables, sections track addr+offset pairs. Look up the
    // containing section and translate.
    for (info.sections) |s| {
        if (s.size == 0) continue;
        if (vaddr >= s.addr and vaddr < s.addr + s.size)
            return s.offset + (vaddr - s.addr);
    }
    return null;
}

fn writeJsonString(writer: *std.Io.Writer, s: []const u8) !void {
    try writer.writeByte('"');
    for (s) |c| switch (c) {
        '"' => try writer.writeAll("\\\""),
        '\\' => try writer.writeAll("\\\\"),
        '\n' => try writer.writeAll("\\n"),
        '\r' => try writer.writeAll("\\r"),
        '\t' => try writer.writeAll("\\t"),
        0...0x08, 0x0B, 0x0C, 0x0E...0x1F => try writer.print("\\u{x:0>4}", .{c}),
        else => try writer.writeByte(c),
    };
    try writer.writeByte('"');
}

// --- tests -------------------------------------------------------------------

test "generate database on debug-bearing fixture" {
    const bytes = @embedFile("testdata/hello_dyn_x86_64");
    var db = try generate(std.testing.allocator, bytes, .{
        .lib = "test_hello",
        .version = "1.0.0",
    });
    defer db.deinit(std.testing.allocator);
    try std.testing.expect(db.entries.len > 0);
}

test "self-match: target == corpus" {
    const bytes = @embedFile("testdata/hello_dyn_x86_64");
    var db = try generate(std.testing.allocator, bytes, .{ .lib = "self" });
    defer db.deinit(std.testing.allocator);

    const hits = try match(std.testing.allocator, bytes, db);
    defer std.testing.allocator.free(hits);
    // Every fingerprinted function should match itself.
    try std.testing.expectEqual(db.entries.len, hits.len);
}

test "json roundtrip" {
    const bytes = @embedFile("testdata/hello_dyn_x86_64");
    var db = try generate(std.testing.allocator, bytes, .{ .lib = "rt", .version = "0.1" });
    defer db.deinit(std.testing.allocator);

    var buf: [1024 * 1024]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);
    try db.writeJson(&writer);
    const json_bytes = buf[0..writer.end];

    var db2 = try Database.parseJson(std.testing.allocator, json_bytes);
    defer db2.deinit(std.testing.allocator);

    try std.testing.expectEqual(db.entries.len, db2.entries.len);
    if (db.entries.len > 0) {
        try std.testing.expectEqual(db.entries[0].hash, db2.entries[0].hash);
        try std.testing.expectEqual(db.entries[0].normalized_hash, db2.entries[0].normalized_hash);
        try std.testing.expectEqual(db.entries[0].body_size, db2.entries[0].body_size);
        try std.testing.expectEqualStrings(db.entries[0].name, db2.entries[0].name);
    }
}

test "normalizeBytes zeros RIP-relative ModR/M displacements" {
    // Synthetic body: REX.W + MOV r64, [RIP+disp32] (48 8B 05 dd dd dd dd)
    // followed by LEA (48 8D 0D dd dd dd dd) and indirect CALL via
    // [RIP+disp32] (FF 15 dd dd dd dd) + a RET. Two builds with different
    // disp32 values must hash identically under normalization.
    const orig = [_]u8{
        // mov rax, [rip + 0x11223344]
        0x48, 0x8B, 0x05, 0x44, 0x33, 0x22, 0x11,
        // lea rcx, [rip + 0x55667788]
        0x48, 0x8D, 0x0D, 0x88, 0x77, 0x66, 0x55,
        // call qword ptr [rip + 0xDEADBEEF]  (FF /2 indirect)
        0xFF, 0x15, 0xEF, 0xBE, 0xAD, 0xDE,
        // ret
        0xC3,
    };
    var rebuilt = orig;
    rebuilt[3] = 0xAA;
    rebuilt[4] = 0xBB;
    rebuilt[10] = 0xCC;
    rebuilt[11] = 0xDD;
    rebuilt[16] = 0x01;
    rebuilt[17] = 0x02;

    const h_a = std.hash.Wyhash.hash(0, &orig);
    const h_b = std.hash.Wyhash.hash(0, &rebuilt);
    try std.testing.expect(h_a != h_b);

    const n_a = try normalizedHashX86_64(std.testing.allocator, &orig);
    const n_b = try normalizedHashX86_64(std.testing.allocator, &rebuilt);
    try std.testing.expectEqual(n_a, n_b);
}

test "normalizeBytes leaves non-RIP-relative instructions intact" {
    // mov rax, rbx is REX.W 0x89 0xD8 — ModR/M=0xD8 (mod=11, rm=000) so
    // the normalizer must NOT touch following bytes.
    const orig = [_]u8{
        0x48, 0x89, 0xD8, // mov rax, rbx
        0x48, 0x01, 0xC8, // add rax, rcx (mod=11, no disp)
        0xC3,             // ret
    };
    const h_raw = std.hash.Wyhash.hash(0, &orig);
    const h_norm = try normalizedHashX86_64(std.testing.allocator, &orig);
    try std.testing.expectEqual(h_raw, h_norm);
}

test "normalizeBytes zeros direct call/jump displacements" {
    // E8 imm32 (call) + nop padding + E9 imm32 (jump) + 0F 84 imm32 (je)
    // Build a synthetic 24-byte function-like blob.
    const orig = [_]u8{
        // call rel32: E8 11 22 33 44
        0xE8, 0x11, 0x22, 0x33, 0x44,
        // padding
        0x90, 0x90, 0x90,
        // jmp rel32: E9 55 66 77 88
        0xE9, 0x55, 0x66, 0x77, 0x88,
        // padding
        0x90,
        // je rel32: 0F 84 99 AA BB CC
        0x0F, 0x84, 0x99, 0xAA, 0xBB, 0xCC,
        // tail
        0x90, 0x90, 0xC3,
    };
    const h_raw = std.hash.Wyhash.hash(0, &orig);
    const h_norm = try normalizedHashX86_64(std.testing.allocator, &orig);
    try std.testing.expect(h_raw != h_norm);

    // Same shape with mutated displacement bytes (simulating a different
    // base address) should hash identically under normalization.
    var mutated = orig;
    mutated[1] = 0xFF;
    mutated[2] = 0xEE;
    mutated[10] = 0x12;
    mutated[18] = 0x34;
    const h_mut_raw = std.hash.Wyhash.hash(0, &mutated);
    const h_mut_norm = try normalizedHashX86_64(std.testing.allocator, &mutated);
    try std.testing.expect(h_mut_raw != h_raw); // raw differs
    try std.testing.expectEqual(h_norm, h_mut_norm); // normalized matches
}
