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
    hash: u64,
    name: []u8, // owned
    lib: []u8, // owned
    version: ?[]u8 = null, // owned
};

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
            try writer.writeAll(", \"name\": ");
            try writeJsonString(writer, e.name);
            try writer.writeAll(", \"lib\": ");
            try writeJsonString(writer, e.lib);
            if (e.version) |v| {
                try writer.writeAll(", \"version\": ");
                try writeJsonString(writer, v);
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
                name: []const u8,
                lib: []const u8,
                version: ?[]const u8 = null,
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
            out[i] = .{
                .hash = hash,
                .name = try allocator.dupe(u8, raw.name),
                .lib = try allocator.dupe(u8, raw.lib),
                .version = if (raw.version) |v| try allocator.dupe(u8, v) else null,
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
        try entries.append(allocator, .{
            .hash = hash,
            .name = try allocator.dupe(u8, name),
            .lib = try allocator.dupe(u8, opts.lib),
            .version = if (opts.version) |v| try allocator.dupe(u8, v) else null,
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

    // Build hash -> entry index lookup.
    var lookup: std.AutoHashMap(u64, usize) = .init(allocator);
    defer lookup.deinit();
    for (db.entries, 0..) |e, i| try lookup.put(e.hash, i);

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

        if (lookup.get(h)) |idx| {
            try hits.append(allocator, .{
                .target_function = name,
                .target_addr = r.start,
                .db_entry = db.entries[idx],
            });
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
        try std.testing.expectEqualStrings(db.entries[0].name, db2.entries[0].name);
    }
}
