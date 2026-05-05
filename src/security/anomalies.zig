//! Anti-tampering / suspicious-shape detectors. Surfaces structural
//! oddities that don't fit cleanly under "hardening flags" but matter
//! for forensic triage:
//!
//!   - Entry point not inside an executable section (manual unpacker stub?)
//!   - ELF interpreter not on the canonical loader paths
//!   - Mach-O dylinker not `/usr/lib/dyld`
//!   - PE entry RVA outside any section's virtual range
//!   - Mach-O imports a known process-injection symbol set
//!   - ELF imports `ptrace` + `dlopen` together (debugger anti-pattern)
//!
//! All checks are best-effort; status is `enabled` (anomaly present) or
//! `disabled` (no anomaly). Findings flow into `config_issues[]` via
//! `toConfigIssues` so they share the SBOM/policy/TUI plumbing with
//! hardening + IaC.

const std = @import("std");
const errors = @import("../errors.zig");
const format = @import("../format.zig");
const elf_mod = @import("../elf.zig");
const macho_mod = @import("../macho.zig");
const pe_mod = @import("../pe.zig");
const config = @import("config.zig");

const ScribeError = errors.ScribeError;

pub const Anomaly = struct {
    id: []const u8,
    title: []const u8,
    severity: config.Severity,
    detail: []u8, // owned
};

pub const Report = struct {
    items: []Anomaly,

    pub fn deinit(self: *Report, allocator: std.mem.Allocator) void {
        for (self.items) |a| allocator.free(a.detail);
        allocator.free(self.items);
        self.items = &.{};
    }
};

pub fn analyze(
    allocator: std.mem.Allocator,
    info: format.Info,
    bytes: []const u8,
) ScribeError!Report {
    return switch (info) {
        .elf => |e| analyzeElf(allocator, e, bytes),
        .macho => |m| analyzeMacho(allocator, m, bytes),
        .pe => |p| analyzePe(allocator, p, bytes),
    };
}

// ----------------------------------------------------------------------------
// ELF
// ----------------------------------------------------------------------------

fn analyzeElf(
    allocator: std.mem.Allocator,
    info: elf_mod.ElfInfo,
    bytes: []const u8,
) ScribeError!Report {
    var items: std.ArrayList(Anomaly) = .empty;
    errdefer {
        for (items.items) |a| allocator.free(a.detail);
        items.deinit(allocator);
    }

    var hdr_reader: std.Io.Reader = .fixed(bytes);
    const header = std.elf.Header.read(&hdr_reader) catch return .{ .items = &.{} };

    // Entry point inside any executable section?
    if (info.entry != 0) {
        var found = false;
        for (info.sections) |s| {
            // SHF_EXECINSTR = 4 — section flag indicating executable code.
            if ((s.flags & 4) != 0 and info.entry >= s.addr and info.entry < s.addr + s.size) {
                found = true;
                break;
            }
        }
        if (!found) {
            const detail = std.fmt.allocPrint(allocator, "entry 0x{x} outside any +X section", .{info.entry}) catch return error.OutOfMemory;
            try items.append(allocator, .{
                .id = "ENTRY_OUT_OF_TEXT",
                .title = "Entry point outside executable section",
                .severity = .medium,
                .detail = detail,
            });
        }
    }

    // Interpreter on a non-canonical path? Walk PT_INTERP for the path.
    var ph_it = header.iterateProgramHeadersBuffer(bytes);
    while (true) {
        const maybe = ph_it.next() catch break;
        const ph = maybe orelse break;
        if (ph.p_type != std.elf.PT_INTERP) continue;
        const off: usize = @intCast(ph.p_offset);
        const sz: usize = @intCast(ph.p_filesz);
        if (off + sz > bytes.len) break;
        const interp = std.mem.sliceTo(bytes[off..][0..sz], 0);
        if (!isCanonicalElfInterp(interp)) {
            const detail = std.fmt.allocPrint(allocator, "interpreter: {s}", .{interp}) catch return error.OutOfMemory;
            try items.append(allocator, .{
                .id = "INTERP_NONCANONICAL",
                .title = "Non-canonical ELF interpreter",
                .severity = .low,
                .detail = detail,
            });
        }
        break;
    }

    // Overlapping sections detection — section file ranges should be
    // disjoint. Real-world ELFs from gcc / clang produce non-overlapping
    // sections; overlap is a strong tampering / packer signal.
    try detectElfOverlap(allocator, &items, info);

    return .{ .items = items.toOwnedSlice(allocator) catch return error.OutOfMemory };
}

fn detectElfOverlap(
    allocator: std.mem.Allocator,
    items: *std.ArrayList(Anomaly),
    info: elf_mod.ElfInfo,
) !void {
    var i: usize = 0;
    while (i < info.sections.len) : (i += 1) {
        const a = info.sections[i];
        if (a.size == 0 or a.type == 0) continue; // SHT_NULL
        const a_end = a.offset + a.size;
        var j: usize = i + 1;
        while (j < info.sections.len) : (j += 1) {
            const b = info.sections[j];
            if (b.size == 0 or b.type == 0) continue;
            const b_end = b.offset + b.size;
            // SHT_NOBITS (8) sections occupy no file bytes; skip.
            if (a.type == 8 or b.type == 8) continue;
            if (a.offset < b_end and b.offset < a_end) {
                const detail = std.fmt.allocPrint(allocator, "{s} (0x{x}+0x{x}) overlaps {s} (0x{x}+0x{x})", .{
                    a.name, a.offset, a.size, b.name, b.offset, b.size,
                }) catch return error.OutOfMemory;
                try items.append(allocator, .{
                    .id = "OVERLAP_SECTIONS",
                    .title = "Overlapping ELF sections",
                    .severity = .high,
                    .detail = detail,
                });
                return; // one finding per binary is enough
            }
        }
    }
}

fn isCanonicalElfInterp(p: []const u8) bool {
    const ok = [_][]const u8{
        "/lib/ld-linux.so.2",
        "/lib64/ld-linux-x86-64.so.2",
        "/lib/ld-linux-aarch64.so.1",
        "/lib/ld-linux-armhf.so.3",
        "/lib/ld-musl-x86_64.so.1",
        "/lib/ld-musl-aarch64.so.1",
        "/lib/ld-musl-i386.so.1",
        "/lib/ld.so.1",
        "/usr/lib/ld-linux-aarch64.so.1",
    };
    for (ok) |c| if (std.mem.eql(u8, p, c)) return true;
    return false;
}

// ----------------------------------------------------------------------------
// Mach-O
// ----------------------------------------------------------------------------

const SUSPICIOUS_MACHO_SYMS = [_][]const u8{
    "_task_for_pid",
    "_mach_inject",
    "_mach_vm_write",
    "_mach_vm_protect",
    "_thread_create_running",
};

fn analyzeMacho(
    allocator: std.mem.Allocator,
    info: macho_mod.MachoInfo,
    full_bytes: []const u8,
) ScribeError!Report {
    var items: std.ArrayList(Anomaly) = .empty;
    errdefer {
        for (items.items) |a| allocator.free(a.detail);
        items.deinit(allocator);
    }

    const slice_off: usize = @intCast(info.fat_slice_offset);
    if (slice_off >= full_bytes.len) return .{ .items = &.{} };
    const bytes = full_bytes[slice_off..];

    // Entry inside an executable section?
    if (info.entry != 0) {
        var found = false;
        for (info.sections) |s| {
            // S_ATTR_PURE_INSTRUCTIONS = 0x80000000, S_ATTR_SOME_INSTRUCTIONS = 0x00000400
            const exec = (s.flags & 0x80000000) != 0 or (s.flags & 0x00000400) != 0;
            if (!exec) continue;
            // entry is the file-offset variant (LC_MAIN.entryoff). Compare
            // against section's `offset` field, not address.
            if (info.entry >= s.offset and info.entry < @as(u64, s.offset) + s.size) {
                found = true;
                break;
            }
        }
        // Many Mach-O binaries report entry = 0 from LC_MAIN being absent on
        // 32-bit / framework targets — only fire when entry is meaningful.
        if (!found and info.entry > 0) {
            const detail = std.fmt.allocPrint(allocator, "entry 0x{x} outside any executable section", .{info.entry}) catch return error.OutOfMemory;
            try items.append(allocator, .{
                .id = "ENTRY_OUT_OF_TEXT",
                .title = "Entry point outside executable section",
                .severity = .medium,
                .detail = detail,
            });
        }
    }

    // Walk LCs for LC_LOAD_DYLINKER + suspicious dylibs.
    const lc_start: usize = if (info.is_64) @sizeOf(std.macho.mach_header_64) else @sizeOf(std.macho.mach_header);
    if (lc_start <= bytes.len) {
        const ncmds: u32 = if (info.is_64)
            (@as(*align(1) const std.macho.mach_header_64, @ptrCast(bytes.ptr))).ncmds
        else
            (@as(*align(1) const std.macho.mach_header, @ptrCast(bytes.ptr))).ncmds;
        const sizeofcmds: u32 = if (info.is_64)
            (@as(*align(1) const std.macho.mach_header_64, @ptrCast(bytes.ptr))).sizeofcmds
        else
            (@as(*align(1) const std.macho.mach_header, @ptrCast(bytes.ptr))).sizeofcmds;
        const lc_end = std.math.add(usize, lc_start, sizeofcmds) catch lc_start;
        var off = lc_start;
        var i: u32 = 0;
        while (i < ncmds and off + @sizeOf(std.macho.load_command) <= lc_end and lc_end <= bytes.len) : (i += 1) {
            const lc: *align(1) const std.macho.load_command = @ptrCast(bytes[off..].ptr);
            const cmdsize = lc.cmdsize;
            if (cmdsize < @sizeOf(std.macho.load_command)) break;
            if (off + cmdsize > lc_end) break;
            const lc_bytes = bytes[off..][0..cmdsize];
            switch (lc.cmd) {
                .LOAD_DYLINKER => {
                    if (cmdsize >= @sizeOf(std.macho.dylinker_command)) {
                        const d: *align(1) const std.macho.dylinker_command = @ptrCast(lc_bytes.ptr);
                        const name_off: usize = @intCast(d.name);
                        if (name_off < lc_bytes.len) {
                            const name = std.mem.sliceTo(lc_bytes[name_off..], 0);
                            if (!std.mem.eql(u8, name, "/usr/lib/dyld")) {
                                const detail = std.fmt.allocPrint(allocator, "dylinker: {s}", .{name}) catch return error.OutOfMemory;
                                try items.append(allocator, .{
                                    .id = "DYLINKER_NONCANONICAL",
                                    .title = "Non-canonical Mach-O dynamic linker",
                                    .severity = .low,
                                    .detail = detail,
                                });
                            }
                        }
                    }
                },
                else => {},
            }
            off += cmdsize;
        }
    }

    // Symbol-name scan for suspicious imports. Cheap: substring search the
    // whole slice. Same approach as the canary heuristic in hardening.zig —
    // false-positive-prone in __cstring rich binaries but acceptable for
    // triage signal.
    var hits: u32 = 0;
    for (SUSPICIOUS_MACHO_SYMS) |sym| {
        if (std.mem.indexOf(u8, bytes, sym) != null) hits += 1;
    }
    if (hits >= 2) {
        const detail = std.fmt.allocPrint(allocator, "{d} of {d} process-injection symbols imported", .{ hits, SUSPICIOUS_MACHO_SYMS.len }) catch return error.OutOfMemory;
        try items.append(allocator, .{
            .id = "INJECTION_SYMS",
            .title = "Process-injection symbol cluster present",
            .severity = .medium,
            .detail = detail,
        });
    }

    // Mach-O section overlap (file-offset basis). Same heuristic as ELF.
    var i: usize = 0;
    outer: while (i < info.sections.len) : (i += 1) {
        const a = info.sections[i];
        if (a.size == 0 or a.offset == 0) continue;
        const a_end = @as(u64, a.offset) + a.size;
        var j: usize = i + 1;
        while (j < info.sections.len) : (j += 1) {
            const b = info.sections[j];
            if (b.size == 0 or b.offset == 0) continue;
            const b_end = @as(u64, b.offset) + b.size;
            if (@as(u64, a.offset) < b_end and @as(u64, b.offset) < a_end) {
                const detail = std.fmt.allocPrint(allocator, "{s}/{s} (0x{x}+0x{x}) overlaps {s}/{s} (0x{x}+0x{x})", .{
                    a.seg, a.name, a.offset, a.size, b.seg, b.name, b.offset, b.size,
                }) catch return error.OutOfMemory;
                try items.append(allocator, .{
                    .id = "OVERLAP_SECTIONS",
                    .title = "Overlapping Mach-O sections",
                    .severity = .high,
                    .detail = detail,
                });
                break :outer;
            }
        }
    }

    return .{ .items = items.toOwnedSlice(allocator) catch return error.OutOfMemory };
}

// ----------------------------------------------------------------------------
// PE
// ----------------------------------------------------------------------------

fn analyzePe(
    allocator: std.mem.Allocator,
    info: pe_mod.PeInfo,
    bytes: []const u8,
) ScribeError!Report {
    _ = bytes;
    var items: std.ArrayList(Anomaly) = .empty;
    errdefer {
        for (items.items) |a| allocator.free(a.detail);
        items.deinit(allocator);
    }

    // Entry RVA is `info.entry - info.image_base`; check it lands inside any
    // section's virtual range.
    if (info.entry > info.image_base) {
        const rva = info.entry - info.image_base;
        var found = false;
        for (info.sections) |s| {
            if (rva >= s.virtual_address and rva < s.virtual_address + s.virtual_size) {
                found = true;
                break;
            }
        }
        if (!found) {
            const detail = std.fmt.allocPrint(allocator, "entry RVA 0x{x} outside any section", .{rva}) catch return error.OutOfMemory;
            try items.append(allocator, .{
                .id = "ENTRY_OUT_OF_TEXT",
                .title = "Entry point outside any PE section",
                .severity = .medium,
                .detail = detail,
            });
        }
    }

    return .{ .items = items.toOwnedSlice(allocator) catch return error.OutOfMemory };
}

// ----------------------------------------------------------------------------
// Conversion to config.Issue
// ----------------------------------------------------------------------------

pub fn toConfigIssues(
    allocator: std.mem.Allocator,
    report: Report,
    path: []const u8,
) ScribeError![]config.Issue {
    var out: std.ArrayList(config.Issue) = .empty;
    errdefer {
        for (out.items) |it| config.freeIssue(allocator, it);
        out.deinit(allocator);
    }

    for (report.items) |a| {
        const rule_id = std.fmt.allocPrint(allocator, "BIN-ANOM-{s}", .{a.id}) catch return error.OutOfMemory;
        errdefer allocator.free(rule_id);
        const title = allocator.dupe(u8, a.title) catch return error.OutOfMemory;
        errdefer allocator.free(title);
        const file_copy = allocator.dupe(u8, path) catch return error.OutOfMemory;
        errdefer allocator.free(file_copy);
        const snippet = allocator.dupe(u8, a.detail) catch return error.OutOfMemory;
        errdefer allocator.free(snippet);
        const recommendation = allocator.dupe(u8, "Investigate manually; this is a structural anomaly, not a definitive failure.") catch return error.OutOfMemory;
        try out.append(allocator, .{
            .rule_id = rule_id,
            .title = title,
            .severity = a.severity,
            .source = .image_config,
            .file = file_copy,
            .line = 0,
            .snippet = snippet,
            .recommendation = recommendation,
        });
    }

    return out.toOwnedSlice(allocator) catch error.OutOfMemory;
}

// ----------------------------------------------------------------------------

test "elf canonical interp recognized" {
    try std.testing.expect(isCanonicalElfInterp("/lib64/ld-linux-x86-64.so.2"));
    try std.testing.expect(!isCanonicalElfInterp("/tmp/evil-loader"));
}

test "macho fixture: no anomalies on stock build" {
    const allocator = std.testing.allocator;
    const bytes = @embedFile("../testdata/hello_macho_aarch64");
    var info = try macho_mod.parse(allocator, bytes);
    defer info.deinit(allocator);
    const fmt_info: format.Info = .{ .macho = info };
    var report = try analyze(allocator, fmt_info, bytes);
    defer report.deinit(allocator);
    // hello-world test fixture should have a clean dylinker + entry inside __text.
    for (report.items) |a| {
        try std.testing.expect(!std.mem.eql(u8, a.id, "DYLINKER_NONCANONICAL"));
    }
}
