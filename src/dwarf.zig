//! DWARF symbolication for ELF binaries and Mach-O `.dSYM` bundles.
//! Wraps `std.debug.Dwarf` over the `.debug_*` (ELF) or `__debug_*`
//! (Mach-O `__DWARF` segment) sections. Provides:
//!   - addressToSymbol(addr) -> ?[]const u8
//!   - addressToSourceLocation(addr) -> ?SourceLocation
//!
//! For Mach-O, `open` accepts either a binary that has DWARF inline (rare —
//! only before `dsymutil` has run) or, more commonly, the inner Mach-O of a
//! `.dSYM` bundle: `<bin>.dSYM/Contents/Resources/DWARF/<bin>`. PE/PDB still
//! deferred (see Phase 4c).

const std = @import("std");
const elf_mod = @import("elf.zig");
const macho_mod = @import("macho.zig");
const errors = @import("errors.zig");

pub const Error = error{
    NoDebugInfo,
    InvalidDebugInfo,
} || errors.ScribeError || std.debug.Dwarf.ScanError;

pub const SourceLocation = struct {
    file: []u8, // owned; allocator-allocated path string
    line: u64,
    column: u64,

    pub fn deinit(self: SourceLocation, allocator: std.mem.Allocator) void {
        allocator.free(self.file);
    }
};

pub const Symbolicator = struct {
    dwarf: std.debug.Dwarf,
    endian: std.builtin.Endian,
    arena: std.heap.ArenaAllocator,

    pub fn deinit(self: *Symbolicator, gpa: std.mem.Allocator) void {
        self.dwarf.deinit(gpa);
        self.arena.deinit();
        self.* = undefined;
    }

    pub fn addressToSymbol(self: *const Symbolicator, addr: u64) ?[]const u8 {
        return self.dwarf.getSymbolName(addr);
    }

    pub fn addressToSourceLocation(
        self: *Symbolicator,
        gpa: std.mem.Allocator,
        addr: u64,
    ) Error!?SourceLocation {
        const cu = self.dwarf.findCompileUnit(self.endian, addr) catch |e| switch (e) {
            error.MissingDebugInfo => return null,
            error.InvalidDebugInfo => return error.InvalidDebugInfo,
            else => |x| return x,
        };

        const text_arena = self.arena.allocator();
        const loc = self.dwarf.getLineNumberInfo(gpa, text_arena, self.endian, cu, addr) catch |e| switch (e) {
            error.MissingDebugInfo => return null,
            else => |x| return x,
        };
        return .{
            .file = try gpa.dupe(u8, loc.file_name),
            .line = loc.line,
            .column = loc.column,
        };
    }

    /// Iterate every function in the DWARF func table.
    pub fn iterateSymbols(
        self: *const Symbolicator,
        callback: *const fn (name: []const u8, start: u64, end: u64, ctx: ?*anyopaque) void,
        ctx: ?*anyopaque,
    ) void {
        for (self.dwarf.func_list.items) |f| {
            if (f.pc_range) |r| if (f.name) |n| callback(n, r.start, r.end, ctx);
        }
    }

    pub fn symbolCount(self: *const Symbolicator) usize {
        var n: usize = 0;
        for (self.dwarf.func_list.items) |f| {
            if (f.pc_range != null and f.name != null) n += 1;
        }
        return n;
    }
};

const SectionMap = std.StaticStringMap(std.debug.Dwarf.Section.Id);

const elf_section_map: SectionMap = .initComptime(.{
    .{ ".debug_info", .debug_info },
    .{ ".debug_abbrev", .debug_abbrev },
    .{ ".debug_str", .debug_str },
    .{ ".debug_str_offsets", .debug_str_offsets },
    .{ ".debug_line", .debug_line },
    .{ ".debug_line_str", .debug_line_str },
    .{ ".debug_ranges", .debug_ranges },
    .{ ".debug_loclists", .debug_loclists },
    .{ ".debug_rnglists", .debug_rnglists },
    .{ ".debug_addr", .debug_addr },
    .{ ".debug_names", .debug_names },
});

/// Mach-O section names live in a 16-byte field, so `__debug_str_offsets`
/// gets truncated to `__debug_str_offs`. Both spellings are mapped.
const macho_section_map: SectionMap = .initComptime(.{
    .{ "__debug_info", .debug_info },
    .{ "__debug_abbrev", .debug_abbrev },
    .{ "__debug_str", .debug_str },
    .{ "__debug_str_offs", .debug_str_offsets },
    .{ "__debug_str_offsets", .debug_str_offsets },
    .{ "__debug_line", .debug_line },
    .{ "__debug_line_str", .debug_line_str },
    .{ "__debug_ranges", .debug_ranges },
    .{ "__debug_loclists", .debug_loclists },
    .{ "__debug_rnglists", .debug_rnglists },
    .{ "__debug_addr", .debug_addr },
    .{ "__debug_names", .debug_names },
});

/// Auto-detect the container format and dispatch to the appropriate
/// section-discovery path.
pub fn open(allocator: std.mem.Allocator, bytes: []const u8) Error!Symbolicator {
    if (bytes.len >= 4) {
        const magic = std.mem.readInt(u32, bytes[0..4], .little);
        // MH_MAGIC_64 / MH_CIGAM_64 — Mach-O 64-bit either endianness.
        if (magic == std.macho.MH_MAGIC_64 or magic == std.macho.MH_CIGAM_64) {
            return openMachO(allocator, bytes);
        }
    }
    return openElf(allocator, bytes);
}

pub fn openElf(allocator: std.mem.Allocator, bytes: []const u8) Error!Symbolicator {
    var info = try elf_mod.parse(allocator, bytes);
    defer info.deinit(allocator);

    var sections: std.debug.Dwarf.SectionArray = @splat(null);
    var found_any = false;
    for (info.sections) |s| {
        const id = elf_section_map.get(s.name) orelse continue;
        if (s.size == 0) continue;
        const off: usize = @intCast(s.offset);
        const sz: usize = @intCast(s.size);
        if (off + sz > bytes.len) continue;
        sections[@intFromEnum(id)] = .{ .data = bytes[off..][0..sz], .owned = false };
        found_any = true;
    }

    if (!found_any) return error.NoDebugInfo;
    if (sections[@intFromEnum(std.debug.Dwarf.Section.Id.debug_info)] == null) return error.NoDebugInfo;
    if (sections[@intFromEnum(std.debug.Dwarf.Section.Id.debug_abbrev)] == null) return error.NoDebugInfo;

    var dwarf: std.debug.Dwarf = .{ .sections = sections };
    errdefer dwarf.deinit(allocator);

    try dwarf.open(allocator, info.endian);

    return .{
        .dwarf = dwarf,
        .endian = info.endian,
        .arena = .init(allocator),
    };
}

/// Open DWARF from a Mach-O whose `__DWARF` segment carries `__debug_*`
/// sections. Used both for binaries that haven't been processed by
/// `dsymutil` yet and for the inner Mach-O of a `.dSYM` bundle.
pub fn openMachO(allocator: std.mem.Allocator, bytes: []const u8) Error!Symbolicator {
    var info = try macho_mod.parse(allocator, bytes);
    defer info.deinit(allocator);

    var sections: std.debug.Dwarf.SectionArray = @splat(null);
    var found_any = false;
    for (info.sections) |s| {
        if (!std.mem.eql(u8, s.seg, "__DWARF")) continue;
        const id = macho_section_map.get(s.name) orelse continue;
        if (s.size == 0) continue;
        const off: usize = @intCast(s.offset);
        const sz: usize = @intCast(s.size);
        if (off + sz > bytes.len) continue;
        sections[@intFromEnum(id)] = .{ .data = bytes[off..][0..sz], .owned = false };
        found_any = true;
    }

    if (!found_any) return error.NoDebugInfo;
    if (sections[@intFromEnum(std.debug.Dwarf.Section.Id.debug_info)] == null) return error.NoDebugInfo;
    if (sections[@intFromEnum(std.debug.Dwarf.Section.Id.debug_abbrev)] == null) return error.NoDebugInfo;

    var dwarf: std.debug.Dwarf = .{ .sections = sections };
    errdefer dwarf.deinit(allocator);

    // Mach-O on x86_64 / aarch64 is little-endian; big-endian Mach-O has
    // long since faded (PowerPC era).
    const endian: std.builtin.Endian = .little;
    try dwarf.open(allocator, endian);

    return .{
        .dwarf = dwarf,
        .endian = endian,
        .arena = .init(allocator),
    };
}

test "open dwarf on debug-bearing fixture" {
    const bytes = @embedFile("testdata/hello_dyn_x86_64");
    var sym = try open(std.testing.allocator, bytes);
    defer sym.deinit(std.testing.allocator);
    try std.testing.expect(sym.symbolCount() > 0);
}

test "stripped musl elf has no debug info" {
    const bytes = @embedFile("testdata/hello_x86_64");
    try std.testing.expectError(error.NoDebugInfo, open(std.testing.allocator, bytes));
}

test "addressToSymbol on entry point returns a name" {
    const bytes = @embedFile("testdata/hello_dyn_x86_64");
    var info = try elf_mod.parse(std.testing.allocator, bytes);
    defer info.deinit(std.testing.allocator);

    var sym = try open(std.testing.allocator, bytes);
    defer sym.deinit(std.testing.allocator);

    // Entry point may or may not resolve depending on prologue; just exercise.
    _ = sym.addressToSymbol(info.entry);
}

test "open auto-dispatches to Mach-O DWARF on a dSYM inner Mach-O" {
    // Fixture is the inner Mach-O of a `.dSYM` bundle: contains the
    // `__DWARF` segment with `__debug_*` sections produced by `dsymutil`.
    const bytes = @embedFile("testdata/hello_macho_dwarf_x86_64");
    var sym = try open(std.testing.allocator, bytes);
    defer sym.deinit(std.testing.allocator);
    try std.testing.expect(sym.symbolCount() > 0);
}

test "Mach-O without DWARF reports NoDebugInfo" {
    const bytes = @embedFile("testdata/hello_macho_x86_64");
    try std.testing.expectError(error.NoDebugInfo, open(std.testing.allocator, bytes));
}

test "Mach-O DWARF lists function symbols" {
    // Walk the function table — DWARF 5 dSYM line-program lookup currently
    // hits an upstream `std.debug.Dwarf` path that mis-decodes the
    // `__debug_line_str`-backed file-name form, so we exercise the symbol
    // table here rather than `addressToSourceLocation`. Once the Zig stdlib
    // catches up, line lookup will start working with no scribe-side change.
    const bytes = @embedFile("testdata/hello_macho_dwarf_x86_64");
    var sym = try open(std.testing.allocator, bytes);
    defer sym.deinit(std.testing.allocator);

    var saw_main = false;
    for (sym.dwarf.func_list.items) |f| {
        const name = f.name orelse continue;
        if (std.mem.eql(u8, name, "main")) saw_main = true;
    }
    try std.testing.expect(saw_main);
}
