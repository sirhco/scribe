//! DWARF symbolication for ELF binaries. Wraps `std.debug.Dwarf` over the
//! `.debug_*` sections that scribe's ELF parser locates. Provides:
//!   - addressToSymbol(addr) -> ?[]const u8
//!   - addressToSourceLocation(addr) -> ?SourceLocation
//!
//! Phase-4a: ELF only. Mach-O .dSYM and PE/PDB deferred.

const std = @import("std");
const elf_mod = @import("elf.zig");
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
const section_map: SectionMap = .initComptime(.{
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

pub fn open(allocator: std.mem.Allocator, bytes: []const u8) Error!Symbolicator {
    var info = try elf_mod.parse(allocator, bytes);
    defer info.deinit(allocator);

    var sections: std.debug.Dwarf.SectionArray = @splat(null);
    var found_any = false;
    for (info.sections) |s| {
        const id = section_map.get(s.name) orelse continue;
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
