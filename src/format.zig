const std = @import("std");
const elf = @import("elf.zig");
const macho = @import("macho.zig");
const pe = @import("pe.zig");
const errors = @import("errors.zig");

pub const Kind = enum { elf, macho, pe };

pub const Info = union(Kind) {
    elf: elf.ElfInfo,
    macho: macho.MachoInfo,
    pe: pe.PeInfo,

    pub fn deinit(self: *Info, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .elf => |*e| e.deinit(allocator),
            .macho => |*m| m.deinit(allocator),
            .pe => |*p| p.deinit(allocator),
        }
    }

    pub fn arch(self: Info) elf.Arch {
        return switch (self) {
            .elf => |e| e.arch,
            .macho => |m| m.arch,
            .pe => |p| p.arch,
        };
    }

    pub fn entry(self: Info) u64 {
        return switch (self) {
            .elf => |e| e.entry,
            .macho => |m| m.entry,
            .pe => |p| p.entry,
        };
    }

    pub fn is64(self: Info) bool {
        return switch (self) {
            .elf => |e| e.is_64,
            .macho => |m| m.is_64,
            .pe => |p| p.is_64,
        };
    }
};

pub fn detect(bytes: []const u8) errors.ScribeError!Kind {
    if (bytes.len >= 4 and std.mem.eql(u8, bytes[0..4], std.elf.MAGIC)) return .elf;
    if (bytes.len >= 4) {
        const m = std.mem.readInt(u32, bytes[0..4], .little);
        if (m == std.macho.MH_MAGIC or m == std.macho.MH_CIGAM or
            m == std.macho.MH_MAGIC_64 or m == std.macho.MH_CIGAM_64)
            return .macho;
    }
    if (bytes.len >= 2 and bytes[0] == 'M' and bytes[1] == 'Z') return .pe;
    return error.NotElf;
}

pub fn parse(allocator: std.mem.Allocator, bytes: []const u8) errors.ScribeError!Info {
    return switch (try detect(bytes)) {
        .elf => .{ .elf = try elf.parse(allocator, bytes) },
        .macho => .{ .macho = try macho.parse(allocator, bytes) },
        .pe => .{ .pe = try pe.parse(allocator, bytes) },
    };
}

test "detect ELF" {
    const bytes = [_]u8{ 0x7F, 'E', 'L', 'F' } ++ ([_]u8{0} ** 64);
    try std.testing.expectEqual(Kind.elf, try detect(&bytes));
}

test "detect Mach-O 64" {
    var bytes: [16]u8 = @splat(0);
    std.mem.writeInt(u32, bytes[0..4], std.macho.MH_MAGIC_64, .little);
    try std.testing.expectEqual(Kind.macho, try detect(&bytes));
}

test "detect PE" {
    const bytes = [_]u8{ 'M', 'Z' } ++ ([_]u8{0} ** 14);
    try std.testing.expectEqual(Kind.pe, try detect(&bytes));
}

test "detect rejects unknown" {
    const bytes = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF } ++ ([_]u8{0} ** 12);
    try std.testing.expectError(error.NotElf, detect(&bytes));
}
