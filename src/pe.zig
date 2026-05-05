const std = @import("std");
const errors = @import("errors.zig");
const elf = @import("elf.zig");

const ScribeError = errors.ScribeError;
const Arch = elf.Arch;

pub fn archFromMachine(m: std.coff.IMAGE.FILE.MACHINE) Arch {
    return switch (m) {
        .AMD64 => .x86_64,
        .ARM64, .ARM64EC, .ARM64X => .aarch64,
        .I386 => .x86,
        .ARM, .ARMNT => .arm,
        else => .unknown,
    };
}

pub const Section = struct {
    name: []const u8,
    virtual_address: u32,
    virtual_size: u32,
    raw_offset: u32,
    raw_size: u32,
    characteristics: u32,
};

pub const PeInfo = struct {
    arch: Arch,
    machine: std.coff.IMAGE.FILE.MACHINE,
    is_64: bool,
    image_base: u64,
    entry: u64,
    sections: []Section,

    pub fn deinit(self: *PeInfo, allocator: std.mem.Allocator) void {
        for (self.sections) |s| allocator.free(s.name);
        allocator.free(self.sections);
        self.sections = &.{};
    }
};

pub fn parse(allocator: std.mem.Allocator, bytes: []const u8) ScribeError!PeInfo {
    if (bytes.len < 0x40) return error.Truncated;
    if (bytes[0] != 'M' or bytes[1] != 'Z') return error.UnsupportedFormat;

    const coff = std.coff.Coff.init(bytes, false) catch |e| switch (e) {
        error.EndOfStream => return error.Truncated,
        error.MissingPEHeader => return error.UnsupportedFormat,
    };

    const hdr = coff.getHeader();
    const opt = coff.getOptionalHeader();
    const is_64 = @intFromEnum(opt.magic) == std.coff.IMAGE_NT_OPTIONAL_HDR64_MAGIC;

    const sects = coff.getSectionHeaders();
    var out = allocator.alloc(Section, sects.len) catch return error.OutOfMemory;
    errdefer {
        for (out) |s| allocator.free(s.name);
        allocator.free(out);
    }

    for (sects, 0..) |*sh, i| {
        const raw_name = coff.getSectionName(sh) catch return error.InvalidStringTable;
        const name_copy = allocator.dupe(u8, raw_name) catch return error.OutOfMemory;
        out[i] = .{
            .name = name_copy,
            .virtual_address = sh.virtual_address,
            .virtual_size = sh.virtual_size,
            .raw_offset = sh.pointer_to_raw_data,
            .raw_size = sh.size_of_raw_data,
            .characteristics = @bitCast(sh.flags),
        };
    }

    return .{
        .arch = archFromMachine(hdr.machine),
        .machine = hdr.machine,
        .is_64 = is_64,
        .image_base = coff.getImageBase(),
        .entry = entryPoint(coff, is_64),
        .sections = out,
    };
}

fn entryPoint(coff: std.coff.Coff, is_64: bool) u64 {
    _ = is_64;
    return coff.getImageBase() + coff.getOptionalHeader().address_of_entry_point;
}

test "parse rejects non-PE magic" {
    const bytes = [_]u8{ 0, 0, 0, 0 } ++ ([_]u8{0} ** 0x40);
    try std.testing.expectError(error.UnsupportedFormat, parse(std.testing.allocator, &bytes));
}

test "parse golden pe x86_64 fixture" {
    const bytes = @embedFile("testdata/hello_pe_x86_64");
    var info = try parse(std.testing.allocator, bytes);
    defer info.deinit(std.testing.allocator);
    try std.testing.expectEqual(Arch.x86_64, info.arch);
    try std.testing.expect(info.is_64);
    try std.testing.expect(info.sections.len > 0);

    var has_text = false;
    for (info.sections) |s| {
        if (std.mem.eql(u8, s.name, ".text")) has_text = true;
    }
    try std.testing.expect(has_text);
}
