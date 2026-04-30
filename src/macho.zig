const std = @import("std");
const errors = @import("errors.zig");
const elf = @import("elf.zig");

const ScribeError = errors.ScribeError;

pub const Arch = elf.Arch;

pub fn archFromCpu(cputype: i32) Arch {
    return switch (cputype) {
        std.macho.CPU_TYPE_X86_64 => .x86_64,
        std.macho.CPU_TYPE_ARM64 => .aarch64,
        7 => .x86, // CPU_TYPE_X86 (no constant in stdlib)
        12 => .arm, // CPU_TYPE_ARM
        else => .unknown,
    };
}

pub const Section = struct {
    name: []const u8,
    seg: []const u8,
    addr: u64,
    size: u64,
    offset: u32,
    flags: u32,
};

pub const Dylib = struct {
    name: []const u8,
    cmd: std.macho.LC,
};

pub const MachoInfo = struct {
    arch: Arch,
    cputype: i32,
    cpusubtype: i32,
    filetype: u32,
    is_64: bool,
    entry: u64,
    sections: []Section,
    dylibs: []Dylib,

    pub fn deinit(self: *MachoInfo, allocator: std.mem.Allocator) void {
        allocator.free(self.sections);
        allocator.free(self.dylibs);
        self.sections = &.{};
        self.dylibs = &.{};
    }
};

pub fn parse(allocator: std.mem.Allocator, bytes: []const u8) ScribeError!MachoInfo {
    if (bytes.len < @sizeOf(std.macho.mach_header_64)) return error.Truncated;

    const magic = std.mem.readInt(u32, bytes[0..4], .little);
    switch (magic) {
        std.macho.MH_MAGIC_64, std.macho.MH_CIGAM_64 => {},
        std.macho.MH_MAGIC, std.macho.MH_CIGAM => return error.UnsupportedClass, // 32-bit Mach-O is rare; skip for now
        0xCAFEBABE, 0xBEBAFECA, 0xCAFEBABF, 0xBFBAFECA => return error.UnsupportedClass, // FAT
        else => return error.NotElf, // not a recognized macho
    }

    const header: *align(1) const std.macho.mach_header_64 = @ptrCast(bytes.ptr);
    const ncmds = header.ncmds;
    const sizeofcmds = header.sizeofcmds;

    const lc_start = @sizeOf(std.macho.mach_header_64);
    const lc_end = std.math.add(usize, lc_start, sizeofcmds) catch return error.Truncated;
    if (lc_end > bytes.len) return error.Truncated;

    var sections: std.ArrayList(Section) = .empty;
    errdefer sections.deinit(allocator);
    var dylibs: std.ArrayList(Dylib) = .empty;
    errdefer dylibs.deinit(allocator);

    var entry: u64 = 0;

    var off: usize = lc_start;
    var i: u32 = 0;
    while (i < ncmds) : (i += 1) {
        if (off + @sizeOf(std.macho.load_command) > lc_end) return error.Truncated;
        const lc: *align(1) const std.macho.load_command = @ptrCast(bytes[off..].ptr);
        const cmdsize = lc.cmdsize;
        if (cmdsize < @sizeOf(std.macho.load_command)) return error.Truncated;
        if (off + cmdsize > lc_end) return error.Truncated;

        const lc_bytes = bytes[off..][0..cmdsize];

        switch (lc.cmd) {
            .SEGMENT_64 => {
                if (lc_bytes.len < @sizeOf(std.macho.segment_command_64)) return error.Truncated;
                const seg: *align(1) const std.macho.segment_command_64 = @ptrCast(lc_bytes.ptr);
                const sect_start = @sizeOf(std.macho.segment_command_64);
                var k: u32 = 0;
                while (k < seg.nsects) : (k += 1) {
                    const sect_off = sect_start + k * @sizeOf(std.macho.section_64);
                    if (sect_off + @sizeOf(std.macho.section_64) > lc_bytes.len) return error.Truncated;
                    const sect: *align(1) const std.macho.section_64 = @ptrCast(lc_bytes[sect_off..].ptr);
                    sections.append(allocator, .{
                        .name = trimName(&sect.sectname),
                        .seg = trimName(&sect.segname),
                        .addr = sect.addr,
                        .size = sect.size,
                        .offset = sect.offset,
                        .flags = sect.flags,
                    }) catch return error.OutOfMemory;
                }
            },
            .LOAD_DYLIB, .LOAD_WEAK_DYLIB, .REEXPORT_DYLIB, .LOAD_UPWARD_DYLIB, .LAZY_LOAD_DYLIB => {
                if (lc_bytes.len < @sizeOf(std.macho.dylib_command)) return error.Truncated;
                const dl: *align(1) const std.macho.dylib_command = @ptrCast(lc_bytes.ptr);
                const name_off: usize = @intCast(dl.dylib.name);
                if (name_off >= lc_bytes.len) return error.Truncated;
                const name = std.mem.sliceTo(lc_bytes[name_off..], 0);
                dylibs.append(allocator, .{ .name = name, .cmd = lc.cmd }) catch
                    return error.OutOfMemory;
            },
            .MAIN => {
                // entry_point_command: cmd, cmdsize, entryoff: u64, stacksize: u64
                if (lc_bytes.len >= @sizeOf(std.macho.entry_point_command)) {
                    const ep: *align(1) const std.macho.entry_point_command = @ptrCast(lc_bytes.ptr);
                    entry = ep.entryoff;
                }
            },
            else => {},
        }

        off += cmdsize;
    }

    return .{
        .arch = archFromCpu(header.cputype),
        .cputype = header.cputype,
        .cpusubtype = header.cpusubtype,
        .filetype = header.filetype,
        .is_64 = true,
        .entry = entry,
        .sections = sections.toOwnedSlice(allocator) catch return error.OutOfMemory,
        .dylibs = dylibs.toOwnedSlice(allocator) catch return error.OutOfMemory,
    };
}

fn trimName(name: *const [16]u8) []const u8 {
    const len = std.mem.indexOfScalar(u8, name, 0) orelse name.len;
    return name[0..len];
}

test "parse rejects non-macho magic" {
    const bytes = [_]u8{ 0, 0, 0, 0 } ++ ([_]u8{0} ** 60);
    try std.testing.expectError(error.NotElf, parse(std.testing.allocator, &bytes));
}

test "parse golden macho x86_64 fixture" {
    const bytes = @embedFile("testdata/hello_macho_x86_64");
    var info = try parse(std.testing.allocator, bytes);
    defer info.deinit(std.testing.allocator);
    try std.testing.expectEqual(Arch.x86_64, info.arch);
    try std.testing.expect(info.is_64);
    try std.testing.expect(info.sections.len > 0);

    var has_text = false;
    for (info.sections) |s| {
        if (std.mem.eql(u8, s.name, "__text") and std.mem.eql(u8, s.seg, "__TEXT")) has_text = true;
    }
    try std.testing.expect(has_text);
}

test "parse golden macho aarch64 fixture" {
    const bytes = @embedFile("testdata/hello_macho_aarch64");
    var info = try parse(std.testing.allocator, bytes);
    defer info.deinit(std.testing.allocator);
    try std.testing.expectEqual(Arch.aarch64, info.arch);
}
