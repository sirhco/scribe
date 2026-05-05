const std = @import("std");
const builtin = @import("builtin");
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
    flags: u32,
    entry: u64,
    sections: []Section,
    dylibs: []Dylib,
    /// When the input was a FAT/Universal binary, the arch of the slice we
    /// picked. `null` for plain (thin) Mach-O inputs.
    fat_slice_arch: ?Arch = null,
    /// Byte offset of the chosen slice within the FAT image (0 for thin).
    /// Section/load-command offsets are relative to the slice, so any
    /// post-parse re-walk over the original bytes must add this base.
    fat_slice_offset: u64 = 0,

    pub fn deinit(self: *MachoInfo, allocator: std.mem.Allocator) void {
        allocator.free(self.sections);
        allocator.free(self.dylibs);
        self.sections = &.{};
        self.dylibs = &.{};
    }
};

/// `fat_arch_64` isn't exposed by the Zig 0.16 stdlib. Declare it here so we
/// can walk FAT_MAGIC_64 archives. Big-endian on disk like `fat_arch`.
const fat_arch_64 = extern struct {
    cputype: i32,
    cpusubtype: i32,
    offset: u64,
    size: u64,
    @"align": u32,
    reserved: u32,
};

pub fn parse(allocator: std.mem.Allocator, bytes: []const u8) ScribeError!MachoInfo {
    if (bytes.len < @sizeOf(std.macho.fat_header)) return error.Truncated;

    const magic = std.mem.readInt(u32, bytes[0..4], .little);
    return switch (magic) {
        std.macho.MH_MAGIC_64, std.macho.MH_CIGAM_64 => parseThin64(allocator, bytes, null),
        std.macho.MH_MAGIC, std.macho.MH_CIGAM => parseThin32(allocator, bytes, null),
        std.macho.FAT_MAGIC, std.macho.FAT_CIGAM => parseFat(allocator, bytes, false),
        std.macho.FAT_MAGIC_64, std.macho.FAT_CIGAM_64 => parseFat(allocator, bytes, true),
        else => error.UnsupportedFormat,
    };
}

/// Walk a FAT/Universal Mach-O. Pick the slice matching the host CPU when
/// possible; otherwise fall back to the first slice. The picked slice is
/// recursed into via `parseThin64`/`parseThin32`, and the resulting
/// `MachoInfo` is annotated with `fat_slice_arch` so callers can surface the
/// choice.
///
/// FAT headers and arch tables are stored big-endian on disk regardless of
/// host. The `*_CIGAM` magics describe the byte-swapped form (only ever
/// produced by big-endian hosts: PowerPC). Modern Apple binaries are always
/// FAT_MAGIC / FAT_MAGIC_64; we read big-endian directly.
fn parseFat(allocator: std.mem.Allocator, bytes: []const u8, is_64: bool) ScribeError!MachoInfo {
    if (bytes.len < @sizeOf(std.macho.fat_header)) return error.Truncated;
    const nfat = std.mem.readInt(u32, bytes[4..8], .big);
    if (nfat == 0 or nfat > 64) return error.UnsupportedFormat;

    const want_cputype: i32 = switch (builtin.cpu.arch) {
        .x86_64 => std.macho.CPU_TYPE_X86_64,
        .aarch64 => std.macho.CPU_TYPE_ARM64,
        else => 0,
    };

    var chosen_off: u64 = 0;
    var chosen_size: u64 = 0;
    var first_off: u64 = 0;
    var first_size: u64 = 0;
    var found = false;

    const entry_size: u64 = if (is_64) @sizeOf(fat_arch_64) else @sizeOf(std.macho.fat_arch);
    const total = std.math.mul(u64, entry_size, nfat) catch return error.Truncated;
    const tail = std.math.add(u64, @sizeOf(std.macho.fat_header), total) catch return error.Truncated;
    if (tail > bytes.len) return error.Truncated;

    var i: u32 = 0;
    while (i < nfat) : (i += 1) {
        const off: usize = @intCast(@sizeOf(std.macho.fat_header) + i * entry_size);
        const cputype = std.mem.readInt(i32, bytes[off..][0..4], .big);
        const slice_off: u64 = if (is_64)
            std.mem.readInt(u64, bytes[off + 8 ..][0..8], .big)
        else
            std.mem.readInt(u32, bytes[off + 8 ..][0..4], .big);
        const slice_size: u64 = if (is_64)
            std.mem.readInt(u64, bytes[off + 16 ..][0..8], .big)
        else
            std.mem.readInt(u32, bytes[off + 12 ..][0..4], .big);
        if (i == 0) {
            first_off = slice_off;
            first_size = slice_size;
        }
        if (!found and cputype == want_cputype) {
            chosen_off = slice_off;
            chosen_size = slice_size;
            found = true;
        }
    }

    if (!found) {
        chosen_off = first_off;
        chosen_size = first_size;
    }

    const end = std.math.add(u64, chosen_off, chosen_size) catch return error.Truncated;
    if (end > bytes.len) return error.Truncated;
    const slice = bytes[@intCast(chosen_off)..@intCast(end)];
    if (slice.len < 4) return error.Truncated;

    const slice_magic = std.mem.readInt(u32, slice[0..4], .little);
    const fat_arch_tag: ?Arch = blk: {
        // Use the arch from the slice header itself rather than the FAT entry —
        // that way the recursion result is internally consistent.
        switch (slice_magic) {
            std.macho.MH_MAGIC_64, std.macho.MH_CIGAM_64 => {
                if (slice.len < @sizeOf(std.macho.mach_header_64)) return error.Truncated;
                const hdr: *align(1) const std.macho.mach_header_64 = @ptrCast(slice.ptr);
                break :blk archFromCpu(hdr.cputype);
            },
            std.macho.MH_MAGIC, std.macho.MH_CIGAM => {
                if (slice.len < @sizeOf(std.macho.mach_header)) return error.Truncated;
                const hdr: *align(1) const std.macho.mach_header = @ptrCast(slice.ptr);
                break :blk archFromCpu(hdr.cputype);
            },
            else => break :blk null,
        }
    };

    var info = switch (slice_magic) {
        std.macho.MH_MAGIC_64, std.macho.MH_CIGAM_64 => try parseThin64(allocator, slice, fat_arch_tag),
        std.macho.MH_MAGIC, std.macho.MH_CIGAM => try parseThin32(allocator, slice, fat_arch_tag),
        else => return error.UnsupportedFormat,
    };
    info.fat_slice_offset = chosen_off;
    return info;
}

fn parseThin64(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    fat_slice_arch: ?Arch,
) ScribeError!MachoInfo {
    if (bytes.len < @sizeOf(std.macho.mach_header_64)) return error.Truncated;

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
        .flags = header.flags,
        .entry = entry,
        .sections = sections.toOwnedSlice(allocator) catch return error.OutOfMemory,
        .dylibs = dylibs.toOwnedSlice(allocator) catch return error.OutOfMemory,
        .fat_slice_arch = fat_slice_arch,
    };
}

fn parseThin32(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    fat_slice_arch: ?Arch,
) ScribeError!MachoInfo {
    if (bytes.len < @sizeOf(std.macho.mach_header)) return error.Truncated;

    const header: *align(1) const std.macho.mach_header = @ptrCast(bytes.ptr);
    const ncmds = header.ncmds;
    const sizeofcmds = header.sizeofcmds;

    const lc_start = @sizeOf(std.macho.mach_header);
    const lc_end = std.math.add(usize, lc_start, sizeofcmds) catch return error.Truncated;
    if (lc_end > bytes.len) return error.Truncated;

    var sections: std.ArrayList(Section) = .empty;
    errdefer sections.deinit(allocator);
    var dylibs: std.ArrayList(Dylib) = .empty;
    errdefer dylibs.deinit(allocator);

    const entry: u64 = 0;

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
            .SEGMENT => {
                if (lc_bytes.len < @sizeOf(std.macho.segment_command)) return error.Truncated;
                const seg: *align(1) const std.macho.segment_command = @ptrCast(lc_bytes.ptr);
                const sect_start = @sizeOf(std.macho.segment_command);
                var k: u32 = 0;
                while (k < seg.nsects) : (k += 1) {
                    const sect_off = sect_start + k * @sizeOf(std.macho.section);
                    if (sect_off + @sizeOf(std.macho.section) > lc_bytes.len) return error.Truncated;
                    const sect: *align(1) const std.macho.section = @ptrCast(lc_bytes[sect_off..].ptr);
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
            // 32-bit Mach-O has no LC_MAIN; entry comes from LC_UNIXTHREAD's
            // thread_state. Layout varies per arch, so leave entry=0 unless
            // we add per-arch decoders later.
            else => {},
        }

        off += cmdsize;
    }

    return .{
        .arch = archFromCpu(header.cputype),
        .cputype = header.cputype,
        .cpusubtype = header.cpusubtype,
        .filetype = header.filetype,
        .is_64 = false,
        .flags = header.flags,
        .entry = entry,
        .sections = sections.toOwnedSlice(allocator) catch return error.OutOfMemory,
        .dylibs = dylibs.toOwnedSlice(allocator) catch return error.OutOfMemory,
        .fat_slice_arch = fat_slice_arch,
    };
}

fn trimName(name: *const [16]u8) []const u8 {
    const len = std.mem.indexOfScalar(u8, name, 0) orelse name.len;
    return name[0..len];
}

test "parse rejects non-macho magic" {
    const bytes = [_]u8{ 0, 0, 0, 0 } ++ ([_]u8{0} ** 60);
    try std.testing.expectError(error.UnsupportedFormat, parse(std.testing.allocator, &bytes));
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

test "parse FAT picks host slice" {
    // Synthesize: fat_header (BE) + 2 fat_arch entries (BE) + 2 thin Mach-O 64
    // headers (LE on host). Slice 0 = x86_64, slice 1 = aarch64.
    const allocator = std.testing.allocator;

    const fh_size = @sizeOf(std.macho.fat_header);
    const fa_size = @sizeOf(std.macho.fat_arch);
    const mh_size = @sizeOf(std.macho.mach_header_64);

    const slice0_off: u32 = @intCast(fh_size + 2 * fa_size);
    const slice0_end: u32 = slice0_off + @as(u32, mh_size);
    const slice1_off: u32 = slice0_end;
    const slice1_end: u32 = slice1_off + @as(u32, mh_size);

    var buf = try allocator.alloc(u8, slice1_end);
    defer allocator.free(buf);
    @memset(buf, 0);

    // fat_header (BE on disk).
    std.mem.writeInt(u32, buf[0..4], std.macho.FAT_MAGIC, .big);
    std.mem.writeInt(u32, buf[4..8], 2, .big);

    // fat_arch[0] — x86_64
    std.mem.writeInt(u32, buf[fh_size..][0..4], @bitCast(std.macho.CPU_TYPE_X86_64), .big);
    std.mem.writeInt(u32, buf[fh_size + 4 ..][0..4], 0, .big);
    std.mem.writeInt(u32, buf[fh_size + 8 ..][0..4], slice0_off, .big);
    std.mem.writeInt(u32, buf[fh_size + 12 ..][0..4], mh_size, .big);
    std.mem.writeInt(u32, buf[fh_size + 16 ..][0..4], 12, .big);

    // fat_arch[1] — aarch64
    const fa1 = fh_size + fa_size;
    std.mem.writeInt(u32, buf[fa1..][0..4], @bitCast(std.macho.CPU_TYPE_ARM64), .big);
    std.mem.writeInt(u32, buf[fa1 + 4 ..][0..4], 0, .big);
    std.mem.writeInt(u32, buf[fa1 + 8 ..][0..4], slice1_off, .big);
    std.mem.writeInt(u32, buf[fa1 + 12 ..][0..4], mh_size, .big);
    std.mem.writeInt(u32, buf[fa1 + 16 ..][0..4], 12, .big);

    // mach_header_64 slice 0 — x86_64
    std.mem.writeInt(u32, buf[slice0_off..][0..4], std.macho.MH_MAGIC_64, .little);
    std.mem.writeInt(u32, buf[slice0_off + 4 ..][0..4], @bitCast(std.macho.CPU_TYPE_X86_64), .little);
    // ncmds=0, sizeofcmds=0 — minimal valid header

    // mach_header_64 slice 1 — aarch64
    std.mem.writeInt(u32, buf[slice1_off..][0..4], std.macho.MH_MAGIC_64, .little);
    std.mem.writeInt(u32, buf[slice1_off + 4 ..][0..4], @bitCast(std.macho.CPU_TYPE_ARM64), .little);

    var info = try parse(allocator, buf);
    defer info.deinit(allocator);

    const expected: Arch = switch (builtin.cpu.arch) {
        .x86_64 => .x86_64,
        .aarch64 => .aarch64,
        else => .x86_64, // fall-back to first slice
    };
    try std.testing.expectEqual(expected, info.arch);
    try std.testing.expectEqual(expected, info.fat_slice_arch.?);
}

test "parse 32-bit thin Mach-O" {
    // Synthesize a minimal mach_header (32-bit) with no load commands.
    const allocator = std.testing.allocator;
    var buf: [@sizeOf(std.macho.mach_header)]u8 = @splat(0);
    std.mem.writeInt(u32, buf[0..4], std.macho.MH_MAGIC, .little);
    std.mem.writeInt(u32, buf[4..8], @bitCast(@as(i32, 7)), .little); // CPU_TYPE_X86

    var info = try parse(allocator, &buf);
    defer info.deinit(allocator);
    try std.testing.expectEqual(Arch.x86, info.arch);
    try std.testing.expect(!info.is_64);
}
