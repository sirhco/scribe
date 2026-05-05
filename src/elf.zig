const std = @import("std");
const errors = @import("errors.zig");

const ScribeError = errors.ScribeError;

pub const Arch = enum {
    x86_64,
    aarch64,
    riscv64,
    x86,
    arm,
    ppc64,
    mips,
    s390,
    unknown,
};

pub fn archFromMachine(em: std.elf.EM) Arch {
    return switch (em) {
        .X86_64 => .x86_64,
        .AARCH64 => .aarch64,
        .RISCV => .riscv64,
        .@"386" => .x86,
        .ARM => .arm,
        .PPC64 => .ppc64,
        .MIPS => .mips,
        .S390 => .s390,
        else => .unknown,
    };
}

pub const SectionHeader = struct {
    name: []const u8,
    type: u32,
    flags: u64,
    addr: u64,
    offset: u64,
    size: u64,
};

pub const ElfInfo = struct {
    arch: Arch,
    machine: std.elf.EM,
    e_type: u16,
    entry: u64,
    is_64: bool,
    endian: std.builtin.Endian,
    sections: []SectionHeader,

    pub fn deinit(self: *ElfInfo, allocator: std.mem.Allocator) void {
        allocator.free(self.sections);
        self.sections = &.{};
    }
};

pub fn parse(allocator: std.mem.Allocator, bytes: []const u8) ScribeError!ElfInfo {
    if (bytes.len < @sizeOf(std.elf.Elf64_Ehdr)) return error.Truncated;
    if (!std.mem.eql(u8, bytes[0..4], std.elf.MAGIC)) return error.UnsupportedFormat;

    var hdr_reader: std.Io.Reader = .fixed(bytes);
    const header = std.elf.Header.read(&hdr_reader) catch |e| switch (e) {
        error.InvalidElfMagic => return error.UnsupportedFormat,
        error.InvalidElfVersion => return error.UnsupportedVersion,
        error.InvalidElfClass => return error.UnsupportedClass,
        error.InvalidElfEndian => return error.UnsupportedEndian,
        else => return error.Truncated,
    };

    const shentsize: u64 = @intCast(header.shentsize);
    const shnum: u64 = @intCast(header.shnum);
    const sh_table_size = std.math.mul(u64, shentsize, shnum) catch return error.Truncated;
    const sh_table_end = std.math.add(u64, header.shoff, sh_table_size) catch return error.Truncated;
    if (header.shoff > bytes.len or sh_table_end > bytes.len) return error.Truncated;

    const shstrtab = try resolveShstrtab(bytes, header);

    var sections = try allocator.alloc(SectionHeader, header.shnum);
    errdefer allocator.free(sections);

    var it = header.iterateSectionHeadersBuffer(bytes);
    var i: usize = 0;
    while (true) {
        const maybe = it.next() catch return error.Truncated;
        const shdr = maybe orelse break;
        if (i >= sections.len) return error.Truncated;

        const name_off: usize = @intCast(shdr.sh_name);
        const name = if (name_off >= shstrtab.len)
            ""
        else
            std.mem.sliceTo(shstrtab[name_off..], 0);

        sections[i] = .{
            .name = name,
            .type = shdr.sh_type,
            .flags = shdr.sh_flags,
            .addr = shdr.sh_addr,
            .offset = shdr.sh_offset,
            .size = shdr.sh_size,
        };
        i += 1;
    }

    return .{
        .arch = archFromMachine(header.machine),
        .machine = header.machine,
        .e_type = @intFromEnum(header.type),
        .entry = header.entry,
        .is_64 = header.is_64,
        .endian = header.endian,
        .sections = sections,
    };
}

fn resolveShstrtab(bytes: []const u8, header: std.elf.Header) ScribeError![]const u8 {
    if (header.shnum == 0) return "";
    if (header.shstrndx >= header.shnum) return error.InvalidStringTable;

    const shentsize: u64 = @intCast(header.shentsize);
    const idx_off = std.math.add(u64, header.shoff, shentsize * header.shstrndx) catch
        return error.InvalidStringTable;
    if (idx_off + shentsize > bytes.len) return error.InvalidStringTable;

    var r: std.Io.Reader = .fixed(bytes[@intCast(idx_off)..]);
    const shdr = std.elf.takeSectionHeader(&r, header.is_64, header.endian) catch
        return error.InvalidStringTable;

    const off: usize = @intCast(shdr.sh_offset);
    const sz: usize = @intCast(shdr.sh_size);
    if (off > bytes.len or off + sz > bytes.len) return error.InvalidStringTable;
    return bytes[off..][0..sz];
}

// Minimal valid ELF64 header bytes (little-endian, x86_64, no sections).
fn makeMinimalHeader() [64]u8 {
    var h: [64]u8 = @splat(0);
    h[0] = 0x7F;
    h[1] = 'E';
    h[2] = 'L';
    h[3] = 'F';
    h[4] = 2; // ELFCLASS64
    h[5] = 1; // ELFDATA2LSB
    h[6] = 1; // EV_CURRENT
    // e_type at offset 16 (u16) = 2 (ET_EXEC)
    std.mem.writeInt(u16, h[16..18], 2, .little);
    // e_machine at 18 (u16) = 62 (EM_X86_64)
    std.mem.writeInt(u16, h[18..20], 62, .little);
    // e_version at 20 (u32) = 1
    std.mem.writeInt(u32, h[20..24], 1, .little);
    // e_entry at 24 (u64) = 0x400000
    std.mem.writeInt(u64, h[24..32], 0x400000, .little);
    // e_phoff = 0 (32..40)
    // e_shoff = 0 (40..48)
    // e_flags = 0 (48..52)
    // e_ehsize at 52 (u16) = 64
    std.mem.writeInt(u16, h[52..54], 64, .little);
    // e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx all 0
    return h;
}

test "parse rejects non-ELF magic" {
    const bytes = [_]u8{ 'M', 'Z', 0, 0 } ++ ([_]u8{0} ** 60);
    try std.testing.expectError(error.UnsupportedFormat, parse(std.testing.allocator, &bytes));
}

test "parse rejects truncated header" {
    const bytes = [_]u8{ 0x7F, 'E', 'L', 'F', 2, 1, 1 };
    try std.testing.expectError(error.Truncated, parse(std.testing.allocator, &bytes));
}

test "parse minimal section-less header" {
    const bytes = makeMinimalHeader();
    var info = try parse(std.testing.allocator, &bytes);
    defer info.deinit(std.testing.allocator);
    try std.testing.expectEqual(Arch.x86_64, info.arch);
    try std.testing.expect(info.is_64);
    try std.testing.expectEqual(@as(u64, 0x400000), info.entry);
    try std.testing.expectEqual(@as(usize, 0), info.sections.len);
}

test "parse golden x86_64 fixture" {
    const bytes = @embedFile("testdata/hello_x86_64");
    var info = try parse(std.testing.allocator, bytes);
    defer info.deinit(std.testing.allocator);
    try std.testing.expectEqual(Arch.x86_64, info.arch);
    try std.testing.expect(info.is_64);
    try std.testing.expect(info.sections.len > 0);

    var has_text = false;
    var has_shstrtab = false;
    for (info.sections) |s| {
        if (std.mem.eql(u8, s.name, ".text")) has_text = true;
        if (std.mem.eql(u8, s.name, ".shstrtab")) has_shstrtab = true;
    }
    try std.testing.expect(has_text);
    try std.testing.expect(has_shstrtab);
}

test "parse golden aarch64 fixture" {
    const bytes = @embedFile("testdata/hello_aarch64");
    var info = try parse(std.testing.allocator, bytes);
    defer info.deinit(std.testing.allocator);
    try std.testing.expectEqual(Arch.aarch64, info.arch);
    try std.testing.expect(info.is_64);
}
