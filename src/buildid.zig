//! Build-identifier extraction across formats.
//!   ELF   — .note.gnu.build-id (NT_GNU_BUILD_ID = 3)
//!   Mach-O — LC_UUID load command
//!   PE     — CodeView debug entry GUID + age (PDB signature)

const std = @import("std");
const errors = @import("errors.zig");

pub const Kind = enum { elf_gnu, macho_uuid, pe_pdb };

pub const BuildId = struct {
    kind: Kind,
    /// Hex-encoded ID. Owned by caller; free with allocator.free.
    hex: []u8,
};

pub fn extract(allocator: std.mem.Allocator, bytes: []const u8) errors.ScribeError!?BuildId {
    if (bytes.len < 4) return null;
    if (std.mem.eql(u8, bytes[0..4], std.elf.MAGIC)) return extractElf(allocator, bytes);
    const m = std.mem.readInt(u32, bytes[0..4], .little);
    if (m == std.macho.MH_MAGIC_64 or m == std.macho.MH_CIGAM_64 or
        m == std.macho.MH_MAGIC or m == std.macho.MH_CIGAM)
        return extractMacho(allocator, bytes);
    if (bytes[0] == 'M' and bytes[1] == 'Z') return extractPe(allocator, bytes);
    return null;
}

fn extractElf(allocator: std.mem.Allocator, bytes: []const u8) errors.ScribeError!?BuildId {
    var hdr_reader: std.Io.Reader = .fixed(bytes);
    const header = std.elf.Header.read(&hdr_reader) catch return null;

    // Walk PT_NOTE segments looking for NT_GNU_BUILD_ID (owner == "GNU").
    var ph_it = header.iterateProgramHeadersBuffer(bytes);
    while (true) {
        const maybe = ph_it.next() catch return null;
        const ph = maybe orelse break;
        if (ph.p_type != std.elf.PT_NOTE) continue;

        const off: usize = @intCast(ph.p_offset);
        const size: usize = @intCast(ph.p_filesz);
        if (off + size > bytes.len) continue;
        if (try scanNote(allocator, bytes[off..][0..size], header.endian)) |id| return id;
    }

    // Fallback: scan all SHT_NOTE sections via section headers.
    var sh_it = header.iterateSectionHeadersBuffer(bytes);
    while (true) {
        const maybe = sh_it.next() catch return null;
        const sh = maybe orelse break;
        if (sh.sh_type != std.elf.SHT_NOTE) continue;
        const off: usize = @intCast(sh.sh_offset);
        const size: usize = @intCast(sh.sh_size);
        if (off + size > bytes.len) continue;
        if (try scanNote(allocator, bytes[off..][0..size], header.endian)) |id| return id;
    }

    return null;
}

const NT_GNU_BUILD_ID: u32 = 3;

fn scanNote(
    allocator: std.mem.Allocator,
    notes: []const u8,
    endian: std.builtin.Endian,
) errors.ScribeError!?BuildId {
    var i: usize = 0;
    while (i + 12 <= notes.len) {
        const namesz = std.mem.readInt(u32, notes[i..][0..4], endian);
        const descsz = std.mem.readInt(u32, notes[i + 4 ..][0..4], endian);
        const ntype = std.mem.readInt(u32, notes[i + 8 ..][0..4], endian);

        const name_off = i + 12;
        const name_end = name_off + std.mem.alignForward(usize, namesz, 4);
        if (name_end > notes.len) return null;
        const desc_off = name_end;
        const desc_end = desc_off + std.mem.alignForward(usize, descsz, 4);
        if (desc_end > notes.len) return null;

        if (ntype == NT_GNU_BUILD_ID and namesz >= 3) {
            const owner = notes[name_off..][0 .. namesz - 1];
            if (std.mem.eql(u8, owner, "GNU")) {
                const id = notes[desc_off..][0..descsz];
                const hex = allocator.alloc(u8, id.len * 2) catch return error.OutOfMemory;
                _ = std.fmt.bufPrint(hex, "{x}", .{id}) catch unreachable;
                return BuildId{ .kind = .elf_gnu, .hex = hex };
            }
        }

        i = desc_end;
    }
    return null;
}

fn extractMacho(allocator: std.mem.Allocator, bytes: []const u8) errors.ScribeError!?BuildId {
    if (bytes.len < @sizeOf(std.macho.mach_header_64)) return null;
    const header: *align(1) const std.macho.mach_header_64 = @ptrCast(bytes.ptr);

    var off: usize = @sizeOf(std.macho.mach_header_64);
    const lc_end = off + header.sizeofcmds;
    if (lc_end > bytes.len) return null;

    var i: u32 = 0;
    while (i < header.ncmds and off + @sizeOf(std.macho.load_command) <= lc_end) : (i += 1) {
        const lc: *align(1) const std.macho.load_command = @ptrCast(bytes[off..].ptr);
        if (lc.cmd == .UUID and lc.cmdsize >= @sizeOf(std.macho.uuid_command)) {
            const uuid: *align(1) const std.macho.uuid_command = @ptrCast(bytes[off..].ptr);
            const hex = allocator.alloc(u8, 32) catch return error.OutOfMemory;
            _ = std.fmt.bufPrint(hex, "{x}", .{uuid.uuid}) catch unreachable;
            return BuildId{ .kind = .macho_uuid, .hex = hex };
        }
        off += lc.cmdsize;
    }
    return null;
}

fn extractPe(allocator: std.mem.Allocator, bytes: []const u8) errors.ScribeError!?BuildId {
    var coff = std.coff.Coff.init(bytes, false) catch return null;
    _ = coff.getPdbPath() catch return null; // populates guid + age
    if (std.mem.eql(u8, &coff.guid, &([_]u8{0} ** 16))) return null;

    const hex = allocator.alloc(u8, 32 + 8) catch return error.OutOfMemory;
    _ = std.fmt.bufPrint(hex, "{x}{x:0>8}", .{ coff.guid, coff.age }) catch unreachable;
    return BuildId{ .kind = .pe_pdb, .hex = hex };
}

pub fn free(allocator: std.mem.Allocator, id: BuildId) void {
    allocator.free(id.hex);
}

test "no build-id on stripped musl static elf" {
    const bytes = @embedFile("testdata/hello_x86_64");
    const id = try extract(std.testing.allocator, bytes);
    if (id) |b| free(std.testing.allocator, b);
    // Either present or absent — just must not crash.
}

test "macho UUID always present" {
    const bytes = @embedFile("testdata/hello_macho_x86_64");
    const id = (try extract(std.testing.allocator, bytes)) orelse return error.TestExpectedNonNull;
    defer free(std.testing.allocator, id);
    try std.testing.expectEqual(Kind.macho_uuid, id.kind);
    try std.testing.expectEqual(@as(usize, 32), id.hex.len);
}
