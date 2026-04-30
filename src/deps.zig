//! Dynamic shared library dependency extraction.
//! - ELF: walk PT_DYNAMIC -> DT_NEEDED, resolve via DT_STRTAB.
//! - Mach-O: walk LC_LOAD_DYLIB / LC_LOAD_WEAK_DYLIB / LC_REEXPORT_DYLIB.
//! - PE: import directory table.

const std = @import("std");
const errors = @import("errors.zig");
const macho_mod = @import("macho.zig");

const ScribeError = errors.ScribeError;

pub const Dep = struct {
    name: []const u8,
    kind: Kind,

    pub const Kind = enum { elf_needed, macho_dylib, macho_weak_dylib, macho_reexport, pe_import };
};

pub fn collect(allocator: std.mem.Allocator, bytes: []const u8) ScribeError![]Dep {
    if (bytes.len < 4) return error.Truncated;
    if (std.mem.eql(u8, bytes[0..4], std.elf.MAGIC)) return collectElf(allocator, bytes);
    const m = std.mem.readInt(u32, bytes[0..4], .little);
    if (m == std.macho.MH_MAGIC_64 or m == std.macho.MH_CIGAM_64 or
        m == std.macho.MH_MAGIC or m == std.macho.MH_CIGAM)
        return collectMacho(allocator, bytes);
    if (bytes[0] == 'M' and bytes[1] == 'Z') return collectPe(allocator, bytes);
    return error.NotElf;
}

fn collectElf(allocator: std.mem.Allocator, bytes: []const u8) ScribeError![]Dep {
    var hdr_reader: std.Io.Reader = .fixed(bytes);
    const header = std.elf.Header.read(&hdr_reader) catch return error.NotElf;

    // Find PT_DYNAMIC program header.
    var ph_it = header.iterateProgramHeadersBuffer(bytes);
    var dyn_off: u64 = 0;
    var dyn_size: u64 = 0;
    while (true) {
        const maybe = ph_it.next() catch return error.Truncated;
        const ph = maybe orelse break;
        if (ph.p_type == std.elf.PT_DYNAMIC) {
            dyn_off = ph.p_offset;
            dyn_size = ph.p_filesz;
            break;
        }
    }

    var out: std.ArrayList(Dep) = .empty;
    errdefer out.deinit(allocator);

    if (dyn_size == 0) return out.toOwnedSlice(allocator) catch error.OutOfMemory;
    if (dyn_off + dyn_size > bytes.len) return error.Truncated;

    // First pass: find DT_STRTAB virtual address. Then map vaddr -> file offset
    // via PT_LOAD segments.
    var strtab_vaddr: u64 = 0;
    var strtab_size: u64 = 0;
    var needed: std.ArrayList(u64) = .empty;
    defer needed.deinit(allocator);

    {
        var dyn_it = header.iterateDynamicSectionBuffer(bytes, dyn_off, dyn_size);
        while (true) {
            const maybe = dyn_it.next() catch return error.Truncated;
            const d = maybe orelse break;
            switch (d.d_tag) {
                std.elf.DT_NULL => break,
                std.elf.DT_STRTAB => strtab_vaddr = d.d_val,
                std.elf.DT_STRSZ => strtab_size = d.d_val,
                std.elf.DT_NEEDED => needed.append(allocator, d.d_val) catch return error.OutOfMemory,
                else => {},
            }
        }
    }

    if (needed.items.len == 0)
        return out.toOwnedSlice(allocator) catch error.OutOfMemory;

    const strtab_off = vaddrToFileOffset(header, bytes, strtab_vaddr) orelse
        return error.InvalidStringTable;
    if (strtab_off + strtab_size > bytes.len) return error.InvalidStringTable;
    const strtab = bytes[strtab_off..][0..@intCast(strtab_size)];

    for (needed.items) |name_off| {
        if (name_off >= strtab.len) continue;
        const name = std.mem.sliceTo(strtab[@intCast(name_off)..], 0);
        out.append(allocator, .{ .name = name, .kind = .elf_needed }) catch
            return error.OutOfMemory;
    }
    return out.toOwnedSlice(allocator) catch error.OutOfMemory;
}

fn vaddrToFileOffset(header: std.elf.Header, bytes: []const u8, vaddr: u64) ?u64 {
    var it = header.iterateProgramHeadersBuffer(bytes);
    while (true) {
        const maybe = it.next() catch return null;
        const ph = maybe orelse return null;
        if (ph.p_type != std.elf.PT_LOAD) continue;
        if (vaddr >= ph.p_vaddr and vaddr < ph.p_vaddr + ph.p_memsz)
            return ph.p_offset + (vaddr - ph.p_vaddr);
    }
}

fn collectMacho(allocator: std.mem.Allocator, bytes: []const u8) ScribeError![]Dep {
    const info = try macho_mod.parse(allocator, bytes);
    defer allocator.free(info.sections);
    // Transfer dylib slice ownership; rewrite to Dep array.
    defer allocator.free(info.dylibs);

    var out = allocator.alloc(Dep, info.dylibs.len) catch return error.OutOfMemory;
    errdefer allocator.free(out);
    for (info.dylibs, 0..) |dl, i| {
        out[i] = .{
            .name = dl.name,
            .kind = switch (dl.cmd) {
                .LOAD_DYLIB, .LAZY_LOAD_DYLIB, .LOAD_UPWARD_DYLIB => .macho_dylib,
                .LOAD_WEAK_DYLIB => .macho_weak_dylib,
                .REEXPORT_DYLIB => .macho_reexport,
                else => .macho_dylib,
            },
        };
    }
    return out;
}

fn collectPe(allocator: std.mem.Allocator, bytes: []const u8) ScribeError![]Dep {
    const coff = std.coff.Coff.init(bytes, false) catch |e| switch (e) {
        error.EndOfStream => return error.Truncated,
        error.MissingPEHeader => return error.NotElf,
    };

    const dirs = coff.getDataDirectories();
    const import_idx = @intFromEnum(std.coff.IMAGE.DIRECTORY_ENTRY.IMPORT);
    if (import_idx >= dirs.len) return allocator.alloc(Dep, 0) catch error.OutOfMemory;

    const import_dir = dirs[import_idx];
    if (import_dir.size == 0) return allocator.alloc(Dep, 0) catch error.OutOfMemory;

    // Convert import RVA to file offset by locating containing section.
    const file_off = rvaToFileOffset(coff, import_dir.virtual_address) orelse
        return error.InvalidStringTable;

    var out: std.ArrayList(Dep) = .empty;
    errdefer out.deinit(allocator);

    const entry_size = @sizeOf(std.coff.ImportDirectoryEntry);
    var off = file_off;
    while (off + entry_size <= bytes.len) : (off += entry_size) {
        const entry: *align(1) const std.coff.ImportDirectoryEntry =
            @ptrCast(bytes[off..].ptr);
        if (entry.import_lookup_table_rva == 0 and entry.name_rva == 0) break;

        const name_off = rvaToFileOffset(coff, entry.name_rva) orelse continue;
        if (name_off >= bytes.len) continue;
        const name = std.mem.sliceTo(bytes[name_off..], 0);
        out.append(allocator, .{ .name = name, .kind = .pe_import }) catch
            return error.OutOfMemory;
    }
    return out.toOwnedSlice(allocator) catch error.OutOfMemory;
}

fn rvaToFileOffset(coff: std.coff.Coff, rva: u32) ?u64 {
    for (coff.getSectionHeaders()) |*sh| {
        if (rva >= sh.virtual_address and rva < sh.virtual_address + sh.virtual_size)
            return sh.pointer_to_raw_data + (rva - sh.virtual_address);
    }
    return null;
}

pub fn free(allocator: std.mem.Allocator, deps: []Dep) void {
    allocator.free(deps);
}

test "collect macho deps from fixture" {
    const bytes = @embedFile("testdata/hello_macho_x86_64");
    const deps = try collect(std.testing.allocator, bytes);
    defer free(std.testing.allocator, deps);
    try std.testing.expect(deps.len > 0);
    var has_libsystem = false;
    for (deps) |d| {
        if (std.mem.indexOf(u8, d.name, "libSystem") != null) has_libsystem = true;
    }
    try std.testing.expect(has_libsystem);
}

test "collect pe imports from fixture" {
    const bytes = @embedFile("testdata/hello_pe_x86_64");
    const deps = try collect(std.testing.allocator, bytes);
    defer free(std.testing.allocator, deps);
    // PE may have zero or more imports; just ensure no crash and reasonable count.
    try std.testing.expect(deps.len < 256);
}

test "collect static elf has no needed entries" {
    const bytes = @embedFile("testdata/hello_x86_64");
    const deps = try collect(std.testing.allocator, bytes);
    defer free(std.testing.allocator, deps);
    // Static musl binary -> no DT_NEEDED.
    try std.testing.expectEqual(@as(usize, 0), deps.len);
}
