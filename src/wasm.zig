//! Minimal WebAssembly binary walker. Parses the magic + version, then
//! enumerates sections (id + size). Sufficient for `scribe wasm` to give
//! a structural overview without taking a dependency on a full Wasm
//! decoder. Function bodies, imports/exports inside CODE / EXPORT
//! sections are left to a future pass.

const std = @import("std");
const errors = @import("errors.zig");

const ScribeError = errors.ScribeError;

pub const MAGIC = [_]u8{ 0x00, 0x61, 0x73, 0x6D }; // "\0asm"

pub const SectionKind = enum(u8) {
    custom = 0,
    type = 1,
    import = 2,
    function = 3,
    table = 4,
    memory = 5,
    global = 6,
    @"export" = 7,
    start = 8,
    element = 9,
    code = 10,
    data = 11,
    data_count = 12,
    _,

    pub fn label(self: SectionKind) []const u8 {
        return switch (self) {
            .custom => "custom",
            .type => "type",
            .import => "import",
            .function => "function",
            .table => "table",
            .memory => "memory",
            .global => "global",
            .@"export" => "export",
            .start => "start",
            .element => "element",
            .code => "code",
            .data => "data",
            .data_count => "data_count",
            _ => "unknown",
        };
    }
};

pub const Section = struct {
    kind: SectionKind,
    /// Offset of the section payload within the file (after the LEB128
    /// header). Useful for `scribe hex --section <id>` style follow-ups.
    payload_offset: usize,
    payload_size: usize,
    /// For custom sections, the leading name string (LEB-prefixed). Empty
    /// otherwise.
    name: []const u8,
};

pub const WasmInfo = struct {
    version: u32,
    sections: []Section,

    pub fn deinit(self: *WasmInfo, allocator: std.mem.Allocator) void {
        allocator.free(self.sections);
        self.sections = &.{};
    }
};

pub fn isWasm(bytes: []const u8) bool {
    return bytes.len >= 8 and std.mem.eql(u8, bytes[0..4], &MAGIC);
}

pub fn parse(allocator: std.mem.Allocator, bytes: []const u8) ScribeError!WasmInfo {
    if (bytes.len < 8) return error.Truncated;
    if (!std.mem.eql(u8, bytes[0..4], &MAGIC)) return error.UnsupportedFormat;
    const version = std.mem.readInt(u32, bytes[4..8], .little);

    var sections: std.ArrayList(Section) = .empty;
    errdefer sections.deinit(allocator);

    var off: usize = 8;
    while (off < bytes.len) {
        if (off >= bytes.len) break;
        const kind_byte = bytes[off];
        off += 1;
        const sz_decode = readUleb128(bytes, off) orelse return error.Truncated;
        const payload_size: usize = @intCast(sz_decode.value);
        off = sz_decode.next;
        if (off + payload_size > bytes.len) return error.Truncated;

        var name: []const u8 = "";
        if (kind_byte == 0 and payload_size > 0) {
            // Custom section — leading LEB length + UTF-8 name.
            if (readUleb128(bytes, off)) |name_len| {
                const nl: usize = @intCast(name_len.value);
                if (name_len.next + nl <= off + payload_size and name_len.next + nl <= bytes.len) {
                    name = bytes[name_len.next..][0..nl];
                }
            }
        }

        sections.append(allocator, .{
            .kind = @enumFromInt(kind_byte),
            .payload_offset = off,
            .payload_size = payload_size,
            .name = name,
        }) catch return error.OutOfMemory;
        off += payload_size;
    }

    return .{
        .version = version,
        .sections = sections.toOwnedSlice(allocator) catch return error.OutOfMemory,
    };
}

const Uleb128 = struct { value: u64, next: usize };

fn readUleb128(bytes: []const u8, start: usize) ?Uleb128 {
    var result: u64 = 0;
    var shift: u32 = 0;
    var i = start;
    while (i < bytes.len) {
        const b = bytes[i];
        i += 1;
        if (shift >= 64) return null;
        result |= @as(u64, b & 0x7f) << @intCast(shift);
        if (b & 0x80 == 0) return .{ .value = result, .next = i };
        shift += 7;
    }
    return null;
}

test "wasm magic + minimal sections" {
    // Magic + version=1 + custom section "scribe" payload "x".
    var buf: [32]u8 = @splat(0);
    @memcpy(buf[0..4], &MAGIC);
    std.mem.writeInt(u32, buf[4..8], 1, .little);
    // section: kind=0 (custom), size=8, [name_len=6, "scribe", payload="x"]
    buf[8] = 0;
    buf[9] = 8; // size
    buf[10] = 6;
    @memcpy(buf[11..17], "scribe");
    buf[17] = 'x';

    var info = try parse(std.testing.allocator, buf[0..18]);
    defer info.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u32, 1), info.version);
    try std.testing.expectEqual(@as(usize, 1), info.sections.len);
    try std.testing.expectEqual(SectionKind.custom, info.sections[0].kind);
    try std.testing.expectEqualStrings("scribe", info.sections[0].name);
}

test "wasm rejects bad magic" {
    const bytes = [_]u8{ 'X', 'X', 'X', 'X', 1, 0, 0, 0 };
    try std.testing.expectError(error.UnsupportedFormat, parse(std.testing.allocator, &bytes));
}
