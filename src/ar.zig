//! AR archive walker (System V / BSD variants). Used by static-library
//! containers (.a / .lib). Each archive starts with `!<arch>\n` and
//! contains a sequence of fixed-header members. Header layout (60 bytes):
//!
//!   off  size  field
//!     0    16  name (space-padded; '/' suffix on SysV; long names live
//!                in the special `//` member)
//!    16    12  modification timestamp (decimal ASCII)
//!    28     6  owner uid (decimal ASCII)
//!    34     6  group gid (decimal ASCII)
//!    40     8  file mode (octal ASCII)
//!    48    10  size (decimal ASCII)
//!    58     2  end magic "`\n"
//!
//! After the header comes the file data, then a 1-byte alignment pad if
//! size is odd.
//!
//! BSD long-name extension: name field is "#1/<N>", and the first <N>
//! bytes of the data are the actual name. We surface that here so users
//! see the real symbol filename rather than the marker.

const std = @import("std");
const errors = @import("errors.zig");

const ScribeError = errors.ScribeError;

pub const MAGIC = "!<arch>\n";

pub const Member = struct {
    /// Resolved name (long-name extensions decoded).
    name: []const u8,
    /// File offset of the member's data (post-header).
    offset: usize,
    /// Member data size.
    size: usize,
};

pub const Archive = struct {
    members: []Member,

    pub fn deinit(self: *Archive, allocator: std.mem.Allocator) void {
        for (self.members) |m| allocator.free(m.name);
        allocator.free(self.members);
        self.members = &.{};
    }
};

pub fn isAr(bytes: []const u8) bool {
    return bytes.len >= MAGIC.len and std.mem.eql(u8, bytes[0..MAGIC.len], MAGIC);
}

pub fn parse(allocator: std.mem.Allocator, bytes: []const u8) ScribeError!Archive {
    if (!isAr(bytes)) return error.UnsupportedFormat;

    var off: usize = MAGIC.len;
    var long_names: []const u8 = ""; // SysV "//" member

    var members: std.ArrayList(Member) = .empty;
    errdefer {
        for (members.items) |m| allocator.free(m.name);
        members.deinit(allocator);
    }

    while (off + 60 <= bytes.len) {
        const hdr = bytes[off..][0..60];
        // End magic.
        if (!(hdr[58] == '`' and hdr[59] == '\n')) break;

        const raw_name = std.mem.trimEnd(u8, hdr[0..16], " ");
        const size = std.fmt.parseInt(usize, std.mem.trim(u8, hdr[48..58], " "), 10) catch
            return error.Truncated;

        const data_start = off + 60;
        if (data_start + size > bytes.len) return error.Truncated;

        // SysV symbol table marker — skip.
        if (raw_name.len >= 1 and raw_name[0] == '/' and (raw_name.len == 1 or raw_name[1] != '/')) {
            // Names like "/", "/<idx>" — special members; skip.
            if (raw_name.len == 1) {
                off = data_start + size + (size & 1);
                continue;
            }
            if (raw_name.len > 1 and isAllDigits(raw_name[1..])) {
                // SysV long-name reference into the "//" member.
                if (long_names.len == 0) {
                    off = data_start + size + (size & 1);
                    continue;
                }
                const idx = std.fmt.parseInt(usize, raw_name[1..], 10) catch 0;
                const name = nullOrSlashTerminated(long_names, idx);
                try appendMember(allocator, &members, name, data_start, size);
                off = data_start + size + (size & 1);
                continue;
            }
        }

        // SysV "//" long-name table.
        if (std.mem.eql(u8, raw_name, "//")) {
            long_names = bytes[data_start..][0..size];
            off = data_start + size + (size & 1);
            continue;
        }

        // BSD #1/<N> long name — first <N> bytes of the data are the name.
        if (raw_name.len > 3 and std.mem.startsWith(u8, raw_name, "#1/")) {
            const nl = std.fmt.parseInt(usize, raw_name[3..], 10) catch 0;
            if (nl <= size and data_start + nl <= bytes.len) {
                const real_name = std.mem.sliceTo(bytes[data_start..][0..nl], 0);
                const adjusted_data_start = data_start + nl;
                const adjusted_size = size - nl;
                try appendMember(allocator, &members, real_name, adjusted_data_start, adjusted_size);
                off = data_start + size + (size & 1);
                continue;
            }
        }

        // Plain SysV name with optional trailing '/'
        const trimmed = std.mem.trimEnd(u8, raw_name, "/");
        try appendMember(allocator, &members, trimmed, data_start, size);
        off = data_start + size + (size & 1);
    }

    return .{ .members = members.toOwnedSlice(allocator) catch return error.OutOfMemory };
}

fn appendMember(
    allocator: std.mem.Allocator,
    out: *std.ArrayList(Member),
    name: []const u8,
    offset: usize,
    size: usize,
) !void {
    if (name.len == 0) return;
    const owned = try allocator.dupe(u8, name);
    errdefer allocator.free(owned);
    out.append(allocator, .{ .name = owned, .offset = offset, .size = size }) catch return error.OutOfMemory;
}

fn isAllDigits(s: []const u8) bool {
    for (s) |c| if (c < '0' or c > '9') return false;
    return s.len > 0;
}

fn nullOrSlashTerminated(blob: []const u8, idx: usize) []const u8 {
    if (idx >= blob.len) return "";
    var end = idx;
    while (end < blob.len and blob[end] != '/' and blob[end] != '\n' and blob[end] != 0) : (end += 1) {}
    return blob[idx..end];
}

test "ar parses simple archive" {
    // Build a minimal archive containing two members "foo" + "bar"
    // (each 4 bytes of data).
    var buf: [256]u8 = @splat(' ');
    @memcpy(buf[0..MAGIC.len], MAGIC);
    var off: usize = MAGIC.len;

    inline for (.{ .{ "foo/", "AAAA" }, .{ "bar/", "BBBB" } }) |entry| {
        // header
        const hdr = buf[off..][0..60];
        @memset(hdr, ' ');
        @memcpy(hdr[0..entry.@"0".len], entry.@"0");
        const size_str = "4";
        @memcpy(hdr[48..][0..size_str.len], size_str);
        hdr[58] = '`';
        hdr[59] = '\n';
        off += 60;
        @memcpy(buf[off..][0..4], entry.@"1");
        off += 4;
    }

    var arc = try parse(std.testing.allocator, buf[0..off]);
    defer arc.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 2), arc.members.len);
    try std.testing.expectEqualStrings("foo", arc.members[0].name);
    try std.testing.expectEqualStrings("bar", arc.members[1].name);
}
