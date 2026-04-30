//! SIMD-accelerated printable-ASCII string scanner. Returns slices into the
//! input buffer (zero-copy). A "string" is a maximal run of printable bytes
//! plus tab/newline of length >= min_len.

const std = @import("std");

pub const Options = struct {
    min_len: usize = 4,
};

const lane_count = std.simd.suggestVectorLength(u8) orelse 16;
const Lane = @Vector(lane_count, u8);

inline fn isPrintableLane(v: Lane) @Vector(lane_count, bool) {
    const space: Lane = @splat(0x20);
    const tilde: Lane = @splat(0x7E);
    const tab: Lane = @splat(0x09);
    const newline: Lane = @splat(0x0A);
    const printable_range = @select(bool, v >= space, v <= tilde, @as(@Vector(lane_count, bool), @splat(false)));
    const is_tab = v == tab;
    const is_nl = v == newline;
    return @select(bool, printable_range, @as(@Vector(lane_count, bool), @splat(true)), @select(bool, is_tab, @as(@Vector(lane_count, bool), @splat(true)), is_nl));
}

inline fn isPrintableScalar(b: u8) bool {
    return (b >= 0x20 and b <= 0x7E) or b == 0x09 or b == 0x0A;
}

pub const Iterator = struct {
    bytes: []const u8,
    pos: usize = 0,
    min_len: usize,

    pub fn next(self: *Iterator) ?[]const u8 {
        const len = self.bytes.len;
        var i = self.pos;

        while (i < len) {
            // SIMD scan for the first printable byte.
            while (i + lane_count <= len) {
                const v: Lane = self.bytes[i..][0..lane_count].*;
                const mask = isPrintableLane(v);
                const any = @reduce(.Or, @select(u8, mask, @as(Lane, @splat(1)), @as(Lane, @splat(0))));
                if (any != 0) break;
                i += lane_count;
            }
            // Scalar advance to the exact start.
            while (i < len and !isPrintableScalar(self.bytes[i])) : (i += 1) {}
            if (i >= len) {
                self.pos = len;
                return null;
            }

            const start = i;
            // SIMD scan for end of printable run.
            while (i + lane_count <= len) {
                const v: Lane = self.bytes[i..][0..lane_count].*;
                const mask = isPrintableLane(v);
                const all = @reduce(.And, @select(u8, mask, @as(Lane, @splat(1)), @as(Lane, @splat(0))));
                if (all == 0) break;
                i += lane_count;
            }
            while (i < len and isPrintableScalar(self.bytes[i])) : (i += 1) {}

            const slice = self.bytes[start..i];
            self.pos = i;
            if (slice.len >= self.min_len) return slice;
        }

        self.pos = len;
        return null;
    }
};

pub fn scan(bytes: []const u8, options: Options) Iterator {
    return .{ .bytes = bytes, .min_len = options.min_len };
}

test "scan recovers basic ASCII strings" {
    const data = "\x00\x00hello\x00\x01\x02world\x00abc\x00";
    var it = scan(data, .{ .min_len = 4 });
    const a = it.next().?;
    try std.testing.expectEqualStrings("hello", a);
    const b = it.next().?;
    try std.testing.expectEqualStrings("world", b);
    try std.testing.expectEqual(@as(?[]const u8, null), it.next());
}

test "scan honours min_len" {
    const data = "ab\x00abcdef\x00x";
    var it = scan(data, .{ .min_len = 6 });
    const a = it.next().?;
    try std.testing.expectEqualStrings("abcdef", a);
    try std.testing.expectEqual(@as(?[]const u8, null), it.next());
}

test "scan handles empty input" {
    var it = scan("", .{});
    try std.testing.expectEqual(@as(?[]const u8, null), it.next());
}

test "scan handles all printable" {
    const data = "this is one long printable string with no nulls";
    var it = scan(data, .{ .min_len = 4 });
    const s = it.next().?;
    try std.testing.expectEqualStrings(data, s);
    try std.testing.expectEqual(@as(?[]const u8, null), it.next());
}
