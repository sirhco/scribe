//! Shannon entropy in bits/byte. Range [0, 8]. Values near 8 indicate
//! compression or encryption; near 0 indicate uniform/repetitive data.

const std = @import("std");

pub fn shannon(bytes: []const u8) f64 {
    if (bytes.len == 0) return 0.0;

    var counts: [256]u64 = @splat(0);
    for (bytes) |b| counts[b] += 1;

    const n: f64 = @floatFromInt(bytes.len);
    var h: f64 = 0.0;
    for (counts) |c| {
        if (c == 0) continue;
        const p: f64 = @as(f64, @floatFromInt(c)) / n;
        h -= p * std.math.log2(p);
    }
    return h;
}

test "entropy of uniform single byte is 0" {
    const data: [256]u8 = @splat('A');
    try std.testing.expectApproxEqAbs(@as(f64, 0.0), shannon(&data), 1e-9);
}

test "entropy of empty is 0" {
    try std.testing.expectEqual(@as(f64, 0.0), shannon(""));
}

test "entropy of two-symbol equal distribution is 1" {
    var data: [256]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = if (i % 2 == 0) 'A' else 'B';
    try std.testing.expectApproxEqAbs(@as(f64, 1.0), shannon(&data), 1e-9);
}

test "entropy of full byte range is 8" {
    var data: [256]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @intCast(i);
    try std.testing.expectApproxEqAbs(@as(f64, 8.0), shannon(&data), 1e-9);
}
