//! SIMD-accelerated secret scanner. Single-pass anchor-byte search over
//! mmap'd buffers. Reuses src/strings.zig for the optional generic
//! high-entropy pass. Findings carry redacted previews only — raw secret
//! bytes never escape this module.
//!
//! Anchor strategy: for each byte stride of `lane_count`, broadcast each
//! pattern's anchor byte across the lane and bitcast the equality vector
//! to an integer mask. `@ctz` walks set lanes; each candidate offset
//! validates the full prefix scalar then runs a pattern-specific
//! validator.
//!
//! Generic high-entropy pass is opt-in (`ScanOptions.include_generic`).
//! It piggybacks on `strings.scan` and uses `entropy.shannon`.

const std = @import("std");
const errors = @import("../errors.zig");
const strings_mod = @import("../strings.zig");
const entropy_mod = @import("../entropy.zig");

pub const Kind = enum {
    aws_access_key,
    aws_secret_key,
    gcp_service_account,
    slack_token,
    github_pat,
    jwt,
    pem_private_key,
    generic_high_entropy,
};

pub const Confidence = enum(u8) {
    low = 30,
    medium = 60,
    high = 90,
    certain = 100,
};

pub const Finding = struct {
    kind: Kind,
    offset: u64,
    length: u32,
    entropy: f32,
    confidence: Confidence,
    /// Owned. Format: "AAAA…ZZZZ (len=N, H=E.EE)" — never contains middle bytes of secret.
    redacted_preview: []u8,
};

pub const ScanOptions = struct {
    min_entropy: f32 = 4.5,
    include_generic: bool = false,
    min_generic_len: usize = 20,
};

pub const Findings = struct {
    items: []Finding,

    pub fn deinit(self: *Findings, allocator: std.mem.Allocator) void {
        for (self.items) |f| freeFinding(allocator, f);
        allocator.free(self.items);
        self.items = &.{};
    }
};

pub fn freeFinding(allocator: std.mem.Allocator, f: Finding) void {
    allocator.free(f.redacted_preview);
}

// ----------------------------------------------------------------------------
// Pattern catalog
// ----------------------------------------------------------------------------

const Pattern = struct {
    kind: Kind,
    prefix: []const u8,
    anchor: u8,
    max_total_len: u32,
    base_confidence: Confidence,
    validate: *const fn (window: []const u8) ?u32,
};

const patterns = [_]Pattern{
    .{ .kind = .aws_access_key, .prefix = "AKIA", .anchor = 'A',
       .max_total_len = 24, .base_confidence = .high, .validate = validateAwsAccessKey },
    .{ .kind = .aws_access_key, .prefix = "ASIA", .anchor = 'A',
       .max_total_len = 24, .base_confidence = .high, .validate = validateAwsAccessKey },
    .{ .kind = .github_pat, .prefix = "ghp_", .anchor = 'g',
       .max_total_len = 44, .base_confidence = .high, .validate = validateGithubPat },
    .{ .kind = .github_pat, .prefix = "gho_", .anchor = 'g',
       .max_total_len = 44, .base_confidence = .high, .validate = validateGithubPat },
    .{ .kind = .github_pat, .prefix = "ghu_", .anchor = 'g',
       .max_total_len = 44, .base_confidence = .high, .validate = validateGithubPat },
    .{ .kind = .github_pat, .prefix = "ghs_", .anchor = 'g',
       .max_total_len = 44, .base_confidence = .high, .validate = validateGithubPat },
    .{ .kind = .github_pat, .prefix = "ghr_", .anchor = 'g',
       .max_total_len = 44, .base_confidence = .high, .validate = validateGithubPat },
    .{ .kind = .slack_token, .prefix = "xoxb-", .anchor = 'x',
       .max_total_len = 256, .base_confidence = .high, .validate = validateSlack },
    .{ .kind = .slack_token, .prefix = "xoxa-", .anchor = 'x',
       .max_total_len = 256, .base_confidence = .high, .validate = validateSlack },
    .{ .kind = .slack_token, .prefix = "xoxp-", .anchor = 'x',
       .max_total_len = 256, .base_confidence = .high, .validate = validateSlack },
    .{ .kind = .slack_token, .prefix = "xoxr-", .anchor = 'x',
       .max_total_len = 256, .base_confidence = .high, .validate = validateSlack },
    .{ .kind = .slack_token, .prefix = "xoxs-", .anchor = 'x',
       .max_total_len = 256, .base_confidence = .high, .validate = validateSlack },
    .{ .kind = .jwt, .prefix = "eyJ", .anchor = 'e',
       .max_total_len = 8192, .base_confidence = .medium, .validate = validateJwt },
    .{ .kind = .pem_private_key, .prefix = "-----BEGIN ", .anchor = '-',
       .max_total_len = 64 * 1024, .base_confidence = .certain, .validate = validatePem },
    // GCP service-account JSON marker. Anchor on `t` (start of `type`) — the
    // canonical literal is `"type": "service_account"`. Anchoring on `"` would
    // produce huge false-positive volume in JSON-heavy buffers.
    .{ .kind = .gcp_service_account, .prefix = "type\": \"service_account\"", .anchor = 't',
       .max_total_len = 32, .base_confidence = .medium, .validate = validateGcpSa },
    // Variant without space after colon.
    .{ .kind = .gcp_service_account, .prefix = "type\":\"service_account\"", .anchor = 't',
       .max_total_len = 32, .base_confidence = .medium, .validate = validateGcpSa },
};

// ----------------------------------------------------------------------------
// Public scan entry point
// ----------------------------------------------------------------------------

pub fn scan(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    opts: ScanOptions,
) errors.ScribeError!Findings {
    var list: std.ArrayList(Finding) = .empty;
    errdefer {
        for (list.items) |f| freeFinding(allocator, f);
        list.deinit(allocator);
    }

    try scanAnchors(allocator, bytes, &list);
    try scanContextualAwsSecret(allocator, bytes, &list);
    if (opts.include_generic) {
        try scanGenericEntropy(allocator, bytes, opts, &list);
    }

    // Sort by offset, then drop overlapping findings of weaker kinds.
    const items = try list.toOwnedSlice(allocator);
    std.mem.sort(Finding, items, {}, lessByOffset);
    const deduped = try dedupOverlaps(allocator, items);
    if (deduped.ptr != items.ptr) allocator.free(items);
    return .{ .items = deduped };
}

fn lessByOffset(_: void, a: Finding, b: Finding) bool {
    return a.offset < b.offset;
}

/// Drop a `generic_high_entropy` finding if it falls entirely inside a stronger finding.
fn dedupOverlaps(
    allocator: std.mem.Allocator,
    items: []Finding,
) errors.ScribeError![]Finding {
    if (items.len == 0) return items;

    var keep = try allocator.alloc(bool, items.len);
    defer allocator.free(keep);
    @memset(keep, true);

    for (items, 0..) |f, i| {
        if (f.kind != .generic_high_entropy) continue;
        const f_end = f.offset + f.length;
        for (items, 0..) |g, j| {
            if (i == j) continue;
            if (g.kind == .generic_high_entropy) continue;
            const g_end = g.offset + g.length;
            // Drop generic finding if it overlaps any stronger finding —
            // either fully contained inside, or engulfing it.
            if (f.offset < g_end and g.offset < f_end) {
                keep[i] = false;
                break;
            }
        }
    }

    var kept_count: usize = 0;
    for (keep) |k| if (k) { kept_count += 1; };
    if (kept_count == items.len) return items;

    var out = try allocator.alloc(Finding, kept_count);
    var w: usize = 0;
    for (items, 0..) |f, i| {
        if (keep[i]) {
            out[w] = f;
            w += 1;
        } else {
            freeFinding(allocator, f);
        }
    }
    return out;
}

// ----------------------------------------------------------------------------
// SIMD anchor scan
// ----------------------------------------------------------------------------

const lane_count: comptime_int = std.simd.suggestVectorLength(u8) orelse 16;
const Lane = @Vector(lane_count, u8);
const Mask = std.meta.Int(.unsigned, lane_count);

fn scanAnchors(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    out: *std.ArrayList(Finding),
) errors.ScribeError!void {
    var i: usize = 0;
    while (i + lane_count <= bytes.len) : (i += lane_count) {
        const v: Lane = bytes[i..][0..lane_count].*;
        inline for (patterns) |pat| {
            const anchor: Lane = @splat(pat.anchor);
            const eq = v == anchor;
            const bits: Mask = @bitCast(eq);
            if (bits != 0) {
                var rest = bits;
                while (rest != 0) {
                    const lane: usize = @ctz(rest);
                    rest &= rest - 1;
                    const off = i + lane;
                    try tryMatch(allocator, bytes, off, pat, out);
                }
            }
        }
    }
    // Scalar tail.
    while (i < bytes.len) : (i += 1) {
        inline for (patterns) |pat| {
            if (bytes[i] == pat.anchor) {
                try tryMatch(allocator, bytes, i, pat, out);
            }
        }
    }
}

fn tryMatch(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    off: usize,
    pat: Pattern,
    out: *std.ArrayList(Finding),
) errors.ScribeError!void {
    if (off + pat.prefix.len > bytes.len) return;
    if (!std.mem.eql(u8, bytes[off..][0..pat.prefix.len], pat.prefix)) return;
    const window_end = @min(bytes.len, off + pat.max_total_len);
    const hit_len = pat.validate(bytes[off..window_end]) orelse return;
    const slice = bytes[off..][0..hit_len];
    const ent: f32 = @floatCast(entropy_mod.shannon(slice));
    const preview = try buildPreview(allocator, slice, ent);
    errdefer allocator.free(preview);
    out.append(allocator, .{
        .kind = pat.kind,
        .offset = off,
        .length = hit_len,
        .entropy = ent,
        .confidence = pat.base_confidence,
        .redacted_preview = preview,
    }) catch return error.OutOfMemory;
}

// ----------------------------------------------------------------------------
// Contextual: AWS secret access key (no usable prefix; anchor on context literal)
// ----------------------------------------------------------------------------

fn scanContextualAwsSecret(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    out: *std.ArrayList(Finding),
) errors.ScribeError!void {
    const literal = "aws_secret_access_key";
    var search_pos: usize = 0;
    while (search_pos < bytes.len) {
        const idx = std.mem.indexOfPos(u8, bytes, search_pos, literal) orelse break;
        const win_lo = if (idx > 256) idx - 256 else 0;
        const win_hi = @min(bytes.len, idx + literal.len + 256);
        const window = bytes[win_lo..win_hi];
        if (findAwsSecretCandidate(window)) |hit| {
            const off = win_lo + hit.start;
            const slice = bytes[off..][0..hit.len];
            const ent: f32 = @floatCast(entropy_mod.shannon(slice));
            // Require enough randomness to avoid matching repeated boilerplate.
            if (ent >= 4.0) {
                const preview = try buildPreview(allocator, slice, ent);
                errdefer allocator.free(preview);
                out.append(allocator, .{
                    .kind = .aws_secret_key,
                    .offset = off,
                    .length = hit.len,
                    .entropy = ent,
                    .confidence = .medium,
                    .redacted_preview = preview,
                }) catch return error.OutOfMemory;
            }
        }
        search_pos = idx + literal.len;
    }
}

const Run = struct { start: usize, len: u32 };

fn findAwsSecretCandidate(window: []const u8) ?Run {
    var i: usize = 0;
    while (i < window.len) : (i += 1) {
        if (!isAwsSecretByte(window[i])) continue;
        var j = i;
        while (j < window.len and isAwsSecretByte(window[j])) : (j += 1) {}
        const len = j - i;
        if (len == 40) return .{ .start = i, .len = 40 };
        i = j;
    }
    return null;
}

fn isAwsSecretByte(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '/' or c == '+' or c == '=';
}

// ----------------------------------------------------------------------------
// Generic high-entropy pass (opt-in)
// ----------------------------------------------------------------------------

fn scanGenericEntropy(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    opts: ScanOptions,
    out: *std.ArrayList(Finding),
) errors.ScribeError!void {
    var it = strings_mod.scan(bytes, .{ .min_len = opts.min_generic_len });
    while (it.next()) |s| {
        if (s.len < opts.min_generic_len) continue;
        const ent: f32 = @floatCast(entropy_mod.shannon(s));
        if (ent < opts.min_entropy) continue;
        // Pointer arithmetic — strings.zig returns slices into the input buffer.
        const off: usize = @intFromPtr(s.ptr) - @intFromPtr(bytes.ptr);
        const preview = try buildPreview(allocator, s, ent);
        errdefer allocator.free(preview);
        out.append(allocator, .{
            .kind = .generic_high_entropy,
            .offset = off,
            .length = @intCast(s.len),
            .entropy = ent,
            .confidence = .low,
            .redacted_preview = preview,
        }) catch return error.OutOfMemory;
    }
}

// ----------------------------------------------------------------------------
// Redaction
// ----------------------------------------------------------------------------

fn buildPreview(
    allocator: std.mem.Allocator,
    slice: []const u8,
    ent: f32,
) errors.ScribeError![]u8 {
    const head_len = @min(@as(usize, 4), slice.len);
    const tail_len = if (slice.len > head_len) @min(@as(usize, 4), slice.len - head_len) else 0;
    const head = slice[0..head_len];
    const tail = slice[slice.len - tail_len ..];
    return std.fmt.allocPrint(
        allocator,
        "{s}\u{2026}{s} (len={d}, H={d:.2})",
        .{ head, tail, slice.len, ent },
    ) catch return error.OutOfMemory;
}

// ----------------------------------------------------------------------------
// Validators
// ----------------------------------------------------------------------------

inline fn isUpperAlnum(c: u8) bool {
    return (c >= 'A' and c <= 'Z') or (c >= '0' and c <= '9');
}

inline fn isAlnum(c: u8) bool {
    return std.ascii.isAlphanumeric(c);
}

inline fn isB64Url(c: u8) bool {
    return isAlnum(c) or c == '_' or c == '-';
}

fn validateAwsAccessKey(window: []const u8) ?u32 {
    if (window.len < 20) return null;
    for (window[4..20]) |c| if (!isUpperAlnum(c)) return null;
    if (window.len > 20 and isUpperAlnum(window[20])) return null;
    return 20;
}

fn validateGithubPat(window: []const u8) ?u32 {
    if (window.len < 40) return null;
    for (window[4..40]) |c| if (!isAlnum(c)) return null;
    if (window.len > 40 and isAlnum(window[40])) return null;
    return 40;
}

fn validateSlack(window: []const u8) ?u32 {
    if (window.len < 24) return null;
    var i: usize = 5;
    var hyphens: usize = 0;
    while (i < window.len and (isAlnum(window[i]) or window[i] == '-')) : (i += 1) {
        if (window[i] == '-') hyphens += 1;
    }
    if (i < 24) return null;
    if (hyphens < 2) return null;
    return @intCast(i);
}

fn validateJwt(window: []const u8) ?u32 {
    if (window.len < 30) return null;
    var i: usize = 3; // skip "eyJ"
    while (i < window.len and isB64Url(window[i])) : (i += 1) {}
    if (i == 3 or i >= window.len or window[i] != '.') return null;
    i += 1;
    const payload_start = i;
    while (i < window.len and isB64Url(window[i])) : (i += 1) {}
    if (i == payload_start or i >= window.len or window[i] != '.') return null;
    i += 1;
    const sig_start = i;
    while (i < window.len and isB64Url(window[i])) : (i += 1) {}
    if (i == sig_start) return null;
    if (i < 30) return null;
    return @intCast(i);
}

fn validatePem(window: []const u8) ?u32 {
    const begin = "-----BEGIN ";
    if (window.len < begin.len) return null;
    var p: usize = begin.len;
    const end_dashes = std.mem.indexOfPos(u8, window, p, "-----") orelse return null;
    const label = window[p..end_dashes];
    const valid_labels = [_][]const u8{
        "RSA PRIVATE KEY",
        "OPENSSH PRIVATE KEY",
        "EC PRIVATE KEY",
        "DSA PRIVATE KEY",
        "PRIVATE KEY",
        "ENCRYPTED PRIVATE KEY",
    };
    var matched = false;
    for (valid_labels) |vl| {
        if (std.mem.eql(u8, label, vl)) { matched = true; break; }
    }
    if (!matched) return null;
    p = end_dashes + 5;

    // Search forward for "-----END <label>-----".
    const haystack = window[p..];
    var search_pos: usize = 0;
    while (search_pos < haystack.len) {
        const eidx = std.mem.indexOfPos(u8, haystack, search_pos, "-----END ") orelse return null;
        const after = haystack[eidx + 9 ..];
        if (after.len < label.len + 5) return null;
        if (std.mem.eql(u8, after[0..label.len], label) and
            std.mem.startsWith(u8, after[label.len..], "-----"))
        {
            const total = p + eidx + 9 + label.len + 5;
            return @intCast(total);
        }
        search_pos = eidx + 9;
    }
    return null;
}

fn validateGcpSa(window: []const u8) ?u32 {
    const a = "type\": \"service_account\"";
    const b = "type\":\"service_account\"";
    if (window.len >= a.len and std.mem.startsWith(u8, window, a)) return @intCast(a.len);
    if (window.len >= b.len and std.mem.startsWith(u8, window, b)) return @intCast(b.len);
    return null;
}

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

const testing = std.testing;

fn countByKind(items: []Finding, kind: Kind) usize {
    var n: usize = 0;
    for (items) |f| if (f.kind == kind) { n += 1; };
    return n;
}

test "AWS access key detected and redacted" {
    const data = "\x00AKIAIOSFODNN7EXAMPLE\x00";
    var f = try scan(testing.allocator, data, .{});
    defer f.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 1), f.items.len);
    const item = f.items[0];
    try testing.expectEqual(Kind.aws_access_key, item.kind);
    try testing.expectEqual(@as(u32, 20), item.length);
    try testing.expectEqual(@as(u64, 1), item.offset);
    // Preview must contain the head and tail markers, never middle.
    try testing.expect(std.mem.indexOf(u8, item.redacted_preview, "AKIA") != null);
    try testing.expect(std.mem.indexOf(u8, item.redacted_preview, "MPLE") != null);
    try testing.expect(std.mem.indexOf(u8, item.redacted_preview, "IOSFODNN7EXA") == null);
}

test "AKIA prefix with bad charset rejected" {
    const data = "\x00AKIA!!!!badbytes\x00";
    var f = try scan(testing.allocator, data, .{});
    defer f.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 0), f.items.len);
}

test "GitHub PAT detected" {
    const data = "ghp_aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5\x00";
    var f = try scan(testing.allocator, data, .{});
    defer f.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 1), f.items.len);
    try testing.expectEqual(Kind.github_pat, f.items[0].kind);
    try testing.expectEqual(@as(u32, 40), f.items[0].length);
}

test "Slack token detected" {
    const data = "xoxb-12345-67890-abcdefghijklmnop\x00";
    var f = try scan(testing.allocator, data, .{});
    defer f.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 1), f.items.len);
    try testing.expectEqual(Kind.slack_token, f.items[0].kind);
}

test "JWT detected" {
    const data = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9FYR2sLOIKfsk\x00";
    var f = try scan(testing.allocator, data, .{});
    defer f.deinit(testing.allocator);
    try testing.expect(countByKind(f.items, .jwt) >= 1);
}

test "PEM private key detected" {
    const data =
        "-----BEGIN RSA PRIVATE KEY-----\n" ++
        "MIIEpAIBAAKCAQEA3Tz2mr7SZiAMfQyuvBjM9Oi..AcDQHDrAOg==\n" ++
        "-----END RSA PRIVATE KEY-----\n";
    var f = try scan(testing.allocator, data, .{});
    defer f.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 1), f.items.len);
    try testing.expectEqual(Kind.pem_private_key, f.items[0].kind);
    try testing.expectEqual(Confidence.certain, f.items[0].confidence);
}

test "Multiple anchored kinds in one buffer" {
    const data =
        "padding\x00" ++
        "AKIAIOSFODNN7EXAMPLE\x00" ++
        "ghp_aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5\x00" ++
        "xoxb-12345-67890-abcdefghijklmnop\x00";
    var f = try scan(testing.allocator, data, .{});
    defer f.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 1), countByKind(f.items, .aws_access_key));
    try testing.expectEqual(@as(usize, 1), countByKind(f.items, .github_pat));
    try testing.expectEqual(@as(usize, 1), countByKind(f.items, .slack_token));
}

test "Generic high-entropy gated by option" {
    // 32-byte high-entropy printable run, no anchored prefix.
    const data = "\x00ZxQwErTyUiOpAsDfGhJkLzXcVbNm0192\x00";
    var off = try scan(testing.allocator, data, .{ .include_generic = false });
    defer off.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 0), countByKind(off.items, .generic_high_entropy));

    var on = try scan(testing.allocator, data, .{ .include_generic = true, .min_entropy = 3.0 });
    defer on.deinit(testing.allocator);
    try testing.expect(countByKind(on.items, .generic_high_entropy) >= 1);
}

test "Empty buffer yields zero findings" {
    var f = try scan(testing.allocator, "", .{});
    defer f.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 0), f.items.len);
}

test "Buffer smaller than lane width still scans (scalar tail)" {
    const data = "AKIAIOSFODNN7EXAMPLE"; // exactly 20 bytes
    var f = try scan(testing.allocator, data, .{});
    defer f.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 1), f.items.len);
    try testing.expectEqual(Kind.aws_access_key, f.items[0].kind);
}

test "Redaction never leaks middle bytes" {
    const middle = "IOSFODNN7EXAMPLE12345678901234567890";
    var buf: [128]u8 = undefined;
    const data = try std.fmt.bufPrint(&buf, "AAAA{s}ZZZZ", .{middle});
    // Build a synthetic 40-char base62 secret and run github_pat validator path.
    const synth = "ghp_" ++ "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5";
    _ = data;
    var f = try scan(testing.allocator, synth, .{});
    defer f.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 1), f.items.len);
    // Middle bytes of the secret must not appear in the preview.
    const middle_of_secret = synth[8..36];
    try testing.expect(std.mem.indexOf(u8, f.items[0].redacted_preview, middle_of_secret) == null);
}

test "PEM dedups overlapping generic high-entropy" {
    const data =
        "-----BEGIN RSA PRIVATE KEY-----\n" ++
        "MIIEpAIBAAKCAQEA3Tz2mr7SZiAMfQyuvBjM9OiAcDQHDrAOgZxQwErTyUiOpAsDf\n" ++
        "-----END RSA PRIVATE KEY-----\n";
    var f = try scan(testing.allocator, data, .{ .include_generic = true, .min_entropy = 3.0 });
    defer f.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 1), countByKind(f.items, .pem_private_key));
    // Generic findings inside the PEM block should be removed.
    for (f.items) |item| {
        if (item.kind != .generic_high_entropy) continue;
        const pem = f.items[0]; // pem appears first by offset
        const inside = item.offset >= pem.offset and item.offset + item.length <= pem.offset + pem.length;
        try testing.expect(!inside);
    }
}

test "GCP service account literal detected" {
    const data = "{\"type\": \"service_account\", \"project_id\": \"foo\"}";
    var f = try scan(testing.allocator, data, .{});
    defer f.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 1), countByKind(f.items, .gcp_service_account));
}

test "AWS secret access key with context" {
    const data = "config:\n  aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n";
    var f = try scan(testing.allocator, data, .{});
    defer f.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 1), countByKind(f.items, .aws_secret_key));
}
