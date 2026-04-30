//! Software Bill of Materials assembly. Combines:
//!   1. Build identifier (GNU build-id / Mach-O UUID / PE PDB GUID).
//!   2. Dynamic library dependencies (DT_NEEDED / LC_LOAD_DYLIB / PE imports).
//!   3. Embedded version-string fingerprints (OpenSSL, zlib, sqlite, glibc, ...).
//!
//! Phase-3a: cheap-cheerful. Function-signature fingerprinting deferred to
//! Phase-3b once a curated corpus exists.

const std = @import("std");
const errors = @import("errors.zig");
const deps_mod = @import("deps.zig");
const buildid_mod = @import("buildid.zig");
const strings_mod = @import("strings.zig");
const security_secrets = @import("security/secrets.zig");

pub const ComponentKind = enum {
    program,
    dynamic_lib,
    static_lib,
    runtime,
    compiler,
};

pub const Evidence = enum {
    build_id,
    dynamic_link,
    embedded_string,
};

pub const Component = struct {
    kind: ComponentKind,
    name: []u8, // owned
    version: ?[]u8 = null, // owned
    evidence: Evidence,
    /// Optional file path inside container/image. Owned.
    path: ?[]u8 = null,
    /// Optional platform tag (e.g. "linux/amd64"). Owned.
    platform: ?[]u8 = null,
};

pub const Sbom = struct {
    components: []Component,
    /// Secret-scan findings. Empty unless populated by the security pipeline.
    findings: []security_secrets.Finding = &.{},

    pub fn deinit(self: *Sbom, allocator: std.mem.Allocator) void {
        for (self.components) |c| freeComponent(allocator, c);
        allocator.free(self.components);
        for (self.findings) |f| security_secrets.freeFinding(allocator, f);
        if (self.findings.len != 0) allocator.free(self.findings);
        self.components = &.{};
        self.findings = &.{};
    }
};

pub fn freeComponent(allocator: std.mem.Allocator, c: Component) void {
    allocator.free(c.name);
    if (c.version) |v| allocator.free(v);
    if (c.path) |p| allocator.free(p);
    if (c.platform) |p| allocator.free(p);
}

pub fn collect(allocator: std.mem.Allocator, bytes: []const u8) errors.ScribeError!Sbom {
    var list: std.ArrayList(Component) = .empty;
    errdefer {
        for (list.items) |c| freeComponent(allocator, c);
        list.deinit(allocator);
    }

    // 1. Build ID -> program component.
    if (try buildid_mod.extract(allocator, bytes)) |bid| {
        defer buildid_mod.free(allocator, bid);
        try appendOwned(allocator, &list, .{
            .kind = .program,
            .name = try allocator.dupe(u8, "binary"),
            .version = try allocator.dupe(u8, bid.hex),
            .evidence = .build_id,
        });
    }

    // 2. Dynamic deps -> runtime/dynamic-lib components.
    const deps = deps_mod.collect(allocator, bytes) catch &[_]deps_mod.Dep{};
    defer if (deps.len != 0) allocator.free(deps);
    for (deps) |d| {
        try appendOwned(allocator, &list, .{
            .kind = .dynamic_lib,
            .name = try allocator.dupe(u8, basename(d.name)),
            .version = null,
            .evidence = .dynamic_link,
        });
    }

    // 3. Embedded version strings.
    try scanFingerprints(allocator, &list, bytes);

    return .{ .components = try list.toOwnedSlice(allocator) };
}

fn appendOwned(
    allocator: std.mem.Allocator,
    list: *std.ArrayList(Component),
    component: Component,
) errors.ScribeError!void {
    list.append(allocator, component) catch return error.OutOfMemory;
}

fn basename(path: []const u8) []const u8 {
    if (std.mem.lastIndexOfScalar(u8, path, '/')) |i| return path[i + 1 ..];
    if (std.mem.lastIndexOfScalar(u8, path, '\\')) |i| return path[i + 1 ..];
    return path;
}

// --- Fingerprint detection ---------------------------------------------------

const Detector = struct {
    name: []const u8,
    kind: ComponentKind,
    /// Returns version slice (within `s`) when the string identifies this lib.
    extractVersion: *const fn (s: []const u8) ?[]const u8,
};

const detectors = [_]Detector{
    .{ .name = "openssl", .kind = .static_lib, .extractVersion = matchOpenSSL },
    .{ .name = "openssl", .kind = .static_lib, .extractVersion = matchOpenSSLFips },
    .{ .name = "zlib", .kind = .static_lib, .extractVersion = matchZlib },
    .{ .name = "sqlite", .kind = .static_lib, .extractVersion = matchSqlite },
    .{ .name = "libcurl", .kind = .static_lib, .extractVersion = matchLibcurl },
    .{ .name = "libxml2", .kind = .static_lib, .extractVersion = matchLibxml2 },
    .{ .name = "libpng", .kind = .static_lib, .extractVersion = matchLibpng },
    .{ .name = "musl", .kind = .runtime, .extractVersion = matchMusl },
    .{ .name = "glibc", .kind = .runtime, .extractVersion = matchGlibc },
    .{ .name = "gcc", .kind = .compiler, .extractVersion = matchGcc },
    .{ .name = "clang", .kind = .compiler, .extractVersion = matchClang },
    .{ .name = "zig", .kind = .compiler, .extractVersion = matchZig },
};

fn scanFingerprints(
    allocator: std.mem.Allocator,
    list: *std.ArrayList(Component),
    bytes: []const u8,
) errors.ScribeError!void {
    // Track best (highest) version seen per detector index for dedup.
    var best_version = [_]?[]u8{null} ** detectors.len;
    var seen = [_]bool{false} ** detectors.len;
    errdefer for (best_version) |v| if (v) |x| allocator.free(x);

    var it = strings_mod.scan(bytes, .{ .min_len = 4 });
    while (it.next()) |s| {
        for (detectors, 0..) |det, idx| {
            const ver = det.extractVersion(s) orelse continue;
            seen[idx] = true;
            if (best_version[idx]) |existing| {
                if (versionCompare(ver, existing) > 0) {
                    allocator.free(existing);
                    best_version[idx] = try allocator.dupe(u8, ver);
                }
            } else {
                best_version[idx] = try allocator.dupe(u8, ver);
            }
        }
    }

    for (detectors, 0..) |det, idx| {
        if (!seen[idx]) continue;
        try appendOwned(allocator, list, .{
            .kind = det.kind,
            .name = try allocator.dupe(u8, det.name),
            .version = best_version[idx],
            .evidence = .embedded_string,
        });
        best_version[idx] = null; // ownership transferred
    }

    for (best_version) |v| if (v) |x| allocator.free(x);
}

/// Lexicographic compare on dotted numeric components. Returns -1/0/1.
fn versionCompare(a: []const u8, b: []const u8) i32 {
    var ai: std.mem.SplitIterator(u8, .scalar) = std.mem.splitScalar(u8, a, '.');
    var bi: std.mem.SplitIterator(u8, .scalar) = std.mem.splitScalar(u8, b, '.');
    while (true) {
        const ap = ai.next();
        const bp = bi.next();
        if (ap == null and bp == null) return 0;
        const an: u64 = if (ap) |p| std.fmt.parseInt(u64, trimTrailingNonDigit(p), 10) catch 0 else 0;
        const bn: u64 = if (bp) |p| std.fmt.parseInt(u64, trimTrailingNonDigit(p), 10) catch 0 else 0;
        if (an < bn) return -1;
        if (an > bn) return 1;
    }
}

fn trimTrailingNonDigit(s: []const u8) []const u8 {
    var end = s.len;
    while (end > 0 and !std.ascii.isDigit(s[end - 1])) : (end -= 1) {}
    return s[0..end];
}

// --- Version extractors ------------------------------------------------------

fn afterPrefix(s: []const u8, prefix: []const u8) ?[]const u8 {
    if (s.len <= prefix.len) return null;
    if (!std.mem.startsWith(u8, s, prefix)) return null;
    return takeVersion(s[prefix.len..]);
}

fn afterPrefixContains(s: []const u8, prefix: []const u8) ?[]const u8 {
    const idx = std.mem.indexOf(u8, s, prefix) orelse return null;
    return takeVersion(s[idx + prefix.len ..]);
}

/// Read leading "X[.Y[.Z[...]]]" optionally followed by a single suffix letter.
fn takeVersion(s: []const u8) ?[]const u8 {
    var i: usize = 0;
    var dots: usize = 0;
    while (i < s.len) : (i += 1) {
        const c = s[i];
        if (std.ascii.isDigit(c)) continue;
        if (c == '.' and i > 0 and i + 1 < s.len and std.ascii.isDigit(s[i + 1])) {
            dots += 1;
            continue;
        }
        break;
    }
    if (i < s.len and std.ascii.isAlphabetic(s[i]) and (i + 1 == s.len or !std.ascii.isAlphabetic(s[i + 1])))
        i += 1;
    if (i == 0 or dots == 0) return null;
    return s[0..i];
}

fn matchOpenSSL(s: []const u8) ?[]const u8 {
    return afterPrefix(s, "OpenSSL ");
}
fn matchOpenSSLFips(s: []const u8) ?[]const u8 {
    return afterPrefix(s, "OpenSSL-fips ");
}
fn matchZlib(s: []const u8) ?[]const u8 {
    if (afterPrefix(s, "deflate 1.") != null or afterPrefix(s, "inflate 1.") != null) {
        // Recover full version starting from "1."
        const idx = std.mem.indexOf(u8, s, "1.") orelse return null;
        return takeVersion(s[idx..]);
    }
    return null;
}
fn matchSqlite(s: []const u8) ?[]const u8 {
    return afterPrefix(s, "SQLite version ") orelse afterPrefix(s, "SQLite-");
}
fn matchLibcurl(s: []const u8) ?[]const u8 {
    return afterPrefixContains(s, "libcurl/");
}
fn matchLibxml2(s: []const u8) ?[]const u8 {
    if (std.mem.indexOf(u8, s, "libxml2") == null) return null;
    return afterPrefixContains(s, "libxml2-");
}
fn matchLibpng(s: []const u8) ?[]const u8 {
    return afterPrefix(s, "libpng version ");
}
fn matchMusl(s: []const u8) ?[]const u8 {
    if (!std.mem.startsWith(u8, s, "musl libc")) return null;
    return afterPrefixContains(s, "Version ");
}
fn matchGlibc(s: []const u8) ?[]const u8 {
    return afterPrefix(s, "GLIBC_");
}
fn matchGcc(s: []const u8) ?[]const u8 {
    return afterPrefixContains(s, "GCC: (GNU) ");
}
fn matchClang(s: []const u8) ?[]const u8 {
    return afterPrefixContains(s, "clang version ");
}
fn matchZig(s: []const u8) ?[]const u8 {
    return afterPrefixContains(s, "zig ") orelse afterPrefixContains(s, "ziglang ");
}

// --- Tests -------------------------------------------------------------------

test "version compare" {
    try std.testing.expectEqual(@as(i32, 1), versionCompare("1.2.3", "1.2.2"));
    try std.testing.expectEqual(@as(i32, -1), versionCompare("1.2.3", "1.3.0"));
    try std.testing.expectEqual(@as(i32, 0), versionCompare("1.0.0", "1.0.0"));
    try std.testing.expectEqual(@as(i32, 1), versionCompare("2.10.0", "2.9.99"));
}

test "matchOpenSSL extracts version" {
    try std.testing.expectEqualStrings("3.2.0", matchOpenSSL("OpenSSL 3.2.0 23 Nov 2023").?);
    try std.testing.expectEqualStrings("1.1.1w", matchOpenSSL("OpenSSL 1.1.1w  11 Sep 2023").?);
    try std.testing.expectEqual(@as(?[]const u8, null), matchOpenSSL("OpenSSL"));
}

test "matchGlibc extracts version" {
    try std.testing.expectEqualStrings("2.34", matchGlibc("GLIBC_2.34").?);
}

test "matchLibcurl extracts version" {
    try std.testing.expectEqualStrings("8.4.0", matchLibcurl("libcurl/8.4.0").?);
}

test "collect from synthetic fixture" {
    const synth = "padding\x00OpenSSL 3.0.12 24 Oct 2023\x00x\x00GLIBC_2.34\x00more\x00libcurl/8.4.0\x00";
    var buf: [4096]u8 = undefined;
    @memcpy(buf[0..synth.len], synth);
    @memset(buf[synth.len..], 0);

    var sbom = try collect(std.testing.allocator, buf[0..synth.len]);
    defer sbom.deinit(std.testing.allocator);

    var found_ssl = false;
    var found_glibc = false;
    var found_curl = false;
    for (sbom.components) |c| {
        if (std.mem.eql(u8, c.name, "openssl")) {
            found_ssl = true;
            try std.testing.expectEqualStrings("3.0.12", c.version.?);
        }
        if (std.mem.eql(u8, c.name, "glibc")) {
            found_glibc = true;
            try std.testing.expectEqualStrings("2.34", c.version.?);
        }
        if (std.mem.eql(u8, c.name, "libcurl")) {
            found_curl = true;
            try std.testing.expectEqualStrings("8.4.0", c.version.?);
        }
    }
    try std.testing.expect(found_ssl and found_glibc and found_curl);
}

test "collect from glibc-linked fixture detects glibc" {
    const bytes = @embedFile("testdata/hello_dyn_x86_64");
    var sbom = try collect(std.testing.allocator, bytes);
    defer sbom.deinit(std.testing.allocator);

    var has_glibc = false;
    var has_libc_so = false;
    for (sbom.components) |c| {
        if (std.mem.eql(u8, c.name, "glibc")) has_glibc = true;
        if (std.mem.eql(u8, c.name, "libc.so.6")) has_libc_so = true;
    }
    try std.testing.expect(has_glibc);
    try std.testing.expect(has_libc_so);
}

test "collect from macho fixture detects libSystem" {
    const bytes = @embedFile("testdata/hello_macho_x86_64");
    var sbom = try collect(std.testing.allocator, bytes);
    defer sbom.deinit(std.testing.allocator);

    var has_lib_system = false;
    var has_uuid = false;
    for (sbom.components) |c| {
        if (std.mem.indexOf(u8, c.name, "libSystem") != null) has_lib_system = true;
        if (c.evidence == .build_id) has_uuid = true;
    }
    try std.testing.expect(has_lib_system);
    try std.testing.expect(has_uuid);
}

// --- CycloneDX 1.5 emitter ---------------------------------------------------

pub fn writeCycloneDX(writer: *std.Io.Writer, sbom: Sbom) !void {
    try writer.writeAll(
        \\{
        \\  "bomFormat": "CycloneDX",
        \\  "specVersion": "1.5",
        \\  "version": 1,
        \\  "components": [
    );

    for (sbom.components, 0..) |c, i| {
        if (i > 0) try writer.writeByte(',');
        try writer.writeAll("\n    {");
        try writer.print(
            \\"type": "{s}", "name":
        , .{cyclonedxType(c.kind)});
        try writeJsonString(writer, c.name);
        if (c.version) |v| {
            try writer.writeAll(", \"version\": ");
            try writeJsonString(writer, v);
        }
        if (c.path) |p| {
            try writer.writeAll(", \"properties\": [{\"name\": \"scribe:path\", \"value\": ");
            try writeJsonString(writer, p);
            if (c.platform) |pl| {
                try writer.writeAll("}, {\"name\": \"scribe:platform\", \"value\": ");
                try writeJsonString(writer, pl);
            }
            try writer.writeAll("}]");
        } else if (c.platform) |pl| {
            try writer.writeAll(", \"properties\": [{\"name\": \"scribe:platform\", \"value\": ");
            try writeJsonString(writer, pl);
            try writer.writeAll("}]");
        }
        try writer.writeAll(", \"evidence\": {\"identity\": [{\"field\": \"name\", \"confidence\": ");
        try writer.print("{d:.2}", .{evidenceConfidence(c.evidence)});
        try writer.writeAll(", \"methods\": [{\"technique\": \"");
        try writer.writeAll(@tagName(c.evidence));
        try writer.writeAll("\"}]}]}}");
    }

    try writer.writeAll("\n  ]");
    if (sbom.findings.len > 0) {
        try writer.writeAll(",\n  \"properties\": [");
        for (sbom.findings, 0..) |f, i| {
            if (i > 0) try writer.writeByte(',');
            try writer.writeAll("\n    {\"name\": \"scribe:secret:");
            try writer.writeAll(@tagName(f.kind));
            try writer.writeAll("\", \"value\": ");
            try writeJsonString(writer, f.redacted_preview);
            try writer.print(
                ", \"confidence\": {d}, \"offset\": {d}",
                .{ @intFromEnum(f.confidence), f.offset },
            );
            try writer.writeByte('}');
        }
        try writer.writeAll("\n  ]");
    }
    try writer.writeAll("\n}\n");
}

fn cyclonedxType(k: ComponentKind) []const u8 {
    return switch (k) {
        .program => "application",
        .dynamic_lib, .static_lib => "library",
        .runtime => "framework",
        .compiler => "application",
    };
}

fn evidenceConfidence(e: Evidence) f32 {
    return switch (e) {
        .build_id => 1.0,
        .dynamic_link => 0.9,
        .embedded_string => 0.6,
    };
}

fn writeJsonString(writer: *std.Io.Writer, s: []const u8) !void {
    try writer.writeByte('"');
    for (s) |c| switch (c) {
        '"' => try writer.writeAll("\\\""),
        '\\' => try writer.writeAll("\\\\"),
        '\n' => try writer.writeAll("\\n"),
        '\r' => try writer.writeAll("\\r"),
        '\t' => try writer.writeAll("\\t"),
        0...0x08, 0x0B, 0x0C, 0x0E...0x1F => try writer.print("\\u{x:0>4}", .{c}),
        else => try writer.writeByte(c),
    };
    try writer.writeByte('"');
}
