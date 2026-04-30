//! Container/OCI image SBOM. Reads `docker save` style tarballs and
//! emits component lists tagged with file path + platform.
//!
//! Supports the OCI/Docker hybrid format produced by Docker 24+ and modern
//! containerd: top-level tar containing manifest.json, config blobs, and
//! gzipped layer blobs. Layers are squashed in order with whiteout semantics
//! before binaries are scanned.
//!
//! Multi-platform: each manifest entry produces components tagged
//! "<os>/<arch>" (e.g. "linux/amd64", "linux/arm64").

const std = @import("std");
const Io = std.Io;
const tar = std.tar;
const flate = std.compress.flate;
const json = std.json;

const errors = @import("errors.zig");
const sbom_mod = @import("sbom.zig");
const format = @import("format.zig");

pub const ImageSbom = struct {
    components: []sbom_mod.Component,

    pub fn deinit(self: *ImageSbom, allocator: std.mem.Allocator) void {
        for (self.components) |c| sbom_mod.freeComponent(allocator, c);
        allocator.free(self.components);
        self.components = &.{};
    }
};

pub const Error = error{
    ManifestMissing,
    InvalidManifest,
    LayerMissing,
    ConfigMissing,
} || errors.ScribeError;

pub fn isContainer(bytes: []const u8) bool {
    // Tar magic: "ustar" at offset 257, or pre-USTAR plain tar (no magic; check
    // header checksum). We accept either USTAR-marked tar or .tar.gz wrapping.
    if (bytes.len >= 2 and bytes[0] == 0x1F and bytes[1] == 0x8B) return true;
    if (bytes.len >= 263 and std.mem.eql(u8, bytes[257..262], "ustar")) return true;
    return false;
}

pub fn collect(allocator: std.mem.Allocator, tar_bytes: []const u8) Error!ImageSbom {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const work = arena.allocator();

    const outer = readTarToMap(work, tar_bytes) catch return error.InvalidManifest;
    return collectFromBlobs(allocator, work, outer);
}

/// Lower-level entry point: caller provides a {path -> bytes} map containing
/// `manifest.json`, the config blob(s), and the layer blob(s). Used by the
/// docker-save path (caller built the map by walking a tar) and the
/// registry-pull path (caller built the map from HTTP responses).
pub fn collectFromBlobs(
    allocator: std.mem.Allocator,
    work: std.mem.Allocator,
    outer: std.StringHashMap([]u8),
) Error!ImageSbom {
    const manifest_raw = outer.get("manifest.json") orelse return error.ManifestMissing;
    const parsed = json.parseFromSlice(
        []ManifestEntry,
        work,
        manifest_raw,
        .{ .ignore_unknown_fields = true },
    ) catch return error.InvalidManifest;
    defer parsed.deinit();

    var components: std.ArrayList(sbom_mod.Component) = .empty;
    errdefer {
        for (components.items) |c| sbom_mod.freeComponent(allocator, c);
        components.deinit(allocator);
    }

    for (parsed.value) |entry| {
        const platform_tag = readPlatform(work, outer, entry.Config) catch
            try work.dupe(u8, "linux/unknown");

        var squash: std.StringHashMap([]u8) = .init(work);
        for (entry.Layers) |layer_path| {
            const layer_bytes = outer.get(layer_path) orelse return error.LayerMissing;
            applyLayer(work, &squash, layer_bytes) catch continue;
        }

        var it = squash.iterator();
        while (it.next()) |kv| {
            const file_path = kv.key_ptr.*;
            const file_bytes = kv.value_ptr.*;
            if (!isExecutableMagic(file_bytes)) continue;

            const sub = sbom_mod.collect(allocator, file_bytes) catch continue;
            for (sub.components) |c| {
                const c2: sbom_mod.Component = .{
                    .kind = c.kind,
                    .name = c.name,
                    .version = c.version,
                    .evidence = c.evidence,
                    .path = allocator.dupe(u8, file_path) catch null,
                    .platform = allocator.dupe(u8, platform_tag) catch null,
                };
                components.append(allocator, c2) catch return error.OutOfMemory;
            }
            allocator.free(sub.components);
        }
    }

    return .{ .components = components.toOwnedSlice(allocator) catch return error.OutOfMemory };
}

const ManifestEntry = struct {
    Config: []const u8,
    RepoTags: ?[]const []const u8 = null,
    Layers: []const []const u8,
};

const ConfigDoc = struct {
    architecture: ?[]const u8 = null,
    os: ?[]const u8 = null,
};

fn readPlatform(
    work: std.mem.Allocator,
    outer: std.StringHashMap([]u8),
    config_path: []const u8,
) ![]u8 {
    const config_bytes = outer.get(config_path) orelse return error.ConfigMissing;
    const cfg = json.parseFromSlice(
        ConfigDoc,
        work,
        config_bytes,
        .{ .ignore_unknown_fields = true },
    ) catch return error.InvalidManifest;
    defer cfg.deinit();

    const os = cfg.value.os orelse "linux";
    const arch = cfg.value.architecture orelse "unknown";
    return std.fmt.allocPrint(work, "{s}/{s}", .{ os, arch });
}

fn readTarToMap(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) !std.StringHashMap([]u8) {
    var map: std.StringHashMap([]u8) = .init(allocator);
    var input: Io.Reader = .fixed(bytes);
    try walkTar(allocator, &input, &map);
    return map;
}

fn applyLayer(
    allocator: std.mem.Allocator,
    squash: *std.StringHashMap([]u8),
    layer_bytes: []const u8,
) !void {
    const is_gzip = layer_bytes.len >= 2 and layer_bytes[0] == 0x1F and layer_bytes[1] == 0x8B;

    var input: Io.Reader = .fixed(layer_bytes);
    if (is_gzip) {
        const window = try allocator.alignedAlloc(u8, .of(u8), flate.max_window_len);
        defer allocator.free(window);
        var dz = flate.Decompress.init(&input, .gzip, window);
        try walkTarApplying(allocator, &dz.reader, squash);
    } else {
        try walkTarApplying(allocator, &input, squash);
    }
}

fn walkTar(
    allocator: std.mem.Allocator,
    reader: *Io.Reader,
    map: *std.StringHashMap([]u8),
) !void {
    var name_buf: [std.fs.max_path_bytes]u8 = undefined;
    var link_buf: [std.fs.max_path_bytes]u8 = undefined;
    var it = tar.Iterator.init(reader, .{
        .file_name_buffer = &name_buf,
        .link_name_buffer = &link_buf,
    });
    while (try it.next()) |file| {
        if (file.kind != .file) continue; // Iterator skips padding on next()
        const buf = try allocator.alloc(u8, @intCast(file.size));
        var w: Io.Writer = .fixed(buf);
        try it.streamRemaining(file, &w);
        const key = try allocator.dupe(u8, file.name);
        try map.put(key, buf);
    }
}

fn walkTarApplying(
    allocator: std.mem.Allocator,
    reader: *Io.Reader,
    squash: *std.StringHashMap([]u8),
) !void {
    var name_buf: [std.fs.max_path_bytes]u8 = undefined;
    var link_buf: [std.fs.max_path_bytes]u8 = undefined;
    var it = tar.Iterator.init(reader, .{
        .file_name_buffer = &name_buf,
        .link_name_buffer = &link_buf,
    });
    while (try it.next()) |file| {
        const norm = stripDotSlash(file.name);

        // Whiteout markers (overlayfs convention used by Docker layers).
        if (isWhiteout(norm)) |target| {
            removeFromSquash(squash, target);
            continue;
        }

        if (file.kind != .file) continue;

        const buf = try allocator.alloc(u8, @intCast(file.size));
        var w: Io.Writer = .fixed(buf);
        try it.streamRemaining(file, &w);

        const key = try allocator.dupe(u8, norm);
        try squash.put(key, buf);
    }
}

fn stripDotSlash(name: []const u8) []const u8 {
    if (std.mem.startsWith(u8, name, "./")) return name[2..];
    return name;
}

fn isWhiteout(path: []const u8) ?[]const u8 {
    const base = std.fs.path.basename(path);
    if (!std.mem.startsWith(u8, base, ".wh.")) return null;
    if (std.mem.eql(u8, base, ".wh..wh..opq")) {
        // Opaque dir whiteout — return the directory path as marker.
        return std.fs.path.dirname(path) orelse "";
    }
    return base[4..];
}

fn removeFromSquash(squash: *std.StringHashMap([]u8), target_basename: []const u8) void {
    // Linear scan: remove any path whose basename matches.
    var to_remove: [16][]const u8 = undefined;
    var n: usize = 0;
    var it = squash.iterator();
    while (it.next()) |kv| {
        if (std.mem.eql(u8, std.fs.path.basename(kv.key_ptr.*), target_basename)) {
            if (n < to_remove.len) {
                to_remove[n] = kv.key_ptr.*;
                n += 1;
            }
        }
    }
    var i: usize = 0;
    while (i < n) : (i += 1) _ = squash.remove(to_remove[i]);
}

fn isExecutableMagic(bytes: []const u8) bool {
    if (bytes.len < 4) return false;
    if (std.mem.eql(u8, bytes[0..4], std.elf.MAGIC)) return true;
    const m = std.mem.readInt(u32, bytes[0..4], .little);
    if (m == std.macho.MH_MAGIC_64 or m == std.macho.MH_CIGAM_64 or
        m == std.macho.MH_MAGIC or m == std.macho.MH_CIGAM) return true;
    if (bytes.len >= 2 and bytes[0] == 'M' and bytes[1] == 'Z') return true;
    return false;
}

// --- tests -------------------------------------------------------------------

test "isContainer detects gzip + ustar" {
    var gz: [4]u8 = .{ 0x1F, 0x8B, 0x08, 0x00 };
    try std.testing.expect(isContainer(&gz));

    var tar_block: [512]u8 = @splat(0);
    @memcpy(tar_block[257..262], "ustar");
    try std.testing.expect(isContainer(&tar_block));

    var elf: [4]u8 = .{ 0x7F, 'E', 'L', 'F' };
    try std.testing.expect(!isContainer(&elf));
}

test "collect from alpine arm64 fixture" {
    const bytes = @embedFile("testdata/alpine_arm64.tar");
    var sbom = collect(std.testing.allocator, bytes) catch |err| {
        std.debug.print("alpine collect err: {s}\n", .{@errorName(err)});
        return err;
    };
    defer sbom.deinit(std.testing.allocator);

    try std.testing.expect(sbom.components.len > 0);

    var has_linux_arm64 = false;
    for (sbom.components) |c| {
        if (c.platform) |p| if (std.mem.eql(u8, p, "linux/arm64")) {
            has_linux_arm64 = true;
        };
    }
    try std.testing.expect(has_linux_arm64);
}
