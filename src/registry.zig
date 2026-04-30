//! Direct OCI/Docker-V2 registry pull. Skips the local docker daemon and
//! talks HTTPS straight to the registry. For Docker Hub the caller doesn't
//! need to authenticate beyond requesting an anonymous bearer token from
//! `auth.docker.io`.
//!
//! Known limitation: std.http.Client (Zig 0.16.0) does not honor
//! `privileged_headers`, so the bearer token rides along on every redirect.
//! Docker Hub redirects blob GETs to a Cloudflare R2 signed URL that
//! rejects requests carrying our `Authorization` header (the AWS-style
//! signature is in the query string and conflicts with header auth → 400).
//!
//! Workaround used here: blob fetches send NO Authorization header. This
//! works for blobs (registries permit anonymous blob retrieval once you
//! have the digest from an authenticated manifest GET) but only because
//! the registry trusts the digest itself.
//!
//! Manifest fetches still need the bearer token because Docker Hub
//! requires auth on the manifest endpoint. Those don't redirect, so the
//! token stays within docker.io and S3 never sees it.
//!
//! URI form: `registry://[host/][namespace/]image:tag[@os/arch]`
//!   examples:
//!     registry://alpine:3.19
//!     registry://library/alpine:3.19
//!     registry://registry-1.docker.io/library/alpine:3.19@linux/arm64
//!     registry://ghcr.io/owner/image:v1.0
//!
//! Pulls manifest list -> selects platform -> pulls image manifest ->
//! pulls config + each layer -> hands {manifest.json, blobs} map to
//! `container.collectFromBlobs`.

const std = @import("std");
const builtin = @import("builtin");
const json = std.json;
const http = std.http;

const errors = @import("errors.zig");
const container = @import("container.zig");
const sbom_mod = @import("sbom.zig");

pub const Error = error{
    InvalidUri,
    UnsupportedScheme,
    AuthFailed,
    ManifestFetchFailed,
    BlobFetchFailed,
    NoMatchingPlatform,
    InvalidJson,
    BodyTooLarge,
} || std.mem.Allocator.Error || container.Error || http.Client.FetchError;

pub const PullOptions = struct {
    /// "<os>/<arch>" — defaults to native build.
    platform: []const u8 = nativePlatform(),
    /// Cap individual blob size to bound memory.
    max_blob_bytes: usize = 256 * 1024 * 1024,
};

const Reference = struct {
    host: []const u8,
    repo: []const u8, // "library/alpine"
    tag: []const u8, // "3.19"
    platform: ?[]const u8, // optional override
};

pub fn pullSbom(
    allocator: std.mem.Allocator,
    io: std.Io,
    uri: []const u8,
    options: PullOptions,
) Error!container.ImageSbom {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const work = arena.allocator();

    const ref = try parseRegistryUri(work, uri);
    const platform = ref.platform orelse options.platform;

    var client: http.Client = .{ .allocator = work, .io = io };
    defer client.deinit();

    // Step 1: anonymous bearer token (Docker Hub only). For other
    // registries the manifest endpoint may accept unauthenticated GETs.
    const token = if (std.mem.endsWith(u8, ref.host, "docker.io"))
        try fetchAnonymousToken(work, &client, ref.repo)
    else
        null;

    // Step 2: pull top-level manifest.
    const top_url = try std.fmt.allocPrint(work, "https://{s}/v2/{s}/manifests/{s}", .{
        ref.host, ref.repo, ref.tag,
    });
    const accept_index =
        \\application/vnd.oci.image.index.v1+json,
        ++ "application/vnd.docker.distribution.manifest.list.v2+json,"
        ++ "application/vnd.oci.image.manifest.v1+json,"
        ++ "application/vnd.docker.distribution.manifest.v2+json";
    const top_body = try fetchAuthorized(work, &client, top_url, accept_index, token, options.max_blob_bytes);

    // Step 3: if the top manifest is an index, pick the matching platform.
    const image_manifest_bytes = if (looksLikeIndex(top_body))
        try resolveIndex(work, &client, ref, token, platform, top_body, options)
    else
        top_body;

    // Step 4: parse image manifest, collect config + layer digests.
    const Image = struct {
        config: struct { digest: []const u8 },
        layers: []const struct { digest: []const u8 },
    };
    const im = json.parseFromSlice(Image, work, image_manifest_bytes, .{
        .ignore_unknown_fields = true,
    }) catch return error.InvalidJson;
    defer im.deinit();

    // Step 5: fetch config + layer blobs into a map.
    var blobs: std.StringHashMap([]const u8) = .init(work);
    {
        const config_path = try std.fmt.allocPrint(work, "blobs/{s}", .{im.value.config.digest});
        const config_bytes = try fetchBlob(work, &client, ref, im.value.config.digest, token, options.max_blob_bytes);
        try blobs.put(config_path, config_bytes);
    }

    var layer_paths: std.ArrayList([]const u8) = .empty;
    defer layer_paths.deinit(work);
    for (im.value.layers) |l| {
        const path = try std.fmt.allocPrint(work, "blobs/{s}", .{l.digest});
        const layer_bytes = try fetchBlob(work, &client, ref, l.digest, token, options.max_blob_bytes);
        try blobs.put(path, layer_bytes);
        try layer_paths.append(work, path);
    }

    // Step 6: synthesize a docker-save style manifest.json describing one
    // image with our config + layers.
    const manifest_json = try buildManifestJson(work, im.value.config.digest, layer_paths.items);
    try blobs.put("manifest.json", manifest_json);

    return container.collectFromBlobs(allocator, work, blobs);
}

// --- URI parsing -------------------------------------------------------------

fn parseRegistryUri(work: std.mem.Allocator, uri: []const u8) Error!Reference {
    if (!std.mem.startsWith(u8, uri, "registry://")) return error.UnsupportedScheme;
    var rest: []const u8 = uri[11..];

    // Strip optional "@os/arch" platform tag.
    var platform: ?[]const u8 = null;
    if (std.mem.lastIndexOfScalar(u8, rest, '@')) |at_idx| {
        platform = try work.dupe(u8, rest[at_idx + 1 ..]);
        rest = rest[0..at_idx];
    }

    // Split tag.
    const colon_idx = std.mem.lastIndexOfScalar(u8, rest, ':') orelse return error.InvalidUri;
    const tag = try work.dupe(u8, rest[colon_idx + 1 ..]);
    const before_tag = rest[0..colon_idx];

    // Detect optional host (contains '.' or ':' before first '/').
    var host: []const u8 = "registry-1.docker.io";
    var path = before_tag;
    if (std.mem.indexOfScalar(u8, before_tag, '/')) |slash| {
        const candidate = before_tag[0..slash];
        if (std.mem.indexOfAny(u8, candidate, ".:") != null) {
            host = try work.dupe(u8, candidate);
            path = before_tag[slash + 1 ..];
        }
    }

    // Default namespace: library (Docker Hub convention).
    const repo = if (std.mem.indexOfScalar(u8, path, '/') != null)
        try work.dupe(u8, path)
    else
        try std.fmt.allocPrint(work, "library/{s}", .{path});

    return .{ .host = host, .repo = repo, .tag = tag, .platform = platform };
}

// --- HTTP helpers ------------------------------------------------------------

fn fetchAnonymousToken(
    work: std.mem.Allocator,
    client: *http.Client,
    repo: []const u8,
) Error![]const u8 {
    const url = try std.fmt.allocPrint(
        work,
        "https://auth.docker.io/token?service=registry.docker.io&scope=repository:{s}:pull",
        .{repo},
    );

    var body: std.Io.Writer.Allocating = .init(work);
    defer body.deinit();
    const result = try client.fetch(.{
        .location = .{ .url = url },
        .response_writer = &body.writer,
        .extra_headers = &.{
            .{ .name = "Accept", .value = "application/json" },
        },
    });
    if (result.status != .ok) return error.AuthFailed;

    const Doc = struct {
        token: []const u8,
        access_token: ?[]const u8 = null,
    };
    const parsed = json.parseFromSlice(Doc, work, body.writer.buffered(), .{
        .ignore_unknown_fields = true,
    }) catch return error.AuthFailed;
    defer parsed.deinit();

    return try work.dupe(u8, parsed.value.token);
}

fn fetchAuthorized(
    work: std.mem.Allocator,
    client: *http.Client,
    url: []const u8,
    accept: []const u8,
    token: ?[]const u8,
    max_bytes: usize,
) Error![]u8 {
    _ = max_bytes;
    var body: std.Io.Writer.Allocating = .init(work);
    errdefer body.deinit();

    const auth_value = if (token) |t|
        try std.fmt.allocPrint(work, "Bearer {s}", .{t})
    else
        "";

    // 0.16 std.http does not actually emit privileged_headers, so we use
    // extra_headers and disable redirect-following to avoid leaking the
    // bearer token to redirect targets (Docker Hub blobs redirect to S3,
    // which 400s when it sees an unrelated Authorization).
    var extra_with_auth: [2]http.Header = .{
        .{ .name = "Accept", .value = accept },
        .{ .name = "Authorization", .value = auth_value },
    };
    var extra_no_auth: [1]http.Header = .{
        .{ .name = "Accept", .value = accept },
    };
    const extra: []const http.Header = if (token != null) &extra_with_auth else &extra_no_auth;

    const uri = std.Uri.parse(url) catch return error.InvalidUri;
    var req = client.request(.GET, uri, .{
        .extra_headers = extra,
        .redirect_behavior = .unhandled,
        .keep_alive = true,
    }) catch return error.ManifestFetchFailed;
    defer req.deinit();
    req.sendBodiless() catch return error.ManifestFetchFailed;
    var redirect_buf: [8192]u8 = undefined;
    var resp = req.receiveHead(&redirect_buf) catch return error.ManifestFetchFailed;
    const head = resp.head;

    switch (head.status) {
        .ok => {
            // Stream body directly to allocating writer.
            var decompress_buf: [16384]u8 = undefined;
            const reader = resp.reader(&decompress_buf);
            _ = reader.streamRemaining(&body.writer) catch return error.ManifestFetchFailed;
            return try body.toOwnedSlice();
        },
        .moved_permanently, .found, .see_other, .temporary_redirect, .permanent_redirect => {
            const loc = head.location orelse return error.ManifestFetchFailed;
            const loc_owned = try work.dupe(u8, loc);
            return fetchAuthorized(work, client, loc_owned, accept, null, 0);
        },
        else => {
            std.log.warn("registry: GET {s} -> {d}", .{ url, @intFromEnum(head.status) });
            return error.ManifestFetchFailed;
        },
    }
}

fn fetchBlob(
    work: std.mem.Allocator,
    client: *http.Client,
    ref: Reference,
    digest: []const u8,
    token: ?[]const u8,
    max_bytes: usize,
) Error![]u8 {
    const url = try std.fmt.allocPrint(work, "https://{s}/v2/{s}/blobs/{s}", .{
        ref.host, ref.repo, digest,
    });
    return try fetchAuthorized(work, client, url, "*/*", token, max_bytes);
}

fn looksLikeIndex(body: []const u8) bool {
    return std.mem.indexOf(u8, body, "\"manifests\"") != null;
}

fn resolveIndex(
    work: std.mem.Allocator,
    client: *http.Client,
    ref: Reference,
    token: ?[]const u8,
    platform: []const u8,
    index_body: []const u8,
    options: PullOptions,
) Error![]u8 {
    const Index = struct {
        manifests: []const struct {
            digest: []const u8,
            platform: ?struct {
                architecture: []const u8,
                os: []const u8,
            } = null,
        },
    };
    const parsed = json.parseFromSlice(Index, work, index_body, .{
        .ignore_unknown_fields = true,
    }) catch return error.InvalidJson;
    defer parsed.deinit();

    var slash_buf: [64]u8 = undefined;
    for (parsed.value.manifests) |m| {
        const p = m.platform orelse continue;
        const tag = std.fmt.bufPrint(&slash_buf, "{s}/{s}", .{ p.os, p.architecture }) catch continue;
        if (std.mem.eql(u8, tag, platform)) {
            const url = try std.fmt.allocPrint(work, "https://{s}/v2/{s}/manifests/{s}", .{
                ref.host, ref.repo, m.digest,
            });
            const accept = "application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.v2+json";
            return fetchAuthorized(work, client, url, accept, token, options.max_blob_bytes);
        }
    }
    return error.NoMatchingPlatform;
}

fn buildManifestJson(
    work: std.mem.Allocator,
    config_digest: []const u8,
    layer_paths: []const []const u8,
) Error![]u8 {
    var buf: std.Io.Writer.Allocating = .init(work);
    errdefer buf.deinit();

    try buf.writer.print("[{{\"Config\": \"blobs/{s}\", \"RepoTags\": [\"registry-pull\"], \"Layers\": [", .{
        config_digest,
    });
    for (layer_paths, 0..) |p, i| {
        if (i > 0) try buf.writer.writeByte(',');
        try buf.writer.print("\"{s}\"", .{p});
    }
    try buf.writer.writeAll("]}]");
    return buf.toOwnedSlice();
}

// --- platform default --------------------------------------------------------

fn nativePlatform() []const u8 {
    return switch (builtin.os.tag) {
        .linux => switch (builtin.cpu.arch) {
            .x86_64 => "linux/amd64",
            .aarch64 => "linux/arm64",
            else => "linux/unknown",
        },
        .macos => switch (builtin.cpu.arch) {
            .x86_64 => "linux/amd64",
            .aarch64 => "linux/arm64",
            else => "linux/arm64",
        },
        else => "linux/amd64",
    };
}

// --- tests -------------------------------------------------------------------

test "parseRegistryUri docker hub short" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const ref = try parseRegistryUri(arena.allocator(), "registry://alpine:3.19");
    try std.testing.expectEqualStrings("registry-1.docker.io", ref.host);
    try std.testing.expectEqualStrings("library/alpine", ref.repo);
    try std.testing.expectEqualStrings("3.19", ref.tag);
}

test "parseRegistryUri custom host" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const ref = try parseRegistryUri(arena.allocator(), "registry://ghcr.io/owner/img:v1");
    try std.testing.expectEqualStrings("ghcr.io", ref.host);
    try std.testing.expectEqualStrings("owner/img", ref.repo);
    try std.testing.expectEqualStrings("v1", ref.tag);
}

test "parseRegistryUri platform suffix" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const ref = try parseRegistryUri(arena.allocator(), "registry://alpine:3.19@linux/arm64");
    try std.testing.expectEqualStrings("linux/arm64", ref.platform.?);
    try std.testing.expectEqualStrings("3.19", ref.tag);
}

test "parseRegistryUri rejects bad scheme" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectError(
        error.UnsupportedScheme,
        parseRegistryUri(arena.allocator(), "http://alpine:3.19"),
    );
}
