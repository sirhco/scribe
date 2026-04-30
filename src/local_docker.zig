//! Local docker daemon source. Spawns `docker save <image>` and feeds the
//! resulting tar stream into `container.collect`. URI form:
//!     docker://<image>[:<tag>]
//!
//! Versus `registry://`: this path requires a running docker daemon and the
//! `docker` CLI on PATH, but it works for any image already in the daemon's
//! image store — including locally-built images that have never been pushed.
//!
//! Memory: the entire `docker save` output is buffered in memory before
//! being walked. Typical alpine/distroless images are <10MB compressed, but
//! large fat images can easily reach hundreds of MB. A streaming variant
//! (Phase-3c-ext) would consume the child's stdout pipe directly via
//! `tar.Iterator` over a Reader, but the current `container.collect`
//! ingestion takes a `[]const u8` and re-walks it.

const std = @import("std");
const errors = @import("errors.zig");
const container = @import("container.zig");

pub const Error = error{
    DockerNotInstalled,
    DockerSaveFailed,
    StreamTooLong,
    SystemResources,
} || std.mem.Allocator.Error || container.Error;

pub fn isLocalDockerUri(uri: []const u8) bool {
    return std.mem.startsWith(u8, uri, "docker://");
}

pub fn parseImage(uri: []const u8) []const u8 {
    if (std.mem.startsWith(u8, uri, "docker://")) return uri[9..];
    return uri;
}

pub fn pullSbom(
    gpa: std.mem.Allocator,
    io: std.Io,
    uri: []const u8,
) Error!container.ImageSbom {
    const image = parseImage(uri);

    const argv = [_][]const u8{ "docker", "save", image };
    const result = std.process.run(gpa, io, .{
        .argv = &argv,
        // docker save can produce hundreds of MB; cap at 2 GiB by default.
        .stdout_limit = .limited(2 * 1024 * 1024 * 1024),
        .stderr_limit = .limited(64 * 1024),
        .reserve_amount = 1 * 1024 * 1024,
    }) catch |err| switch (err) {
        error.FileNotFound => return error.DockerNotInstalled,
        error.StreamTooLong => return error.StreamTooLong,
        else => |e| {
            std.log.warn("docker save spawn failed: {s}", .{@errorName(e)});
            return error.DockerSaveFailed;
        },
    };
    defer gpa.free(result.stderr);
    errdefer gpa.free(result.stdout);

    switch (result.term) {
        .exited => |code| if (code != 0) {
            std.log.warn("docker save '{s}' exited {d}: {s}", .{
                image,
                code,
                result.stderr,
            });
            gpa.free(result.stdout);
            return error.DockerSaveFailed;
        },
        else => {
            gpa.free(result.stdout);
            return error.DockerSaveFailed;
        },
    }

    if (result.stdout.len == 0) {
        gpa.free(result.stdout);
        return error.DockerSaveFailed;
    }

    const sbom = try container.collect(gpa, result.stdout);
    gpa.free(result.stdout);
    return sbom;
}

test "parseImage strips docker:// scheme" {
    try std.testing.expectEqualStrings("alpine:3.19", parseImage("docker://alpine:3.19"));
    try std.testing.expectEqualStrings("alpine:3.19", parseImage("alpine:3.19"));
}

test "isLocalDockerUri detects scheme" {
    try std.testing.expect(isLocalDockerUri("docker://alpine:3.19"));
    try std.testing.expect(!isLocalDockerUri("registry://alpine:3.19"));
    try std.testing.expect(!isLocalDockerUri("/local/path"));
}
