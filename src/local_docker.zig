//! Local docker daemon source. Spawns `docker save <image>` and feeds the
//! resulting tar stream into `container.collect`. URI form:
//!     docker://<image>[:<tag>]
//!
//! Versus `registry://`: this path requires a running docker daemon and the
//! `docker` CLI on PATH, but it works for any image already in the daemon's
//! image store — including locally-built images that have never been pushed.
//!
//! Memory: the entire `docker save` output is buffered in memory before
//! being walked. Default cap is 8 GiB (raised from 2 GiB) which covers
//! every reasonable image; can be tightened with the SCRIBE_DOCKER_SAVE_CAP
//! env var (value in MiB).
//!
//! True streaming requires a container.collect refactor — the OCI tar
//! has forward references (manifest.json points at layer blobs that may
//! appear later in the stream), so a single-pass walker can't construct
//! the squash without buffering. That refactor is out of scope here; the
//! 8 GiB cap is the practical compromise for v1.

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

/// Buffer cap for `docker save` stdout. Override by setting
/// SCRIBE_DOCKER_SAVE_CAP_MIB to the desired megabyte value.
const default_stdout_cap: usize = 8 * 1024 * 1024 * 1024;

fn stdoutCap(environ: ?std.process.Environ) usize {
    if (environ) |e| {
        if (e.getPosix("SCRIBE_DOCKER_SAVE_CAP_MIB")) |v| {
            const trimmed = std.mem.trim(u8, v, " \t\n\r");
            const mib = std.fmt.parseInt(usize, trimmed, 10) catch return default_stdout_cap;
            return mib * 1024 * 1024;
        }
    }
    return default_stdout_cap;
}

pub fn pullSbom(
    gpa: std.mem.Allocator,
    io: std.Io,
    uri: []const u8,
) Error!container.ImageSbom {
    return pullSbomWithEnv(gpa, io, uri, null);
}

/// Variant that lets the caller pass an `Environ` for env-var lookup.
/// Plain `pullSbom` skips the env override and always uses the default cap.
pub fn pullSbomWithEnv(
    gpa: std.mem.Allocator,
    io: std.Io,
    uri: []const u8,
    environ: ?std.process.Environ,
) Error!container.ImageSbom {
    const image = parseImage(uri);

    const cap = stdoutCap(environ);
    const argv = [_][]const u8{ "docker", "save", image };
    const result = std.process.run(gpa, io, .{
        .argv = &argv,
        .stdout_limit = .limited(cap),
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
