//! Local docker daemon source. Spawns `docker save <image>` and feeds the
//! resulting tar stream into `container.collect`. URI form:
//!     docker://<image>[:<tag>]
//!
//! Versus `registry://`: this path requires a running docker daemon and the
//! `docker` CLI on PATH, but it works for any image already in the daemon's
//! image store — including locally-built images that have never been pushed.
//!
//! Memory: `docker save` stdout is redirected straight to a tempfile via
//! `std.process.spawn` + `StdIo.file` rather than buffered into the parent's
//! heap. Once the child exits the tempfile is mmap'd and `container.collect`
//! walks it zero-copy. Resident memory is bounded by the working set of the
//! squash + decompressed-layer-at-a-time, regardless of image size; the
//! image just lives on disk for a moment. The legacy in-memory cap (and its
//! `SCRIBE_DOCKER_SAVE_CAP_MIB` override) no longer applies.

const std = @import("std");
const errors = @import("errors.zig");
const container = @import("container.zig");
const mmap_mod = @import("mmap.zig");
const progress_mod = @import("progress.zig");

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
    return pullSbomWithProgress(gpa, io, uri, null);
}

/// Compatibility shim — the env override is no longer consulted now that
/// stdout goes straight to a tempfile, but the signature is preserved for
/// existing callers / tests.
pub fn pullSbomWithEnv(
    gpa: std.mem.Allocator,
    io: std.Io,
    uri: []const u8,
    environ: ?std.process.Environ,
) Error!container.ImageSbom {
    _ = environ;
    return pullSbomWithProgress(gpa, io, uri, null);
}

pub fn pullSbomWithProgress(
    gpa: std.mem.Allocator,
    io: std.Io,
    uri: []const u8,
    reporter: ?*progress_mod.Reporter,
) Error!container.ImageSbom {
    const prog = progress_mod.Handle.from(reporter);
    const image = parseImage(uri);

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const tmp_path = buildTempPath(&path_buf) catch return error.SystemResources;

    var out_file = std.Io.Dir.createFileAbsolute(io, tmp_path, .{
        .read = true,
        .truncate = true,
    }) catch return error.SystemResources;
    // Always unlink — mmap below holds the inode open, so deleting the
    // pathname doesn't free the bytes until we drop the mapping.
    defer std.Io.Dir.deleteFileAbsolute(io, tmp_path) catch {};

    prog.stepf("docker save {s}", .{image});
    const argv = [_][]const u8{ "docker", "save", image };
    var child = std.process.spawn(io, .{
        .argv = &argv,
        .stdin = .ignore,
        .stdout = .{ .file = out_file },
        .stderr = .inherit,
    }) catch |err| {
        out_file.close(io);
        switch (err) {
            error.FileNotFound => return error.DockerNotInstalled,
            else => {
                std.log.warn("docker save spawn failed: {s}", .{@errorName(err)});
                return error.DockerSaveFailed;
            },
        }
    };
    // Parent's copy of the stdout fd is no longer needed; the child has its
    // own. Closing here means the inode's only writer becomes the child, so
    // when the child exits the file's contents are final.
    out_file.close(io);
    errdefer child.kill(io);

    const term = child.wait(io) catch return error.DockerSaveFailed;
    switch (term) {
        .exited => |code| if (code != 0) {
            std.log.warn("docker save '{s}' exited {d}", .{ image, code });
            return error.DockerSaveFailed;
        },
        else => return error.DockerSaveFailed,
    }

    var mapping = mmap_mod.open(io, tmp_path) catch |err| switch (err) {
        error.EmptyFile => return error.DockerSaveFailed,
        else => return error.DockerSaveFailed,
    };
    defer mapping.deinit();

    prog.step("analyzing image layers");
    return try container.collect(gpa, mapping.bytes());
}

/// Process-local counter so multiple `pullSbom` calls in the same PID
/// don't collide on the tempfile path.
var tempfile_counter = std.atomic.Value(u64).init(0);

/// Build a unique tempfile path under `/tmp`. The PID makes paths unique
/// across concurrent scribes on the same host; a process-local counter
/// covers repeat calls within a single scribe run. Sticking to `/tmp`
/// keeps this POSIX-only path simple — the docker-save flow already
/// requires a POSIX docker daemon anyway.
fn buildTempPath(buf: []u8) ![]const u8 {
    const pid = std.posix.system.getpid();
    const seq = tempfile_counter.fetchAdd(1, .monotonic);
    return std.fmt.bufPrint(buf, "/tmp/scribe-docker-save-{d}-{d}.tar", .{ pid, seq });
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
