//! Inline progress reporter. Writes a spinner + status label to stderr,
//! redrawing in place via CR + erase-line. No-op when stderr is not a
//! TTY, so piped/JSON/scripted invocations stay byte-identical to before.
//!
//! Usage:
//!     var prog = Reporter.init(io, environ);
//!     defer prog.deinit();
//!     prog.start("resolving manifest");
//!     prog.step("fetching layer 1/8");
//!     prog.finish("done"); // or prog.fail("oops")
//!
//! Library entry points take `?*Reporter`. Pass `null` (or omit) when
//! no UI is wanted; the implementation is compiled out at the call site.
//! The reporter is single-threaded; concurrent steps must serialize.

const std = @import("std");
const Io = std.Io;

const codes = struct {
    const reset = "\x1b[0m";
    const cyan = "\x1b[36m";
    const green = "\x1b[32m";
    const red = "\x1b[31m";
    const dim = "\x1b[2m";
    const erase_line = "\r\x1b[2K";
};

pub const Reporter = struct {
    io: Io,
    enabled: bool,
    color: bool,
    frame: u4 = 0,
    active: bool = false,

    const frames: []const []const u8 = &.{ "⣾", "⣽", "⣻", "⢿", "⡿", "⣟", "⣯", "⣷" };

    pub fn init(io: Io, environ: std.process.Environ) Reporter {
        const f: Io.File = .stderr();
        const tty = f.isTty(io) catch false;
        const no_color = if (environ.getPosix("NO_COLOR")) |v| v.len > 0 else false;
        return .{ .io = io, .enabled = tty, .color = !no_color };
    }

    pub fn off() Reporter {
        return .{ .io = undefined, .enabled = false, .color = false };
    }

    pub fn deinit(self: *Reporter) void {
        if (self.active) self.clear();
    }

    /// Begin a progress session with an initial label.
    pub fn start(self: *Reporter, label: []const u8) void {
        if (!self.enabled) return;
        self.active = true;
        self.paint(label);
    }

    /// Advance the spinner and update the label. Implicit `start` if
    /// not yet active.
    pub fn step(self: *Reporter, label: []const u8) void {
        if (!self.enabled) return;
        if (!self.active) {
            self.start(label);
            return;
        }
        self.frame = (self.frame + 1) % @as(u4, @intCast(frames.len));
        self.paint(label);
    }

    /// printf-style `step` for one-off allocations on caller's stack.
    pub fn stepf(self: *Reporter, comptime fmt: []const u8, args: anytype) void {
        if (!self.enabled) return;
        var buf: [256]u8 = undefined;
        const msg = std.fmt.bufPrint(&buf, fmt, args) catch buf[0..];
        self.step(msg);
    }

    /// Clear the progress line and print a final success message
    /// (`✓ <msg>`). `null` clears without a final line.
    pub fn finish(self: *Reporter, msg: ?[]const u8) void {
        if (!self.enabled or !self.active) {
            self.active = false;
            return;
        }
        self.active = false;
        var buf: [256]u8 = undefined;
        var fw: Io.File.Writer = .init(.stderr(), self.io, &buf);
        const w = &fw.interface;
        w.writeAll(codes.erase_line) catch {};
        if (msg) |m| {
            if (self.color) w.writeAll(codes.green) catch {};
            w.writeAll("✓ ") catch {};
            if (self.color) w.writeAll(codes.reset) catch {};
            w.writeAll(m) catch {};
            w.writeByte('\n') catch {};
        }
        w.flush() catch {};
    }

    /// Clear the progress line and print `✗ <msg>` in red.
    pub fn fail(self: *Reporter, msg: []const u8) void {
        if (!self.enabled or !self.active) {
            self.active = false;
            return;
        }
        self.active = false;
        var buf: [256]u8 = undefined;
        var fw: Io.File.Writer = .init(.stderr(), self.io, &buf);
        const w = &fw.interface;
        w.writeAll(codes.erase_line) catch {};
        if (self.color) w.writeAll(codes.red) catch {};
        w.writeAll("✗ ") catch {};
        if (self.color) w.writeAll(codes.reset) catch {};
        w.writeAll(msg) catch {};
        w.writeByte('\n') catch {};
        w.flush() catch {};
    }

    fn clear(self: *Reporter) void {
        self.active = false;
        var buf: [32]u8 = undefined;
        var fw: Io.File.Writer = .init(.stderr(), self.io, &buf);
        const w = &fw.interface;
        w.writeAll(codes.erase_line) catch {};
        w.flush() catch {};
    }

    fn paint(self: *Reporter, label: []const u8) void {
        var buf: [512]u8 = undefined;
        var fw: Io.File.Writer = .init(.stderr(), self.io, &buf);
        const w = &fw.interface;
        w.writeAll(codes.erase_line) catch return;
        if (self.color) w.writeAll(codes.cyan) catch {};
        w.writeAll(frames[self.frame]) catch {};
        if (self.color) w.writeAll(codes.reset) catch {};
        w.writeByte(' ') catch {};
        w.writeAll(label) catch {};
        w.flush() catch {};
    }
};

/// Optional reporter handle: nullable pointer with helper methods so
/// library code can call `prog.step(...)` without unwrapping.
pub const Handle = struct {
    inner: ?*Reporter,

    pub fn from(p: ?*Reporter) Handle {
        return .{ .inner = p };
    }

    pub fn step(self: Handle, label: []const u8) void {
        if (self.inner) |r| r.step(label);
    }

    pub fn stepf(self: Handle, comptime fmt: []const u8, args: anytype) void {
        if (self.inner) |r| r.stepf(fmt, args);
    }
};

test "Reporter.off is silent" {
    var r = Reporter.off();
    defer r.deinit();
    r.start("nope");
    r.step("still nope");
    r.finish("done");
}

test "Handle wraps null cleanly" {
    const h = Handle.from(null);
    h.step("ignored");
    h.stepf("ignored {d}", .{1});
}
