//! Terminal styling. ANSI escape sequences with TTY auto-detect and
//! NO_COLOR honoring (https://no-color.org/). All helpers no-op when
//! `Style.enabled == false`, so emitters can use the same code path
//! whether output is a tty or a pipe.
//!
//! Convention:
//!   - Section headers: bold
//!   - Field labels: dim
//!   - Severity tags: severityColor(severity) -> ANSI code
//!   - Counts: green when 0, red when present (call site picks)
//!   - Critical: red bold; High: red; Medium: yellow; Low: cyan; Info: gray
//!
//! Caller picks `auto`, `on`, or `off` once per process; pass the Style
//! into emitters.

const std = @import("std");
const Io = std.Io;

pub const codes = struct {
    pub const reset = "\x1b[0m";
    pub const bold = "\x1b[1m";
    pub const dim = "\x1b[2m";
    pub const underline = "\x1b[4m";

    pub const red = "\x1b[31m";
    pub const green = "\x1b[32m";
    pub const yellow = "\x1b[33m";
    pub const blue = "\x1b[34m";
    pub const magenta = "\x1b[35m";
    pub const cyan = "\x1b[36m";
    pub const gray = "\x1b[90m";

    pub const bright_red = "\x1b[91m";
    pub const bright_green = "\x1b[92m";
    pub const bright_yellow = "\x1b[93m";

    pub const bold_red = "\x1b[1;31m";
    pub const bold_green = "\x1b[1;32m";
    pub const bold_red_bg_white = "\x1b[1;37;41m";
};

pub const Style = struct {
    enabled: bool,

    pub fn off() Style {
        return .{ .enabled = false };
    }

    pub fn on() Style {
        return .{ .enabled = true };
    }

    /// Enable when stdout is a TTY and NO_COLOR is unset.
    pub fn auto(io: Io, environ: std.process.Environ) Style {
        if (environ.getPosix("NO_COLOR")) |v| if (v.len > 0) return .{ .enabled = false };
        const out: Io.File = .stdout();
        const tty = out.isTty(io) catch false;
        return .{ .enabled = tty };
    }

    /// Wrap `s` with `code` ... reset.
    pub fn span(self: Style, w: *Io.Writer, code: []const u8, s: []const u8) !void {
        if (self.enabled) try w.writeAll(code);
        try w.writeAll(s);
        if (self.enabled) try w.writeAll(codes.reset);
    }

    /// Open a styled span; caller must call `closeStyle` after writing.
    pub fn open(self: Style, w: *Io.Writer, code: []const u8) !void {
        if (self.enabled) try w.writeAll(code);
    }

    pub fn close(self: Style, w: *Io.Writer) !void {
        if (self.enabled) try w.writeAll(codes.reset);
    }

    pub fn bold(self: Style, w: *Io.Writer, s: []const u8) !void {
        try self.span(w, codes.bold, s);
    }

    pub fn dim(self: Style, w: *Io.Writer, s: []const u8) !void {
        try self.span(w, codes.dim, s);
    }

    /// Color string by severity name (case-insensitive). Returns the input
    /// unchanged when style is off.
    pub fn writeSeverity(self: Style, w: *Io.Writer, severity: []const u8) !void {
        const code = severityCode(severity);
        try self.span(w, code, severity);
    }

    /// Wrap a count with green when zero, red when nonzero. Always emits
    /// the form `(N suffix)\n`.
    pub fn writeCount(self: Style, w: *Io.Writer, n: usize, suffix: []const u8) !void {
        const code = if (n == 0) codes.bold_green else codes.bold_red;
        if (self.enabled) try w.writeAll(code);
        try w.print("({d} {s})", .{ n, suffix });
        if (self.enabled) try w.writeAll(codes.reset);
        try w.writeByte('\n');
    }
};

pub fn severityCode(severity: []const u8) []const u8 {
    if (eqlNoCase(severity, "critical")) return codes.bold_red_bg_white;
    if (eqlNoCase(severity, "high")) return codes.red;
    if (eqlNoCase(severity, "medium") or eqlNoCase(severity, "moderate")) return codes.yellow;
    if (eqlNoCase(severity, "low")) return codes.cyan;
    if (eqlNoCase(severity, "info")) return codes.gray;
    return codes.dim;
}

fn eqlNoCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| if (std.ascii.toLower(x) != std.ascii.toLower(y)) return false;
    return true;
}

test "Style.off no-ops everything" {
    const s = Style.off();
    var buf: [128]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    try s.span(&w, codes.red, "hello");
    try std.testing.expectEqualStrings("hello", buf[0..w.end]);
}

test "Style.on writes ANSI codes" {
    const s = Style.on();
    var buf: [128]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    try s.span(&w, codes.red, "hello");
    try std.testing.expectEqualStrings("\x1b[31mhello\x1b[0m", buf[0..w.end]);
}

test "severityCode maps known levels" {
    try std.testing.expectEqualStrings(codes.bold_red_bg_white, severityCode("critical"));
    try std.testing.expectEqualStrings(codes.red, severityCode("high"));
    try std.testing.expectEqualStrings(codes.yellow, severityCode("medium"));
    try std.testing.expectEqualStrings(codes.yellow, severityCode("Moderate"));
    try std.testing.expectEqualStrings(codes.cyan, severityCode("low"));
    try std.testing.expectEqualStrings(codes.gray, severityCode("info"));
}
