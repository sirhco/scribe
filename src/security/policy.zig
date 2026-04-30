//! Gatekeeper. Evaluates a `Sbom` (with optional secret findings, vuln
//! matches, IaC config issues) against a JSON-defined `Policy` and
//! produces a pass/fail `Result` plus a list of triggered violations.
//!
//! Policy axes:
//!   - `vulnerabilities.max_severity` — fail if any matched advisory has
//!     severity >= this rank.
//!   - `vulnerabilities.deny` — explicit advisory ID deny list.
//!   - `secrets.fail_on_any` — fail if any secret detected.
//!   - `secrets.fail_on_kinds` — fail only on listed Kind values.
//!   - `config.max_severity` — fail if any IaC issue >= rank.
//!   - `config.deny` — rule ID deny list (e.g. "DKR001", "K8S006").
//!   - `components.deny` — component name deny list (substring match).
//!
//! Evaluator is allocator-strict and produces owned `Violation` records.
//! Return verdict drives CLI exit code.

const std = @import("std");
const errors = @import("../errors.zig");
const sbom_mod = @import("../sbom.zig");
const secrets_mod = @import("secrets.zig");
const vuln_mod = @import("vulnerability.zig");
const config_mod = @import("config.zig");

pub const Verdict = enum { pass, fail };

pub const Axis = enum { vulnerability, secret, config_issue, component };

pub const Violation = struct {
    axis: Axis,
    rule: []u8, // owned. Policy rule identifier ("vuln.max_severity", "secrets.fail_on_kinds", etc.)
    detail: []u8, // owned. What triggered it (advisory ID, rule ID, component name…)
    severity_text: []u8, // owned. Triggering item's severity tag.
};

pub const Result = struct {
    verdict: Verdict,
    violations: []Violation,

    pub fn deinit(self: *Result, allocator: std.mem.Allocator) void {
        for (self.violations) |v| freeViolation(allocator, v);
        allocator.free(self.violations);
        self.violations = &.{};
    }
};

fn freeViolation(allocator: std.mem.Allocator, v: Violation) void {
    allocator.free(v.rule);
    allocator.free(v.detail);
    allocator.free(v.severity_text);
}

// ----------------------------------------------------------------------------
// Policy
// ----------------------------------------------------------------------------

pub const Policy = struct {
    /// null → no severity gate.
    vuln_max_severity: ?vuln_mod.Severity = null,
    /// Owned slices.
    vuln_deny: [][]u8 = &.{},

    fail_on_any_secret: bool = false,
    /// Owned slices.
    secret_fail_kinds: []secrets_mod.Kind = &.{},

    /// null → no severity gate.
    config_max_severity: ?config_mod.Severity = null,
    /// Owned slices.
    config_deny: [][]u8 = &.{},

    /// Owned slices. Substring match against `Component.name` (lowercased).
    component_deny: [][]u8 = &.{},

    pub fn deinit(self: *Policy, allocator: std.mem.Allocator) void {
        freeStringList(allocator, self.vuln_deny);
        allocator.free(self.secret_fail_kinds);
        freeStringList(allocator, self.config_deny);
        freeStringList(allocator, self.component_deny);
        self.vuln_deny = &.{};
        self.secret_fail_kinds = &.{};
        self.config_deny = &.{};
        self.component_deny = &.{};
    }

    pub fn loadJson(
        allocator: std.mem.Allocator,
        json_bytes: []const u8,
    ) errors.ScribeError!Policy {
        const Doc = struct {
            version: ?u32 = null,
            vulnerabilities: ?struct {
                max_severity: ?[]const u8 = null,
                deny: ?[]const []const u8 = null,
            } = null,
            secrets: ?struct {
                fail_on_any: ?bool = null,
                fail_on_kinds: ?[]const []const u8 = null,
            } = null,
            config: ?struct {
                max_severity: ?[]const u8 = null,
                deny: ?[]const []const u8 = null,
            } = null,
            components: ?struct {
                deny: ?[]const []const u8 = null,
            } = null,
        };

        const parsed = std.json.parseFromSlice(Doc, allocator, json_bytes, .{
            .ignore_unknown_fields = true,
        }) catch return error.NotImplemented;
        defer parsed.deinit();

        var p: Policy = .{};
        errdefer p.deinit(allocator);

        if (parsed.value.vulnerabilities) |v| {
            if (v.max_severity) |s| p.vuln_max_severity = vuln_mod.Severity.fromString(s);
            if (v.deny) |d| p.vuln_deny = try dupeStringList(allocator, d);
        }
        if (parsed.value.secrets) |s| {
            if (s.fail_on_any) |b| p.fail_on_any_secret = b;
            if (s.fail_on_kinds) |k| p.secret_fail_kinds = try parseSecretKinds(allocator, k);
        }
        if (parsed.value.config) |c| {
            if (c.max_severity) |s| p.config_max_severity = parseConfigSeverity(s);
            if (c.deny) |d| p.config_deny = try dupeStringList(allocator, d);
        }
        if (parsed.value.components) |comp| {
            if (comp.deny) |d| p.component_deny = try dupeLowerStringList(allocator, d);
        }
        return p;
    }
};

fn dupeStringList(
    allocator: std.mem.Allocator,
    src: []const []const u8,
) errors.ScribeError![][]u8 {
    const out = try allocator.alloc([]u8, src.len);
    var built: usize = 0;
    errdefer {
        for (out[0..built]) |s| allocator.free(s);
        allocator.free(out);
    }
    for (src, 0..) |s, i| {
        out[i] = try allocator.dupe(u8, s);
        built += 1;
    }
    return out;
}

fn dupeLowerStringList(
    allocator: std.mem.Allocator,
    src: []const []const u8,
) errors.ScribeError![][]u8 {
    const out = try allocator.alloc([]u8, src.len);
    var built: usize = 0;
    errdefer {
        for (out[0..built]) |s| allocator.free(s);
        allocator.free(out);
    }
    for (src, 0..) |s, i| {
        const buf = try allocator.alloc(u8, s.len);
        for (s, 0..) |c, j| buf[j] = std.ascii.toLower(c);
        out[i] = buf;
        built += 1;
    }
    return out;
}

fn freeStringList(allocator: std.mem.Allocator, list: [][]u8) void {
    for (list) |s| allocator.free(s);
    if (list.len != 0) allocator.free(list);
}

fn parseSecretKinds(
    allocator: std.mem.Allocator,
    names: []const []const u8,
) errors.ScribeError![]secrets_mod.Kind {
    const out = try allocator.alloc(secrets_mod.Kind, names.len);
    var w: usize = 0;
    for (names) |n| {
        if (secretKindFromString(n)) |k| {
            out[w] = k;
            w += 1;
        }
    }
    if (w == names.len) return out;
    // Some names didn't parse; shrink.
    const trimmed = try allocator.alloc(secrets_mod.Kind, w);
    @memcpy(trimmed, out[0..w]);
    allocator.free(out);
    return trimmed;
}

fn secretKindFromString(s: []const u8) ?secrets_mod.Kind {
    inline for (@typeInfo(secrets_mod.Kind).@"enum".fields) |f| {
        if (std.mem.eql(u8, s, f.name)) return @field(secrets_mod.Kind, f.name);
    }
    return null;
}

fn parseConfigSeverity(s: []const u8) ?config_mod.Severity {
    if (std.ascii.eqlIgnoreCase(s, "info")) return .info;
    if (std.ascii.eqlIgnoreCase(s, "low")) return .low;
    if (std.ascii.eqlIgnoreCase(s, "medium") or std.ascii.eqlIgnoreCase(s, "moderate")) return .medium;
    if (std.ascii.eqlIgnoreCase(s, "high")) return .high;
    if (std.ascii.eqlIgnoreCase(s, "critical")) return .critical;
    return null;
}

// ----------------------------------------------------------------------------
// Evaluation
// ----------------------------------------------------------------------------

pub fn evaluate(
    allocator: std.mem.Allocator,
    policy: Policy,
    sbom: sbom_mod.Sbom,
) errors.ScribeError!Result {
    var list: std.ArrayList(Violation) = .empty;
    errdefer {
        for (list.items) |v| freeViolation(allocator, v);
        list.deinit(allocator);
    }

    // Vulnerabilities axis.
    for (sbom.vulnerabilities) |v| {
        if (policy.vuln_max_severity) |max| {
            if (@intFromEnum(v.severity) >= @intFromEnum(max)) {
                try appendViolation(allocator, &list, .{
                    .axis = .vulnerability,
                    .rule = "vulnerabilities.max_severity",
                    .detail = v.advisory_id,
                    .severity = @tagName(v.severity),
                });
                continue;
            }
        }
        for (policy.vuln_deny) |denied| {
            if (std.mem.eql(u8, denied, v.advisory_id)) {
                try appendViolation(allocator, &list, .{
                    .axis = .vulnerability,
                    .rule = "vulnerabilities.deny",
                    .detail = v.advisory_id,
                    .severity = @tagName(v.severity),
                });
                break;
            }
        }
    }

    // Secrets axis.
    for (sbom.findings) |f| {
        if (policy.fail_on_any_secret) {
            try appendViolation(allocator, &list, .{
                .axis = .secret,
                .rule = "secrets.fail_on_any",
                .detail = @tagName(f.kind),
                .severity = severityForConfidence(f.confidence),
            });
            continue;
        }
        for (policy.secret_fail_kinds) |k| {
            if (k == f.kind) {
                try appendViolation(allocator, &list, .{
                    .axis = .secret,
                    .rule = "secrets.fail_on_kinds",
                    .detail = @tagName(f.kind),
                    .severity = severityForConfidence(f.confidence),
                });
                break;
            }
        }
    }

    // Config axis.
    for (sbom.config_issues) |it| {
        if (policy.config_max_severity) |max| {
            if (@intFromEnum(it.severity) >= @intFromEnum(max)) {
                try appendViolation(allocator, &list, .{
                    .axis = .config_issue,
                    .rule = "config.max_severity",
                    .detail = it.rule_id,
                    .severity = @tagName(it.severity),
                });
                continue;
            }
        }
        for (policy.config_deny) |denied| {
            if (std.mem.eql(u8, denied, it.rule_id)) {
                try appendViolation(allocator, &list, .{
                    .axis = .config_issue,
                    .rule = "config.deny",
                    .detail = it.rule_id,
                    .severity = @tagName(it.severity),
                });
                break;
            }
        }
    }

    // Component axis (substring match, lowercased).
    if (policy.component_deny.len > 0) {
        for (sbom.components) |c| {
            const lower = lowercaseStack(c.name);
            for (policy.component_deny) |needle| {
                if (std.mem.indexOf(u8, lower[0..@min(c.name.len, lower.len)], needle) != null) {
                    try appendViolation(allocator, &list, .{
                        .axis = .component,
                        .rule = "components.deny",
                        .detail = c.name,
                        .severity = @tagName(c.kind),
                    });
                    break;
                }
            }
        }
    }

    const items = list.toOwnedSlice(allocator) catch return error.OutOfMemory;
    return .{
        .verdict = if (items.len == 0) .pass else .fail,
        .violations = items,
    };
}

const ViolationSpec = struct {
    axis: Axis,
    rule: []const u8,
    detail: []const u8,
    severity: []const u8,
};

fn appendViolation(
    allocator: std.mem.Allocator,
    list: *std.ArrayList(Violation),
    spec: ViolationSpec,
) errors.ScribeError!void {
    const v: Violation = .{
        .axis = spec.axis,
        .rule = try allocator.dupe(u8, spec.rule),
        .detail = try allocator.dupe(u8, spec.detail),
        .severity_text = try allocator.dupe(u8, spec.severity),
    };
    list.append(allocator, v) catch return error.OutOfMemory;
}

fn severityForConfidence(c: secrets_mod.Confidence) []const u8 {
    return switch (c) {
        .low => "low",
        .medium => "medium",
        .high => "high",
        .certain => "critical",
    };
}

fn lowercaseStack(s: []const u8) [256]u8 {
    var out: [256]u8 = @splat(0);
    const n = @min(s.len, out.len);
    for (s[0..n], 0..) |c, i| out[i] = std.ascii.toLower(c);
    return out;
}

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

const testing = std.testing;

fn synthSbomEmpty() sbom_mod.Sbom {
    return .{ .components = &.{} };
}

test "Policy.loadJson populates all axes" {
    const json =
        \\{
        \\  "version": 1,
        \\  "vulnerabilities": {"max_severity": "high", "deny": ["CVE-2099-9999"]},
        \\  "secrets": {"fail_on_any": false, "fail_on_kinds": ["aws_access_key", "pem_private_key"]},
        \\  "config": {"max_severity": "high", "deny": ["DKR001"]},
        \\  "components": {"deny": ["openssl"]}
        \\}
    ;
    var p = try Policy.loadJson(testing.allocator, json);
    defer p.deinit(testing.allocator);
    try testing.expectEqual(vuln_mod.Severity.high, p.vuln_max_severity.?);
    try testing.expectEqual(@as(usize, 1), p.vuln_deny.len);
    try testing.expect(!p.fail_on_any_secret);
    try testing.expectEqual(@as(usize, 2), p.secret_fail_kinds.len);
    try testing.expectEqual(config_mod.Severity.high, p.config_max_severity.?);
    try testing.expectEqual(@as(usize, 1), p.config_deny.len);
    try testing.expectEqual(@as(usize, 1), p.component_deny.len);
}

test "evaluate: empty SBOM passes empty policy" {
    var p: Policy = .{};
    defer p.deinit(testing.allocator);
    const s = synthSbomEmpty();
    var r = try evaluate(testing.allocator, p, s);
    defer r.deinit(testing.allocator);
    try testing.expectEqual(Verdict.pass, r.verdict);
    try testing.expectEqual(@as(usize, 0), r.violations.len);
}

test "evaluate: vuln severity gate" {
    const v = vuln_mod.Vulnerability{
        .advisory_id = try testing.allocator.dupe(u8, "CVE-2023-1"),
        .package = try testing.allocator.dupe(u8, "openssl"),
        .matched_version = try testing.allocator.dupe(u8, "3.0.7"),
        .severity = .high,
        .cvss = 7.5,
        .summary = try testing.allocator.dupe(u8, ""),
        .fixed_version = null,
        .references = try testing.allocator.alloc([]const u8, 0),
    };
    var vulns = try testing.allocator.alloc(vuln_mod.Vulnerability, 1);
    vulns[0] = v;
    var s = sbom_mod.Sbom{ .components = &.{}, .vulnerabilities = vulns };
    defer s.deinit(testing.allocator);

    var p_pass: Policy = .{ .vuln_max_severity = .critical };
    defer p_pass.deinit(testing.allocator);
    var r_pass = try evaluate(testing.allocator, p_pass, s);
    defer r_pass.deinit(testing.allocator);
    try testing.expectEqual(Verdict.pass, r_pass.verdict);

    var p_fail: Policy = .{ .vuln_max_severity = .high };
    defer p_fail.deinit(testing.allocator);
    var r_fail = try evaluate(testing.allocator, p_fail, s);
    defer r_fail.deinit(testing.allocator);
    try testing.expectEqual(Verdict.fail, r_fail.verdict);
    try testing.expectEqual(@as(usize, 1), r_fail.violations.len);
    try testing.expectEqual(Axis.vulnerability, r_fail.violations[0].axis);
}

test "evaluate: vuln explicit deny" {
    const v = vuln_mod.Vulnerability{
        .advisory_id = try testing.allocator.dupe(u8, "CVE-2099-9999"),
        .package = try testing.allocator.dupe(u8, "rustyhammer"),
        .matched_version = null,
        .severity = .low,
        .cvss = null,
        .summary = try testing.allocator.dupe(u8, ""),
        .fixed_version = null,
        .references = try testing.allocator.alloc([]const u8, 0),
    };
    var vulns = try testing.allocator.alloc(vuln_mod.Vulnerability, 1);
    vulns[0] = v;
    var s = sbom_mod.Sbom{ .components = &.{}, .vulnerabilities = vulns };
    defer s.deinit(testing.allocator);

    const denies = try testing.allocator.alloc([]u8, 1);
    denies[0] = try testing.allocator.dupe(u8, "CVE-2099-9999");
    var p: Policy = .{ .vuln_deny = denies };
    defer p.deinit(testing.allocator);

    var r = try evaluate(testing.allocator, p, s);
    defer r.deinit(testing.allocator);
    try testing.expectEqual(Verdict.fail, r.verdict);
    try testing.expectEqual(@as(usize, 1), r.violations.len);
    try testing.expectEqualStrings("vulnerabilities.deny", r.violations[0].rule);
}

test "evaluate: secrets fail_on_any" {
    const findings = try testing.allocator.alloc(secrets_mod.Finding, 1);
    findings[0] = .{
        .kind = .aws_access_key,
        .offset = 0,
        .length = 20,
        .entropy = 4.0,
        .confidence = .high,
        .redacted_preview = try testing.allocator.dupe(u8, "AAAA…ZZZZ"),
    };
    var s = sbom_mod.Sbom{ .components = &.{}, .findings = findings };
    defer s.deinit(testing.allocator);

    var p: Policy = .{ .fail_on_any_secret = true };
    defer p.deinit(testing.allocator);
    var r = try evaluate(testing.allocator, p, s);
    defer r.deinit(testing.allocator);
    try testing.expectEqual(Verdict.fail, r.verdict);
}

test "evaluate: secrets fail_on_kinds matches subset" {
    const findings = try testing.allocator.alloc(secrets_mod.Finding, 2);
    findings[0] = .{
        .kind = .generic_high_entropy,
        .offset = 0,
        .length = 32,
        .entropy = 5.0,
        .confidence = .low,
        .redacted_preview = try testing.allocator.dupe(u8, "x"),
    };
    findings[1] = .{
        .kind = .pem_private_key,
        .offset = 50,
        .length = 100,
        .entropy = 4.5,
        .confidence = .certain,
        .redacted_preview = try testing.allocator.dupe(u8, "y"),
    };
    var s = sbom_mod.Sbom{ .components = &.{}, .findings = findings };
    defer s.deinit(testing.allocator);

    const kinds = try testing.allocator.alloc(secrets_mod.Kind, 1);
    kinds[0] = .pem_private_key;
    var p: Policy = .{ .secret_fail_kinds = kinds };
    defer p.deinit(testing.allocator);

    var r = try evaluate(testing.allocator, p, s);
    defer r.deinit(testing.allocator);
    try testing.expectEqual(Verdict.fail, r.verdict);
    try testing.expectEqual(@as(usize, 1), r.violations.len);
    try testing.expectEqualStrings("pem_private_key", r.violations[0].detail);
}

test "evaluate: config severity gate" {
    const issues = try testing.allocator.alloc(config_mod.Issue, 1);
    issues[0] = .{
        .rule_id = try testing.allocator.dupe(u8, "DKR004"),
        .title = try testing.allocator.dupe(u8, "RUN with --privileged"),
        .severity = .critical,
        .source = .dockerfile,
        .file = try testing.allocator.dupe(u8, "Dockerfile"),
        .line = 5,
        .snippet = try testing.allocator.dupe(u8, ""),
        .recommendation = try testing.allocator.dupe(u8, ""),
    };
    var s = sbom_mod.Sbom{ .components = &.{}, .config_issues = issues };
    defer s.deinit(testing.allocator);

    var p: Policy = .{ .config_max_severity = .high };
    defer p.deinit(testing.allocator);
    var r = try evaluate(testing.allocator, p, s);
    defer r.deinit(testing.allocator);
    try testing.expectEqual(Verdict.fail, r.verdict);
    try testing.expectEqualStrings("DKR004", r.violations[0].detail);
}

test "evaluate: config deny by rule_id" {
    const issues = try testing.allocator.alloc(config_mod.Issue, 1);
    issues[0] = .{
        .rule_id = try testing.allocator.dupe(u8, "DKR001"),
        .title = try testing.allocator.dupe(u8, "USER root"),
        .severity = .high,
        .source = .dockerfile,
        .file = try testing.allocator.dupe(u8, "Dockerfile"),
        .line = 1,
        .snippet = try testing.allocator.dupe(u8, ""),
        .recommendation = try testing.allocator.dupe(u8, ""),
    };
    var s = sbom_mod.Sbom{ .components = &.{}, .config_issues = issues };
    defer s.deinit(testing.allocator);

    const deny = try testing.allocator.alloc([]u8, 1);
    deny[0] = try testing.allocator.dupe(u8, "DKR001");
    var p: Policy = .{ .config_deny = deny };
    defer p.deinit(testing.allocator);
    var r = try evaluate(testing.allocator, p, s);
    defer r.deinit(testing.allocator);
    try testing.expectEqual(Verdict.fail, r.verdict);
    try testing.expectEqualStrings("config.deny", r.violations[0].rule);
}

test "evaluate: component substring deny" {
    const comps = try testing.allocator.alloc(sbom_mod.Component, 2);
    comps[0] = .{
        .kind = .static_lib,
        .name = try testing.allocator.dupe(u8, "openssl"),
        .version = try testing.allocator.dupe(u8, "1.1.1"),
        .evidence = .embedded_string,
    };
    comps[1] = .{
        .kind = .runtime,
        .name = try testing.allocator.dupe(u8, "glibc"),
        .version = try testing.allocator.dupe(u8, "2.30"),
        .evidence = .embedded_string,
    };
    var s = sbom_mod.Sbom{ .components = comps };
    defer s.deinit(testing.allocator);

    const deny = try testing.allocator.alloc([]u8, 1);
    deny[0] = try testing.allocator.dupe(u8, "openssl");
    var p: Policy = .{ .component_deny = deny };
    defer p.deinit(testing.allocator);

    var r = try evaluate(testing.allocator, p, s);
    defer r.deinit(testing.allocator);
    try testing.expectEqual(Verdict.fail, r.verdict);
    try testing.expectEqual(@as(usize, 1), r.violations.len);
    try testing.expectEqualStrings("openssl", r.violations[0].detail);
}

test "evaluate: multiple axes accumulate violations" {
    const comps = try testing.allocator.alloc(sbom_mod.Component, 1);
    comps[0] = .{
        .kind = .static_lib,
        .name = try testing.allocator.dupe(u8, "openssl"),
        .version = try testing.allocator.dupe(u8, "1.0.0"),
        .evidence = .embedded_string,
    };
    const issues = try testing.allocator.alloc(config_mod.Issue, 1);
    issues[0] = .{
        .rule_id = try testing.allocator.dupe(u8, "DKR001"),
        .title = try testing.allocator.dupe(u8, "USER root"),
        .severity = .high,
        .source = .dockerfile,
        .file = try testing.allocator.dupe(u8, "Dockerfile"),
        .line = 1,
        .snippet = try testing.allocator.dupe(u8, ""),
        .recommendation = try testing.allocator.dupe(u8, ""),
    };
    var s = sbom_mod.Sbom{ .components = comps, .config_issues = issues };
    defer s.deinit(testing.allocator);

    const cdeny = try testing.allocator.alloc([]u8, 1);
    cdeny[0] = try testing.allocator.dupe(u8, "openssl");
    var p: Policy = .{
        .component_deny = cdeny,
        .config_max_severity = .high,
    };
    defer p.deinit(testing.allocator);
    var r = try evaluate(testing.allocator, p, s);
    defer r.deinit(testing.allocator);
    try testing.expectEqual(Verdict.fail, r.verdict);
    try testing.expectEqual(@as(usize, 2), r.violations.len);
}

test "evaluate: vuln severity below max passes" {
    const v = vuln_mod.Vulnerability{
        .advisory_id = try testing.allocator.dupe(u8, "CVE-low"),
        .package = try testing.allocator.dupe(u8, "x"),
        .matched_version = null,
        .severity = .low,
        .cvss = null,
        .summary = try testing.allocator.dupe(u8, ""),
        .fixed_version = null,
        .references = try testing.allocator.alloc([]const u8, 0),
    };
    var vulns = try testing.allocator.alloc(vuln_mod.Vulnerability, 1);
    vulns[0] = v;
    var s = sbom_mod.Sbom{ .components = &.{}, .vulnerabilities = vulns };
    defer s.deinit(testing.allocator);

    var p: Policy = .{ .vuln_max_severity = .high };
    defer p.deinit(testing.allocator);
    var r = try evaluate(testing.allocator, p, s);
    defer r.deinit(testing.allocator);
    try testing.expectEqual(Verdict.pass, r.verdict);
}
