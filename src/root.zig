//! Scribe — static binary forensics library.
//! Phase-2: ELF + Mach-O + PE parsing, SIMD strings, Shannon entropy,
//! dynamic dependency extraction. DWARF symbolication arrives in Phase-3
//! (paired with scribe-live).

const std = @import("std");

pub const elf = @import("elf.zig");
pub const macho = @import("macho.zig");
pub const pe = @import("pe.zig");
pub const wasm = @import("wasm.zig");
pub const ar = @import("ar.zig");
pub const format = @import("format.zig");
pub const errors = @import("errors.zig");
pub const mmap = @import("mmap.zig");
pub const strings = @import("strings.zig");
pub const entropy = @import("entropy.zig");
pub const deps = @import("deps.zig");
pub const buildid = @import("buildid.zig");
pub const sbom = @import("sbom.zig");
pub const container = @import("container.zig");
pub const dwarf = @import("dwarf.zig");
pub const fingerprint = @import("fingerprint.zig");
pub const registry = @import("registry.zig");
pub const local_docker = @import("local_docker.zig");
pub const security = @import("security/mod.zig");
pub const term = @import("term.zig");
pub const progress = @import("progress.zig");
pub const yaml = @import("yaml.zig");

pub const ScribeError = errors.ScribeError;
pub const Arch = elf.Arch;
pub const ElfInfo = elf.ElfInfo;
pub const MachoInfo = macho.MachoInfo;
pub const PeInfo = pe.PeInfo;
pub const FormatInfo = format.Info;
pub const FormatKind = format.Kind;

pub const parseElf = elf.parse;
pub const parseMacho = macho.parse;
pub const parsePe = pe.parse;
pub const detectFormat = format.detect;
pub const parseFormat = format.parse;

/// Convenience: mmap a path and parse its format in one call. The returned
/// `Parsed` owns both the mapping and the info; deinit frees both.
pub const Parsed = struct {
    mapping: mmap.Mapping,
    info: format.Info,

    pub fn bytes(self: *const Parsed) []const u8 {
        return self.mapping.bytes();
    }

    pub fn deinit(self: *Parsed, allocator: std.mem.Allocator) void {
        self.info.deinit(allocator);
        self.mapping.deinit();
    }
};

pub fn parseFromFile(
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
) !Parsed {
    var mapping = try mmap.open(io, path);
    errdefer mapping.deinit();
    const info = try format.parse(allocator, mapping.bytes());
    return .{ .mapping = mapping, .info = info };
}
pub const collectDeps = deps.collect;
pub const shannon = entropy.shannon;
pub const scanStrings = strings.scan;
pub const scanSecrets = security.secrets.scan;
pub const SecretFinding = security.secrets.Finding;
pub const VulnerabilityDb = security.vulnerability.Database;
pub const Vulnerability = security.vulnerability.Vulnerability;
pub const matchVulnerabilities = security.vulnerability.match;
pub const mergeVulnerabilityDbs = security.vulnerability.merge;
pub const ConfigIssue = security.config.Issue;
pub const auditConfig = security.config.audit;
pub const Policy = security.policy.Policy;
pub const evaluatePolicy = security.policy.evaluate;
pub const HardeningReport = security.hardening.Report;
pub const HardeningCheck = security.hardening.Check;
pub const HardeningStatus = security.hardening.Status;
pub const analyzeHardening = security.hardening.analyze;
pub const YaraRuleSet = security.yara.RuleSet;
pub const YaraMatch = security.yara.Match;
pub const parseYara = security.yara.parse;
pub const scanYara = security.yara.scan;
pub const AnomalyReport = security.anomalies.Report;
pub const analyzeAnomalies = security.anomalies.analyze;

// Smoke-fuzz harness — exercises parsers with malformed input to catch
// panics-on-bad-bytes regressions.
test {
    _ = @import("fuzz.zig");
    std.testing.refAllDecls(@This());
}
