//! Scribe — static binary forensics library.
//! Phase-2: ELF + Mach-O + PE parsing, SIMD strings, Shannon entropy,
//! dynamic dependency extraction. DWARF symbolication arrives in Phase-3
//! (paired with scribe-live).

const std = @import("std");

pub const elf = @import("elf.zig");
pub const macho = @import("macho.zig");
pub const pe = @import("pe.zig");
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
pub const collectDeps = deps.collect;
pub const shannon = entropy.shannon;
pub const scanStrings = strings.scan;
pub const scanSecrets = security.secrets.scan;
pub const SecretFinding = security.secrets.Finding;
pub const VulnerabilityDb = security.vulnerability.Database;
pub const Vulnerability = security.vulnerability.Vulnerability;
pub const matchVulnerabilities = security.vulnerability.match;
pub const ConfigIssue = security.config.Issue;
pub const auditConfig = security.config.audit;
pub const Policy = security.policy.Policy;
pub const evaluatePolicy = security.policy.evaluate;

test {
    std.testing.refAllDecls(@This());
}
