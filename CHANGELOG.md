# Changelog

All notable changes to scribe land here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) loosely; semantic
versioning per [SemVer 2.0.0](https://semver.org/).

## [0.2.0] — 2026-05-04

### Added

- **FAT / Universal Mach-O auto-resolve** — `scribe info /bin/zsh` now picks
  the host-arch slice (x86_64 on Intel, aarch64 on Apple Silicon) instead
  of erroring. `--all-slices` dumps every slice's arch/entry/section count.
- **32-bit Mach-O parity** — `MH_MAGIC` / `MH_CIGAM` parser alongside the
  existing 64-bit code; sections + dylibs extracted the same way.
- **`scribe harden`** — cross-format exploit-mitigation report:
  - ELF: PIE, NX, RELRO (full/partial), CANARY, FORTIFY, RPATH/RUNPATH, STRIPPED
  - Mach-O: PIE, NX_HEAP, STACK_EXEC, CODE_SIG, ENCRYPTED, RPATH, CANARY, RESTRICT
  - PE: ASLR, HIGH_ENTROPY_VA, DEP, CFG, GS, SafeSEH, AUTHENTICODE
  Findings fold into `scribe scan` config_issues automatically.
- **`scribe yara`** — YARA-subset rule engine with:
  - `strings:` literals (ascii / wide / nocase / fullword) + hex patterns with `??` wildcards
  - `condition:` `any of them`, `all of them`, `N of them`, `and / or / not`, parens
  - `--rules <p>` runs against a binary; `--json` emits structured matches
  - `scribe scan --yara <p>` rolls matches into config_issues as `YARA-<rule>`
- **Anti-tampering anomalies** — auto-run on every binary in `scribe scan`:
  entry-outside-text, non-canonical interpreter / dylinker, process-injection
  symbol clusters. IDs `BIN-ANOM-*`.
- **`scribe hex`** — hex+ASCII dump with `--offset`, `--length`, `--section`.
- **`scribe exports`** — list dynamically-exported symbols (ELF `.dynsym`,
  Mach-O `LC_SYMTAB` N_EXT, PE export directory).
- **`scribe diff`** — structural diff of two binaries: format, arch,
  section set, hardening posture.
- **JSON output** for `info`, `deps`, `strings`, `entropy`, `harden`, `yara`,
  `exports`, `diff`. `--json` flag.
- **`--version` / `-h` / `--help`** top-level flags.
- **`scribe completion bash|zsh|fish`** — emit static completion script.
- **TUI hardening tab** — new filter (`6`) splits `BIN-*` and `YARA-*`
  findings from `DKR/K8S/OCI` config issues.
- **TUI search extended** to detail-pane segments, not just titles.
- **TUI `?` help overlay** — interactive key-map in the detail pane.
- **Container hardening per-binary** — `scribe scan <image>.tar` now runs
  hardening + anomalies on every executable inside the squashed image,
  feeding findings into `config_issues[]`.
- **Example YARA rule packs** — `examples/yara/suspicious_imports.yar`,
  `examples/yara/secrets_anchor.yar`.
- **Example policy** — `examples/policy.json` shows fail-on / ignore shape.

### Changed

- Renamed `error.NotElf` → `error.UnsupportedFormat` (no compat shim).

### Fixed

- libvaxis (vendored) divide-by-zero, null-height assert, and unsigned
  underflow when terminals report 0×0 dimensions before the first real
  resize event. `scribe ui` no longer panics-and-exits on terminals that
  send a synthetic 0×0 winsize. Patches in
  `zig-pkg/vaxis-*/src/vxfw/{App,SplitView,FlexColumn}.zig`.
- Mach-O hardening + anomaly analyzers now correctly rebase section
  offsets via `MachoInfo.fat_slice_offset` for FAT inputs.

## [0.1.0] — initial public form

- ELF / Mach-O / PE parsers, SIMD strings, Shannon entropy, dynamic deps
- CycloneDX 1.5 SBOM, container/registry/local-docker SBOM
- DWARF symbolication (ELF + Mach-O dSYM)
- Function-byte fingerprint corpus + matcher
- Security pipeline: secrets, vulnerability, config (IaC), policy gate
- `scribe ui` libvaxis TUI
- Inline progress reporter
