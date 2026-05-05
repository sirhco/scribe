# Changelog

All notable changes to scribe land here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) loosely; semantic
versioning per [SemVer 2.0.0](https://semver.org/).

## [0.2.0] — 2026-05-04

### Added (Phase 8 + UX polish)

- **CI** — `.github/workflows/ci.yml` runs `zig fmt --check`, `zig build`,
  `zig build test`, and a smoke-pass over the fixtures on Linux + macOS.
- **Smoke-fuzz harness** (`src/fuzz.zig`) — exercises every parser with
  malformed / random inputs; `zig build test` blocks regressions. Caught
  two real bugs while landing it (wasm ULEB128 `u6` shift overflow, YARA
  parse-error allocation leaks).
- **Wasm walker** — `scribe wasm <path>` lists module sections; magic +
  version + section enum + custom-section name extraction.
- **AR archive walker** — `scribe ar list <path>` enumerates static
  archive members; handles SysV `//` long-name table + BSD `#1/<N>`
  long-name extension.
- **`scribe imports`** — companion to `scribe exports`; ELF dynsym
  undefined refs, Mach-O `LC_SYMTAB` `N_EXT` undefineds, PE shares
  with `deps`.
- **`scribe info --hashes`** — per-section SHA-256 (first 8 bytes hex).
- **Per-section permission labels** in `scribe info` (`r-x`, `rw-`,
  `r--`, ...) for ELF / Mach-O / PE.
- **SARIF 2.1.0 output** for `scribe scan --sarif` — single run, single
  tool, results with stable rule IDs and physical-location regions.
- **GitHub Annotations output** for `scribe scan --github-annotations`
  (`--gha`) — Workflow-command lines for `::error`/`::warning`/`::notice`.
- **Mach-O code signature partial parse** — extracts CodeDirectory
  identifier (`CS_IDENT`) and team-id (`CS_TEAM`, when CD version
  ≥ 0x20200) from the EmbeddedSignature SuperBlob. CMS chain validation
  + entitlement plist parse remain out of scope.
- **`BIN-ANOM-OVERLAP_SECTIONS`** — high-severity anti-tampering anomaly
  for ELF + Mach-O when section file ranges overlap.
- **Mach-O 32-bit `LC_UNIXTHREAD` entry decode** — extracts `eip`
  (i386, state[10]) / `pc` (ARM, state[15]) from thread state.
- **`--quiet` / `-q`** top-level flag — disables the inline progress
  spinner (writes nothing to stderr).
- **`--no-color`** top-level flag — forces ANSI styling off (mirrors
  `NO_COLOR=1`).
- **`scribe completion bash|zsh|fish`** — emits a static completion
  script.
- **`scribe.parseFromFile(allocator, io, path)`** — library-side
  convenience that bundles `mmap.open` + `format.parse` and exposes a
  single `Parsed.deinit` for cleanup.
- **`Dockerfile`** — multi-stage Alpine build producing
  `scribe` at `-Doptimize=ReleaseFast`.
- **man page** — `man/scribe.1` covers every subcommand.
- **TUI page navigation** — `J` / `K` (and `PageDown` / `PageUp`)
  jump 10 rows at a time.
- **TUI Hardening filter** is reachable via `Tab` cycling now (the
  previous `@mod(... 5)` left it unreachable except via `6`).

### Added (earlier in 0.2.0 — Phase 8 base)

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
