# Contributing to scribe

Thanks for considering a contribution. scribe is a Zig-native binary
forensics library + CLI; the project values small, reviewable patches
over large rewrites.

## Build + test

Requires Zig 0.16.0 or newer.

```sh
zig build         # produces zig-out/bin/scribe
zig build test    # runs the test suite (unit + golden-fixture)
```

The test suite is fully self-contained — no network, no Docker daemon.
Golden binary fixtures live under `src/testdata/`.

## Repository shape

| Path                   | Purpose                                                |
| ---------------------- | ------------------------------------------------------ |
| `src/`                 | Library + CLI source                                   |
| `src/main.zig`         | CLI dispatcher                                         |
| `src/root.zig`         | Library root — re-exports the public API               |
| `src/security/`        | secrets, vulnerability, config (IaC), policy, hardening, anomalies, yara |
| `src/testdata/`        | Golden binary fixtures (committed as binary blobs)     |
| `examples/`            | YARA rule packs, example policy.json                   |
| `zig-pkg/`             | Fetched dependency cache (gitignored)                  |
| `README.md`            | High-level overview + CLI reference                    |
| `SECURITY.md`          | Security pipeline reference + rule catalogs            |
| `CHANGELOG.md`         | User-facing change history                             |

## Development principles

- **Allocator-threaded.** Every public function takes an
  `std.mem.Allocator`. No globals, no thread-local caches.
- **Zero-copy by default.** Parsers slice into the input mmap buffer
  rather than allocating; only outputs (Findings, Issues, Vulnerabilities)
  own their string content.
- **TTY-aware output.** ANSI styling and the inline spinner are
  no-ops when stderr is piped; piped/JSON/scripted output stays
  byte-identical.
- **Error set is closed.** Library errors come from `errors.ScribeError`
  in `src/errors.zig`. Add new variants there; don't return ad-hoc errors
  out of public functions.
- **Tests live with their module.** Inline `test "..."` blocks pass under
  `std.testing.allocator` (leak-detecting). New behavior should ship with
  a test that fails before your patch and passes after.

## Pull request checklist

- `zig build` passes.
- `zig build test` passes (no leaks, no skipped tests).
- New CLI flags / subcommands appear in `usage` (`src/main.zig`) AND
  `README.md`.
- New rule IDs or finding kinds documented in `SECURITY.md`.
- User-visible changes noted in `CHANGELOG.md` under `## [Unreleased]`.

## Filing issues

Open a GitHub issue with:
1. Zig version (`zig version`).
2. Host triple (e.g. `aarch64-macos`, `x86_64-linux-gnu`).
3. Exact command + output (use `--json` for structured reproducers).
4. Sample input file or minimal test case if possible.

For security-sensitive reports, see `SECURITY.md`.
