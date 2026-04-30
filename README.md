# Scribe

Scribe is a high-performance, cross-platform binary forensics library and CLI written in Zig. It parses ELF, Mach-O, and PE binaries with zero-copy techniques, extracts dynamic dependencies and DWARF symbols, computes per-section Shannon entropy, recovers strings via SIMD, fingerprints functions for static-library identification, and weaves Software Bills of Materials (SBOMs) for both individual binaries and full container images — including direct OCI registry pulls without a Docker daemon.

---

## Table of contents

- [Status](#status)
- [Install](#install)
- [Quick start](#quick-start)
- [CLI reference](#cli-reference)
  - [`scribe info`](#scribe-info-path) — format, arch, sections
  - [`scribe deps`](#scribe-deps-path) — dynamic dependencies
  - [`scribe strings`](#scribe-strings-path-min) — printable runs (SIMD)
  - [`scribe entropy`](#scribe-entropy-path) — Shannon entropy per section
  - [`scribe sbom`](#scribe-sbom-source---plain) — Software Bill of Materials
  - [`scribe symbols`](#scribe-symbols-path) — DWARF function table
  - [`scribe addr2line`](#scribe-addr2line-path-hex) — address → source location
  - [`scribe fp generate`](#scribe-fp-generate-path-lib-version) — fingerprint database
  - [`scribe fp match`](#scribe-fp-match-target-dbjson) — fingerprint match
- [Security pipeline](#security-pipeline) (`secrets`, `vulns`, `config`, `scan`, `policy`, `vulndb`) — see [SECURITY.md](SECURITY.md) for the full reference
- [Library usage (Zig)](#library-usage-zig)
- [Source ingestion: file, container, registry](#source-ingestion-file-container-registry)
- [Format support matrix](#format-support-matrix)
- [Architecture](#architecture)
- [Caveats and known limitations](#caveats-and-known-limitations)
- [Roadmap](#roadmap)

---

## Status

| Phase | Capability                                                         | State |
| ----- | ------------------------------------------------------------------ | ----- |
| 1     | ELF parser (zero-copy mmap, sections, entry, arch)                 | done  |
| 2     | Mach-O + PE parsers, SIMD strings, Shannon entropy, dynamic deps   | done  |
| 3a    | SBOM (build-id, dynamic links, embedded version strings, CycloneDX) | done  |
| 3b    | Function-signature fingerprinting (Wyhash, DWARF-keyed)            | done  |
| 3c    | Container SBOM (docker save tar, layer squash with whiteouts)      | done  |
| 3d    | Direct OCI registry pull (no docker daemon, multi-arch)            | done  |
| 4a    | DWARF symbolication (ELF)                                          | done  |
| 4b    | DWARF symbolication (Mach-O `.dSYM`) — symbol enumeration; auto-finds the bundle next to the binary | partial |
| 5a    | Security: SIMD secret scan (anchored + UTF-16LE + entropy)         | done  |
| 5b    | Security: vuln matcher (OSV-lite + OSV native + binary `.scvd`)    | done  |
| 5c    | Security: IaC audit (Dockerfile + Kubernetes + OCI image-config)   | done  |
| 5d    | Security: policy gate, fingerprint cross-ref, `scribe scan` umbrella | done  |
| 5e    | Security: vulndb merge, NVD CVE 2.0 ingest, CVSS v2 parser           | done  |
| 5e-ext | IaC audit driven by an AST YAML walker (multi-doc, anchors/aliases, block + flow style, Helm `{{ ... }}` tolerated) | done |
| 3b-ext | Sliding-window fingerprint match (stripped binaries) + x86_64 relocation-normalized hashes (E8/E9/0F8x branches, RIP-relative ModR/M loads/stores/LEAs/indirect calls) | done |
| 3c-ext | `docker save` stdout spooled straight to a tempfile (no in-memory cap); outer-tar walk is zero-copy via mmap so resident memory tracks the working set, not the image size | done |

Tests: 146 unit + integration tests (`zig build test`).

---

## Install

Requires Zig 0.16.0 or newer.

```sh
git clone https://github.com/<you>/scribe.git
cd scribe
zig build                # produces zig-out/bin/scribe
zig build test           # runs the test suite

# Optional: put it on PATH so the examples below work without ./zig-out/bin/ prefix.
export PATH="$PWD/zig-out/bin:$PATH"
# Or override the install prefix:
sudo zig build --prefix /usr/local install   # writes /usr/local/bin/scribe
```

`zig build install` and plain `zig build` both write to
`./zig-out/bin/scribe` by default — no system-wide install happens unless
you pass `--prefix`. All examples below assume `scribe` resolves on
`PATH`; otherwise call the binary directly: `./zig-out/bin/scribe ...`.

Or import as a Zig dependency in another project:

```zon
.dependencies = .{
    .scribe = .{ .path = "../scribe" }, // or .url + .hash
},
```

Then in your `build.zig`:

```zig
const scribe_dep = b.dependency("scribe", .{ .target = target, .optimize = optimize });
exe.root_module.addImport("scribe", scribe_dep.module("scribe"));
```

---

## Quick start

```sh
# What is this binary?
scribe info /usr/bin/zsh

# What does it dynamically link against?
scribe deps /usr/bin/zsh

# Generate a CycloneDX 1.5 SBOM
scribe sbom /usr/bin/zsh > zsh.cdx.json

# Same, but for a container image without docker daemon
scribe sbom 'registry://alpine:3.19@linux/amd64' > alpine.cdx.json

# Walk a docker save tar
docker save alpine:3.19 -o alpine.tar
scribe sbom alpine.tar --plain
```

---

## CLI reference

All subcommands accept a single positional argument: a local file path. The
`sbom` subcommand additionally accepts `docker://` and `registry://` URIs
(described below). Errors go to stderr; structured output goes to stdout.

### `scribe info <path>`

Prints format, architecture, entry point, 64-bit flag, and the section table.

```sh
$ scribe info src/testdata/hello_x86_64
file:     src/testdata/hello_x86_64
format:   elf
arch:     x86_64
entry:    0x1008180
64-bit:   true
sections: 12
  [  1] .rodata                  type=0x0001 addr=0x0000000001000240 size=0x37d0
  [  4] .text                    type=0x0001 addr=0x0000000001008180 size=0x14189
  ...
```

For Mach-O, sections are printed as `<segment>/<section>` (e.g. `__TEXT/__text`).
For PE, sections include `image base` and virtual/raw size pairs.

### `scribe deps <path>`

Lists dynamic library dependencies.

| Format | Source                              |
| ------ | ----------------------------------- |
| ELF    | `PT_DYNAMIC` → `DT_NEEDED` strings  |
| Mach-O | `LC_LOAD_DYLIB` / `LC_LOAD_WEAK_DYLIB` / `LC_REEXPORT_DYLIB` |
| PE     | Import directory (`IMAGE.DIRECTORY_ENTRY.IMPORT`) |

```sh
$ scribe deps /usr/bin/python3
  /usr/lib/libSystem.B.dylib                [macho_dylib]
  /usr/lib/libpython3.11.dylib              [macho_dylib]

$ scribe deps src/testdata/hello_pe_x86_64
  ntdll.dll                  [pe_import]
  KERNEL32.dll               [pe_import]
```

### `scribe strings <path> [min]`

SIMD-accelerated printable-ASCII run extractor. Default minimum length: 4.
Equivalent to GNU `strings` but typically much faster on large binaries.

```sh
scribe strings /bin/ls           # min 4
scribe strings /bin/ls 16        # only runs ≥ 16 chars
```

The implementation uses `@Vector(N, u8)` with `std.simd.suggestVectorLength`
to pick lane width per architecture; outputs are zero-copy slices into the
mmap'd file.

### `scribe entropy <path>`

Reports overall Shannon entropy in bits/byte plus per-section breakdown.
Values near 0 indicate uniform/repetitive data; near 8 indicate compression
or encryption — useful for spotting packed payloads.

```sh
$ scribe entropy ./suspect.bin
overall: 7.9982 bits/byte             # very high — compressed or encrypted
  .text                    6.4299
  .rodata                  5.3971
  .data                    0.0268
  .upx_payload             7.9914     # likely packed
```

### `scribe sbom <source> [--plain]`

Produces a CycloneDX 1.5 JSON SBOM by default, or a human-readable table
with `--plain`. The `<source>` may be:

1. A local binary file (ELF/Mach-O/PE).
2. A `docker save` tarball (gzip or raw, OCI or legacy layout).
3. A `docker://` URI: any image already in the **local** docker daemon's
   image store. Spawns `docker save <image>` under the hood, so it works
   for locally-built images that have never been pushed.
4. A `registry://` URI: pulls directly from a registry over HTTPS without
   needing a local docker daemon. Form:
   `registry://[host/][namespace/]image:tag[@os/arch]`.

```sh
scribe sbom /usr/bin/zsh                          # single binary
scribe sbom alpine.tar                            # tarball
scribe sbom 'docker://alpine:3.19'                # local docker image
scribe sbom 'docker://my-locally-built:dev'       # never-pushed local build
scribe sbom 'registry://alpine:3.19'              # OCI pull, native arch
scribe sbom 'registry://alpine:3.19@linux/amd64'  # specific platform
scribe sbom 'registry://ghcr.io/owner/img:v1'     # private/non-Hub registries
```

| Scheme        | Needs docker | Needs network | Multi-arch select | Note                                  |
| ------------- | :----------: | :-----------: | :---------------: | ------------------------------------- |
| (file path)   |      —       |       —       |        —          | Single binary or `docker save` tar    |
| `docker://`   |      ✓       |   only on pull| native daemon     | Honors local image store              |
| `registry://` |      —       |       ✓       |   `@os/arch` opt  | Direct OCI V2 pull                    |

Components are detected from three evidence streams:

| Evidence          | Confidence | Source                                                                |
| ----------------- | ---------- | --------------------------------------------------------------------- |
| `build_id`        | 1.0        | ELF `.note.gnu.build-id`, Mach-O `LC_UUID`, PE PDB GUID               |
| `dynamic_link`    | 0.9        | DT_NEEDED, LC_LOAD_DYLIB, PE imports                                  |
| `embedded_string` | 0.6        | Pattern detectors (openssl, zlib, sqlite, libcurl, libxml2, libpng, musl, glibc, gcc, clang, zig) |

Output format example (`--plain`):

```
program       binary    2e2217c4...    linux/arm64    via=build_id      @ lib/libapk.so.2.14.0
dynamic_lib   libssl.so.3              linux/arm64    via=dynamic_link  @ lib/libapk.so.2.14.0
runtime       glibc        2.28        linux/amd64    via=embedded_string
compiler      zig          0.16.0      linux/amd64    via=embedded_string
```

Container/registry sources tag every component with both `path` (file
location inside the squashed image) and `platform` (`<os>/<arch>`).
Multi-arch manifest lists are resolved against the requested platform.

### `scribe symbols <path>`

Dumps the DWARF function table of an ELF binary or a Mach-O whose
debug info lives in a sibling `.dSYM` bundle (the macOS default after
`dsymutil`). For Mach-O, scribe first tries DWARF inline; if absent, it
auto-resolves `<path>.dSYM/Contents/Resources/DWARF/<basename>` and
parses that. You can also pass the inner Mach-O of the bundle directly.

```sh
$ scribe symbols ./myapp | head -5
0x00000000004012f0-0x0000000000401318 main
0x0000000000401320-0x0000000000401350 helper
...
(5185 symbols)
```

PE `.pdb` is still not supported (Phase-4c — see [Roadmap](#roadmap)).

### `scribe addr2line <path> <hex>`

Resolves a runtime address to function name and source `file:line:column`.

```sh
$ scribe addr2line ./myapp 0x4012f0
addr:    0x4012f0
symbol:  main
source:  /home/me/proj/main.zig:3:20
```

Address forms accepted: `0xDEADBEEF`, `0XDEADBEEF`, or bare `DEADBEEF`.

### `scribe fp generate <path> <lib> [version]`

Walks every DWARF function ≥ 32 bytes in `<path>`, hashes its raw bytes
with Wyhash, and writes a JSON fingerprint database to stdout.

```sh
scribe fp generate /usr/lib/libssl.so.3 openssl 3.2.0 > openssl-3.2.0.fp.json
```

The database has the following shape:

```json
{
  "version": 1,
  "entries": [
    {"hash": "0x4c3a0b1f...", "name": "SSL_read", "lib": "openssl", "version": "3.2.0"},
    ...
  ]
}
```

Build a corpus by running `fp generate` against every interesting library
version. Concatenate or merge databases as needed (CLI-side merging is
trivial: load each, concat entries, dedupe by hash).

### `scribe fp match <target> <db.json>`

Hashes each function in `<target>` and reports hits against the database.

```sh
$ scribe fp match ./suspect-binary openssl-3.2.0.fp.json
0x000000000040a1c0  SSL_read              ->  openssl 3.2.0
0x000000000040a230  SSL_write             ->  openssl 3.2.0
0x000000000040b500  EVP_CipherInit_ex     ->  openssl 3.2.0
(127 matches)
```

Useful for identifying statically linked libraries in stripped binaries
where DT_NEEDED and embedded version strings are absent.

---

### Security pipeline

scribe ships a daemon-free, no-Go-deps security scanner built on the same
zero-copy primitives as the SBOM stack. Six subcommands cover secret
scanning, CVE matching, IaC audit, policy gates, and advisory-DB
management:

```bash
scribe secrets ./myapp                                 # SIMD anchored + UTF-16LE secret scan
scribe vulns   ./myapp --db osv.scvd                   # CVE matcher (binary)
scribe vulns   alpine.tar --db osv.scvd                # CVE matcher (container tar)
scribe vulns   'registry://alpine:3.19' --db osv.scvd  # CVE matcher (direct registry pull)
scribe config  ./Dockerfile                            # IaC misconfig audit (Dockerfile / k8s / OCI image-config)
scribe scan    ./myapp --db osv.scvd --config Dockerfile --fp-db corpus.json   # full pipeline
scribe policy  ./myapp --policy ci.json --db osv.scvd  # exits 1 on violation; CI-friendly
scribe vulndb  compile osv-lite.json osv.scvd          # JSON → mmap binary
scribe vulndb  update  --from <url> --out osv.scvd     # HTTPS fetch + compile
```

`vulns`, `scan`, `policy`, and `sbom` all share the same source detection
— pass a binary path, a `docker save` tar, a `docker://` URI, or a
`registry://` URI to any of them. Container sources auto-discover every
bundled binary, embedded Dockerfile / `*.yaml`, and OCI image-config
hygiene problems in one pass.

All security signals merge into a single CycloneDX 1.5 SBOM with
`components[]`, `properties[]` (secrets + IaC findings), and
`vulnerabilities[]`. Container targets (`docker save` tar,
`registry://`, `docker://`) auto-discover embedded Dockerfiles / YAMLs
and audit the OCI image config blob.

#### Populating the advisory DB

scribe ships with no built-in advisory data. Pull from OSV.dev's
per-ecosystem zips, the CISA KEV catalog, or any feed you can `curl + jq`
into scribe's OSV-lite shape. Quick PyPI example:

```bash
mkdir osv && cd osv
curl -sSL "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip" -o all.zip
unzip -q all.zip
jq -s '.' *.json | scribe vulndb compile - ../osv-pypi.scvd
cd .. && rm -rf osv
scribe vulns ./myapp --db osv-pypi.scvd
```

OSV bulk URL pattern: `https://osv-vulnerabilities.storage.googleapis.com/<ecosystem>/all.zip`
(ecosystems: `PyPI`, `npm`, `Go`, `RubyGems`, `crates.io`, `Maven`,
`NuGet`, `Packagist`, `Hex`, `Pub`, `Debian`, `Ubuntu`, `Alpine`, …).
Full list at <https://osv.dev/data>.

`scribe vulndb compile` also accepts `-` to read JSON from stdin —
useful as a TLS escape hatch when `scribe vulndb update` chokes on a
server's cert chain (Zig 0.16's `std.http.Client` has known TLS gaps).

See [**SECURITY.md**](SECURITY.md) for: subcommand reference, JSON
formats (OSV-lite, OSV native, SCVD binary spec, policy.json), full
rule catalog (`DKR###`, `K8S###`, `OCI###`), the secret pattern table,
**ready-made recipes for OSV / CISA KEV / NVD ingestion**, performance
notes, and CI integration examples.

---

## Library usage (Zig)

Add scribe as a dependency, then import it:

```zig
const scribe = @import("scribe");

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;

    // Mmap-open any binary or container source.
    var mapping = try scribe.mmap.open(io, "/usr/bin/python3");
    defer mapping.deinit();

    // Auto-detect format and parse.
    var info = try scribe.parseFormat(gpa, mapping.bytes());
    defer info.deinit(gpa);

    std.log.info("arch={s} entry=0x{x}", .{ @tagName(info.arch()), info.entry() });

    // SBOM the same bytes.
    var bom = try scribe.sbom.collect(gpa, mapping.bytes());
    defer bom.deinit(gpa);
    for (bom.components) |c| {
        std.log.info("{s} {s} {s}", .{
            @tagName(c.kind), c.name, c.version orelse "-",
        });
    }
}
```

Module surface:

| Module              | Purpose                                                        |
| ------------------- | -------------------------------------------------------------- |
| `scribe.mmap`       | RAII mmap wrapper over `Io.File.MemoryMap`                     |
| `scribe.elf`        | ELF32/64 zero-copy parser (`parse`, `ElfInfo`, `SectionHeader`) |
| `scribe.macho`      | Mach-O 64-bit parser, sections + dylibs                        |
| `scribe.pe`         | PE/COFF parser via `std.coff.Coff`                             |
| `scribe.format`     | Unified `Info` union + `detect`/`parse`                        |
| `scribe.strings`    | SIMD printable-ASCII iterator                                  |
| `scribe.entropy`    | Shannon entropy (`shannon([]const u8) -> f64`)                 |
| `scribe.deps`       | Unified dynamic dependency extractor                           |
| `scribe.buildid`    | ELF build-id / Mach-O UUID / PE PDB GUID                       |
| `scribe.sbom`       | `Component`, `Sbom`, `collect`, `writeCycloneDX`               |
| `scribe.container`  | OCI/docker save tarball SBOM                                   |
| `scribe.local_docker`| Local docker daemon source (spawns `docker save`)             |
| `scribe.registry`   | Direct HTTPS pull from OCI registries                          |
| `scribe.dwarf`      | `Symbolicator` over `.debug_info`/`.debug_line`                |
| `scribe.fingerprint`| Wyhash function-signature corpus + matcher                     |
| `scribe.security.secrets`     | SIMD anchored + UTF-16LE + entropy secret scanner    |
| `scribe.security.vulnerability` | Advisory matcher (OSV-lite, OSV native, SCVD binary) |
| `scribe.security.config`      | IaC audit (Dockerfile, Kubernetes, OCI image-config) |
| `scribe.security.policy`      | JSON-driven gatekeeper over a populated `Sbom`       |
| `scribe.yaml`                 | YAML 1.2 subset parser (multi-doc, anchors/aliases, block + flow, Helm tolerated) — backs the Kubernetes audit |

All public APIs allocate via the caller's allocator; no implicit globals.
`*Info` and `Sbom` types own their string buffers and require explicit
`deinit(allocator)`.

---

## Source ingestion: file, container, registry

The same `scribe sbom <source>` UX accepts four kinds of inputs:

```
              ┌──────────────────────────────┐
              │        scribe sbom <source>  │
              └──────────────┬───────────────┘
                             │
       ┌─────────┬───────────┴────────┬────────────────┐
       │         │                    │                │
   file path   docker://…       *.tar / *.tar.gz   registry://…
       │         │                    │                │
   mmap.open    local_docker.pullSbom │                registry.pullSbom
       │         │  (spawns           │                  │ (HTTPS+OCI V2)
       │         │   docker save)     │                  │
       │         └─────────┐          │          ┌──────┘
       │                   ▼          ▼          ▼
       │          container.collect / collectFromBlobs
       │                                │
       └────▶ sbom.collect ◀────────────┘
                            │
                writeCycloneDX or plain table
```

Container source detection:

- Magic check at offsets 0 (gzip `1F 8B`) or 257 (`ustar`).
- Layers may be gzipped (`tar+gz`) or raw.
- Whiteouts (`.wh.<file>`) remove from the squash accumulator.
- Multi-image manifest.json arrays produce multiple per-platform component sets.

Local docker source (`docker://`):

- Requires `docker` CLI on `PATH` and a running daemon.
- Spawns `docker save <image>` and redirects stdout straight to a
  tempfile under `/tmp` via `StdIo.file`. Works for any image in the
  daemon's local store, including ones never pushed to a registry.
- Memory: tar is mmap'd from disk and walked zero-copy, so resident
  memory tracks the working set (manifest + one decompressed layer at a
  time) rather than the image size. The legacy
  `SCRIBE_DOCKER_SAVE_CAP_MIB` knob no longer applies.
- `docker://<image>[:<tag>]`. Tag defaults to whatever docker resolves
  (typically `latest`). Use full repo names for non-Hub local images
  (e.g. `docker://my-org/svc:dev`).

Registry source:

- Anonymous bearer-token flow against `auth.docker.io` for Docker Hub.
- Non-Docker-Hub registries use unauthenticated GETs.
- Manifest list / OCI image index → match on `os/arch` → image manifest.
- Manual redirect handling drops `Authorization` on cross-domain hops to
  avoid the bearer token leaking to S3-backed blob CDNs.
- Layer blobs are decompressed and squashed identically to the local tar
  path; the same `container.collectFromBlobs` performs per-binary SBOM.

---

## Format support matrix

| Capability         | ELF | Mach-O | PE  |
| ------------------ | --- | ------ | --- |
| Header / arch      | ✓   | ✓      | ✓   |
| Section table      | ✓   | ✓      | ✓   |
| Entry point        | ✓   | ✓ (LC_MAIN) | ✓ (image base + RVA) |
| Dynamic deps       | ✓ (DT_NEEDED) | ✓ (LC_LOAD_DYLIB) | ✓ (import dir) |
| Build identifier   | ✓ (`.note.gnu.build-id`) | ✓ (`LC_UUID`) | ✓ (PDB GUID + age) |
| DWARF symbols      | ✓   | ✓ (`.dSYM` auto-resolved) | —   |
| Source line lookup | ✓   | partial | —   |
| Strings (SIMD)     | ✓   | ✓      | ✓   |
| Entropy            | ✓   | ✓      | ✓   |
| Fingerprint corpus | ✓   | —      | —   |

Mach-O `.dSYM` symbol enumeration ships in 4b; source-line lookup is
tracked under 4b+ (blocked on a `std.debug.Dwarf` upstream bug). PE
`.pdb` parsing is still under 4c. See [Roadmap](#roadmap).

---

## Architecture

```
                    ┌────────────────────┐
                    │      main.zig      │   CLI dispatcher
                    └─────────┬──────────┘
                              │
         ┌────────────────────┼────────────────────┐
         │                    │                    │
   ┌─────────────┐     ┌──────────────┐     ┌───────────────┐
   │  format.zig │     │ container.zig│     │ registry.zig  │
   │ detect+union│     │ tar squash   │     │ HTTPS+auth    │
   └──┬───┬───┬──┘     └──────┬───────┘     └───────┬───────┘
      │   │   │               │                     │
      │   │   ▼               │                     │
      │   │ pe.zig            │                     │
      │   ▼                   ▼                     ▼
      │ macho.zig    ┌────────────────────────────────────┐
      ▼              │           sbom.zig                 │
   elf.zig    ────▶  │  build_id + deps + version strings │
      │              └────────────┬───────────────────────┘
      ▼                           │
   dwarf.zig                      ▼
      │                  CycloneDX 1.5 JSON
      ▼
   fingerprint.zig (Wyhash over .text)
```

Cross-cutting modules: `mmap.zig` (RAII file mapping), `errors.zig` (unified error set), `strings.zig` and `entropy.zig` (shared SIMD/scalar utilities).

---

## Caveats and known limitations

- **macOS DWARF**: scribe parses the inner Mach-O of a `.dSYM` bundle
  (`<bin>.dSYM/Contents/Resources/DWARF/<bin>`) and auto-resolves the
  bundle when you pass the binary itself. Function-symbol enumeration
  works; `addr2line` source-line lookup against DWARF 5 line programs
  trips a `std.debug.Dwarf` upstream bug on the `__debug_line_str` form.
  Tracked under Phase 4b+.
- **PE PDB**: scribe extracts the PDB GUID from the debug directory but
  does not (yet) parse the PDB file itself. Address symbolication on PE
  requires the matching `.pdb` and PDB parsing — neither currently
  implemented in std nor in scribe.
- **FAT Mach-O**: universal binaries (FAT magic) return
  `error.UnsupportedClass`. Pre-extract a slice with `lipo -extract` for
  now.
- **Fingerprint robustness**: each entry carries both a raw Wyhash and a
  normalized Wyhash. The normalizer zeros the disp32 of E8/E9/0F8x
  branches and of RIP-relative ModR/M loads/stores/LEAs/indirect-calls
  before hashing, so the same source built with different relocation
  targets still matches. The pass is a pattern scan, not a full x86_64
  length decoder, so it can mis-fire on operand bytes that look like one
  of those opcodes — see Phase 3b-ext+.
- **Registry redirect bug**: Zig 0.16.0's `std.http.Client` accepts
  `privileged_headers` but never writes them to the wire. Scribe uses a
  manual redirect path that drops `Authorization` on cross-domain hops to
  bypass this — works for Docker Hub and most CDN-fronted registries.
- **macOS `docker save` cross-platform**: Docker Desktop on Apple Silicon
  cannot reliably `docker save` a `linux/amd64` image (manifest digest
  errors); use `scribe sbom registry://<image>:tag@linux/amd64` to fetch
  directly.

---

## Roadmap

Shipped: Phases 1 through 5e plus 3b-ext, 3c-ext, 4b, and 5e-ext
(full forensics + security pipeline + fingerprint-robustness
extensions + Mach-O `.dSYM` symbol enumeration + AST YAML for IaC +
mmap-spooled `docker save`). Open work:

| Phase   | Item                                                                                  |
| ------- | ------------------------------------------------------------------------------------- |
| 3b-ext+ | Relocation normalization is still a pattern scan (E8/E9 + cond-jump + RIP-relative ModR/M across a curated set of common opcodes), not a full length decoder. It will mis-fire when one of those opcode bytes happens to appear inside another instruction's operand. Replacing with a real disassembler-driven pass is the next step; the corpus JSON shape stays the same. |
| 3c-ext+ | The full `docker save` tar is now spooled to a tempfile and walked via mmap rather than copied through the heap (the previous 8 GiB RAM cap is gone). True single-pass streaming from a `Reader` would still be a refactor of `container.collect` itself, since manifest.json forward-references layer blobs that may appear later in the stream — the spool-and-mmap path delivers the same memory savings without that surgery. |
| 4b+     | Mach-O `.dSYM` symbol enumeration ships and the CLI auto-resolves `<bin>.dSYM/...`. Source-line lookup currently bails on `error.InvalidDebugInfo` for DWARF 5 line programs whose file-name forms reference `__debug_line_str`; this is in `std.debug.Dwarf`'s line-program decoder, not in scribe — once the upstream path lands, `addr2line` will start working with no scribe-side change. |
| 4c      | PE PDB parsing — scribe extracts the PDB GUID from the debug directory, but std.zig has no PDB parser. Multi-week port from the LLVM/MSF reverse-engineered docs. |
| 5e-ext+ | YAML parser is a deliberate 1.2 subset — no merge keys (`<<:`), no YAML 1.1 booleans (`yes`/`no`/`on`/`off`), no complex keys (`?`). Covers every k8s manifest shape we've audited; widening to full 1.2 is on the table if real users hit it. |
| 6       | Function-flow CFG construction, anti-tampering checks, yara-style rule integration — research direction; deeper static analysis as a foundation for `scribe-live` correlation. |

The `3b-ext+` / `3c-ext+` / `4b+` / `5e-ext+` rows are **partials** —
the core capability is shipped (RIP-relative-aware normalized hashes,
mmap-spooled `docker save`, Mach-O `.dSYM` symbol enumeration, AST YAML
walker covering anchors / aliases / flow / Helm) but the underlying
architectural item flagged above is the natural follow-on. `4b+` is
specifically blocked on a `std.debug.Dwarf` line-program bug, not on
scribe-side work. `4c` and `6` are genuinely future work — not
single-session deliverables.
