# Scribe Security Pipeline

A Zig-native, daemon-free, no-Go-deps security scanner built on top of
Scribe's binary forensics primitives. Five integrated modules:

| Module                 | What it does                                                                              |
| ---------------------- | ----------------------------------------------------------------------------------------- |
| `security.secrets`     | SIMD-accelerated secret scanner: anchored patterns + UTF-16LE pass + opt-in entropy filter |
| `security.vulnerability` | CVE / advisory matcher with JSON (OSV-lite, OSV native) and binary mmap'd DBs             |
| `security.config`      | IaC misconfiguration audit for Dockerfiles, Kubernetes manifests, OCI image-config blobs   |
| `security.policy`      | Gatekeeper that evaluates SBOMs against JSON-defined fail conditions                       |
| `fingerprint` (cross-ref) | Bridges Wyhash function-byte fingerprints into the vuln matcher for stripped binaries  |

Output: every signal flows into a single CycloneDX 1.5 SBOM
(`components[]` + `properties[]` for secrets / IaC issues +
`vulnerabilities[]`). Same shape regardless of source (binary, container
tar, registry pull, local-docker pull).

---

## Table of Contents

- [Quick Start](#quick-start)
- [Subcommands](#subcommands)
  - [`scribe secrets`](#scribe-secrets)
  - [`scribe vulns`](#scribe-vulns)
  - [`scribe config`](#scribe-config)
  - [`scribe scan`](#scribe-scan-umbrella)
  - [`scribe policy`](#scribe-policy)
  - [`scribe vulndb compile / update`](#scribe-vulndb)
- [Populating the Advisory Database](#populating-the-advisory-database)
  - OSV.dev per-ecosystem zips (PyPI, npm, Go, …)
  - CISA KEV catalog
  - NVD, generic recipes, refresh cadence
- [Data Formats](#data-formats)
  - [SCVD binary advisory DB](#scvd-binary-advisory-db)
  - [Scribe OSV-lite JSON](#scribe-osv-lite-json)
  - [OSV.dev native JSON](#osvdev-native-json)
  - [Policy JSON](#policy-json)
  - [CycloneDX output extensions](#cyclonedx-output-extensions)
- [Rule Catalog](#rule-catalog)
  - [Dockerfile (`DKR###`)](#dockerfile-rules-dkr)
  - [Kubernetes (`K8S###`)](#kubernetes-rules-k8s)
  - [OCI image-config (`OCI###`)](#oci-image-config-rules-oci)
- [Secret Pattern Catalog](#secret-pattern-catalog)
- [Memory & Allocator Philosophy](#memory--allocator-philosophy)
- [Performance Notes](#performance-notes)
- [CI Integration Examples](#ci-integration-examples)
- [Caveats](#caveats)

---

## Quick Start

### Build

```bash
# Builds the binary into ./zig-out/bin/scribe.
zig build

# Optional: put it on PATH for the examples below.
export PATH="$PWD/zig-out/bin:$PATH"
# Or copy / symlink:
sudo cp zig-out/bin/scribe /usr/local/bin/
# Or change the install prefix (see `zig build --help`):
sudo zig build --prefix /usr/local install
```

`zig build install` writes to `./zig-out/bin/` by default — same place a
plain `zig build` puts it. There is no system-wide install target unless
you pass `--prefix`. If you don't add `zig-out/bin` to `PATH`, invoke the
binary directly: `./zig-out/bin/scribe ...`.

### Run

```bash
# Scan a binary for embedded secrets
scribe secrets ./myapp

# Scan a Dockerfile / Kubernetes manifest
scribe config ./Dockerfile
scribe config ./pod.yaml

# Match a binary against a CVE database
scribe vulns ./myapp --db osv-lite.json

# Run the full pipeline (SBOM + secrets + vulns + IaC + fingerprint cross-ref)
scribe scan ./myapp --db osv-lite.json --config ./Dockerfile --fp-db ./openssl-corpus.json

# Same against a container tar (auto-discovers embedded YAMLs / Dockerfiles)
scribe scan alpine.tar

# Direct OCI registry pull, no docker daemon required
scribe scan 'registry://alpine:3.19@linux/amd64' --db osv-lite.json

# CI gate — exits 1 on policy violation
scribe policy ./myapp --policy ci-policy.json --db osv.scvd

# Compile a JSON advisory DB to a compact mmap'd binary (~3-5x smaller)
scribe vulndb compile osv-lite.json osv.scvd

# Fetch + compile in one step over HTTPS
scribe vulndb update --from https://example.com/feed.json --out osv.scvd
```

> Examples above assume `scribe` resolves on `PATH`. If you skipped the
> PATH export above, prefix every invocation with `./zig-out/bin/`
> (e.g. `./zig-out/bin/scribe secrets ./myapp`).

---

## Subcommands

### `scribe secrets`

```
scribe secrets <path> [--json] [--include-generic] [--include-wide] [--min-entropy N]
```

SIMD anchor-byte search across the file's mmap'd bytes. Default catalog
covers AWS access/secret keys, GCP service-account markers, Slack tokens,
GitHub PATs (`ghp_/gho_/ghu_/ghs_/ghr_`), JWTs, and PEM private-key
headers (RSA / OPENSSH / EC / DSA / generic / encrypted).

Flags:

- `--json` — JSON array of findings instead of plain table.
- `--include-generic` — also emit high-entropy generic strings (≥ 20 chars,
  Shannon ≥ `--min-entropy`). Off by default — anchored patterns have far
  better signal/noise.
- `--include-wide` — also scan UTF-16LE encoded strings. Auto-enabled
  when target starts with `MZ` (PE binary) and `scribe scan` is used.
- `--min-entropy N` — Shannon threshold for the generic pass. Default 4.5.

Findings carry **only redacted previews** (`first4…last4 (len=N, H=E.EE)`).
Raw secret bytes never appear in CLI output, JSON output, or CycloneDX.

#### Plain output

```
aws_access_key          off=0x00000015  conf= 90  AKIA…MPLE (len=20, H=3.68)
github_pat              off=0x0000002a  conf= 90  ghp_…3xY5 (len=40, H=4.83)
slack_token             off=0x00000053  conf= 90  xoxb…mnop (len=33, H=4.72)
pem_private_key         off=0x000000a3  conf=100  ----…---- (len=113, H=4.66)
(4 findings)
```

### `scribe vulns`

```
scribe vulns <path> --db <p> [--json]
```

Builds an SBOM from the target binary, then matches each component
against the advisory database. `<p>` may be:

- A scribe OSV-lite JSON file
- An OSV.dev native JSON file (single object or array)
- A precompiled `.scvd` binary (zero-copy mmap loaded)

Database format is auto-detected (SCVD magic vs `"advisories"` key vs
OSV native).

```
CVE-2018-FAKE       glibc@2.28  [high] cvss=7.5 fixed=2.30
  synthetic glibc 2.28 issue
(1 vulnerabilities)
```

### `scribe config`

```
scribe config <path> [--type dockerfile|kubernetes] [--json]
```

Static analyzer for Infrastructure-as-Code text. Auto-detects via
basename (`Dockerfile`, `*.yaml`, `*.yml`) and content (first non-comment
`FROM` for Dockerfile, `apiVersion:` + `kind:` for Kubernetes).

```
DKR009  [high]  Pipe-to-shell network install  (Dockerfile:3)
        > RUN curl https://x.com/install.sh | sh
        fix: Download to a file, verify a checksum, then execute.
DKR001  [high]  No USER directive (defaults to root)  (Dockerfile)
        fix: Add a non-root USER directive before CMD/ENTRYPOINT.
(2 issues)
```

### `scribe scan` (umbrella)

```
scribe scan <path> [--db <p>] [--config <p>] [--fp-db <p>]
                   [--include-generic] [--include-wide] [--min-entropy N]
                   [--plain]
```

Runs the full pipeline. Detects the target type:

| Target              | Pipeline                                                          |
| ------------------- | ----------------------------------------------------------------- |
| ELF / Mach-O / PE   | `sbom.collect` → secrets scan → optional vuln + fp + config       |
| OCI tar             | `container.collect` (auto-discovers YAMLs / Dockerfiles +         |
|                     | image-config) → secrets scan → optional vuln + fp + config        |
| `MZ`-prefixed (PE)  | wide-string scan auto-enabled                                     |

Outputs unified CycloneDX 1.5 by default, or `--plain` for human review.

```bash
scribe scan ./myapp --db osv.scvd --config ./Dockerfile --fp-db ./openssl-corpus.json
```

### `scribe policy`

```
scribe policy <path> --policy <p> [--db <p>] [--config <p>]
                                  [--include-generic] [--json]
```

Runs the same pipeline as `scan`, then evaluates results against a JSON
policy. Exits **1** on any violation, **0** on pass. Designed for CI.

```bash
$ scribe policy ./myapp --policy ci.json --db osv.scvd; echo "exit=$?"
verdict: fail
violations:
  [vulnerability]   vulnerabilities.max_severity  -> CVE-2024-1234   (high)
  [config_issue]    config.max_severity           -> DKR001          (high)
  [component]       components.deny               -> openssl         (static_lib)
(3 violations)
exit=1
```

### `scribe vulndb`

```
scribe vulndb compile <in.json|-> <out.scvd>
scribe vulndb update  --from <url> --out <out.scvd>
```

`compile` accepts any DB shape `Database.load` can read (scribe OSV-lite,
OSV native single, OSV native array, even an existing `.scvd`) and emits
the compact mmap-friendly binary. Typical size: 3-5× smaller than JSON.
Pass `-` as the input path to read JSON from stdin (handy with
`curl | jq | scribe vulndb compile -`).

`update` does HTTPS GET via `std.http.Client`, parses the response as
above, and writes a `.scvd`. URL must serve advisory JSON in any
supported shape.

```bash
scribe vulndb compile osv-lite.json osv.scvd
scribe vulndb compile - osv.scvd <  ./osv-feed.json
scribe vulndb update --from https://example.com/advisories.json --out osv.scvd
```

> Zig 0.16's `std.http.Client` TLS implementation does not handle every
> server. If `update` errors with `TlsInitializationFailed`, the binary
> prints a `curl ... | scribe vulndb compile - ...` workaround. See
> [Populating the Advisory Database](#populating-the-advisory-database)
> below for ready-made recipes against OSV.dev's per-ecosystem feeds and
> the CISA KEV catalog.

---

## Populating the Advisory Database

scribe ships with **no built-in advisory data**. You bring your own. Three
common feeds, plus a generic stdin recipe:

### OSV.dev (per-ecosystem zips) — recommended

OSV.dev publishes one zip per ecosystem at:

```
https://osv-vulnerabilities.storage.googleapis.com/<ecosystem>/all.zip
```

Each zip contains thousands of `*.json` files, each a single OSV native
advisory. scribe's `parseOsv` handles the array form, so concatenate
with `jq -s '.'` before piping into `compile -`.

Common ecosystems (case-sensitive in the URL):

| Ecosystem      | URL                                                                            |
| -------------- | ------------------------------------------------------------------------------ |
| PyPI           | `https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip`              |
| npm            | `https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip`               |
| Go             | `https://osv-vulnerabilities.storage.googleapis.com/Go/all.zip`                |
| RubyGems       | `https://osv-vulnerabilities.storage.googleapis.com/RubyGems/all.zip`          |
| crates.io      | `https://osv-vulnerabilities.storage.googleapis.com/crates.io/all.zip`         |
| Maven          | `https://osv-vulnerabilities.storage.googleapis.com/Maven/all.zip`             |
| NuGet          | `https://osv-vulnerabilities.storage.googleapis.com/NuGet/all.zip`             |
| Packagist      | `https://osv-vulnerabilities.storage.googleapis.com/Packagist/all.zip`         |
| Hex            | `https://osv-vulnerabilities.storage.googleapis.com/Hex/all.zip`               |
| Pub            | `https://osv-vulnerabilities.storage.googleapis.com/Pub/all.zip`               |
| Debian         | `https://osv-vulnerabilities.storage.googleapis.com/Debian/all.zip`            |
| Ubuntu         | `https://osv-vulnerabilities.storage.googleapis.com/Ubuntu/all.zip`            |
| Alpine         | `https://osv-vulnerabilities.storage.googleapis.com/Alpine/all.zip`            |
| Rocky Linux    | `https://osv-vulnerabilities.storage.googleapis.com/Rocky%20Linux/all.zip`     |
| GitHub Actions | `https://osv-vulnerabilities.storage.googleapis.com/GitHub%20Actions/all.zip`  |

Canonical ecosystem list at <https://osv.dev/data>. URLs containing
spaces (`Rocky Linux`, `GitHub Actions`) must be percent-encoded.

GHSA covers PyPI / npm / Go / RubyGems / crates.io / Maven / NuGet /
Packagist / Pub / Hex / Erlang / Swift / GitHub Actions ecosystems —
there is no single "GHSA bulk" URL; pick by language ecosystem.

#### Single ecosystem

```bash
mkdir -p osv-pypi && cd osv-pypi
curl -sSL "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip" -o all.zip
unzip -q all.zip
jq -s '.' *.json | scribe vulndb compile - ../osv-pypi.scvd
cd .. && rm -rf osv-pypi
```

Rough sizes:

| Ecosystem | Zip download | SCVD output | Advisory count (approx) |
| --------- | ------------:| -----------:| -----------------------:|
| Go        |       ~5 MB  |      ~2 MB  |              1 000      |
| PyPI      |     ~20 MB   |      ~7 MB  |              7 000      |
| npm       |     ~30 MB   |     ~10 MB  |             14 000      |
| Debian    |     ~50 MB   |     ~20 MB  |             40 000      |

#### Multiple ecosystems combined

scribe doesn't yet have a `vulndb merge`, but `parseOsv` accepts arrays,
so concatenate the JSON before piping:

```bash
mkdir -p osv-all
for eco in PyPI npm Go RubyGems crates.io Maven; do
  curl -sSL "https://osv-vulnerabilities.storage.googleapis.com/$eco/all.zip" \
    -o "osv-all/$eco.zip"
  unzip -q "osv-all/$eco.zip" -d "osv-all/$eco"
done
jq -s '.' osv-all/*/*.json | scribe vulndb compile - osv-all.scvd
rm -rf osv-all
```

Combined SCVD: ~50-100 MB depending on ecosystem coverage. One mmap'd
load matches against any binary regardless of language.

> **Memory tip.** `jq -s '.' *.json` keeps the full array in RAM. For
> Debian / Ubuntu (40k+ records) plan for 200-500 MB peak. If RAM-tight,
> chunk the input or shard the SCVDs and run `scribe vulns` against each.

### CISA KEV catalog

The CISA Known Exploited Vulnerabilities feed uses its own shape — neither
scribe OSV-lite nor OSV native. Convert with `jq` first:

```bash
curl -sSL "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" \
  | jq '{
      version: 1,
      advisories: [.vulnerabilities[] | {
        id: .cveID,
        summary: .vulnerabilityName,
        severity: "high",
        package: (.product | ascii_downcase),
        ranges: [],
        references: ["https://nvd.nist.gov/vuln/detail/\(.cveID)"]
      }]
    }' \
  | scribe vulndb compile - cisa-kev.scvd
```

KEV doesn't track version ranges — every CVE matches the named product
across all versions (empty `ranges`). KEV severity is implicit ("actively
exploited") so we map everything to `high`. Pair KEV with OSV.dev for
breadth — scribe matches against the first DB it's pointed at, so keep
them as separate `.scvd` files and call `scribe vulns` once per DB.

### NVD (CVE JSON 2.0)

NVD publishes per-year JSON archives at
`https://nvd.nist.gov/vuln/data-feeds`. The schema is verbose; the
shortest path to scribe is to convert NVD CVE Items to OSV-lite via `jq`,
treating each `cve.id` as the advisory id, `descriptions[].value` as
summary, and `cpeMatch` entries as ranges. Recipe is fiddly enough to
warrant a dedicated tool — out of scope here. If you only need critical
exploited CVEs, use CISA KEV instead.

### Generic recipe — anything that emits JSON

Anything you can `curl` and shape with `jq` to scribe OSV-lite or OSV
native works:

```bash
curl -sSL <url> | jq '<transform>' | scribe vulndb compile - out.scvd
```

scribe's `parseJson` (OSV-lite) accepts the simplest shape:

```json
{
  "version": 1,
  "advisories": [
    { "id": "...", "summary": "...", "severity": "high",
      "package": "openssl",
      "ranges": [{"introduced": "0", "fixed": "3.0.8"}],
      "references": ["https://..."] }
  ]
}
```

If your transform produces this, you're done. Match-time package
normalization (alias map: `libcrypto.so.3` → `openssl`, `libc.musl-*` →
`musl`, etc.) is automatic — emit canonical package names in the DB.

### Refresh cadence

- **OSV.dev / GHSA:** updated continuously. Daily `cron` rebuild is fine
  for CI; weekly for personal use. Drop the rebuild script in a Makefile
  target.
- **CISA KEV:** updated weekly. Refresh the `.scvd` weekly to catch
  newly-exploited CVEs.
- **NVD:** the JSON 2.0 modified feed updates every 2 hours, but most
  scribe users won't need to re-pull that often.

A typical CI pipeline pulls + compiles in <30 s for PyPI+npm+Go combined
(~30 MB total download).

---

## Data Formats

### SCVD binary advisory DB

Compact little-endian binary format. Strings inside the file are referenced
by length-prefixed offsets; `parseBinary` returns `Advisory` records whose
`[]const u8` slices point directly into the input (zero-copy mmap path).

```
Header (16 bytes, little-endian):
  magic           : [4]u8 = "SCVD"
  version         : u32   = 1
  advisory_count  : u32
  reserved        : u32   = 0

Per advisory (variable length, walked sequentially):
  id_len          : u16
  summary_len     : u32
  package_len     : u16
  severity        : u8     ; @intFromEnum(Severity): 0=none .. 4=critical
  cvss_enc        : u32    ; 0 = no cvss; else (cvss * 100) + 1
  range_count     : u8
  ref_count       : u16
  id_bytes        : [id_len]u8
  summary_bytes   : [summary_len]u8
  package_bytes   : [package_len]u8        ; pre-lowercased for binary search
  ranges          : [range_count] {
                       intro_len : u16     ; 0xFFFF sentinel = null (whole package)
                       fixed_len : u16     ; 0xFFFF sentinel = null (no fix yet)
                       intro_bytes  (if intro_len != 0xFFFF)
                       fixed_bytes  (if fixed_len != 0xFFFF)
                    }
  references      : [ref_count] { ref_len : u16; ref_bytes }
```

`writeBinary` sorts advisories by lowercase package name before emitting,
so `parseBinary` produces a database ready for binary-search lookup
in `match`. The sort is stable.

### Scribe OSV-lite JSON

```json
{
  "version": 1,
  "advisories": [
    {
      "id": "CVE-2023-0286",
      "summary": "OpenSSL X.400 type confusion",
      "severity": "high",
      "cvss": 7.4,
      "package": "openssl",
      "ranges": [
        {"introduced": "3.0.0", "fixed": "3.0.8"},
        {"introduced": "1.1.1", "fixed": "1.1.1t"}
      ],
      "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-0286"]
    }
  ]
}
```

Field semantics:

- `package` — lowercase advisory package name. Match is case-insensitive.
- `ranges[]` — half-open `[introduced, fixed)`. Either bound may be absent.
- `severity` — one of `none|low|medium|high|critical|moderate` (moderate
  aliases to medium).
- `cvss` — optional f32, 0–10. When omitted, severity comes from the
  string field.
- `references` — optional array of URLs.

`ranges` may be empty, meaning the advisory affects all versions of the
package.

### OSV.dev native JSON

scribe also accepts the raw OSV-schema shape (https://ossf.github.io/osv-schema/):

```json
{
  "id": "GHSA-xxxx-xxxx-xxxx",
  "summary": "django path traversal",
  "details": "long-form text",
  "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
  "affected": [{
    "package": {"name": "Django", "ecosystem": "PyPI"},
    "ranges": [{
      "type": "ECOSYSTEM",
      "events": [{"introduced": "0"}, {"fixed": "3.2.13"}]
    }]
  }],
  "references": [{"type": "ADVISORY", "url": "https://github.com/advisories/GHSA-xxxx-xxxx-xxxx"}],
  "database_specific": {"severity": "HIGH"}
}
```

scribe flattens each `affected[].package` into one Advisory record. Severity
prefers `database_specific.severity` (used by GHSA), falls back to a CVSS
v3 vector parsed via `parseCvssVector` and mapped through standard NVD
qualitative bands (`0.1-3.9` low, `4-6.9` medium, `7-8.9` high, `9-10`
critical). CVSS v2 vectors are ignored — scribe v1 covers v3.0/v3.1 only.

Both single-object and array-of-objects forms are accepted.

`Database.load` auto-routes:

- SCVD magic → `parseBinary`
- substring `"advisories"` → `parseJson` (scribe OSV-lite)
- otherwise → `parseOsv` (OSV native)

### Policy JSON

```json
{
  "version": 1,
  "vulnerabilities": {
    "max_severity": "high",
    "deny": ["CVE-2024-1234", "GHSA-xxxx-xxxx-xxxx"]
  },
  "secrets": {
    "fail_on_any": false,
    "fail_on_kinds": ["aws_access_key", "pem_private_key", "github_pat"]
  },
  "config": {
    "max_severity": "high",
    "deny": ["DKR001", "DKR004", "K8S006"]
  },
  "components": {
    "deny": ["openssl", "log4j"]
  }
}
```

- `max_severity` — fail when any matched item's severity rank ≥ this rank.
  Vuln severity order: `none < low < medium < high < critical`.
  Config severity order: `info < low < medium < high < critical`.
- `deny` — fail when any matched item's id / rule_id / package contains
  this string (substring match for components; exact match for advisory
  IDs and config rule IDs).
- `fail_on_any` — fail the build if any secret of any kind is detected.
  `fail_on_kinds` is OR'd in: at least one of the kinds triggers.

All four sections are optional; an empty policy passes everything.

### CycloneDX output extensions

All scribe output is CycloneDX 1.5-conformant. scribe-specific extensions
ride in `properties[]` and `vulnerabilities[]`:

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "components": [
    {"type": "library", "name": "openssl", "version": "3.0.7", "evidence": {...}}
  ],
  "properties": [
    {"name": "scribe:secret:aws_access_key", "value": "AKIA…MPLE (len=20, H=3.68)",
     "confidence": 90, "offset": 21},
    {"name": "scribe:config:dockerfile:DKR001", "value": "USER root (or UID 0)",
     "severity": "high", "file": "Dockerfile", "line": 5,
     "recommendation": "Switch to a non-root user."}
  ],
  "vulnerabilities": [
    {"id": "CVE-2023-0286", "description": "...",
     "ratings": [{"severity": "high", "score": 7.4, "method": "CVSSv3"}],
     "affects": [{"ref": "openssl@3.0.7"}],
     "advisories": [{"url": "https://nvd.nist.gov/..."}]}
  ]
}
```

Property name conventions:

- `scribe:secret:<kind>` — secret findings (kind ∈ `aws_access_key`,
  `aws_secret_key`, `gcp_service_account`, `slack_token`, `github_pat`,
  `jwt`, `pem_private_key`, `generic_high_entropy`)
- `scribe:config:<source>:<rule_id>` — IaC misconfigurations
  (source ∈ `dockerfile`, `kubernetes`, `image_config`)

---

## Rule Catalog

### Dockerfile rules (`DKR`)

| ID      | Severity | Title                                                           |
| ------- | -------- | --------------------------------------------------------------- |
| DKR001  | high     | USER root (or UID 0) / no USER directive (defaults to root)     |
| DKR002  | medium   | ADD with remote URL                                             |
| DKR003  | low      | FROM uses :latest tag or no tag (defaults to :latest)           |
| DKR004  | critical | RUN with --privileged                                           |
| DKR005  | high     | Secret-like value in ENV (matches `password`/`secret`/`token`/`key`) |
| DKR006  | info     | Missing HEALTHCHECK                                             |
| DKR007  | info     | apt-get install without `--no-install-recommends`               |
| DKR008  | high     | World-writable chmod (777 or `chmod -R 777`)                    |
| DKR009  | high     | Pipe-to-shell network install (`curl ... \| sh` / `wget ... \| bash`) |

### Kubernetes rules (`K8S`)

| ID      | Severity | Title                                                          |
| ------- | -------- | -------------------------------------------------------------- |
| K8S001  | high     | `runAsNonRoot: false`                                          |
| K8S002  | medium   | Workload missing `securityContext` block                       |
| K8S003  | high     | `runAsUser: 0` (root)                                          |
| K8S004  | critical | `hostNetwork: true`                                            |
| K8S005  | critical | `hostPID: true`                                                |
| K8S006  | critical | `privileged: true`                                             |
| K8S007  | critical | `capabilities.add` includes `SYS_ADMIN`                        |
| K8S008  | low      | Workload missing `resources.limits` / `requests`               |
| K8S009  | medium   | `automountServiceAccountToken: true` (default)                 |
| K8S010  | low      | `image:` uses `:latest` tag (or no tag)                        |
| K8S011  | high     | `allowPrivilegeEscalation: true`                               |

Multi-document YAML (`---` separators) is supported. Workload kinds
(`Pod`, `Deployment`, `StatefulSet`, `DaemonSet`, `Job`, `CronJob`,
`ReplicaSet`) drive the "missing securityContext / resources" gates;
`ConfigMap`/`Secret`/`Service`/etc. don't trigger them.

### OCI image-config rules (`OCI`)

| ID      | Severity | Title                                                          |
| ------- | -------- | -------------------------------------------------------------- |
| OCI001  | high     | image config USER missing / `root` / UID 0                     |
| OCI002  | high     | image config Env contains a secret-like value                  |
| OCI003  | info     | image has no HEALTHCHECK (or set to `NONE`)                    |
| OCI004  | medium   | image exposes SSH port (22)                                    |

OCI rules see the **effective runtime state** of the image (post
multi-stage build, post FROM inheritance) — they catch problems
Dockerfile-text rules can miss when the offending state comes from a
base image.

---

## Secret Pattern Catalog

| Kind                    | Anchor / Trigger                                | Validator                         | Confidence |
| ----------------------- | ----------------------------------------------- | --------------------------------- | ---------- |
| `aws_access_key`        | `AKIA` / `ASIA` prefix                          | 20 chars `[A-Z0-9]`               | high (90)  |
| `aws_secret_key`        | nearby `aws_secret_access_key` literal          | 40 chars `[A-Za-z0-9/+=]` + entropy ≥ 4.0 | medium (60) |
| `gcp_service_account`   | `type": "service_account"` literal              | exact                             | medium (60) |
| `slack_token`           | `xoxb-` / `xoxa-` / `xoxp-` / `xoxr-` / `xoxs-` prefix | hyphen-segmented `[A-Za-z0-9-]{20,}`, ≥ 2 hyphens | high (90) |
| `github_pat`            | `ghp_` / `gho_` / `ghu_` / `ghs_` / `ghr_` prefix | 36 chars base62                  | high (90)  |
| `jwt`                   | `eyJ` prefix                                    | base64url`.`base64url`.`base64url, length ≥ 30 | medium (60) |
| `pem_private_key`       | `-----BEGIN ` prefix                            | recognized label + matching `-----END ` | certain (100) |
| `generic_high_entropy`  | strings.scan-derived runs ≥ 20 chars            | Shannon ≥ `min_entropy`           | low (30)   |

The byte-aligned anchor scan uses `@Vector(N, u8)` to broadcast each
anchor byte across the lane and bitmask via `@bitCast(eq)`; `@ctz` walks
set lanes. UTF-16LE pass extracts the ASCII byte stream from runs where
even-indexed bytes are printable and odd-indexed bytes are 0x00, then
runs the same pattern catalog over the recovered string.

After matching, an overlap dedup pass removes `generic_high_entropy`
findings that intersect a stronger finding (PEM-block contents would
otherwise re-fire as generic).

---

## Memory & Allocator Philosophy

scribe core is **no-globals + allocator-threaded**. The security pipeline
preserves that invariant.

- Every public function takes an `std.mem.Allocator`. No module-level
  state, no thread-local caches.
- `Database.mode = {owned, borrowed}` lets binary-mmap'd advisories share
  string memory with the input buffer; JSON-loaded DBs allocate copies.
  `deinit` dispatches on `mode`.
- Findings (`Finding`, `Vulnerability`, `Issue`, `Violation`) own all of
  their string content and free it explicitly via per-type `freeXxx`
  helpers driven by a parent collection's `deinit(allocator)`.
- Redacted previews are **always** owned heap-allocated strings — they
  must outlive the input mmap (preview text is metadata, not raw bytes).
- The CLI uses `std.heap.GeneralPurposeAllocator` (gpa) for persistent
  state and `std.heap.ArenaAllocator` for argv / temporary work, mirroring
  scribe's existing convention.

Test suite runs every test under `std.testing.allocator` (leak-detecting
gpa). 120 tests, no leaks, ASAN-clean.

---

## Performance Notes

| Operation                            | Algorithm                                                  | Cost                              |
| ------------------------------------ | ---------------------------------------------------------- | --------------------------------- |
| Secret anchor scan                   | `@Vector(N, u8)` broadcast cmp → bitmask → `@ctz` walk      | O(file_size), single pass         |
| Generic entropy filter               | reuses `strings.scan` SIMD iterator + `entropy.shannon`     | O(printable_runs) post-anchor      |
| Wide-string scan                     | scalar walk + scratch buffer + anchor reuse                 | O(file_size) (ASCII-aligned)      |
| SCVD parse                           | sequential record walk, slices into mmap                    | O(advisory_count), zero-copy      |
| Vulnerability match                  | binary search on sorted package + linear walk of equals     | O(C × log A) per scan             |
| IaC YAML scan                        | per-doc text patterns, no full YAML parse                   | O(file_size × rule_count)          |
| Container squash                     | tar walk + whiteout map + per-binary mmap reuse             | O(layer_bytes), single-pass        |

Empirical measurements (M2 MacBook, scribe at `-Drelease`, run from cold
cache; figures are illustrative — re-measure on your hardware):

- `scribe secrets` on a 50 MB binary: ~120 MB/s anchored scan; +50% for
  `--include-generic`; +30% for `--include-wide` on PE.
- `scribe vulndb compile` from a 10k-advisory OSV feed: ~80 ms total.
- `scribe vulns` against a 10k-advisory `.scvd`: ~5 ms (mmap load + 30
  binary searches against the sorted package index).
- `scribe scan alpine.tar` with full pipeline: dominated by gzip
  decompression of layer blobs (~200 MB/s on M2); secret scan adds <5%.

---

## CI Integration Examples

### GitHub Actions

```yaml
name: security-gate
on: [pull_request]

jobs:
  scribe:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: mlugg/setup-zig@v1
        with: { version: '0.16.0' }
      - run: zig build
      - run: echo "$PWD/zig-out/bin" >> "$GITHUB_PATH"
      - name: Refresh advisory DB
        run: scribe vulndb update --from ${{ secrets.OSV_FEED_URL }} --out osv.scvd
      - name: Build target
        run: cargo build --release
      - name: Policy gate
        run: |
          scribe policy ./target/release/myapp \
            --policy .scribe/policy.json \
            --db osv.scvd \
            --config Dockerfile
```

### Pre-commit / local hook

```bash
#!/usr/bin/env bash
set -euo pipefail

# Fail on any high-severity finding before committing.
scribe policy ./build/myapp --policy .scribe/policy.json --db ~/.cache/scribe/osv.scvd
```

### Batch container audit

```bash
for img in $(cat images.txt); do
  echo "=== $img ==="
  scribe scan "registry://$img" --db osv.scvd | jq '.vulnerabilities | length'
done
```

### Producing the corpus for fingerprint-based detection

```bash
# One-time: build a fingerprint corpus from the libraries you care about.
scribe fp generate /usr/lib/libssl.so.3 openssl 3.2.0 > openssl-3.2.0.fp.json
scribe fp generate /usr/lib/libcrypto.so.3 openssl 3.2.0 >> /tmp/tmp.fp.json
# Concat / dedupe by hash, then use in scan:
scribe scan ./stripped-binary --db osv.scvd --fp-db openssl-corpus.json
```

---

## Terminal Output

scribe's plain-mode emitters auto-detect whether stdout is a terminal and
apply tasteful ANSI styling on TTYs. Behavior:

- **TTY** (interactive shell): bold section headers, severity-colored
  badges (`critical` red+bold on white, `high` red, `medium` yellow,
  `low` cyan, `info` dim gray), bold rule IDs, dim labels, green/red
  count totals, `✓`/`✗` glyphs on policy verdicts.
- **Piped** (`scribe ... | jq`, `> file`, CI logs): color disabled
  automatically. Output is plain ASCII so downstream tools (grep, awk,
  diff) work cleanly.
- **`NO_COLOR=1`** environment variable: color disabled even on a TTY.
  Honors the [no-color.org](https://no-color.org/) convention.

CycloneDX (`scribe scan`) and `--json` outputs are **always** machine-
readable — color is applied only to the human plain-mode tables and the
`scribe policy` verdict block.

Severity color map:

| Severity        | ANSI                                  |
| --------------- | ------------------------------------- |
| `critical`      | bold red on white background          |
| `high`          | red                                   |
| `medium` / `moderate` | yellow                          |
| `low`           | cyan                                  |
| `info`          | gray                                  |
| `none`          | dim                                   |

---

## Caveats

- **Linear vuln-DB load cost on large feeds.** `parseJson` + `parseOsv`
  copy every string. Compile to `.scvd` once; reuse mmap'd. JSON path is
  fine up to ~10k advisories on first load (~100 ms).
- **Binary search assumes sorted package field.** `Database.parseJson`
  and `parseBinary` always sort by lowercase package before returning;
  if you build a `Database` by hand, call `sortByPackage` (private) or
  go through one of the loaders.
- **OSV `last_affected` semantics.** OSV's `last_affected` is inclusive;
  scribe ranges are half-open. Versions exactly equal to `last_affected`
  won't match. v1 trade-off — affects perhaps 1% of advisories that use
  the inclusive form instead of `fixed`.
- **CVSS v2 unsupported.** `parseCvssVector` returns null on v2 vectors.
  Affected advisories will lack a `cvss` field but still match by
  `severity` (text).
- **Fingerprint cross-ref needs DWARF on target.** The Wyhash signature
  scheme keys on DWARF function ranges. Stripped targets without symbols
  can't be matched today; the fingerprint module (Phase-3b-ext on the
  scribe roadmap) will gain sliding-window detection for that.
- **Wide-string scan is ASCII-aligned only.** Recovers wide strings whose
  even bytes are ASCII printable; doesn't decode actual UTF-16 surrogate
  pairs or BMP characters above 0x7E. Adequate for secret detection.
- **YAML scanner is text-pattern based.** No anchor / alias / Helm
  template expansion. Full YAML parsing is on the roadmap; text scan
  catches the vast majority of misconfigurations encountered in
  CI-checked manifests.
- **Network behavior of `vulndb update`.** Uses Zig 0.16's
  `std.http.Client`. TLS cert verification is enabled by default; redirect
  handling is the std default. For self-signed feeds, mirror the JSON
  locally and use `vulndb compile`.
- **Policy result is not part of CycloneDX output.** Verdict + violations
  are CLI-only (plain or `--json`). CycloneDX ships the SBOM data; whether
  it passes a policy is a consumer-side determination.

---

## See Also

- [README.md](README.md) — base scribe (binary forensics, SBOM, registry/docker pulls).
- Module-level docs (`//!` headers in each `src/security/*.zig` file).
- Inline tests (`zig build test`) — 120 tests covering every module.
