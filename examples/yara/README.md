# Example YARA rule packs

Two starter rule files compatible with scribe's YARA-subset engine
(`scribe yara` / `scribe scan --yara`):

| File                       | What it covers                                       |
| -------------------------- | ---------------------------------------------------- |
| `suspicious_imports.yar`   | Process-injection symbol clusters (Windows / Mac / Linux), JIT markers, UPX packer signature, shell-spawn patterns |
| `secrets_anchor.yar`       | Plain-prefix anchors for AWS / GitHub / Slack tokens and PEM blocks (cross-check with `scribe secrets`) |

```sh
scribe yara /usr/bin/some_binary --rules examples/yara/suspicious_imports.yar
scribe scan ./suspect.tar --yara examples/yara/secrets_anchor.yar --plain
```

## Engine subset

scribe parses a tractable subset of YARA syntax:

- `rule NAME [: tag ...] { meta: strings: condition: }`
- `$id = "literal" [ascii] [wide] [nocase] [fullword]`
- `$id = { AA BB ?? CC }` — bytes + single-byte wildcards
- `condition`: `$id`, `any of them`, `all of them`, `N of them`,
  `expr and expr`, `expr or expr`, `not expr`, `( expr )`,
  `true`, `false`
- Comments: `// line`, `/* block */`

Out of scope (parser returns `error.NotImplemented`):

- Jump ranges `[2-5]`
- Hex alternates `(AA | BB)`
- Regex strings `/pattern/`
- `for any/all of` loops
- `at`, `in`, `filesize`, `entrypoint`
- `import "module"`
- `$*` set references

If you need full YARA, run upstream YARA against the same target and
ingest its JSON output as a separate finding stream.
