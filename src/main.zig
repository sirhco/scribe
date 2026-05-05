const std = @import("std");
const Io = std.Io;

const scribe = @import("scribe");
const ui = @import("ui.zig");

const scribe_version = "0.2.0";

const usage =
    \\scribe — binary forensics
    \\
    \\Usage:
    \\  scribe info <path> [opts]      format, arch, entry, sections, hardening ([--json] [--all-slices] [--hashes])
    \\  scribe harden <path> [--json]  exploit-mitigation report (PIE/NX/RELRO/CFG/...)
    \\  scribe yara <path> --rules <p> match a YARA-subset rule file ([--json])
    \\  scribe deps <path> [--json]    dynamic library dependencies
    \\  scribe strings <path> [min]    printable ASCII runs (default min=4) [--json]
    \\  scribe entropy <path> [--json] Shannon entropy per section
    \\  scribe hex <path> [opts]       hex + ASCII dump ([--offset 0x..] [--length N] [--section name])
    \\  scribe exports <path> [--json] dynamically-exported symbols
    \\  scribe diff <a> <b> [--json]   structural diff: arch, sections, deps, hardening
    \\  scribe imports <path> [--json] dynamically-imported symbols
    \\  scribe wasm <path> [--json]    list WebAssembly module sections
    \\  scribe ar list <path> [--json] list members of a static archive (.a / .lib)
    \\  scribe sbom <path> [--plain]   bill of materials (CycloneDX 1.5 by default; --plain for human)
    \\  scribe secrets <path> [opts]   SIMD secret scan ([--json] [--include-generic] [--include-wide] [--min-entropy N])
    \\  scribe vulns <path> --db <p>   match SBOM components against advisory DB ([--json])
    \\  scribe config <path> [opts]    audit Dockerfile / k8s manifest ([--type dockerfile|kubernetes] [--json])
    \\  scribe scan <path> [opts]      full pipeline: SBOM + secrets + vulns + IaC + fingerprint + hardening + anomalies
    \\                                 ([--db p] [--config p] [--fp-db p] [--yara p] [--include-generic] [--include-wide] [--plain] [--sarif] [--github-annotations])
    \\  scribe policy <path> --policy <p>  evaluate scan results against policy ([--db d] [--config c] [--json]); exits 1 on fail
    \\  scribe vulndb compile <in.json|-> <out.scvd>    compile JSON advisory DB to mmap-friendly binary (.scvd)
    \\  scribe vulndb merge <out.scvd> <in1> [in2...]   merge multiple .scvd or JSON advisory DBs into one
    \\  scribe vulndb update --from <url> --out <p>     fetch advisory JSON over HTTPS, compile to .scvd
    \\  scribe symbols <path>          DWARF function symbols (ELF or Mach-O dSYM)
    \\  scribe addr2line <path> <hex>  resolve address to source location
    \\  scribe fp generate <path> <lib> [version]    write fingerprint DB to stdout (JSON)
    \\  scribe fp match <path> <db.json>             match fns in <path> against DB
    \\  scribe ui <source> [opts]      interactive scan-results browser (TUI)
    \\                                 ([--db p] [--config p] [--fp-db p] [--include-generic] [--include-wide])
    \\
    \\Sources for `sbom`:
    \\  - local file path                                       (binary or docker save tar)
    \\  - docker://image[:tag]                                  (local docker daemon, spawns `docker save`)
    \\  - registry://[host/]name:tag[@os/arch]                  (HTTPS pull, no daemon)
    \\
;

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const gpa = init.gpa;
    const io = init.io;

    var stderr_buf: [1024]u8 = undefined;
    var stderr_fw: Io.File.Writer = .init(.stderr(), io, &stderr_buf);
    const stderr = &stderr_fw.interface;

    var stdout_buf: [4096]u8 = undefined;
    var stdout_fw: Io.File.Writer = .init(.stdout(), io, &stdout_buf);
    const stdout = &stdout_fw.interface;
    defer stdout.flush() catch {};

    // TTY-aware ANSI styling. Off when piped, off when NO_COLOR is set.
    var style = scribe.term.Style.auto(io, init.minimal.environ);

    // Inline progress reporter for long-running ops. No-op when stderr
    // is not a TTY, so piped/scripted invocations stay byte-identical.
    var prog = scribe.progress.Reporter.init(io, init.minimal.environ);
    defer prog.deinit();

    const raw_args = try init.minimal.args.toSlice(arena);

    // Top-level --quiet / --no-color filtering. These flags are positional-
    // independent: any occurrence (before or after the subcommand) tweaks
    // global output behavior and gets stripped from the dispatch slice.
    var force_no_color = false;
    var force_quiet = false;
    var filtered = std.ArrayList([]const u8).empty;
    defer filtered.deinit(arena);
    for (raw_args) |a| {
        if (std.mem.eql(u8, a, "--no-color") or std.mem.eql(u8, a, "--no-colour")) {
            force_no_color = true;
            continue;
        }
        if (std.mem.eql(u8, a, "--quiet") or std.mem.eql(u8, a, "-q")) {
            force_quiet = true;
            continue;
        }
        filtered.append(arena, a) catch {};
    }
    if (force_no_color) style.enabled = false;
    if (force_quiet) prog = scribe.progress.Reporter.off();

    const args = filtered.items;
    if (args.len < 2) return die(stderr, usage, 1);

    const cmd = args[1];
    if (std.mem.eql(u8, cmd, "--version") or std.mem.eql(u8, cmd, "-V") or std.mem.eql(u8, cmd, "version")) {
        try stdout.print("scribe {s}\n", .{scribe_version});
        return;
    }
    if (std.mem.eql(u8, cmd, "--help") or std.mem.eql(u8, cmd, "-h") or std.mem.eql(u8, cmd, "help")) {
        try stdout.writeAll(usage);
        return;
    }
    if (std.mem.eql(u8, cmd, "completion")) {
        if (args.len < 3) return die(stderr, "error: 'completion' requires shell name (bash|zsh|fish)\n", 1);
        try emitCompletion(stdout, args[2]);
        return;
    }
    if (std.mem.eql(u8, cmd, "info")) {
        if (args.len < 3) return die(stderr, "error: 'info' requires a path\n", 1);
        var json = false;
        var all_slices = false;
        var hashes = false;
        for (args[3..]) |a| {
            if (std.mem.eql(u8, a, "--json")) json = true;
            if (std.mem.eql(u8, a, "--all-slices")) all_slices = true;
            if (std.mem.eql(u8, a, "--hashes")) hashes = true;
        }
        runInfo(io, gpa, stdout, args[2], json, all_slices, hashes, style) catch |err| return dieErr(stderr, err);
        return;
    }
    if (std.mem.eql(u8, cmd, "harden")) {
        if (args.len < 3) return die(stderr, "error: 'harden' requires a path\n", 1);
        var json = false;
        for (args[3..]) |a| {
            if (std.mem.eql(u8, a, "--json")) json = true;
        }
        runHarden(io, gpa, stdout, args[2], json, style) catch |err| return dieErr(stderr, err);
        return;
    }
    if (std.mem.eql(u8, cmd, "hex")) {
        if (args.len < 3) return die(stderr, "error: 'hex' requires a path\n", 1);
        var off_opt: ?u64 = null;
        var len_opt: ?usize = null;
        var section: ?[]const u8 = null;
        var idx: usize = 3;
        while (idx < args.len) : (idx += 1) {
            const a = args[idx];
            if (std.mem.eql(u8, a, "--offset")) {
                if (idx + 1 >= args.len) return die(stderr, "error: --offset requires a value\n", 1);
                idx += 1;
                off_opt = std.fmt.parseInt(u64, stripHexPrefix(args[idx]), 16) catch
                    std.fmt.parseInt(u64, args[idx], 10) catch return die(stderr, "error: invalid --offset\n", 1);
            } else if (std.mem.eql(u8, a, "--length")) {
                if (idx + 1 >= args.len) return die(stderr, "error: --length requires a value\n", 1);
                idx += 1;
                len_opt = std.fmt.parseInt(usize, args[idx], 10) catch return die(stderr, "error: invalid --length\n", 1);
            } else if (std.mem.eql(u8, a, "--section")) {
                if (idx + 1 >= args.len) return die(stderr, "error: --section requires a name\n", 1);
                idx += 1;
                section = args[idx];
            } else {
                return die(stderr, "error: unknown 'hex' option\n", 1);
            }
        }
        runHex(io, gpa, stdout, args[2], off_opt, len_opt, section) catch |err| return dieErr(stderr, err);
        return;
    }
    if (std.mem.eql(u8, cmd, "exports")) {
        if (args.len < 3) return die(stderr, "error: 'exports' requires a path\n", 1);
        var json = false;
        for (args[3..]) |a| if (std.mem.eql(u8, a, "--json")) { json = true; };
        runExports(io, gpa, stdout, args[2], json) catch |err| return dieErr(stderr, err);
        return;
    }
    if (std.mem.eql(u8, cmd, "imports")) {
        if (args.len < 3) return die(stderr, "error: 'imports' requires a path\n", 1);
        var json = false;
        for (args[3..]) |a| if (std.mem.eql(u8, a, "--json")) { json = true; };
        runImports(io, gpa, stdout, args[2], json) catch |err| return dieErr(stderr, err);
        return;
    }
    if (std.mem.eql(u8, cmd, "wasm")) {
        if (args.len < 3) return die(stderr, "error: 'wasm' requires a path\n", 1);
        var json = false;
        for (args[3..]) |a| if (std.mem.eql(u8, a, "--json")) { json = true; };
        runWasm(io, gpa, stdout, args[2], json) catch |err| return dieErr(stderr, err);
        return;
    }
    if (std.mem.eql(u8, cmd, "ar")) {
        if (args.len < 4 or !std.mem.eql(u8, args[2], "list"))
            return die(stderr, "error: 'ar list <path>'\n", 1);
        var json = false;
        for (args[4..]) |a| if (std.mem.eql(u8, a, "--json")) { json = true; };
        runArList(io, gpa, stdout, args[3], json) catch |err| return dieErr(stderr, err);
        return;
    }
    if (std.mem.eql(u8, cmd, "diff")) {
        if (args.len < 4) return die(stderr, "error: 'diff' requires two paths\n", 1);
        var json = false;
        for (args[4..]) |a| if (std.mem.eql(u8, a, "--json")) { json = true; };
        runDiff(io, gpa, stdout, args[2], args[3], json, style) catch |err| return dieErr(stderr, err);
        return;
    }
    if (std.mem.eql(u8, cmd, "yara")) {
        if (args.len < 3) return die(stderr, "error: 'yara' requires a path\n", 1);
        var json = false;
        var rules_path: ?[]const u8 = null;
        var idx: usize = 3;
        while (idx < args.len) : (idx += 1) {
            const a = args[idx];
            if (std.mem.eql(u8, a, "--json")) {
                json = true;
            } else if (std.mem.eql(u8, a, "--rules")) {
                if (idx + 1 >= args.len) return die(stderr, "error: --rules requires a path\n", 1);
                idx += 1;
                rules_path = args[idx];
            } else {
                return die(stderr, "error: unknown 'yara' option\n", 1);
            }
        }
        const rp = rules_path orelse return die(stderr, "error: 'yara' requires --rules <path>\n", 1);
        runYara(io, gpa, stdout, args[2], rp, json, style) catch |err| return dieErr(stderr, err);
        return;
    }
    if (std.mem.eql(u8, cmd, "deps")) {
        if (args.len < 3) return die(stderr, "error: 'deps' requires a path\n", 1);
        var json = false;
        for (args[3..]) |a| if (std.mem.eql(u8, a, "--json")) { json = true; };
        runDeps(io, gpa, stdout, args[2], json) catch |err| return dieErr(stderr, err);
        return;
    }
    if (std.mem.eql(u8, cmd, "strings")) {
        if (args.len < 3) return die(stderr, "error: 'strings' requires a path\n", 1);
        var json = false;
        var min: usize = 4;
        var idx: usize = 3;
        while (idx < args.len) : (idx += 1) {
            const a = args[idx];
            if (std.mem.eql(u8, a, "--json")) {
                json = true;
            } else {
                min = std.fmt.parseInt(usize, a, 10) catch
                    return die(stderr, "error: invalid min length or unknown 'strings' option\n", 1);
            }
        }
        runStrings(io, stdout, args[2], min, json) catch |err| return dieErr(stderr, err);
        return;
    }
    if (std.mem.eql(u8, cmd, "entropy")) {
        if (args.len < 3) return die(stderr, "error: 'entropy' requires a path\n", 1);
        var json = false;
        for (args[3..]) |a| if (std.mem.eql(u8, a, "--json")) { json = true; };
        runEntropy(io, gpa, stdout, args[2], json) catch |err| return dieErr(stderr, err);
        return;
    }
    if (std.mem.eql(u8, cmd, "fp")) {
        if (args.len < 3) return die(stderr, "error: 'fp' requires sub-action\n", 1);
        const sub = args[2];
        if (std.mem.eql(u8, sub, "generate")) {
            if (args.len < 5) return die(stderr, "error: fp generate <path> <lib> [version]\n", 1);
            const ver: ?[]const u8 = if (args.len >= 6) args[5] else null;
            runFpGenerate(io, gpa, stdout, args[3], args[4], ver) catch |err| return dieErr(stderr, err);
            return;
        }
        if (std.mem.eql(u8, sub, "match")) {
            if (args.len < 5) return die(stderr, "error: fp match <path> <db.json>\n", 1);
            runFpMatch(io, gpa, stdout, args[3], args[4]) catch |err| return dieErr(stderr, err);
            return;
        }
        return die(stderr, "error: fp <generate|match>\n", 1);
    }
    if (std.mem.eql(u8, cmd, "symbols")) {
        if (args.len < 3) return die(stderr, "error: 'symbols' requires a path\n", 1);
        runSymbols(io, gpa, stdout, args[2]) catch |err| return dieErr(stderr, err);
        return;
    }
    if (std.mem.eql(u8, cmd, "addr2line")) {
        if (args.len < 4) return die(stderr, "error: 'addr2line' requires <path> <hex-addr>\n", 1);
        const addr = std.fmt.parseInt(u64, stripHexPrefix(args[3]), 16) catch
            return die(stderr, "error: invalid hex address\n", 1);
        runAddr2Line(io, gpa, stdout, args[2], addr) catch |err| return dieErr(stderr, err);
        return;
    }
    if (std.mem.eql(u8, cmd, "sbom")) {
        if (args.len < 3) return die(stderr, "error: 'sbom' requires a path\n", 1);
        var plain = false;
        for (args[3..]) |a| {
            if (std.mem.eql(u8, a, "--plain")) plain = true;
        }
        runSbom(io, gpa, stdout, args[2], plain, style, &prog) catch |err| {
            prog.fail(@errorName(err));
            return dieErr(stderr, err);
        };
        return;
    }
    if (std.mem.eql(u8, cmd, "secrets")) {
        if (args.len < 3) return die(stderr, "error: 'secrets' requires a path\n", 1);
        var json = false;
        var opts: scribe.security.secrets.ScanOptions = .{};
        var idx: usize = 3;
        while (idx < args.len) : (idx += 1) {
            const a = args[idx];
            if (std.mem.eql(u8, a, "--json")) {
                json = true;
            } else if (std.mem.eql(u8, a, "--include-generic")) {
                opts.include_generic = true;
            } else if (std.mem.eql(u8, a, "--include-wide")) {
                opts.scan_wide = true;
            } else if (std.mem.eql(u8, a, "--min-entropy")) {
                if (idx + 1 >= args.len) return die(stderr, "error: --min-entropy requires a value\n", 1);
                idx += 1;
                opts.min_entropy = std.fmt.parseFloat(f32, args[idx]) catch
                    return die(stderr, "error: invalid --min-entropy value\n", 1);
            } else {
                return die(stderr, "error: unknown 'secrets' option\n", 1);
            }
        }
        runSecrets(io, gpa, stdout, args[2], opts, json, style) catch |err| return dieErr(stderr, err);
        return;
    }
    if (std.mem.eql(u8, cmd, "vulns")) {
        if (args.len < 3) return die(stderr, "error: 'vulns' requires a path\n", 1);
        var json = false;
        var db_path: ?[]const u8 = null;
        var idx: usize = 3;
        while (idx < args.len) : (idx += 1) {
            const a = args[idx];
            if (std.mem.eql(u8, a, "--json")) {
                json = true;
            } else if (std.mem.eql(u8, a, "--db")) {
                if (idx + 1 >= args.len) return die(stderr, "error: --db requires a path\n", 1);
                idx += 1;
                db_path = args[idx];
            } else {
                return die(stderr, "error: unknown 'vulns' option\n", 1);
            }
        }
        const db = db_path orelse return die(stderr, "error: 'vulns' requires --db <path>\n", 1);
        runVulns(io, gpa, stdout, args[2], db, json, style, &prog) catch |err| {
            prog.fail(@errorName(err));
            return dieErr(stderr, err);
        };
        return;
    }
    if (std.mem.eql(u8, cmd, "config")) {
        if (args.len < 3) return die(stderr, "error: 'config' requires a path\n", 1);
        var json = false;
        var ctype: scribe.security.config.ConfigType = .auto;
        var idx: usize = 3;
        while (idx < args.len) : (idx += 1) {
            const a = args[idx];
            if (std.mem.eql(u8, a, "--json")) {
                json = true;
            } else if (std.mem.eql(u8, a, "--type")) {
                if (idx + 1 >= args.len) return die(stderr, "error: --type requires a value\n", 1);
                idx += 1;
                if (std.mem.eql(u8, args[idx], "dockerfile")) ctype = .dockerfile
                else if (std.mem.eql(u8, args[idx], "kubernetes")) ctype = .kubernetes
                else return die(stderr, "error: --type must be 'dockerfile' or 'kubernetes'\n", 1);
            } else {
                return die(stderr, "error: unknown 'config' option\n", 1);
            }
        }
        runConfig(io, gpa, stdout, args[2], ctype, json, style) catch |err| return dieErr(stderr, err);
        return;
    }
    if (std.mem.eql(u8, cmd, "scan")) {
        if (args.len < 3) return die(stderr, "error: 'scan' requires a path\n", 1);
        var plain = false;
        var sarif = false;
        var gha = false;
        var db_path: ?[]const u8 = null;
        var config_path: ?[]const u8 = null;
        var fp_db_path: ?[]const u8 = null;
        var yara_path: ?[]const u8 = null;
        var sec_opts: scribe.security.secrets.ScanOptions = .{};
        var idx: usize = 3;
        while (idx < args.len) : (idx += 1) {
            const a = args[idx];
            if (std.mem.eql(u8, a, "--sarif")) {
                sarif = true;
            } else if (std.mem.eql(u8, a, "--github-annotations") or std.mem.eql(u8, a, "--gha")) {
                gha = true;
            } else if (std.mem.eql(u8, a, "--plain")) {
                plain = true;
            } else if (std.mem.eql(u8, a, "--include-generic")) {
                sec_opts.include_generic = true;
            } else if (std.mem.eql(u8, a, "--include-wide")) {
                sec_opts.scan_wide = true;
            } else if (std.mem.eql(u8, a, "--min-entropy")) {
                if (idx + 1 >= args.len) return die(stderr, "error: --min-entropy requires a value\n", 1);
                idx += 1;
                sec_opts.min_entropy = std.fmt.parseFloat(f32, args[idx]) catch
                    return die(stderr, "error: invalid --min-entropy value\n", 1);
            } else if (std.mem.eql(u8, a, "--db")) {
                if (idx + 1 >= args.len) return die(stderr, "error: --db requires a path\n", 1);
                idx += 1;
                db_path = args[idx];
            } else if (std.mem.eql(u8, a, "--config")) {
                if (idx + 1 >= args.len) return die(stderr, "error: --config requires a path\n", 1);
                idx += 1;
                config_path = args[idx];
            } else if (std.mem.eql(u8, a, "--fp-db")) {
                if (idx + 1 >= args.len) return die(stderr, "error: --fp-db requires a path\n", 1);
                idx += 1;
                fp_db_path = args[idx];
            } else if (std.mem.eql(u8, a, "--yara")) {
                if (idx + 1 >= args.len) return die(stderr, "error: --yara requires a path\n", 1);
                idx += 1;
                yara_path = args[idx];
            } else {
                return die(stderr, "error: unknown 'scan' option\n", 1);
            }
        }
        runScan(io, gpa, stdout, args[2], db_path, config_path, fp_db_path, yara_path, sec_opts, plain, sarif, gha, style, &prog) catch |err| {
            prog.fail(@errorName(err));
            return dieErr(stderr, err);
        };
        return;
    }
    if (std.mem.eql(u8, cmd, "vulndb")) {
        if (args.len < 3) return die(stderr, "error: 'vulndb' requires sub-action\n", 1);
        const sub = args[2];
        if (std.mem.eql(u8, sub, "compile")) {
            if (args.len < 5) return die(stderr, "error: vulndb compile <in.json> <out.scvd>\n", 1);
            runVulndbCompile(io, gpa, stdout, args[3], args[4]) catch |err| return dieErr(stderr, err);
            return;
        }
        if (std.mem.eql(u8, sub, "merge")) {
            if (args.len < 5) return die(stderr, "error: vulndb merge <out.scvd> <in1> [in2...]\n", 1);
            runVulndbMerge(io, gpa, stdout, args[3], args[4..]) catch |err| return dieErr(stderr, err);
            return;
        }
        if (std.mem.eql(u8, sub, "update")) {
            var from_url: ?[]const u8 = null;
            var out_path: ?[]const u8 = null;
            var idx: usize = 3;
            while (idx < args.len) : (idx += 1) {
                const a = args[idx];
                if (std.mem.eql(u8, a, "--from")) {
                    if (idx + 1 >= args.len) return die(stderr, "error: --from requires a URL\n", 1);
                    idx += 1;
                    from_url = args[idx];
                } else if (std.mem.eql(u8, a, "--out")) {
                    if (idx + 1 >= args.len) return die(stderr, "error: --out requires a path\n", 1);
                    idx += 1;
                    out_path = args[idx];
                } else {
                    return die(stderr, "error: unknown 'vulndb update' option\n", 1);
                }
            }
            const url = from_url orelse return die(stderr, "error: vulndb update requires --from <url>\n", 1);
            const op = out_path orelse return die(stderr, "error: vulndb update requires --out <path>\n", 1);
            runVulndbUpdate(io, gpa, stdout, url, op, &prog) catch |err| {
                prog.fail(@errorName(err));
                return dieErr(stderr, err);
            };
            return;
        }
        return die(stderr, "error: vulndb <compile|update>\n", 1);
    }
    if (std.mem.eql(u8, cmd, "ui")) {
        if (args.len < 3) return die(stderr, "error: 'ui' requires a path\n", 1);
        var db_path: ?[]const u8 = null;
        var config_path: ?[]const u8 = null;
        var fp_db_path: ?[]const u8 = null;
        var sec_opts: scribe.security.secrets.ScanOptions = .{};
        var idx: usize = 3;
        while (idx < args.len) : (idx += 1) {
            const a = args[idx];
            if (std.mem.eql(u8, a, "--include-generic")) {
                sec_opts.include_generic = true;
            } else if (std.mem.eql(u8, a, "--include-wide")) {
                sec_opts.scan_wide = true;
            } else if (std.mem.eql(u8, a, "--db")) {
                if (idx + 1 >= args.len) return die(stderr, "error: --db requires a path\n", 1);
                idx += 1;
                db_path = args[idx];
            } else if (std.mem.eql(u8, a, "--config")) {
                if (idx + 1 >= args.len) return die(stderr, "error: --config requires a path\n", 1);
                idx += 1;
                config_path = args[idx];
            } else if (std.mem.eql(u8, a, "--fp-db")) {
                if (idx + 1 >= args.len) return die(stderr, "error: --fp-db requires a path\n", 1);
                idx += 1;
                fp_db_path = args[idx];
            } else {
                return die(stderr, "error: unknown 'ui' option\n", 1);
            }
        }
        ui.run(io, gpa, init.environ_map, args[2], .{
            .db_path = db_path,
            .config_path = config_path,
            .fp_db_path = fp_db_path,
            .sec_opts = sec_opts,
        }, &prog) catch |err| {
            prog.fail(@errorName(err));
            return dieErr(stderr, err);
        };
        return;
    }
    if (std.mem.eql(u8, cmd, "policy")) {
        if (args.len < 3) return die(stderr, "error: 'policy' requires a path\n", 1);
        var json = false;
        var policy_path: ?[]const u8 = null;
        var db_path: ?[]const u8 = null;
        var config_path: ?[]const u8 = null;
        var sec_opts: scribe.security.secrets.ScanOptions = .{};
        var idx: usize = 3;
        while (idx < args.len) : (idx += 1) {
            const a = args[idx];
            if (std.mem.eql(u8, a, "--json")) {
                json = true;
            } else if (std.mem.eql(u8, a, "--policy")) {
                if (idx + 1 >= args.len) return die(stderr, "error: --policy requires a path\n", 1);
                idx += 1;
                policy_path = args[idx];
            } else if (std.mem.eql(u8, a, "--db")) {
                if (idx + 1 >= args.len) return die(stderr, "error: --db requires a path\n", 1);
                idx += 1;
                db_path = args[idx];
            } else if (std.mem.eql(u8, a, "--config")) {
                if (idx + 1 >= args.len) return die(stderr, "error: --config requires a path\n", 1);
                idx += 1;
                config_path = args[idx];
            } else if (std.mem.eql(u8, a, "--include-generic")) {
                sec_opts.include_generic = true;
            } else {
                return die(stderr, "error: unknown 'policy' option\n", 1);
            }
        }
        const pp = policy_path orelse return die(stderr, "error: 'policy' requires --policy <path>\n", 1);
        const code = runPolicy(io, gpa, stdout, args[2], pp, db_path, config_path, sec_opts, json, style, &prog) catch |err| {
            prog.fail(@errorName(err));
            return dieErr(stderr, err);
        };
        stdout.flush() catch {};
        std.process.exit(code);
    }

    try stderr.print("error: unknown command '{s}'\n", .{cmd});
    try stderr.writeAll(usage);
    try stderr.flush();
    std.process.exit(1);
}

fn emitCompletion(out: *Io.Writer, shell: []const u8) !void {
    if (std.mem.eql(u8, shell, "bash")) {
        try out.writeAll(bash_completion);
        return;
    }
    if (std.mem.eql(u8, shell, "zsh")) {
        try out.writeAll(zsh_completion);
        return;
    }
    if (std.mem.eql(u8, shell, "fish")) {
        try out.writeAll(fish_completion);
        return;
    }
    return error.NotImplemented;
}

const subcommand_list = "info harden yara deps strings entropy hex exports diff sbom secrets vulns config scan policy symbols addr2line fp ui completion vulndb help version";

const bash_completion =
    \\# scribe bash completion. Source: `source <(scribe completion bash)` or
    \\# write to /etc/bash_completion.d/scribe.
    \\_scribe() {
    \\    local cur prev cmds
    \\    COMPREPLY=()
    \\    cur="${COMP_WORDS[COMP_CWORD]}"
    \\    cmds="info harden yara deps strings entropy hex exports diff sbom secrets vulns config scan policy symbols addr2line fp ui completion vulndb help version --version --help"
    \\    if [ "$COMP_CWORD" -eq 1 ]; then
    \\        COMPREPLY=( $(compgen -W "$cmds" -- "$cur") )
    \\        return 0
    \\    fi
    \\    COMPREPLY=( $(compgen -f -- "$cur") )
    \\}
    \\complete -F _scribe scribe
    \\
;

const zsh_completion =
    \\# scribe zsh completion. Source: `source <(scribe completion zsh)` or
    \\# write to a directory on $fpath named _scribe.
    \\#compdef scribe
    \\_scribe() {
    \\    local -a cmds
    \\    cmds=(
    \\        'info:format, arch, entry, sections, hardening'
    \\        'harden:exploit-mitigation report'
    \\        'yara:match a YARA-subset rule file'
    \\        'deps:dynamic library dependencies'
    \\        'strings:printable ASCII runs'
    \\        'entropy:Shannon entropy per section'
    \\        'hex:hex dump of file or section'
    \\        'exports:list dynamically exported symbols'
    \\        'diff:compare two binaries'
    \\        'sbom:bill of materials (CycloneDX or plain)'
    \\        'secrets:SIMD secret scan'
    \\        'vulns:CVE / advisory matcher'
    \\        'config:audit Dockerfile / k8s manifest'
    \\        'scan:full pipeline (SBOM + secrets + vulns + IaC + hardening + anomalies + YARA)'
    \\        'policy:evaluate scan results against policy'
    \\        'symbols:DWARF function symbols'
    \\        'addr2line:resolve address to source location'
    \\        'fp:fingerprint database operations'
    \\        'ui:interactive scan-results browser (TUI)'
    \\        'vulndb:advisory DB management'
    \\        'completion:emit shell completion script'
    \\        'help:print usage'
    \\        'version:print version'
    \\    )
    \\    if (( CURRENT == 2 )); then
    \\        _describe 'command' cmds
    \\    else
    \\        _files
    \\    fi
    \\}
    \\compdef _scribe scribe
    \\
;

const fish_completion =
    \\# scribe fish completion. Source: `scribe completion fish | source` or
    \\# write to ~/.config/fish/completions/scribe.fish.
    \\complete -c scribe -f
    \\complete -c scribe -n '__fish_use_subcommand' -a info -d 'format, arch, sections, hardening'
    \\complete -c scribe -n '__fish_use_subcommand' -a harden -d 'exploit-mitigation report'
    \\complete -c scribe -n '__fish_use_subcommand' -a yara -d 'match YARA-subset rules'
    \\complete -c scribe -n '__fish_use_subcommand' -a deps -d 'dynamic library dependencies'
    \\complete -c scribe -n '__fish_use_subcommand' -a strings -d 'printable ASCII runs (SIMD)'
    \\complete -c scribe -n '__fish_use_subcommand' -a entropy -d 'Shannon entropy per section'
    \\complete -c scribe -n '__fish_use_subcommand' -a hex -d 'hex dump'
    \\complete -c scribe -n '__fish_use_subcommand' -a exports -d 'exported symbols'
    \\complete -c scribe -n '__fish_use_subcommand' -a diff -d 'compare two binaries'
    \\complete -c scribe -n '__fish_use_subcommand' -a sbom -d 'CycloneDX SBOM'
    \\complete -c scribe -n '__fish_use_subcommand' -a secrets -d 'SIMD secret scan'
    \\complete -c scribe -n '__fish_use_subcommand' -a vulns -d 'CVE matcher'
    \\complete -c scribe -n '__fish_use_subcommand' -a config -d 'IaC misconfig audit'
    \\complete -c scribe -n '__fish_use_subcommand' -a scan -d 'full security pipeline'
    \\complete -c scribe -n '__fish_use_subcommand' -a policy -d 'policy gate'
    \\complete -c scribe -n '__fish_use_subcommand' -a symbols -d 'DWARF symbols'
    \\complete -c scribe -n '__fish_use_subcommand' -a addr2line -d 'address to source'
    \\complete -c scribe -n '__fish_use_subcommand' -a fp -d 'fingerprint DB'
    \\complete -c scribe -n '__fish_use_subcommand' -a ui -d 'interactive TUI'
    \\complete -c scribe -n '__fish_use_subcommand' -a vulndb -d 'advisory DB management'
    \\complete -c scribe -n '__fish_use_subcommand' -a completion -d 'emit shell completion'
    \\complete -c scribe -n '__fish_use_subcommand' -a help -d 'print usage'
    \\complete -c scribe -n '__fish_use_subcommand' -a version -d 'print version'
    \\
;

fn die(stderr: *Io.Writer, msg: []const u8, code: u8) noreturn {
    stderr.writeAll(msg) catch {};
    stderr.flush() catch {};
    std.process.exit(code);
}

fn dieErr(stderr: *Io.Writer, err: anyerror) noreturn {
    stderr.print("error: {s}\n", .{@errorName(err)}) catch {};
    stderr.flush() catch {};
    std.process.exit(1);
}

fn runInfo(
    io: Io,
    gpa: std.mem.Allocator,
    out: *Io.Writer,
    path: []const u8,
    json: bool,
    all_slices: bool,
    hashes: bool,
    style: scribe.term.Style,
) !void {
    var mapping = try scribe.mmap.open(io, path);
    defer mapping.deinit();
    const bytes = mapping.bytes();

    if (all_slices) {
        try emitAllSlices(out, bytes, gpa, path, json);
        return;
    }

    var info = try scribe.parseFormat(gpa, bytes);
    defer info.deinit(gpa);

    if (json) {
        try out.print("{{\"file\":\"{s}\",\"format\":\"{s}\",\"arch\":\"{s}\",\"entry\":\"0x{x}\",\"is_64\":{},\"sections\":[", .{
            path, @tagName(info), @tagName(info.arch()), info.entry(), info.is64(),
        });
        switch (info) {
            .elf => |e| for (e.sections, 0..) |s, i| {
                if (i != 0) try out.writeAll(",");
                try out.print("{{\"name\":\"{s}\",\"addr\":\"0x{x}\",\"size\":\"0x{x}\"}}", .{ s.name, s.addr, s.size });
            },
            .macho => |m| for (m.sections, 0..) |s, i| {
                if (i != 0) try out.writeAll(",");
                try out.print("{{\"seg\":\"{s}\",\"name\":\"{s}\",\"addr\":\"0x{x}\",\"size\":\"0x{x}\"}}", .{ s.seg, s.name, s.addr, s.size });
            },
            .pe => |p| for (p.sections, 0..) |s, i| {
                if (i != 0) try out.writeAll(",");
                try out.print("{{\"name\":\"{s}\",\"vaddr\":\"0x{x}\",\"vsize\":\"0x{x}\",\"raw\":\"0x{x}\"}}", .{ s.name, s.virtual_address, s.virtual_size, s.raw_size });
            },
        }
        try out.writeAll("]");
        if (info == .macho) {
            if (info.macho.fat_slice_arch) |slice_arch| {
                try out.print(",\"slice\":\"{s}\"", .{@tagName(slice_arch)});
            }
        }
        if (scribe.analyzeHardening(gpa, info, bytes)) |report_const| {
            var report = report_const;
            defer report.deinit(gpa);
            try out.writeAll(",\"hardening\":[");
            for (report.checks, 0..) |c, i| {
                if (i != 0) try out.writeAll(",");
                try out.print("{{\"id\":\"{s}\",\"status\":\"{s}\"}}", .{ c.id, c.status.label() });
            }
            try out.writeAll("]");
        } else |_| {}
        try out.writeAll("}\n");
        return;
    }

    try out.print("file:    {s}\n", .{path});
    try out.print("format:  {s}\n", .{@tagName(info)});
    try out.print("arch:    {s}\n", .{@tagName(info.arch())});
    if (info == .macho) {
        if (info.macho.fat_slice_arch) |slice_arch| {
            try out.print("slice:   {s} (selected from FAT/Universal binary)\n", .{@tagName(slice_arch)});
        }
    }
    try out.print("entry:   0x{x}\n", .{info.entry()});
    try out.print("64-bit:  {}\n", .{info.is64()});
    switch (info) {
        .elf => |e| try printElfSections(out, e, hashes, bytes),
        .macho => |m| try printMachoSections(out, m, hashes, bytes),
        .pe => |p| try printPeSections(out, p, hashes, bytes),
    }

    var report = scribe.analyzeHardening(gpa, info, bytes) catch |e| {
        try out.print("hardening: (unavailable: {s})\n", .{@errorName(e)});
        return;
    };
    defer report.deinit(gpa);
    try printHardening(out, report, style);
}

fn emitAllSlices(
    out: *Io.Writer,
    bytes: []const u8,
    gpa: std.mem.Allocator,
    path: []const u8,
    json: bool,
) !void {
    if (bytes.len < 8) return error.Truncated;
    const m = std.mem.readInt(u32, bytes[0..4], .little);
    const is_fat_64 = m == std.macho.FAT_MAGIC_64 or m == std.macho.FAT_CIGAM_64;
    const is_fat = is_fat_64 or m == std.macho.FAT_MAGIC or m == std.macho.FAT_CIGAM;
    if (!is_fat) {
        // Not a FAT file — emit single-slice info.
        if (json) try out.writeAll("{\"slices\":[") else try out.writeAll("(input is not a FAT/Universal binary; --all-slices applies only to Mach-O fat archives)\n");
        if (json) try out.writeAll("]}\n");
        return;
    }
    const nfat = std.mem.readInt(u32, bytes[4..8], .big);
    const entry_size: usize = if (is_fat_64) 32 else 20;
    const tail = std.math.add(usize, 8, entry_size * nfat) catch return error.Truncated;
    if (tail > bytes.len) return error.Truncated;

    if (json) try out.print("{{\"file\":\"{s}\",\"slices\":[", .{path}) else try out.print("file:    {s}\nslices:  {d}\n", .{ path, nfat });

    var i: u32 = 0;
    while (i < nfat) : (i += 1) {
        const off: usize = 8 + i * entry_size;
        const cputype = std.mem.readInt(i32, bytes[off..][0..4], .big);
        const slice_off: u64 = if (is_fat_64)
            std.mem.readInt(u64, bytes[off + 8 ..][0..8], .big)
        else
            std.mem.readInt(u32, bytes[off + 8 ..][0..4], .big);
        const slice_size: u64 = if (is_fat_64)
            std.mem.readInt(u64, bytes[off + 16 ..][0..8], .big)
        else
            std.mem.readInt(u32, bytes[off + 12 ..][0..4], .big);
        const arch = scribe.macho.archFromCpu(cputype);
        if (slice_off + slice_size > bytes.len) continue;
        const slice = bytes[@intCast(slice_off)..@intCast(slice_off + slice_size)];

        // Parse the thin slice for entry + section count.
        var entry: u64 = 0;
        var sections: usize = 0;
        var info = scribe.macho.parse(gpa, slice) catch null;
        defer if (info) |*ii| ii.deinit(gpa);
        if (info) |ii| {
            entry = ii.entry;
            sections = ii.sections.len;
        }

        if (json) {
            if (i != 0) try out.writeAll(",");
            try out.print("{{\"index\":{d},\"arch\":\"{s}\",\"offset\":\"0x{x}\",\"size\":\"0x{x}\",\"entry\":\"0x{x}\",\"sections\":{d}}}", .{ i, @tagName(arch), slice_off, slice_size, entry, sections });
        } else {
            try out.print("  [{d}] arch={s:<8} offset=0x{x:0>8} size=0x{x} entry=0x{x} sections={d}\n", .{ i, @tagName(arch), slice_off, slice_size, entry, sections });
        }
    }
    if (json) try out.writeAll("]}\n");
}

fn runHex(
    io: Io,
    gpa: std.mem.Allocator,
    out: *Io.Writer,
    path: []const u8,
    off_opt: ?u64,
    len_opt: ?usize,
    section: ?[]const u8,
) !void {
    var mapping = try scribe.mmap.open(io, path);
    defer mapping.deinit();
    const bytes = mapping.bytes();

    var start: u64 = off_opt orelse 0;
    var len: usize = len_opt orelse 256;

    if (section) |sec_name| {
        var info = try scribe.parseFormat(gpa, bytes);
        defer info.deinit(gpa);
        const range = sectionRange(info, sec_name) orelse {
            try out.print("error: section {s} not found\n", .{sec_name});
            return;
        };
        start = range.offset;
        if (len_opt == null) len = @min(range.size, 4096);
    }

    if (start > bytes.len) {
        try out.print("error: offset 0x{x} past end of file (size 0x{x})\n", .{ start, bytes.len });
        return;
    }
    const window = bytes[@intCast(start)..@min(bytes.len, @as(usize, @intCast(start)) + len)];
    try writeHexDump(out, window, start);
}

const SectionRange = struct { offset: u64, size: u64 };

fn sectionRange(info: scribe.FormatInfo, name: []const u8) ?SectionRange {
    return switch (info) {
        .elf => |e| blk: {
            for (e.sections) |s| if (std.mem.eql(u8, s.name, name))
                break :blk .{ .offset = s.offset, .size = s.size };
            break :blk null;
        },
        .macho => |m| blk: {
            // Section offsets are slice-relative; add fat_slice_offset so we
            // index into the original FAT file correctly.
            const base = m.fat_slice_offset;
            // Accept "__text" (section name) or "__TEXT/__text" composite.
            for (m.sections) |s| {
                if (std.mem.eql(u8, s.name, name)) break :blk .{ .offset = base + s.offset, .size = s.size };
                var buf: [64]u8 = undefined;
                const composite = std.fmt.bufPrint(&buf, "{s}/{s}", .{ s.seg, s.name }) catch continue;
                if (std.mem.eql(u8, composite, name)) break :blk .{ .offset = base + s.offset, .size = s.size };
            }
            break :blk null;
        },
        .pe => |p| blk: {
            for (p.sections) |s| if (std.mem.eql(u8, s.name, name))
                break :blk .{ .offset = s.raw_offset, .size = s.raw_size };
            break :blk null;
        },
    };
}

fn writeHexDump(out: *Io.Writer, data: []const u8, base_offset: u64) !void {
    var i: usize = 0;
    while (i < data.len) : (i += 16) {
        try out.print("{x:0>8}  ", .{base_offset + @as(u64, i)});
        const row_end = @min(i + 16, data.len);
        var k: usize = i;
        while (k < i + 16) : (k += 1) {
            if (k < row_end) {
                try out.print("{x:0>2} ", .{data[k]});
            } else {
                try out.writeAll("   ");
            }
            if (k == i + 7) try out.writeAll(" ");
        }
        try out.writeAll(" |");
        for (data[i..row_end]) |b| {
            try out.writeByte(if (b >= 0x20 and b < 0x7f) b else '.');
        }
        try out.writeAll("|\n");
    }
}

fn runExports(
    io: Io,
    gpa: std.mem.Allocator,
    out: *Io.Writer,
    path: []const u8,
    json: bool,
) !void {
    var mapping = try scribe.mmap.open(io, path);
    defer mapping.deinit();
    const bytes = mapping.bytes();

    var info = try scribe.parseFormat(gpa, bytes);
    defer info.deinit(gpa);

    var names: std.ArrayList([]const u8) = .empty;
    defer names.deinit(gpa);

    switch (info) {
        .elf => |e| try collectElfExports(gpa, &names, e, bytes),
        .macho => |m| try collectMachoExports(gpa, &names, m, bytes),
        .pe => |p| try collectPeExports(gpa, &names, p, bytes),
    }

    if (json) {
        try out.print("{{\"file\":\"{s}\",\"format\":\"{s}\",\"exports\":[", .{ path, @tagName(info) });
        for (names.items, 0..) |n, i| {
            if (i != 0) try out.writeAll(",");
            try out.print("\"{s}\"", .{n});
        }
        try out.writeAll("]}\n");
        return;
    }
    if (names.items.len == 0) {
        try out.writeAll("(no exports)\n");
        return;
    }
    for (names.items) |n| try out.print("{s}\n", .{n});
    try out.print("({d} exports)\n", .{names.items.len});
}

fn collectElfExports(
    gpa: std.mem.Allocator,
    out: *std.ArrayList([]const u8),
    info: scribe.ElfInfo,
    bytes: []const u8,
) !void {
    // Walk .dynsym; collect symbols with binding GLOBAL/WEAK and shndx != 0
    // (= defined in this image, not undefined references).
    var dynsym_off: u64 = 0;
    var dynsym_size: u64 = 0;
    var dynstr_off: u64 = 0;
    var dynstr_size: u64 = 0;
    for (info.sections) |s| {
        if (std.mem.eql(u8, s.name, ".dynsym")) {
            dynsym_off = s.offset;
            dynsym_size = s.size;
        } else if (std.mem.eql(u8, s.name, ".dynstr")) {
            dynstr_off = s.offset;
            dynstr_size = s.size;
        }
    }
    if (dynsym_size == 0 or dynstr_size == 0) return;
    if (dynsym_off + dynsym_size > bytes.len or dynstr_off + dynstr_size > bytes.len) return;
    const strtab = bytes[@intCast(dynstr_off)..][0..@intCast(dynstr_size)];

    const ent_size: u64 = if (info.is_64) @sizeOf(std.elf.Elf64_Sym) else @sizeOf(std.elf.Elf32_Sym);
    var off: u64 = dynsym_off;
    while (off + ent_size <= dynsym_off + dynsym_size) : (off += ent_size) {
        const slot = bytes[@intCast(off)..][0..@intCast(ent_size)];
        const st_name: u32 = std.mem.readInt(u32, slot[0..4], info.endian);
        const st_info_byte: u8 = if (info.is_64) slot[4] else slot[12];
        const st_shndx: u16 = if (info.is_64) std.mem.readInt(u16, slot[6..8], info.endian)
            else std.mem.readInt(u16, slot[14..16], info.endian);
        const bind = st_info_byte >> 4;
        // STB_GLOBAL=1, STB_WEAK=2; SHN_UNDEF=0 means undefined import.
        if ((bind != 1 and bind != 2) or st_shndx == 0) continue;
        if (st_name >= strtab.len) continue;
        const name = std.mem.sliceTo(strtab[st_name..], 0);
        if (name.len == 0) continue;
        try out.append(gpa, name);
    }
}

fn collectMachoExports(
    gpa: std.mem.Allocator,
    out: *std.ArrayList([]const u8),
    info: scribe.MachoInfo,
    full_bytes: []const u8,
) !void {
    // Walk LC_SYMTAB. Symbols with N_EXT bit set + N_TYPE != N_UNDF are
    // exports of this image. Names live in the string table at strtab_off.
    const slice_off: usize = @intCast(info.fat_slice_offset);
    if (slice_off >= full_bytes.len) return;
    const bytes = full_bytes[slice_off..];

    const lc_start: usize = if (info.is_64) @sizeOf(std.macho.mach_header_64) else @sizeOf(std.macho.mach_header);
    if (lc_start > bytes.len) return;
    const ncmds: u32 = if (info.is_64)
        (@as(*align(1) const std.macho.mach_header_64, @ptrCast(bytes.ptr))).ncmds
    else
        (@as(*align(1) const std.macho.mach_header, @ptrCast(bytes.ptr))).ncmds;

    var off: usize = lc_start;
    var i: u32 = 0;
    while (i < ncmds and off + @sizeOf(std.macho.load_command) <= bytes.len) : (i += 1) {
        const lc: *align(1) const std.macho.load_command = @ptrCast(bytes[off..].ptr);
        const cmdsize = lc.cmdsize;
        if (cmdsize < @sizeOf(std.macho.load_command)) break;
        if (off + cmdsize > bytes.len) break;
        if (lc.cmd == .SYMTAB) {
            if (cmdsize >= @sizeOf(std.macho.symtab_command)) {
                const sc: *align(1) const std.macho.symtab_command = @ptrCast(bytes[off..].ptr);
                const sym_off: usize = sc.symoff;
                const nsyms: usize = sc.nsyms;
                const str_off: usize = sc.stroff;
                const str_sz: usize = sc.strsize;
                const ent: usize = if (info.is_64) @sizeOf(std.macho.nlist_64) else @sizeOf(std.macho.nlist);
                if (str_off + str_sz > bytes.len) return;
                if (sym_off + nsyms * ent > bytes.len) return;
                const strtab = bytes[str_off..][0..str_sz];
                var k: usize = 0;
                while (k < nsyms) : (k += 1) {
                    const nl_off = sym_off + k * ent;
                    const n_strx: u32 = std.mem.readInt(u32, bytes[nl_off..][0..4], .little);
                    const n_type: u8 = bytes[nl_off + 4];
                    // N_EXT = 0x01, N_TYPE mask = 0x0E, N_UNDF = 0x0
                    const n_ext = (n_type & 0x01) != 0;
                    const ntype = n_type & 0x0E;
                    if (!n_ext or ntype == 0x0) continue;
                    if (n_strx >= strtab.len) continue;
                    const name = std.mem.sliceTo(strtab[n_strx..], 0);
                    if (name.len == 0) continue;
                    try out.append(gpa, name);
                }
            }
            return;
        }
        off += cmdsize;
    }
}

fn collectPeExports(
    gpa: std.mem.Allocator,
    out: *std.ArrayList([]const u8),
    info: scribe.PeInfo,
    bytes: []const u8,
) !void {
    // Walk Export Directory (data dir #0). Resolve RVAs via section table.
    if (bytes.len < 0x40) return;
    const e_lfanew = std.mem.readInt(u32, bytes[0x3c..][0..4], .little);
    const sig_off: usize = e_lfanew;
    if (sig_off + 24 > bytes.len) return;
    const opt_off = sig_off + 4 + 20; // PE\0\0 + IMAGE_FILE_HEADER
    const dd_off: usize = opt_off + (if (info.is_64) @as(usize, 0x88) else @as(usize, 0x70));
    if (dd_off + 8 > bytes.len) return;
    const exp_rva = std.mem.readInt(u32, bytes[dd_off..][0..4], .little);
    const exp_size = std.mem.readInt(u32, bytes[dd_off + 4 ..][0..4], .little);
    if (exp_rva == 0 or exp_size == 0) return;
    const exp_off = peRvaToFileOffset(info, exp_rva) orelse return;
    if (exp_off + 40 > bytes.len) return;
    // IMAGE_EXPORT_DIRECTORY layout:
    //   0  DWORD Characteristics
    //   4  DWORD TimeDateStamp
    //   8  WORD  MajorVersion / WORD MinorVersion
    //  12  DWORD Name (RVA)
    //  16  DWORD Base
    //  20  DWORD NumberOfFunctions
    //  24  DWORD NumberOfNames
    //  28  DWORD AddressOfFunctions (RVA)
    //  32  DWORD AddressOfNames (RVA)
    //  36  DWORD AddressOfNameOrdinals (RVA)
    const num_names = std.mem.readInt(u32, bytes[exp_off + 24 ..][0..4], .little);
    const names_rva = std.mem.readInt(u32, bytes[exp_off + 32 ..][0..4], .little);
    const names_off = peRvaToFileOffset(info, names_rva) orelse return;
    if (names_off + num_names * 4 > bytes.len) return;
    var i: u32 = 0;
    while (i < num_names) : (i += 1) {
        const name_rva = std.mem.readInt(u32, bytes[names_off + i * 4 ..][0..4], .little);
        const name_off = peRvaToFileOffset(info, name_rva) orelse continue;
        if (name_off >= bytes.len) continue;
        const name = std.mem.sliceTo(bytes[name_off..], 0);
        if (name.len == 0) continue;
        try out.append(gpa, name);
    }
}

fn peRvaToFileOffset(info: scribe.PeInfo, rva: u32) ?u64 {
    for (info.sections) |s| {
        if (rva >= s.virtual_address and rva < s.virtual_address + s.virtual_size)
            return @as(u64, s.raw_offset) + (rva - s.virtual_address);
    }
    return null;
}

fn runImports(
    io: Io,
    gpa: std.mem.Allocator,
    out: *Io.Writer,
    path: []const u8,
    json: bool,
) !void {
    var mapping = try scribe.mmap.open(io, path);
    defer mapping.deinit();
    const bytes = mapping.bytes();

    var info = try scribe.parseFormat(gpa, bytes);
    defer info.deinit(gpa);

    var names: std.ArrayList([]const u8) = .empty;
    defer names.deinit(gpa);

    switch (info) {
        .elf => |e| try collectElfImports(gpa, &names, e, bytes),
        .macho => |m| try collectMachoImports(gpa, &names, m, bytes),
        .pe => |p| {
            // PE imports = `scribe deps` table; walk + flatten Library!Symbol
            // pairs. For brevity, surface library names only — symbol-level
            // import detail belongs in a future `--detailed` flag.
            const list = try scribe.collectDeps(gpa, bytes);
            defer gpa.free(list);
            for (list) |d| try names.append(gpa, d.name);
            _ = p;
        },
    }

    if (json) {
        try out.print("{{\"file\":\"{s}\",\"format\":\"{s}\",\"imports\":[", .{ path, @tagName(info) });
        for (names.items, 0..) |n, i| {
            if (i != 0) try out.writeAll(",");
            try out.print("\"{s}\"", .{n});
        }
        try out.writeAll("]}\n");
        return;
    }
    if (names.items.len == 0) {
        try out.writeAll("(no imports)\n");
        return;
    }
    for (names.items) |n| try out.print("{s}\n", .{n});
    try out.print("({d} imports)\n", .{names.items.len});
}

fn collectElfImports(
    gpa: std.mem.Allocator,
    out: *std.ArrayList([]const u8),
    info: scribe.ElfInfo,
    bytes: []const u8,
) !void {
    // Mirror collectElfExports but inverted: bind GLOBAL/WEAK + shndx == 0
    // (undefined → must be resolved by another lib at load time).
    var dynsym_off: u64 = 0;
    var dynsym_size: u64 = 0;
    var dynstr_off: u64 = 0;
    var dynstr_size: u64 = 0;
    for (info.sections) |s| {
        if (std.mem.eql(u8, s.name, ".dynsym")) {
            dynsym_off = s.offset;
            dynsym_size = s.size;
        } else if (std.mem.eql(u8, s.name, ".dynstr")) {
            dynstr_off = s.offset;
            dynstr_size = s.size;
        }
    }
    if (dynsym_size == 0 or dynstr_size == 0) return;
    if (dynsym_off + dynsym_size > bytes.len or dynstr_off + dynstr_size > bytes.len) return;
    const strtab = bytes[@intCast(dynstr_off)..][0..@intCast(dynstr_size)];

    const ent_size: u64 = if (info.is_64) @sizeOf(std.elf.Elf64_Sym) else @sizeOf(std.elf.Elf32_Sym);
    var off: u64 = dynsym_off;
    while (off + ent_size <= dynsym_off + dynsym_size) : (off += ent_size) {
        const slot = bytes[@intCast(off)..][0..@intCast(ent_size)];
        const st_name: u32 = std.mem.readInt(u32, slot[0..4], info.endian);
        const st_info_byte: u8 = if (info.is_64) slot[4] else slot[12];
        const st_shndx: u16 = if (info.is_64) std.mem.readInt(u16, slot[6..8], info.endian)
            else std.mem.readInt(u16, slot[14..16], info.endian);
        const bind = st_info_byte >> 4;
        if ((bind != 1 and bind != 2) or st_shndx != 0) continue;
        if (st_name >= strtab.len) continue;
        const name = std.mem.sliceTo(strtab[st_name..], 0);
        if (name.len == 0) continue;
        try out.append(gpa, name);
    }
}

fn collectMachoImports(
    gpa: std.mem.Allocator,
    out: *std.ArrayList([]const u8),
    info: scribe.MachoInfo,
    full_bytes: []const u8,
) !void {
    // LC_SYMTAB + N_EXT + N_TYPE == N_UNDF
    const slice_off: usize = @intCast(info.fat_slice_offset);
    if (slice_off >= full_bytes.len) return;
    const bytes = full_bytes[slice_off..];

    const lc_start: usize = if (info.is_64) @sizeOf(std.macho.mach_header_64) else @sizeOf(std.macho.mach_header);
    if (lc_start > bytes.len) return;
    const ncmds: u32 = if (info.is_64)
        (@as(*align(1) const std.macho.mach_header_64, @ptrCast(bytes.ptr))).ncmds
    else
        (@as(*align(1) const std.macho.mach_header, @ptrCast(bytes.ptr))).ncmds;

    var off: usize = lc_start;
    var i: u32 = 0;
    while (i < ncmds and off + @sizeOf(std.macho.load_command) <= bytes.len) : (i += 1) {
        const lc: *align(1) const std.macho.load_command = @ptrCast(bytes[off..].ptr);
        const cmdsize = lc.cmdsize;
        if (cmdsize < @sizeOf(std.macho.load_command)) break;
        if (off + cmdsize > bytes.len) break;
        if (lc.cmd == .SYMTAB) {
            if (cmdsize >= @sizeOf(std.macho.symtab_command)) {
                const sc: *align(1) const std.macho.symtab_command = @ptrCast(bytes[off..].ptr);
                const sym_off: usize = sc.symoff;
                const nsyms: usize = sc.nsyms;
                const str_off: usize = sc.stroff;
                const str_sz: usize = sc.strsize;
                const ent: usize = if (info.is_64) @sizeOf(std.macho.nlist_64) else @sizeOf(std.macho.nlist);
                if (str_off + str_sz > bytes.len) return;
                if (sym_off + nsyms * ent > bytes.len) return;
                const strtab = bytes[str_off..][0..str_sz];
                var k: usize = 0;
                while (k < nsyms) : (k += 1) {
                    const nl_off = sym_off + k * ent;
                    const n_strx: u32 = std.mem.readInt(u32, bytes[nl_off..][0..4], .little);
                    const n_type: u8 = bytes[nl_off + 4];
                    const n_ext = (n_type & 0x01) != 0;
                    const ntype = n_type & 0x0E;
                    if (!n_ext or ntype != 0x0) continue;
                    if (n_strx >= strtab.len) continue;
                    const name = std.mem.sliceTo(strtab[n_strx..], 0);
                    if (name.len == 0) continue;
                    try out.append(gpa, name);
                }
            }
            return;
        }
        off += cmdsize;
    }
}

fn runWasm(
    io: Io,
    gpa: std.mem.Allocator,
    out: *Io.Writer,
    path: []const u8,
    json: bool,
) !void {
    var mapping = try scribe.mmap.open(io, path);
    defer mapping.deinit();
    const bytes = mapping.bytes();
    if (!scribe.wasm.isWasm(bytes)) {
        try out.writeAll("error: not a WebAssembly module\n");
        return;
    }
    var info = try scribe.wasm.parse(gpa, bytes);
    defer info.deinit(gpa);

    if (json) {
        try out.print("{{\"file\":\"{s}\",\"version\":{d},\"sections\":[", .{ path, info.version });
        for (info.sections, 0..) |s, i| {
            if (i != 0) try out.writeAll(",");
            try out.print("{{\"kind\":\"{s}\",\"offset\":\"0x{x}\",\"size\":{d}", .{ s.kind.label(), s.payload_offset, s.payload_size });
            if (s.name.len != 0) try out.print(",\"name\":\"{s}\"", .{s.name});
            try out.writeAll("}");
        }
        try out.writeAll("]}\n");
        return;
    }
    try out.print("file:    {s}\n", .{path});
    try out.print("format:  wasm\n", .{});
    try out.print("version: {d}\n", .{info.version});
    try out.print("sections: {d}\n", .{info.sections.len});
    for (info.sections, 0..) |s, i| {
        if (s.name.len > 0) {
            try out.print("  [{d:>3}] {s:<12} offset=0x{x:0>8} size={d:<8}  name={s}\n", .{ i, s.kind.label(), s.payload_offset, s.payload_size, s.name });
        } else {
            try out.print("  [{d:>3}] {s:<12} offset=0x{x:0>8} size={d}\n", .{ i, s.kind.label(), s.payload_offset, s.payload_size });
        }
    }
}

fn runArList(
    io: Io,
    gpa: std.mem.Allocator,
    out: *Io.Writer,
    path: []const u8,
    json: bool,
) !void {
    var mapping = try scribe.mmap.open(io, path);
    defer mapping.deinit();
    const bytes = mapping.bytes();
    if (!scribe.ar.isAr(bytes)) {
        try out.writeAll("error: not an AR archive (no `!<arch>\\n` magic)\n");
        return;
    }
    var arc = try scribe.ar.parse(gpa, bytes);
    defer arc.deinit(gpa);

    if (json) {
        try out.print("{{\"file\":\"{s}\",\"members\":[", .{path});
        for (arc.members, 0..) |m, i| {
            if (i != 0) try out.writeAll(",");
            try out.print("{{\"name\":\"{s}\",\"offset\":{d},\"size\":{d}}}", .{ m.name, m.offset, m.size });
        }
        try out.writeAll("]}\n");
        return;
    }
    try out.print("file:    {s}\n", .{path});
    try out.print("members: {d}\n", .{arc.members.len});
    for (arc.members) |m| try out.print("  {s:<48}  offset=0x{x:0>8}  size={d}\n", .{ m.name, m.offset, m.size });
}

fn runDiff(
    io: Io,
    gpa: std.mem.Allocator,
    out: *Io.Writer,
    path_a: []const u8,
    path_b: []const u8,
    json: bool,
    style: scribe.term.Style,
) !void {
    var ma = try scribe.mmap.open(io, path_a);
    defer ma.deinit();
    var mb = try scribe.mmap.open(io, path_b);
    defer mb.deinit();
    var ia = try scribe.parseFormat(gpa, ma.bytes());
    defer ia.deinit(gpa);
    var ib = try scribe.parseFormat(gpa, mb.bytes());
    defer ib.deinit(gpa);

    if (json) {
        try out.print("{{\"a\":\"{s}\",\"b\":\"{s}\",", .{ path_a, path_b });
        try out.print("\"format_a\":\"{s}\",\"format_b\":\"{s}\",", .{ @tagName(ia), @tagName(ib) });
        try out.print("\"arch_a\":\"{s}\",\"arch_b\":\"{s}\"", .{ @tagName(ia.arch()), @tagName(ib.arch()) });
        try out.writeAll("}\n");
        return;
    }

    try out.print("a:        {s}\n", .{path_a});
    try out.print("b:        {s}\n", .{path_b});

    if (@as(scribe.FormatKind, ia) != @as(scribe.FormatKind, ib)) {
        try style.bold(out, "format:   ");
        try out.print("{s} ≠ {s}\n", .{ @tagName(ia), @tagName(ib) });
    } else {
        try out.print("format:   {s} (matches)\n", .{@tagName(ia)});
    }
    if (ia.arch() != ib.arch()) {
        try style.bold(out, "arch:     ");
        try out.print("{s} ≠ {s}\n", .{ @tagName(ia.arch()), @tagName(ib.arch()) });
    } else {
        try out.print("arch:     {s} (matches)\n", .{@tagName(ia.arch())});
    }

    // Section name set diff.
    const names_a = try sectionNames(gpa, ia);
    defer gpa.free(names_a);
    const names_b = try sectionNames(gpa, ib);
    defer gpa.free(names_b);

    try out.writeAll("sections:\n");
    var only_a: usize = 0;
    var only_b: usize = 0;
    for (names_a) |na| {
        if (!containsSlice(names_b, na)) {
            try out.print("  - {s}  (only in A)\n", .{na});
            only_a += 1;
        }
    }
    for (names_b) |nb| {
        if (!containsSlice(names_a, nb)) {
            try out.print("  + {s}  (only in B)\n", .{nb});
            only_b += 1;
        }
    }
    if (only_a == 0 and only_b == 0) try out.writeAll("  (identical section sets)\n");

    // Hardening diff.
    var ra = scribe.analyzeHardening(gpa, ia, ma.bytes()) catch null;
    defer if (ra) |*r| r.deinit(gpa);
    var rb = scribe.analyzeHardening(gpa, ib, mb.bytes()) catch null;
    defer if (rb) |*r| r.deinit(gpa);

    if (ra != null and rb != null) {
        try out.writeAll("hardening:\n");
        var any = false;
        for (ra.?.checks) |ca| {
            for (rb.?.checks) |cb| {
                if (!std.mem.eql(u8, ca.id, cb.id)) continue;
                if (ca.status != cb.status) {
                    try out.print("  {s:<18} {s} → {s}\n", .{ ca.id, ca.status.label(), cb.status.label() });
                    any = true;
                }
            }
        }
        if (!any) try out.writeAll("  (identical hardening posture)\n");
    }
}

fn sectionNames(gpa: std.mem.Allocator, info: scribe.FormatInfo) ![][]const u8 {
    return switch (info) {
        .elf => |e| blk: {
            const out = try gpa.alloc([]const u8, e.sections.len);
            for (e.sections, 0..) |s, i| out[i] = s.name;
            break :blk out;
        },
        .macho => |m| blk: {
            const out = try gpa.alloc([]const u8, m.sections.len);
            for (m.sections, 0..) |s, i| out[i] = s.name;
            break :blk out;
        },
        .pe => |p| blk: {
            const out = try gpa.alloc([]const u8, p.sections.len);
            for (p.sections, 0..) |s, i| out[i] = s.name;
            break :blk out;
        },
    };
}

fn containsSlice(haystack: []const []const u8, needle: []const u8) bool {
    for (haystack) |h| if (std.mem.eql(u8, h, needle)) return true;
    return false;
}

fn runYara(
    io: Io,
    gpa: std.mem.Allocator,
    out: *Io.Writer,
    target_path: []const u8,
    rules_path: []const u8,
    json: bool,
    style: scribe.term.Style,
) !void {
    var rules_map = try scribe.mmap.open(io, rules_path);
    defer rules_map.deinit();
    var rules = try scribe.security.yara.parse(gpa, rules_map.bytes());
    defer rules.deinit(gpa);

    var target = try scribe.mmap.open(io, target_path);
    defer target.deinit();
    const matches = try scribe.security.yara.scan(gpa, rules, target.bytes());
    defer scribe.security.yara.freeMatches(gpa, matches);

    if (json) {
        try out.print("{{\"file\":\"{s}\",\"matches\":[", .{target_path});
        for (matches, 0..) |m, i| {
            if (i != 0) try out.writeAll(",");
            try out.print("{{\"rule\":\"{s}\",\"hits\":[", .{m.rule});
            for (m.hits, 0..) |h, j| {
                if (j != 0) try out.writeAll(",");
                try out.print("{{\"name\":\"{s}\",\"offset\":{d}}}", .{ h.name, h.offset });
            }
            try out.writeAll("]}");
        }
        try out.writeAll("]}\n");
        return;
    }

    if (matches.len == 0) {
        try style.dim(out, "(no rules matched)");
        try out.writeByte('\n');
        return;
    }
    for (matches) |m| {
        try style.bold(out, m.rule);
        try out.writeAll("  ");
        try out.print("{d} hit(s)", .{m.hits.len});
        if (m.tags.len > 0) {
            try out.writeAll("  [");
            for (m.tags, 0..) |t, i| {
                if (i != 0) try out.writeAll(",");
                try out.writeAll(t);
            }
            try out.writeAll("]");
        }
        try out.writeByte('\n');
        for (m.hits) |h| {
            try out.print("    ${s} @ 0x{x}\n", .{ h.name, h.offset });
        }
    }
}

fn runHarden(
    io: Io,
    gpa: std.mem.Allocator,
    out: *Io.Writer,
    path: []const u8,
    json: bool,
    style: scribe.term.Style,
) !void {
    var mapping = try scribe.mmap.open(io, path);
    defer mapping.deinit();
    const bytes = mapping.bytes();

    var info = try scribe.parseFormat(gpa, bytes);
    defer info.deinit(gpa);

    var report = try scribe.analyzeHardening(gpa, info, bytes);
    defer report.deinit(gpa);

    if (json) {
        try out.print("{{\"file\":\"{s}\",\"format\":\"{s}\",\"checks\":[", .{ path, @tagName(report.format) });
        for (report.checks, 0..) |c, i| {
            if (i != 0) try out.writeAll(",");
            try out.print("{{\"id\":\"{s}\",\"name\":\"{s}\",\"status\":\"{s}\"", .{ c.id, c.name, c.status.label() });
            if (c.detail) |d| {
                try out.print(",\"detail\":\"{s}\"", .{d});
            }
            try out.writeAll("}");
        }
        try out.writeAll("]}\n");
        return;
    }

    try out.print("file:    {s}\n", .{path});
    try out.print("format:  {s}\n", .{@tagName(report.format)});
    try printHardening(out, report, style);
}

fn printHardening(out: *Io.Writer, report: scribe.HardeningReport, style: scribe.term.Style) !void {
    try out.print("hardening: {d}\n", .{report.checks.len});
    for (report.checks) |c| {
        const code = switch (c.status) {
            .enabled => "32",   // green
            .partial => "33",   // yellow
            .disabled => "31",  // red
            .unknown => "90",   // dim
            .na => "90",
        };
        if (style.enabled) {
            try out.print(
                "  {s:<18} \x1b[{s}m{s:<8}\x1b[0m {s}",
                .{ c.id, code, c.status.label(), c.name },
            );
        } else {
            try out.print(
                "  {s:<18} {s:<8} {s}",
                .{ c.id, c.status.label(), c.name },
            );
        }
        if (c.detail) |d| try out.print("  ({s})", .{d});
        try out.writeByte('\n');
    }
}

fn printElfSections(out: *Io.Writer, e: scribe.ElfInfo, hashes: bool, bytes: []const u8) !void {
    try out.print("sections: {d}\n", .{e.sections.len});
    for (e.sections, 0..) |s, i| {
        const perm = elfPermLabel(s.flags);
        if (hashes) {
            const h = sectionShaShort(bytes, s.offset, s.size);
            try out.print(
                "  [{d:>3}] {s:<24} type=0x{x:0>4} addr=0x{x:0>16} size=0x{x:<8} {s}  sha={s}\n",
                .{ i, s.name, s.type, s.addr, s.size, perm, h },
            );
        } else {
            try out.print(
                "  [{d:>3}] {s:<24} type=0x{x:0>4} addr=0x{x:0>16} size=0x{x:<8} {s}\n",
                .{ i, s.name, s.type, s.addr, s.size, perm },
            );
        }
    }
}

fn printMachoSections(out: *Io.Writer, m: scribe.MachoInfo, hashes: bool, bytes: []const u8) !void {
    try out.print("sections: {d}\n", .{m.sections.len});
    const base = m.fat_slice_offset;
    for (m.sections, 0..) |s, i| {
        const perm = machoSectionPermLabel(s.flags);
        if (hashes) {
            const h = sectionShaShort(bytes, base + s.offset, s.size);
            try out.print(
                "  [{d:>3}] {s:<16} {s:<16} addr=0x{x:0>16} size=0x{x:<8} {s}  sha={s}\n",
                .{ i, s.seg, s.name, s.addr, s.size, perm, h },
            );
        } else {
            try out.print(
                "  [{d:>3}] {s:<16} {s:<16} addr=0x{x:0>16} size=0x{x:<8} {s}\n",
                .{ i, s.seg, s.name, s.addr, s.size, perm },
            );
        }
    }
}

fn printPeSections(out: *Io.Writer, p: scribe.PeInfo, hashes: bool, bytes: []const u8) !void {
    try out.print("image base: 0x{x}\n", .{p.image_base});
    try out.print("sections: {d}\n", .{p.sections.len});
    for (p.sections, 0..) |s, i| {
        const perm = pePermLabel(s.characteristics);
        if (hashes) {
            const h = sectionShaShort(bytes, s.raw_offset, s.raw_size);
            try out.print(
                "  [{d:>3}] {s:<10} vaddr=0x{x:0>8} vsize=0x{x:0>6} raw=0x{x:0>6} {s}  sha={s}\n",
                .{ i, s.name, s.virtual_address, s.virtual_size, s.raw_size, perm, h },
            );
        } else {
            try out.print(
                "  [{d:>3}] {s:<10} vaddr=0x{x:0>8} vsize=0x{x:0>6} raw=0x{x:0>6} {s}\n",
                .{ i, s.name, s.virtual_address, s.virtual_size, s.raw_size, perm },
            );
        }
    }
}

fn sectionShaShort(bytes: []const u8, off: u64, size: u64) [16]u8 {
    var hex_buf: [16]u8 = undefined;
    @memset(&hex_buf, '-');
    if (size == 0 or off + size > bytes.len) return hex_buf;
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes[@intCast(off)..][0..@intCast(size)], &hash, .{});
    const charset = "0123456789abcdef";
    for (hash[0..8], 0..) |b, i| {
        hex_buf[i * 2] = charset[(b >> 4) & 0xF];
        hex_buf[i * 2 + 1] = charset[b & 0xF];
    }
    return hex_buf;
}

fn elfPermLabel(flags: u64) [3]u8 {
    // SHF_ALLOC = 0x2 (mapped), SHF_WRITE = 0x1, SHF_EXECINSTR = 0x4.
    var s: [3]u8 = .{ '-', '-', '-' };
    if (flags & 0x2 != 0) s[0] = 'r';
    if (flags & 0x1 != 0) s[1] = 'w';
    if (flags & 0x4 != 0) s[2] = 'x';
    return s;
}

fn machoSectionPermLabel(flags: u32) [3]u8 {
    // S_ATTR_PURE_INSTRUCTIONS = 0x80000000, S_ATTR_SOME_INSTRUCTIONS = 0x00000400.
    // Sections always count as readable in mapped memory.
    var s: [3]u8 = .{ 'r', '-', '-' };
    if ((flags & 0x80000000) != 0 or (flags & 0x00000400) != 0) s[2] = 'x';
    return s;
}

fn pePermLabel(characteristics: u32) [3]u8 {
    // IMAGE_SCN_MEM_READ = 0x40000000, IMAGE_SCN_MEM_WRITE = 0x80000000,
    // IMAGE_SCN_MEM_EXECUTE = 0x20000000.
    var s: [3]u8 = .{ '-', '-', '-' };
    if (characteristics & 0x40000000 != 0) s[0] = 'r';
    if (characteristics & 0x80000000 != 0) s[1] = 'w';
    if (characteristics & 0x20000000 != 0) s[2] = 'x';
    return s;
}

fn runDeps(io: Io, gpa: std.mem.Allocator, out: *Io.Writer, path: []const u8, json: bool) !void {
    var mapping = try scribe.mmap.open(io, path);
    defer mapping.deinit();

    const list = try scribe.collectDeps(gpa, mapping.bytes());
    defer gpa.free(list);

    if (json) {
        try out.print("{{\"file\":\"{s}\",\"deps\":[", .{path});
        for (list, 0..) |d, i| {
            if (i != 0) try out.writeAll(",");
            try out.print("{{\"name\":\"{s}\",\"kind\":\"{s}\"}}", .{ d.name, @tagName(d.kind) });
        }
        try out.writeAll("]}\n");
        return;
    }

    if (list.len == 0) {
        try out.writeAll("(no dynamic dependencies)\n");
        return;
    }
    for (list) |d| try out.print("  {s:<24} [{s}]\n", .{ d.name, @tagName(d.kind) });
}

fn runStrings(io: Io, out: *Io.Writer, path: []const u8, min_len: usize, json: bool) !void {
    var mapping = try scribe.mmap.open(io, path);
    defer mapping.deinit();

    var it = scribe.scanStrings(mapping.bytes(), .{ .min_len = min_len });
    if (json) {
        try out.print("{{\"file\":\"{s}\",\"min_len\":{d},\"strings\":[", .{ path, min_len });
        var first = true;
        while (it.next()) |s| {
            if (!first) try out.writeAll(",");
            first = false;
            try out.writeByte('"');
            try writeJsonEscaped(out, s);
            try out.writeByte('"');
        }
        try out.writeAll("]}\n");
        return;
    }
    while (it.next()) |s| {
        try out.writeAll(s);
        try out.writeByte('\n');
    }
}

fn writeJsonEscaped(out: *Io.Writer, s: []const u8) !void {
    for (s) |c| {
        switch (c) {
            '"' => try out.writeAll("\\\""),
            '\\' => try out.writeAll("\\\\"),
            '\n' => try out.writeAll("\\n"),
            '\r' => try out.writeAll("\\r"),
            '\t' => try out.writeAll("\\t"),
            0...0x08, 0x0B, 0x0C, 0x0E...0x1F => try out.print("\\u{x:0>4}", .{c}),
            else => try out.writeByte(c),
        }
    }
}

fn runEntropy(io: Io, gpa: std.mem.Allocator, out: *Io.Writer, path: []const u8, json: bool) !void {
    var mapping = try scribe.mmap.open(io, path);
    defer mapping.deinit();
    const bytes = mapping.bytes();

    const overall = scribe.shannon(bytes);
    if (json) {
        try out.print("{{\"file\":\"{s}\",\"overall\":{d:.4},\"sections\":[", .{ path, overall });
        var first = true;
        if (scribe.parseFormat(gpa, bytes)) |info_const| {
            var info = info_const;
            defer info.deinit(gpa);
            switch (info) {
                .elf => |e| for (e.sections) |s| {
                    if (s.size == 0 or s.offset + s.size > bytes.len) continue;
                    const sb = bytes[@intCast(s.offset)..][0..@intCast(s.size)];
                    if (!first) try out.writeAll(",");
                    first = false;
                    try out.print("{{\"name\":\"{s}\",\"entropy\":{d:.4}}}", .{ s.name, scribe.shannon(sb) });
                },
                .macho => |m| {
                    const base = m.fat_slice_offset;
                    for (m.sections) |s| {
                        if (s.size == 0 or base + s.offset + s.size > bytes.len) continue;
                        const sb = bytes[@intCast(base + s.offset)..][0..@intCast(s.size)];
                        if (!first) try out.writeAll(",");
                        first = false;
                        try out.print("{{\"seg\":\"{s}\",\"name\":\"{s}\",\"entropy\":{d:.4}}}", .{ s.seg, s.name, scribe.shannon(sb) });
                    }
                },
                .pe => |p| for (p.sections) |s| {
                    if (s.raw_size == 0 or s.raw_offset + s.raw_size > bytes.len) continue;
                    const sb = bytes[s.raw_offset..][0..s.raw_size];
                    if (!first) try out.writeAll(",");
                    first = false;
                    try out.print("{{\"name\":\"{s}\",\"entropy\":{d:.4}}}", .{ s.name, scribe.shannon(sb) });
                },
            }
        } else |_| {}
        try out.writeAll("]}\n");
        return;
    }
    try out.print("overall: {d:.4} bits/byte\n", .{overall});

    var info = scribe.parseFormat(gpa, bytes) catch |e| {
        try out.print("(could not parse sections: {s})\n", .{@errorName(e)});
        return;
    };
    defer info.deinit(gpa);

    switch (info) {
        .elf => |e| {
            for (e.sections) |s| {
                if (s.size == 0 or s.offset + s.size > bytes.len) continue;
                const slice = bytes[@intCast(s.offset)..][0..@intCast(s.size)];
                const h = scribe.shannon(slice);
                try out.print("  {s:<24} {d:.4}\n", .{ s.name, h });
            }
        },
        .macho => |m| {
            for (m.sections) |s| {
                if (s.size == 0 or s.offset == 0) continue;
                const start: usize = s.offset;
                const end: usize = start + @as(usize, @intCast(s.size));
                if (end > bytes.len) continue;
                const h = scribe.shannon(bytes[start..end]);
                try out.print("  {s:<16}/{s:<16} {d:.4}\n", .{ s.seg, s.name, h });
            }
        },
        .pe => |p| {
            for (p.sections) |s| {
                if (s.raw_size == 0) continue;
                const start: usize = s.raw_offset;
                const end: usize = start + s.raw_size;
                if (end > bytes.len) continue;
                const h = scribe.shannon(bytes[start..end]);
                try out.print("  {s:<10} {d:.4}\n", .{ s.name, h });
            }
        },
    }
}

fn runSbom(
    io: Io,
    gpa: std.mem.Allocator,
    out: *Io.Writer,
    path: []const u8,
    plain: bool,
    style: scribe.term.Style,
    prog: *scribe.progress.Reporter,
) !void {
    if (std.mem.startsWith(u8, path, "registry://")) {
        var bom = try scribe.registry.pullSbom(gpa, io, path, .{ .progress = prog });
        defer bom.deinit(gpa);
        prog.finish(null);
        try emitSbom(out, .{ .components = bom.components, .config_issues = bom.config_issues }, plain, style);
        return;
    }

    if (scribe.local_docker.isLocalDockerUri(path)) {
        var bom = try scribe.local_docker.pullSbomWithProgress(gpa, io, path, prog);
        defer bom.deinit(gpa);
        prog.finish(null);
        try emitSbom(out, .{ .components = bom.components, .config_issues = bom.config_issues }, plain, style);
        return;
    }

    var mapping = try scribe.mmap.open(io, path);
    defer mapping.deinit();
    const bytes = mapping.bytes();

    if (scribe.container.isContainer(bytes)) {
        prog.start("analyzing image layers");
        var bom = try scribe.container.collect(gpa, bytes);
        defer bom.deinit(gpa);
        prog.finish(null);
        try emitSbom(out, .{ .components = bom.components, .config_issues = bom.config_issues }, plain, style);
    } else {
        var bom = try scribe.sbom.collect(gpa, bytes);
        defer bom.deinit(gpa);
        try emitSbom(out, bom, plain, style);
    }
}

fn emitSbom(out: *Io.Writer, bom: scribe.sbom.Sbom, plain: bool, style: scribe.term.Style) !void {
    if (plain) {
        if (bom.components.len == 0) {
            try style.span(out, scribe.term.codes.dim, "(no components detected)");
            try out.writeByte('\n');
            return;
        }
        for (bom.components) |c| {
            // kind (cyan) + name (default) + version (bright) + platform + evidence (dim)
            try style.span(out, scribe.term.codes.cyan, @tagName(c.kind));
            try out.writeAll(" ");
            // pad to width 13 manually so ANSI codes don't break alignment.
            try padTo(out, @tagName(c.kind).len, 13);
            try out.print("{s:<28} ", .{c.name});
            if (c.version) |v| {
                try style.span(out, scribe.term.codes.bright_yellow, v);
                try padTo(out, v.len, 16);
            } else {
                try out.writeAll("-");
                try padTo(out, 1, 16);
            }
            try out.print("{s:<14} ", .{c.platform orelse "-"});
            try style.dim(out, "via=");
            try style.dim(out, @tagName(c.evidence));
            if (c.path) |p| {
                try out.writeAll(" ");
                try style.dim(out, "@ ");
                try style.dim(out, p);
            }
            try out.writeByte('\n');
        }
    } else {
        try scribe.sbom.writeCycloneDX(out, bom);
    }
}

/// Pad with spaces from `current_len` to `target_width`. Keeps columns
/// aligned even when ANSI sequences inflate the byte length.
fn padTo(out: *Io.Writer, current_len: usize, target_width: usize) !void {
    if (current_len >= target_width) {
        try out.writeByte(' ');
        return;
    }
    var i: usize = 0;
    while (i < target_width - current_len) : (i += 1) try out.writeByte(' ');
}

fn stripHexPrefix(s: []const u8) []const u8 {
    if (s.len >= 2 and s[0] == '0' and (s[1] == 'x' or s[1] == 'X')) return s[2..];
    return s;
}

/// Build the conventional `.dSYM` companion path for a Mach-O binary:
/// `<bin>.dSYM/Contents/Resources/DWARF/<basename>`. Returns null when the
/// constructed path wouldn't fit in `buf` (filename too long).
fn dsymCandidate(bin_path: []const u8, buf: []u8) ?[]const u8 {
    const base = std.fs.path.basename(bin_path);
    return std.fmt.bufPrint(
        buf,
        "{s}.dSYM/Contents/Resources/DWARF/{s}",
        .{ bin_path, base },
    ) catch null;
}

fn runSymbols(
    io: Io,
    gpa: std.mem.Allocator,
    out: *Io.Writer,
    path: []const u8,
) !void {
    var mapping = try scribe.mmap.open(io, path);
    defer mapping.deinit();

    var dsym_path_buf: [std.fs.max_path_bytes]u8 = undefined;
    var dsym_mapping_opt: ?scribe.mmap.Mapping = null;
    defer if (dsym_mapping_opt) |*m| m.deinit();

    var sym = scribe.dwarf.open(gpa, mapping.bytes()) catch |err| switch (err) {
        error.NoDebugInfo => blk: {
            // For Mach-O, fall back to a sibling `.dSYM` bundle (the macOS
            // toolchain default — debug info lives there, not in the
            // binary). For ELF/PE, no fallback path; rethrow.
            if (dsymCandidate(path, &dsym_path_buf)) |candidate| {
                dsym_mapping_opt = scribe.mmap.open(io, candidate) catch return err;
                break :blk try scribe.dwarf.open(gpa, dsym_mapping_opt.?.bytes());
            }
            return err;
        },
        else => return err,
    };
    defer sym.deinit(gpa);

    const Ctx = struct {
        out: *Io.Writer,
        printed: usize = 0,
        err: ?anyerror = null,
    };
    var ctx: Ctx = .{ .out = out };

    const cb = struct {
        fn f(name: []const u8, start: u64, end: u64, p: ?*anyopaque) void {
            const c: *Ctx = @ptrCast(@alignCast(p.?));
            if (c.err != null) return;
            c.out.print("0x{x:0>16}-0x{x:0>16} {s}\n", .{ start, end, name }) catch |e| {
                c.err = e;
                return;
            };
            c.printed += 1;
        }
    }.f;

    sym.iterateSymbols(cb, @ptrCast(&ctx));
    if (ctx.err) |e| return e;
    try out.print("({d} symbols)\n", .{ctx.printed});
}

fn runAddr2Line(
    io: Io,
    gpa: std.mem.Allocator,
    out: *Io.Writer,
    path: []const u8,
    addr: u64,
) !void {
    var mapping = try scribe.mmap.open(io, path);
    defer mapping.deinit();

    var dsym_path_buf: [std.fs.max_path_bytes]u8 = undefined;
    var dsym_mapping_opt: ?scribe.mmap.Mapping = null;
    defer if (dsym_mapping_opt) |*m| m.deinit();

    var sym = scribe.dwarf.open(gpa, mapping.bytes()) catch |err| switch (err) {
        error.NoDebugInfo => blk: {
            if (dsymCandidate(path, &dsym_path_buf)) |candidate| {
                dsym_mapping_opt = scribe.mmap.open(io, candidate) catch return err;
                break :blk try scribe.dwarf.open(gpa, dsym_mapping_opt.?.bytes());
            }
            return err;
        },
        else => return err,
    };
    defer sym.deinit(gpa);

    const name = sym.addressToSymbol(addr);
    const loc = try sym.addressToSourceLocation(gpa, addr);
    defer if (loc) |l| l.deinit(gpa);

    try out.print("addr:    0x{x}\n", .{addr});
    try out.print("symbol:  {s}\n", .{name orelse "(unknown)"});
    if (loc) |l| {
        try out.print("source:  {s}:{d}:{d}\n", .{ l.file, l.line, l.column });
    } else {
        try out.writeAll("source:  (unknown)\n");
    }
}

fn runFpGenerate(
    io: Io,
    gpa: std.mem.Allocator,
    out: *Io.Writer,
    path: []const u8,
    lib: []const u8,
    version: ?[]const u8,
) !void {
    var mapping = try scribe.mmap.open(io, path);
    defer mapping.deinit();

    var db = try scribe.fingerprint.generate(gpa, mapping.bytes(), .{
        .lib = lib,
        .version = version,
    });
    defer db.deinit(gpa);
    try db.writeJson(out);
}

fn runFpMatch(
    io: Io,
    gpa: std.mem.Allocator,
    out: *Io.Writer,
    path: []const u8,
    db_path: []const u8,
) !void {
    var target_map = try scribe.mmap.open(io, path);
    defer target_map.deinit();

    var db_map = try scribe.mmap.open(io, db_path);
    defer db_map.deinit();

    var db = try scribe.fingerprint.Database.parseJson(gpa, db_map.bytes());
    defer db.deinit(gpa);

    var hits = try scribe.fingerprint.match(gpa, target_map.bytes(), db);
    defer gpa.free(hits);

    var via_sliding = false;
    if (hits.len == 0) {
        // Target lacked DWARF/symtab, or no symbol-driven hits. Fall back
        // to sliding-window match against the corpus's body sizes.
        gpa.free(hits);
        hits = scribe.fingerprint.matchSliding(gpa, target_map.bytes(), db) catch &[_]scribe.fingerprint.Match{};
        via_sliding = true;
    }

    if (hits.len == 0) {
        try out.writeAll("(no fingerprint matches)\n");
        return;
    }
    if (via_sliding) try out.writeAll("# matches via sliding-window scan (target has no DWARF)\n");
    for (hits) |h| {
        try out.print(
            "0x{x:0>16}  {s:<32}  ->  {s} {s}{s}{s}\n",
            .{
                h.target_addr,
                h.target_function,
                h.db_entry.lib,
                if (h.db_entry.version) |_| " " else "",
                h.db_entry.version orelse "",
                if (!via_sliding and !std.mem.eql(u8, h.db_entry.name, h.target_function))
                    " (renamed)"
                else
                    "",
            },
        );
    }
    try out.print("({d} matches)\n", .{hits.len});
}

fn runSecrets(
    io: Io,
    gpa: std.mem.Allocator,
    out: *Io.Writer,
    path: []const u8,
    opts: scribe.security.secrets.ScanOptions,
    json: bool,
    style: scribe.term.Style,
) !void {
    var mapping = try scribe.mmap.open(io, path);
    defer mapping.deinit();

    var findings = try scribe.security.secrets.scan(gpa, mapping.bytes(), opts);
    defer findings.deinit(gpa);

    if (json) {
        try emitFindingsJson(out, findings);
    } else {
        try emitFindingsPlain(out, findings, style);
    }
}

fn emitFindingsPlain(
    out: *Io.Writer,
    findings: scribe.security.secrets.Findings,
    style: scribe.term.Style,
) !void {
    if (findings.items.len == 0) {
        try style.span(out, scribe.term.codes.bold_green, "✓ no secrets detected");
        try out.writeByte('\n');
        return;
    }
    for (findings.items) |f| {
        // kind (yellow), label-dim, value, severity-colored confidence
        try style.span(out, scribe.term.codes.bright_yellow, @tagName(f.kind));
        try out.writeAll("  ");
        try style.dim(out, "off=");
        try out.print("0x{x:0>8}  ", .{f.offset});
        try style.dim(out, "conf=");
        try out.print("{d:>3}  ", .{@intFromEnum(f.confidence)});
        try out.writeAll(f.redacted_preview);
        try out.writeByte('\n');
    }
    try style.writeCount(out, findings.items.len, "findings");
}

fn emitFindingsJson(out: *Io.Writer, findings: scribe.security.secrets.Findings) !void {
    try out.writeAll("[");
    for (findings.items, 0..) |f, i| {
        if (i > 0) try out.writeByte(',');
        try out.writeAll("\n  {\"kind\": \"");
        try out.writeAll(@tagName(f.kind));
        try out.print(
            "\", \"offset\": {d}, \"length\": {d}, \"entropy\": {d:.3}, \"confidence\": {d}, \"preview\": ",
            .{ f.offset, f.length, f.entropy, @intFromEnum(f.confidence) },
        );
        try writeJsonString(out, f.redacted_preview);
        try out.writeByte('}');
    }
    if (findings.items.len > 0) try out.writeByte('\n');
    try out.writeAll("]\n");
}

fn runVulns(
    io: Io,
    gpa: std.mem.Allocator,
    out: *Io.Writer,
    target_path: []const u8,
    db_path: []const u8,
    json: bool,
    style: scribe.term.Style,
    prog: *scribe.progress.Reporter,
) !void {
    prog.start("loading advisory db");
    var db_map = try scribe.mmap.open(io, db_path);
    defer db_map.deinit();
    var db = try scribe.security.vulnerability.load(gpa, db_map.bytes());
    defer db.deinit(gpa);

    // Build an Sbom from the target. Same source-detection as `runSbom` /
    // `runScan` so vuln matching works against binaries, container tars,
    // local docker images, and direct registry pulls.
    var bom: scribe.sbom.Sbom = blk: {
        if (std.mem.startsWith(u8, target_path, "registry://")) {
            var img = try scribe.registry.pullSbom(gpa, io, target_path, .{ .progress = prog });
            const s: scribe.sbom.Sbom = .{
                .components = img.components,
                .config_issues = img.config_issues,
            };
            img.components = &.{};
            img.config_issues = &.{};
            break :blk s;
        }
        if (scribe.local_docker.isLocalDockerUri(target_path)) {
            var img = try scribe.local_docker.pullSbomWithProgress(gpa, io, target_path, prog);
            const s: scribe.sbom.Sbom = .{
                .components = img.components,
                .config_issues = img.config_issues,
            };
            img.components = &.{};
            img.config_issues = &.{};
            break :blk s;
        }
        var target = try scribe.mmap.open(io, target_path);
        defer target.deinit();
        const bytes = target.bytes();
        if (scribe.container.isContainer(bytes)) {
            prog.step("analyzing image layers");
            var img = try scribe.container.collect(gpa, bytes);
            const s: scribe.sbom.Sbom = .{
                .components = img.components,
                .config_issues = img.config_issues,
            };
            img.components = &.{};
            img.config_issues = &.{};
            break :blk s;
        }
        prog.step("collecting sbom");
        break :blk try scribe.sbom.collect(gpa, bytes);
    };
    defer bom.deinit(gpa);

    prog.step("matching advisories");
    const refs = try gpa.alloc(scribe.security.vulnerability.ComponentRef, bom.components.len);
    defer gpa.free(refs);
    for (bom.components, 0..) |c, i| {
        refs[i] = .{ .name = c.name, .version = if (c.version) |v| v else null };
    }

    var vulns = try scribe.security.vulnerability.match(gpa, refs, db);
    defer vulns.deinit(gpa);

    prog.finish(null);
    if (json) {
        try emitVulnsJson(out, vulns);
    } else {
        try emitVulnsPlain(out, vulns, style);
    }
}

fn emitVulnsPlain(
    out: *Io.Writer,
    vulns: scribe.security.vulnerability.Vulnerabilities,
    style: scribe.term.Style,
) !void {
    if (vulns.items.len == 0) {
        try style.span(out, scribe.term.codes.bold_green, "✓ no advisories matched");
        try out.writeByte('\n');
        return;
    }
    for (vulns.items) |v| {
        // advisory id bold; package@version normal; severity colored.
        try style.bold(out, v.advisory_id);
        try out.writeAll("  ");
        try out.writeAll(v.package);
        if (v.matched_version) |mv| {
            try style.dim(out, "@");
            try out.writeAll(mv);
        }
        try out.writeAll("  [");
        try style.writeSeverity(out, @tagName(v.severity));
        try out.writeByte(']');
        if (v.cvss) |c| {
            try out.writeAll(" ");
            try style.dim(out, "cvss=");
            try out.print("{d:.1}", .{c});
        }
        if (v.fixed_version) |f| {
            try out.writeAll(" ");
            try style.dim(out, "fixed=");
            try out.writeAll(f);
        }
        try out.writeAll("\n  ");
        try style.dim(out, v.summary);
        try out.writeByte('\n');
    }
    try style.writeCount(out, vulns.items.len, "vulnerabilities");
}

fn emitVulnsJson(out: *Io.Writer, vulns: scribe.security.vulnerability.Vulnerabilities) !void {
    try out.writeAll("[");
    for (vulns.items, 0..) |v, i| {
        if (i > 0) try out.writeByte(',');
        try out.writeAll("\n  {\"id\": ");
        try writeJsonString(out, v.advisory_id);
        try out.writeAll(", \"package\": ");
        try writeJsonString(out, v.package);
        if (v.matched_version) |ver| {
            try out.writeAll(", \"version\": ");
            try writeJsonString(out, ver);
        }
        try out.writeAll(", \"severity\": \"");
        try out.writeAll(@tagName(v.severity));
        try out.writeByte('"');
        if (v.cvss) |c| try out.print(", \"cvss\": {d:.2}", .{c});
        if (v.fixed_version) |f| {
            try out.writeAll(", \"fixed\": ");
            try writeJsonString(out, f);
        }
        try out.writeAll(", \"summary\": ");
        try writeJsonString(out, v.summary);
        if (v.references.len > 0) {
            try out.writeAll(", \"references\": [");
            for (v.references, 0..) |r, j| {
                if (j > 0) try out.writeByte(',');
                try writeJsonString(out, r);
            }
            try out.writeByte(']');
        }
        try out.writeByte('}');
    }
    if (vulns.items.len > 0) try out.writeByte('\n');
    try out.writeAll("]\n");
}

fn runScan(
    io: Io,
    gpa: std.mem.Allocator,
    out: *Io.Writer,
    target_path: []const u8,
    db_path: ?[]const u8,
    config_path: ?[]const u8,
    fp_db_path: ?[]const u8,
    yara_path: ?[]const u8,
    sec_opts: scribe.security.secrets.ScanOptions,
    plain: bool,
    sarif: bool,
    gha: bool,
    style: scribe.term.Style,
    prog: *scribe.progress.Reporter,
) !void {
    prog.start("opening target");
    var target = try scribe.mmap.open(io, target_path);
    defer target.deinit();
    const bytes = target.bytes();

    // Detect container vs binary target. Container path also auto-runs IaC
    // audit on embedded Dockerfiles / *.yaml / *.yml from the squashed layers.
    var bom: scribe.sbom.Sbom = if (scribe.container.isContainer(bytes)) blk: {
        prog.step("analyzing image layers");
        var img = try scribe.container.collect(gpa, bytes);
        const s: scribe.sbom.Sbom = .{
            .components = img.components,
            .config_issues = img.config_issues,
        };
        img.components = &.{};
        img.config_issues = &.{};
        break :blk s;
    } else cb: {
        prog.step("collecting sbom");
        break :cb try scribe.sbom.collect(gpa, bytes);
    };
    defer bom.deinit(gpa);

    // Auto-enable wide-string scanning for PE targets — wide UTF-16LE
    // strings are the primary text-storage convention in Windows binaries.
    prog.step("scanning secrets");
    var sec_opts_eff = sec_opts;
    if (bytes.len >= 2 and bytes[0] == 'M' and bytes[1] == 'Z') sec_opts_eff.scan_wide = true;
    var findings = try scribe.security.secrets.scan(gpa, bytes, sec_opts_eff);
    bom.findings = findings.items; // ownership moves into Sbom.deinit
    findings.items = &.{};

    // Fingerprint cross-ref: match function-byte fingerprints against the
    // corpus and append unique (lib, version) hits as Components evidenced
    // by `fingerprint`. Downstream vuln matcher then looks them up.
    if (fp_db_path) |fp| {
        prog.step("matching fingerprints");
        try augmentBomWithFingerprint(io, gpa, bytes, fp, &bom);
    }

    // YARA pass — optional. Folds matches into config_issues with severity
    // info (rule had no `meta: severity = "..."` field surfaced yet). Each
    // rule that fires becomes one issue.
    if (yara_path) |yp| {
        prog.step("running yara rules");
        var rules_map = try scribe.mmap.open(io, yp);
        defer rules_map.deinit();
        var rules = try scribe.security.yara.parse(gpa, rules_map.bytes());
        defer rules.deinit(gpa);
        const matches = try scribe.security.yara.scan(gpa, rules, bytes);
        defer scribe.security.yara.freeMatches(gpa, matches);

        if (matches.len > 0) {
            const yara_issues = try gpa.alloc(scribe.security.config.Issue, matches.len);
            errdefer gpa.free(yara_issues);
            for (matches, 0..) |m, i| {
                const rule_id = std.fmt.allocPrint(gpa, "YARA-{s}", .{m.rule}) catch return error.OutOfMemory;
                errdefer gpa.free(rule_id);
                const title = std.fmt.allocPrint(gpa, "YARA rule matched: {s} ({d} hits)", .{ m.rule, m.hits.len }) catch return error.OutOfMemory;
                errdefer gpa.free(title);
                const file_copy = gpa.dupe(u8, target_path) catch return error.OutOfMemory;
                errdefer gpa.free(file_copy);
                const snippet = if (m.hits.len > 0)
                    std.fmt.allocPrint(gpa, "first hit @ 0x{x}", .{m.hits[0].offset}) catch return error.OutOfMemory
                else
                    gpa.dupe(u8, "") catch return error.OutOfMemory;
                errdefer gpa.free(snippet);
                const recommendation = gpa.dupe(u8, "Investigate matched bytes; tune rule or whitelist if benign.") catch return error.OutOfMemory;
                yara_issues[i] = .{
                    .rule_id = rule_id,
                    .title = title,
                    .severity = .medium,
                    .source = .image_config,
                    .file = file_copy,
                    .line = 0,
                    .snippet = snippet,
                    .recommendation = recommendation,
                };
            }
            const merged = try gpa.alloc(scribe.security.config.Issue, bom.config_issues.len + yara_issues.len);
            @memcpy(merged[0..bom.config_issues.len], bom.config_issues);
            @memcpy(merged[bom.config_issues.len..], yara_issues);
            gpa.free(bom.config_issues);
            gpa.free(yara_issues);
            bom.config_issues = merged;
        }
    }

    // Hardening + anomaly passes — only meaningful on a single binary
    // target. Container sources iterate per-bundled-binary themselves;
    // skip for now to avoid duplicating image_config issues.
    if (!scribe.container.isContainer(bytes)) {
        prog.step("checking exploit mitigations");
        if (scribe.parseFormat(gpa, bytes)) |fmt_info_const| {
            var fmt_info = fmt_info_const;
            defer fmt_info.deinit(gpa);
            if (scribe.analyzeHardening(gpa, fmt_info, bytes)) |report_const| {
                var report = report_const;
                defer report.deinit(gpa);
                if (scribe.security.hardening.toConfigIssues(gpa, report, target_path)) |hard_issues| {
                    if (hard_issues.len > 0) {
                        const merged = try gpa.alloc(scribe.security.config.Issue, bom.config_issues.len + hard_issues.len);
                        @memcpy(merged[0..bom.config_issues.len], bom.config_issues);
                        @memcpy(merged[bom.config_issues.len..], hard_issues);
                        gpa.free(bom.config_issues);
                        gpa.free(hard_issues);
                        bom.config_issues = merged;
                    } else {
                        gpa.free(hard_issues);
                    }
                } else |_| {}
            } else |_| {}
            // Anti-tampering anomalies — separate analyzer over same parse.
            if (scribe.security.anomalies.analyze(gpa, fmt_info, bytes)) |arep_const| {
                var arep = arep_const;
                defer arep.deinit(gpa);
                if (scribe.security.anomalies.toConfigIssues(gpa, arep, target_path)) |anom_issues| {
                    if (anom_issues.len > 0) {
                        const merged = try gpa.alloc(scribe.security.config.Issue, bom.config_issues.len + anom_issues.len);
                        @memcpy(merged[0..bom.config_issues.len], bom.config_issues);
                        @memcpy(merged[bom.config_issues.len..], anom_issues);
                        gpa.free(bom.config_issues);
                        gpa.free(anom_issues);
                        bom.config_issues = merged;
                    } else {
                        gpa.free(anom_issues);
                    }
                } else |_| {}
            } else |_| {}
        } else |_| {}
    }

    if (db_path) |dp| {
        prog.step("matching advisories");
        var db_map = try scribe.mmap.open(io, dp);
        defer db_map.deinit();
        var db = try scribe.security.vulnerability.load(gpa, db_map.bytes());
        defer db.deinit(gpa);

        const refs = try gpa.alloc(scribe.security.vulnerability.ComponentRef, bom.components.len);
        defer gpa.free(refs);
        for (bom.components, 0..) |c, i| {
            refs[i] = .{ .name = c.name, .version = if (c.version) |v| v else null };
        }
        var vulns = try scribe.security.vulnerability.match(gpa, refs, db);
        bom.vulnerabilities = vulns.items;
        vulns.items = &.{};
    }

    // Explicit --config <path> appends issues alongside any auto-discovered
    // ones from the container layers.
    if (config_path) |cp| {
        prog.step("auditing config");
        var cfg_map = try scribe.mmap.open(io, cp);
        defer cfg_map.deinit();
        var issues = try scribe.security.config.audit(gpa, cfg_map.bytes(), cp, .auto);
        if (bom.config_issues.len == 0) {
            bom.config_issues = issues.items;
            issues.items = &.{};
        } else {
            const merged = try gpa.alloc(scribe.security.config.Issue, bom.config_issues.len + issues.items.len);
            @memcpy(merged[0..bom.config_issues.len], bom.config_issues);
            @memcpy(merged[bom.config_issues.len..], issues.items);
            gpa.free(bom.config_issues);
            gpa.free(issues.items);
            bom.config_issues = merged;
            issues.items = &.{};
        }
    }

    prog.finish(null);
    if (sarif) {
        try emitSarif(out, target_path, bom);
        return;
    }
    if (gha) {
        try emitGitHubAnnotations(out, bom);
        return;
    }
    if (plain) {
        // Components header
        try writeSection(out, style, "components");
        try emitSbom(out, bom, true, style);

        if (bom.findings.len > 0) {
            try out.writeByte('\n');
            try writeSection(out, style, "secrets");
            for (bom.findings) |f| {
                try out.writeAll("  ");
                try style.span(out, scribe.term.codes.bright_yellow, @tagName(f.kind));
                try out.writeAll("  ");
                try style.dim(out, "off=");
                try out.print("0x{x:0>8}  ", .{f.offset});
                try style.dim(out, "conf=");
                try out.print("{d:>3}  ", .{@intFromEnum(f.confidence)});
                try out.writeAll(f.redacted_preview);
                try out.writeByte('\n');
            }
        }
        if (bom.vulnerabilities.len > 0) {
            try out.writeByte('\n');
            try writeSection(out, style, "vulnerabilities");
            for (bom.vulnerabilities) |v| {
                try out.writeAll("  ");
                try style.bold(out, v.advisory_id);
                try out.writeAll("  ");
                try out.writeAll(v.package);
                if (v.matched_version) |mv| {
                    try style.dim(out, "@");
                    try out.writeAll(mv);
                }
                try out.writeAll("  [");
                try style.writeSeverity(out, @tagName(v.severity));
                try out.writeAll("]\n");
            }
        }
        if (bom.config_issues.len > 0) {
            try out.writeByte('\n');
            try writeSection(out, style, "config issues");
            for (bom.config_issues) |it| {
                try out.writeAll("  ");
                try style.bold(out, it.rule_id);
                try out.writeAll("  [");
                try style.writeSeverity(out, @tagName(it.severity));
                try out.writeAll("]  ");
                try out.writeAll(it.title);
                if (it.line > 0) {
                    try out.writeAll("  ");
                    try style.dim(out, "(");
                    try style.dim(out, it.file);
                    try style.dim(out, ":");
                    var lbuf: [16]u8 = undefined;
                    const ls = std.fmt.bufPrint(&lbuf, "{d}", .{it.line}) catch "?";
                    try style.dim(out, ls);
                    try style.dim(out, ")");
                } else {
                    try out.writeAll("  ");
                    try style.dim(out, "(");
                    try style.dim(out, it.file);
                    try style.dim(out, ")");
                }
                try out.writeByte('\n');
            }
        }

        // Trailer summary line.
        try out.writeByte('\n');
        try writeSummary(out, style, bom);
    } else {
        try scribe.sbom.writeCycloneDX(out, bom);
    }
}

fn emitSarif(out: *Io.Writer, target_path: []const u8, bom: scribe.sbom.Sbom) !void {
    // SARIF 2.1.0 minimal — single run, single tool. Each finding is a result
    // with a stable ruleId, severity mapping, message, and a partial location
    // (file path; line numbers absent for binary-derived findings).
    try out.writeAll("{\"version\":\"2.1.0\",\"$schema\":\"https://docs.oasis-open.org/sarif/sarif/v2.1.0/cs01/schemas/sarif-schema-2.1.0.json\",\"runs\":[{");
    try out.writeAll("\"tool\":{\"driver\":{\"name\":\"scribe\",\"version\":\"");
    try out.writeAll(scribe_version);
    try out.writeAll("\",\"informationUri\":\"https://github.com/anthropic-experimental/scribe\"}},");
    try out.writeAll("\"results\":[");

    var first = true;
    for (bom.findings) |f| {
        if (!first) try out.writeAll(",");
        first = false;
        try out.print("{{\"ruleId\":\"SECRET-{s}\",\"level\":\"warning\",\"message\":{{\"text\":\"secret {s} (confidence={d})\"}},", .{
            @tagName(f.kind), @tagName(f.kind), @intFromEnum(f.confidence),
        });
        try out.print("\"locations\":[{{\"physicalLocation\":{{\"artifactLocation\":{{\"uri\":\"{s}\"}},\"region\":{{\"byteOffset\":{d}}}}}}}]}}", .{ target_path, f.offset });
    }
    for (bom.vulnerabilities) |v| {
        if (!first) try out.writeAll(",");
        first = false;
        const lvl = sarifLevelForSeverity(@tagName(v.severity));
        try out.print("{{\"ruleId\":\"{s}\",\"level\":\"{s}\",\"message\":{{\"text\":\"{s} affects {s}", .{ v.advisory_id, lvl, v.advisory_id, v.package });
        if (v.matched_version) |mv| try out.print("@{s}", .{mv});
        try out.writeAll("\"}");
        try out.print(",\"locations\":[{{\"physicalLocation\":{{\"artifactLocation\":{{\"uri\":\"{s}\"}}}}}}]}}", .{target_path});
    }
    for (bom.config_issues) |it| {
        if (!first) try out.writeAll(",");
        first = false;
        const lvl = sarifLevelForSeverity(@tagName(it.severity));
        try out.print("{{\"ruleId\":\"{s}\",\"level\":\"{s}\",\"message\":{{\"text\":\"", .{ it.rule_id, lvl });
        try writeJsonEscaped(out, it.title);
        try out.writeAll("\"},");
        try out.print("\"locations\":[{{\"physicalLocation\":{{\"artifactLocation\":{{\"uri\":\"{s}\"}}", .{it.file});
        if (it.line > 0) try out.print(",\"region\":{{\"startLine\":{d}}}", .{it.line});
        try out.writeAll("}}]}");
    }

    try out.writeAll("]}]}\n");
}

fn sarifLevelForSeverity(s: []const u8) []const u8 {
    if (std.mem.eql(u8, s, "critical")) return "error";
    if (std.mem.eql(u8, s, "high")) return "error";
    if (std.mem.eql(u8, s, "medium")) return "warning";
    if (std.mem.eql(u8, s, "low")) return "note";
    return "note";
}

fn emitGitHubAnnotations(out: *Io.Writer, bom: scribe.sbom.Sbom) !void {
    // GitHub Actions workflow command format:
    //   ::warning file=...,line=...::message
    //   ::error file=...::message
    // One annotation per line. Severity → "warning" / "error" / "notice".
    for (bom.vulnerabilities) |v| {
        const lvl = ghaLevelForSeverity(@tagName(v.severity));
        try out.print("::{s} title={s}::{s} affects {s}", .{ lvl, v.advisory_id, v.advisory_id, v.package });
        if (v.matched_version) |mv| try out.print("@{s}", .{mv});
        try out.writeByte('\n');
    }
    for (bom.config_issues) |it| {
        const lvl = ghaLevelForSeverity(@tagName(it.severity));
        try out.print("::{s} file={s}", .{ lvl, it.file });
        if (it.line > 0) try out.print(",line={d}", .{it.line});
        try out.print(",title={s}::", .{it.rule_id});
        try out.writeAll(it.title);
        try out.writeByte('\n');
    }
    for (bom.findings) |f| {
        try out.print("::warning title=secret-{s}::{s} match (confidence={d}, offset=0x{x})\n", .{
            @tagName(f.kind), @tagName(f.kind), @intFromEnum(f.confidence), f.offset,
        });
    }
}

fn ghaLevelForSeverity(s: []const u8) []const u8 {
    if (std.mem.eql(u8, s, "critical")) return "error";
    if (std.mem.eql(u8, s, "high")) return "error";
    if (std.mem.eql(u8, s, "medium")) return "warning";
    return "notice";
}

fn writeSection(out: *Io.Writer, style: scribe.term.Style, label: []const u8) !void {
    try style.span(out, scribe.term.codes.bold, label);
    try style.dim(out, ":");
    try out.writeByte('\n');
}

fn writeSummary(out: *Io.Writer, style: scribe.term.Style, bom: scribe.sbom.Sbom) !void {
    try style.bold(out, "summary");
    try style.dim(out, ":  ");
    try out.print("{d} components", .{bom.components.len});
    try style.dim(out, ", ");
    if (bom.findings.len == 0) {
        try style.span(out, scribe.term.codes.green, "0 secrets");
    } else {
        try style.span(out, scribe.term.codes.bold_red, "");
        try out.print("{d} secrets", .{bom.findings.len});
        try style.close(out);
    }
    try style.dim(out, ", ");
    if (bom.vulnerabilities.len == 0) {
        try style.span(out, scribe.term.codes.green, "0 vulns");
    } else {
        try style.open(out, scribe.term.codes.bold_red);
        try out.print("{d} vulns", .{bom.vulnerabilities.len});
        try style.close(out);
    }
    try style.dim(out, ", ");
    if (bom.config_issues.len == 0) {
        try style.span(out, scribe.term.codes.green, "0 config issues");
    } else {
        try style.open(out, scribe.term.codes.bold_red);
        try out.print("{d} config issues", .{bom.config_issues.len});
        try style.close(out);
    }
    try out.writeByte('\n');
}

fn runConfig(
    io: Io,
    gpa: std.mem.Allocator,
    out: *Io.Writer,
    path: []const u8,
    ctype: scribe.security.config.ConfigType,
    json: bool,
    style: scribe.term.Style,
) !void {
    var mapping = try scribe.mmap.open(io, path);
    defer mapping.deinit();

    var issues = try scribe.security.config.audit(gpa, mapping.bytes(), path, ctype);
    defer issues.deinit(gpa);

    if (json) {
        try emitConfigJson(out, issues);
    } else {
        try emitConfigPlain(out, issues, style);
    }
}

fn emitConfigPlain(
    out: *Io.Writer,
    issues: scribe.security.config.Issues,
    style: scribe.term.Style,
) !void {
    if (issues.items.len == 0) {
        try style.span(out, scribe.term.codes.bold_green, "✓ no misconfigurations found");
        try out.writeByte('\n');
        return;
    }
    for (issues.items) |it| {
        try style.bold(out, it.rule_id);
        try out.writeAll("  [");
        try style.writeSeverity(out, @tagName(it.severity));
        try out.writeAll("]  ");
        try out.writeAll(it.title);
        try out.writeAll("  ");
        if (it.line > 0) {
            try style.dim(out, "(");
            try style.dim(out, it.file);
            try style.span(out, scribe.term.codes.dim, ":");
            var lbuf: [16]u8 = undefined;
            const ls = std.fmt.bufPrint(&lbuf, "{d}", .{it.line}) catch "?";
            try style.dim(out, ls);
            try style.dim(out, ")");
        } else {
            try style.dim(out, "(");
            try style.dim(out, it.file);
            try style.dim(out, ")");
        }
        try out.writeByte('\n');
        if (it.snippet.len > 0) {
            try style.dim(out, "        > ");
            try out.writeAll(it.snippet);
            try out.writeByte('\n');
        }
        if (it.recommendation.len > 0) {
            try style.span(out, scribe.term.codes.cyan, "        fix: ");
            try out.writeAll(it.recommendation);
            try out.writeByte('\n');
        }
    }
    try style.writeCount(out, issues.items.len, "issues");
}

fn emitConfigJson(out: *Io.Writer, issues: scribe.security.config.Issues) !void {
    try out.writeAll("[");
    for (issues.items, 0..) |it, i| {
        if (i > 0) try out.writeByte(',');
        try out.writeAll("\n  {\"rule_id\": ");
        try writeJsonString(out, it.rule_id);
        try out.writeAll(", \"title\": ");
        try writeJsonString(out, it.title);
        try out.print(
            ", \"severity\": \"{s}\", \"source\": \"{s}\", \"file\": ",
            .{ @tagName(it.severity), @tagName(it.source) },
        );
        try writeJsonString(out, it.file);
        if (it.line > 0) try out.print(", \"line\": {d}", .{it.line});
        if (it.snippet.len > 0) {
            try out.writeAll(", \"snippet\": ");
            try writeJsonString(out, it.snippet);
        }
        if (it.recommendation.len > 0) {
            try out.writeAll(", \"recommendation\": ");
            try writeJsonString(out, it.recommendation);
        }
        try out.writeByte('}');
    }
    if (issues.items.len > 0) try out.writeByte('\n');
    try out.writeAll("]\n");
}

fn runPolicy(
    io: Io,
    gpa: std.mem.Allocator,
    out: *Io.Writer,
    target_path: []const u8,
    policy_path: []const u8,
    db_path: ?[]const u8,
    config_path: ?[]const u8,
    sec_opts: scribe.security.secrets.ScanOptions,
    json: bool,
    style: scribe.term.Style,
    prog: *scribe.progress.Reporter,
) !u8 {
    prog.start("loading policy");
    var policy_map = try scribe.mmap.open(io, policy_path);
    defer policy_map.deinit();
    var policy = try scribe.security.policy.Policy.loadJson(gpa, policy_map.bytes());
    defer policy.deinit(gpa);

    var target = try scribe.mmap.open(io, target_path);
    defer target.deinit();
    const bytes = target.bytes();

    var bom: scribe.sbom.Sbom = if (scribe.container.isContainer(bytes)) blk: {
        prog.step("analyzing image layers");
        var img = try scribe.container.collect(gpa, bytes);
        const s: scribe.sbom.Sbom = .{
            .components = img.components,
            .config_issues = img.config_issues,
        };
        img.components = &.{};
        img.config_issues = &.{};
        break :blk s;
    } else cb: {
        prog.step("collecting sbom");
        break :cb try scribe.sbom.collect(gpa, bytes);
    };
    defer bom.deinit(gpa);

    prog.step("scanning secrets");
    var sec_opts_eff = sec_opts;
    if (bytes.len >= 2 and bytes[0] == 'M' and bytes[1] == 'Z') sec_opts_eff.scan_wide = true;
    var findings = try scribe.security.secrets.scan(gpa, bytes, sec_opts_eff);
    bom.findings = findings.items;
    findings.items = &.{};

    if (db_path) |dp| {
        prog.step("matching advisories");
        var db_map = try scribe.mmap.open(io, dp);
        defer db_map.deinit();
        var db = try scribe.security.vulnerability.load(gpa, db_map.bytes());
        defer db.deinit(gpa);
        const refs = try gpa.alloc(scribe.security.vulnerability.ComponentRef, bom.components.len);
        defer gpa.free(refs);
        for (bom.components, 0..) |c, i| refs[i] = .{ .name = c.name, .version = c.version };
        var vulns = try scribe.security.vulnerability.match(gpa, refs, db);
        bom.vulnerabilities = vulns.items;
        vulns.items = &.{};
    }

    if (config_path) |cp| {
        prog.step("auditing config");
        var cfg_map = try scribe.mmap.open(io, cp);
        defer cfg_map.deinit();
        var issues = try scribe.security.config.audit(gpa, cfg_map.bytes(), cp, .auto);
        if (bom.config_issues.len == 0) {
            bom.config_issues = issues.items;
            issues.items = &.{};
        } else {
            const merged = try gpa.alloc(scribe.security.config.Issue, bom.config_issues.len + issues.items.len);
            @memcpy(merged[0..bom.config_issues.len], bom.config_issues);
            @memcpy(merged[bom.config_issues.len..], issues.items);
            gpa.free(bom.config_issues);
            gpa.free(issues.items);
            bom.config_issues = merged;
            issues.items = &.{};
        }
    }

    prog.step("evaluating policy");
    var result = try scribe.security.policy.evaluate(gpa, policy, bom);
    defer result.deinit(gpa);

    prog.finish(null);
    if (json) {
        try emitPolicyJson(out, result);
    } else {
        try emitPolicyPlain(out, result, style);
    }

    return if (result.verdict == .pass) @as(u8, 0) else @as(u8, 1);
}

fn emitPolicyPlain(out: *Io.Writer, r: scribe.security.policy.Result, style: scribe.term.Style) !void {
    try style.bold(out, "verdict");
    try style.dim(out, ": ");
    if (r.verdict == .pass) {
        try style.span(out, scribe.term.codes.bold_green, "✓ pass");
    } else {
        try style.span(out, scribe.term.codes.bold_red, "✗ fail");
    }
    try out.writeByte('\n');
    if (r.violations.len == 0) return;
    try style.bold(out, "violations");
    try style.dim(out, ":");
    try out.writeByte('\n');
    for (r.violations) |v| {
        try out.writeAll("  [");
        try style.span(out, scribe.term.codes.bright_yellow, @tagName(v.axis));
        try out.writeAll("]  ");
        try style.dim(out, v.rule);
        try out.writeAll("  ");
        try style.dim(out, "→ ");
        try style.bold(out, v.detail);
        try out.writeAll("  (");
        try style.writeSeverity(out, v.severity_text);
        try out.writeAll(")\n");
    }
    try style.writeCount(out, r.violations.len, "violations");
}

fn emitPolicyJson(out: *Io.Writer, r: scribe.security.policy.Result) !void {
    try out.print("{{\n  \"verdict\": \"{s}\",\n  \"violations\": [", .{@tagName(r.verdict)});
    for (r.violations, 0..) |v, i| {
        if (i > 0) try out.writeByte(',');
        try out.writeAll("\n    {\"axis\": \"");
        try out.writeAll(@tagName(v.axis));
        try out.writeAll("\", \"rule\": ");
        try writeJsonString(out, v.rule);
        try out.writeAll(", \"detail\": ");
        try writeJsonString(out, v.detail);
        try out.writeAll(", \"severity\": ");
        try writeJsonString(out, v.severity_text);
        try out.writeByte('}');
    }
    if (r.violations.len > 0) try out.writeByte('\n');
    try out.writeAll("  ]\n}\n");
}

fn runVulndbCompile(
    io: Io,
    gpa: std.mem.Allocator,
    out: *Io.Writer,
    in_path: []const u8,
    out_path: []const u8,
) !void {
    // Special-case: `-` reads JSON from stdin. Useful for piping past
    // scribe's TLS issues (e.g. `curl <url> | scribe vulndb compile - out.scvd`).
    var stdin_owned: ?[]u8 = null;
    defer if (stdin_owned) |b| gpa.free(b);

    if (!std.mem.eql(u8, in_path, "-")) {
        // File path: mmap and parse in place.
        var in_map = try scribe.mmap.open(io, in_path);
        defer in_map.deinit();
        var db_local = try scribe.security.vulnerability.load(gpa, in_map.bytes());
        defer db_local.deinit(gpa);

        var aw: std.Io.Writer.Allocating = .init(gpa);
        defer aw.deinit();
        try scribe.security.vulnerability.writeBinary(db_local, &aw.writer);
        const bytes = aw.written();

        try Io.Dir.cwd().writeFile(io, .{ .sub_path = out_path, .data = bytes });
        try out.print(
            "compiled {d} advisories  ->  {s}  ({d} bytes)\n",
            .{ db_local.advisories.len, out_path, bytes.len },
        );
        return;
    }

    // Stdin path: drain everything into a buffer.
    var stdin_buf: [16 * 1024]u8 = undefined;
    var sin: Io.File.Reader = .init(.stdin(), io, &stdin_buf);
    var aw_in: std.Io.Writer.Allocating = .init(gpa);
    defer aw_in.deinit();
    _ = sin.interface.streamRemaining(&aw_in.writer) catch |err| {
        try out.print("error: failed to read stdin: {s}\n", .{@errorName(err)});
        return err;
    };
    const owned = try aw_in.toOwnedSlice();
    stdin_owned = owned;
    const json_bytes: []const u8 = owned;

    // Stdin path: parse json_bytes (owned), write binary, write file.
    var db = scribe.security.vulnerability.load(gpa, json_bytes) catch |err| {
        try out.print("error: advisory JSON parse failed: {s}\n", .{@errorName(err)});
        try out.writeAll(
            \\(scribe accepts: scribe OSV-lite, OSV.dev native, or .scvd binary.
            \\ The CISA KEV catalog uses a different shape and needs jq conversion;
            \\ see SECURITY.md for the recipe.)
            \\
        );
        return err;
    };
    defer db.deinit(gpa);

    var aw2: std.Io.Writer.Allocating = .init(gpa);
    defer aw2.deinit();
    try scribe.security.vulnerability.writeBinary(db, &aw2.writer);
    const out_bytes = aw2.written();

    try Io.Dir.cwd().writeFile(io, .{ .sub_path = out_path, .data = out_bytes });
    try out.print(
        "compiled {d} advisories  ->  {s}  ({d} bytes)\n",
        .{ db.advisories.len, out_path, out_bytes.len },
    );
}

fn runVulndbMerge(
    io: Io,
    gpa: std.mem.Allocator,
    out: *Io.Writer,
    out_path: []const u8,
    in_paths: []const []const u8,
) !void {
    // Mmap each input DB. Lifetimes need to outlive `merge` because borrowed
    // SCVD strings reference the mappings.
    var mappings: std.ArrayList(scribe.mmap.Mapping) = .empty;
    defer {
        for (mappings.items) |*m| m.deinit();
        mappings.deinit(gpa);
    }
    var dbs: std.ArrayList(scribe.security.vulnerability.Database) = .empty;
    defer {
        for (dbs.items) |*d| d.deinit(gpa);
        dbs.deinit(gpa);
    }

    for (in_paths) |p| {
        const m = try scribe.mmap.open(io, p);
        try mappings.append(gpa, m);
        const db = try scribe.security.vulnerability.load(gpa, mappings.items[mappings.items.len - 1].bytes());
        try dbs.append(gpa, db);
    }

    var merged = try scribe.security.vulnerability.merge(gpa, dbs.items);
    defer merged.deinit(gpa);

    var aw: std.Io.Writer.Allocating = .init(gpa);
    defer aw.deinit();
    try scribe.security.vulnerability.writeBinary(merged, &aw.writer);
    const bytes = aw.written();

    try Io.Dir.cwd().writeFile(io, .{ .sub_path = out_path, .data = bytes });
    try out.print(
        "merged {d} inputs ({d} advisories total)  ->  {s}  ({d} bytes)\n",
        .{ in_paths.len, merged.advisories.len, out_path, bytes.len },
    );
}

fn runVulndbUpdate(
    io: Io,
    gpa: std.mem.Allocator,
    out: *Io.Writer,
    url: []const u8,
    out_path: []const u8,
    prog: *scribe.progress.Reporter,
) !void {
    var client: std.http.Client = .{ .allocator = gpa, .io = io };
    defer client.deinit();

    var body: std.Io.Writer.Allocating = .init(gpa);
    defer body.deinit();

    prog.stepf("fetching {s}", .{url});
    const result = client.fetch(.{
        .location = .{ .url = url },
        .response_writer = &body.writer,
        .extra_headers = &.{
            .{ .name = "Accept", .value = "application/json" },
        },
    }) catch |err| {
        try out.print("error: HTTP fetch failed: {s}\n", .{@errorName(err)});
        // Zig 0.16's std.http.Client TLS impl doesn't handle every server
        // out there (some cipher suites, ECH, oddball cert chains). Always
        // print a curl-based fallback so users have a path forward.
        try out.print(
            \\
            \\workaround — fetch externally and pipe in:
            \\  curl -sSL "{s}" | scribe vulndb compile - {s}
            \\
            \\
        ,
            .{ url, out_path },
        );
        out.flush() catch {};
        return err;
    };
    if (result.status != .ok) {
        try out.print("error: HTTP {d} from {s}\n", .{ @intFromEnum(result.status), url });
        return error.NotImplemented;
    }

    prog.step("parsing advisories");
    const json_bytes = body.writer.buffered();
    var db = scribe.security.vulnerability.load(gpa, json_bytes) catch |err| {
        try out.print("error: advisory JSON parse failed: {s}\n", .{@errorName(err)});
        return err;
    };
    defer db.deinit(gpa);

    prog.step("compiling .scvd");
    var aw: std.Io.Writer.Allocating = .init(gpa);
    defer aw.deinit();
    try scribe.security.vulnerability.writeBinary(db, &aw.writer);
    const out_bytes = aw.written();

    prog.stepf("writing {s}", .{out_path});
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = out_path, .data = out_bytes });
    prog.finish(null);
    try out.print(
        "fetched {d} advisories from {s}  ->  {s}  ({d} bytes)\n",
        .{ db.advisories.len, url, out_path, out_bytes.len },
    );
}

/// Run fingerprint.match against the target's function bytes using the
/// fingerprint corpus at `fp_db_path`. Append one Component per unique
/// (lib, version) pair to `bom.components` with evidence = .fingerprint.
/// Existing components carrying the same lib are *not* deduplicated —
/// the fingerprint hit acts as additional evidence of presence.
fn augmentBomWithFingerprint(
    io: Io,
    gpa: std.mem.Allocator,
    bytes: []const u8,
    fp_db_path: []const u8,
    bom: *scribe.sbom.Sbom,
) !void {
    var fp_db_map = try scribe.mmap.open(io, fp_db_path);
    defer fp_db_map.deinit();
    var fp_db = try scribe.fingerprint.Database.parseJson(gpa, fp_db_map.bytes());
    defer fp_db.deinit(gpa);

    const hits = scribe.fingerprint.match(gpa, bytes, fp_db) catch return;
    defer gpa.free(hits);
    if (hits.len == 0) return;

    // Dedupe by (lib, version).
    const Pair = struct { lib: []const u8, version: ?[]const u8 };
    var seen: std.ArrayList(Pair) = .empty;
    defer seen.deinit(gpa);

    var to_add: std.ArrayList(scribe.sbom.Component) = .empty;
    errdefer {
        for (to_add.items) |c| scribe.sbom.freeComponent(gpa, c);
        to_add.deinit(gpa);
    }

    outer: for (hits) |h| {
        for (seen.items) |s| {
            if (!std.mem.eql(u8, s.lib, h.db_entry.lib)) continue;
            const sv = s.version orelse "";
            const hv = h.db_entry.version orelse "";
            if (std.mem.eql(u8, sv, hv)) continue :outer;
        }
        try seen.append(gpa, .{ .lib = h.db_entry.lib, .version = h.db_entry.version });

        try to_add.append(gpa, .{
            .kind = .static_lib,
            .name = try gpa.dupe(u8, h.db_entry.lib),
            .version = if (h.db_entry.version) |v| try gpa.dupe(u8, v) else null,
            .evidence = .fingerprint,
        });
    }

    if (to_add.items.len == 0) return;

    const merged = try gpa.alloc(scribe.sbom.Component, bom.components.len + to_add.items.len);
    @memcpy(merged[0..bom.components.len], bom.components);
    @memcpy(merged[bom.components.len..], to_add.items);
    gpa.free(bom.components);
    bom.components = merged;
    to_add.items = &.{};
}

fn writeJsonString(out: *Io.Writer, s: []const u8) !void {
    try out.writeByte('"');
    for (s) |c| switch (c) {
        '"' => try out.writeAll("\\\""),
        '\\' => try out.writeAll("\\\\"),
        '\n' => try out.writeAll("\\n"),
        '\r' => try out.writeAll("\\r"),
        '\t' => try out.writeAll("\\t"),
        0...0x08, 0x0B, 0x0C, 0x0E...0x1F => try out.print("\\u{x:0>4}", .{c}),
        else => try out.writeByte(c),
    };
    try out.writeByte('"');
}

test "module imports resolve" {
    _ = scribe;
}
