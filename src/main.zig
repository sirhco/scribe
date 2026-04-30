const std = @import("std");
const Io = std.Io;

const scribe = @import("scribe");

const usage =
    \\scribe — binary forensics
    \\
    \\Usage:
    \\  scribe info <path>             format, arch, entry, sections
    \\  scribe deps <path>             dynamic library dependencies
    \\  scribe strings <path> [min]    printable ASCII runs (default min=4)
    \\  scribe entropy <path>          Shannon entropy per section
    \\  scribe sbom <path> [--plain]   bill of materials (CycloneDX 1.5 by default; --plain for human)
    \\  scribe secrets <path> [opts]   SIMD secret scan ([--json] [--include-generic] [--include-wide] [--min-entropy N])
    \\  scribe vulns <path> --db <p>   match SBOM components against advisory DB ([--json])
    \\  scribe config <path> [opts]    audit Dockerfile / k8s manifest ([--type dockerfile|kubernetes] [--json])
    \\  scribe scan <path> [opts]      full pipeline: SBOM + secrets + vulns + IaC + fingerprint
    \\                                 ([--db p] [--config p] [--fp-db p] [--include-generic] [--include-wide] [--plain])
    \\  scribe policy <path> --policy <p>  evaluate scan results against policy ([--db d] [--config c] [--json]); exits 1 on fail
    \\  scribe vulndb compile <in.json|-> <out.scvd>    compile JSON advisory DB to mmap-friendly binary (.scvd)
    \\  scribe vulndb merge <out.scvd> <in1> [in2...]   merge multiple .scvd or JSON advisory DBs into one
    \\  scribe vulndb update --from <url> --out <p>     fetch advisory JSON over HTTPS, compile to .scvd
    \\  scribe symbols <path>          DWARF function symbols (ELF or Mach-O dSYM)
    \\  scribe addr2line <path> <hex>  resolve address to source location
    \\  scribe fp generate <path> <lib> [version]    write fingerprint DB to stdout (JSON)
    \\  scribe fp match <path> <db.json>             match fns in <path> against DB
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
    const style = scribe.term.Style.auto(io, init.minimal.environ);

    const args = try init.minimal.args.toSlice(arena);
    if (args.len < 2) return die(stderr, usage, 1);

    const cmd = args[1];
    if (std.mem.eql(u8, cmd, "info")) {
        if (args.len < 3) return die(stderr, "error: 'info' requires a path\n", 1);
        runInfo(io, gpa, stdout, args[2]) catch |err| return dieErr(stderr, err);
        return;
    }
    if (std.mem.eql(u8, cmd, "deps")) {
        if (args.len < 3) return die(stderr, "error: 'deps' requires a path\n", 1);
        runDeps(io, gpa, stdout, args[2]) catch |err| return dieErr(stderr, err);
        return;
    }
    if (std.mem.eql(u8, cmd, "strings")) {
        if (args.len < 3) return die(stderr, "error: 'strings' requires a path\n", 1);
        const min: usize = if (args.len >= 4)
            std.fmt.parseInt(usize, args[3], 10) catch
                return die(stderr, "error: invalid min length\n", 1)
        else
            4;
        runStrings(io, stdout, args[2], min) catch |err| return dieErr(stderr, err);
        return;
    }
    if (std.mem.eql(u8, cmd, "entropy")) {
        if (args.len < 3) return die(stderr, "error: 'entropy' requires a path\n", 1);
        runEntropy(io, gpa, stdout, args[2]) catch |err| return dieErr(stderr, err);
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
        runSbom(io, gpa, stdout, args[2], plain, style) catch |err| return dieErr(stderr, err);
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
        runVulns(io, gpa, stdout, args[2], db, json, style) catch |err| return dieErr(stderr, err);
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
        var db_path: ?[]const u8 = null;
        var config_path: ?[]const u8 = null;
        var fp_db_path: ?[]const u8 = null;
        var sec_opts: scribe.security.secrets.ScanOptions = .{};
        var idx: usize = 3;
        while (idx < args.len) : (idx += 1) {
            const a = args[idx];
            if (std.mem.eql(u8, a, "--plain")) {
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
            } else {
                return die(stderr, "error: unknown 'scan' option\n", 1);
            }
        }
        runScan(io, gpa, stdout, args[2], db_path, config_path, fp_db_path, sec_opts, plain, style) catch |err| return dieErr(stderr, err);
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
            runVulndbUpdate(io, gpa, stdout, url, op) catch |err| return dieErr(stderr, err);
            return;
        }
        return die(stderr, "error: vulndb <compile|update>\n", 1);
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
        const code = runPolicy(io, gpa, stdout, args[2], pp, db_path, config_path, sec_opts, json, style) catch |err| return dieErr(stderr, err);
        stdout.flush() catch {};
        std.process.exit(code);
    }

    try stderr.print("error: unknown command '{s}'\n", .{cmd});
    try stderr.writeAll(usage);
    try stderr.flush();
    std.process.exit(1);
}

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

fn runInfo(io: Io, gpa: std.mem.Allocator, out: *Io.Writer, path: []const u8) !void {
    var mapping = try scribe.mmap.open(io, path);
    defer mapping.deinit();
    const bytes = mapping.bytes();

    var info = try scribe.parseFormat(gpa, bytes);
    defer info.deinit(gpa);

    try out.print("file:    {s}\n", .{path});
    try out.print("format:  {s}\n", .{@tagName(info)});
    try out.print("arch:    {s}\n", .{@tagName(info.arch())});
    try out.print("entry:   0x{x}\n", .{info.entry()});
    try out.print("64-bit:  {}\n", .{info.is64()});
    switch (info) {
        .elf => |e| try printElfSections(out, e),
        .macho => |m| try printMachoSections(out, m),
        .pe => |p| try printPeSections(out, p),
    }
}

fn printElfSections(out: *Io.Writer, e: scribe.ElfInfo) !void {
    try out.print("sections: {d}\n", .{e.sections.len});
    for (e.sections, 0..) |s, i| {
        try out.print(
            "  [{d:>3}] {s:<24} type=0x{x:0>4} addr=0x{x:0>16} size=0x{x}\n",
            .{ i, s.name, s.type, s.addr, s.size },
        );
    }
}

fn printMachoSections(out: *Io.Writer, m: scribe.MachoInfo) !void {
    try out.print("sections: {d}\n", .{m.sections.len});
    for (m.sections, 0..) |s, i| {
        try out.print(
            "  [{d:>3}] {s:<16} {s:<16} addr=0x{x:0>16} size=0x{x}\n",
            .{ i, s.seg, s.name, s.addr, s.size },
        );
    }
}

fn printPeSections(out: *Io.Writer, p: scribe.PeInfo) !void {
    try out.print("image base: 0x{x}\n", .{p.image_base});
    try out.print("sections: {d}\n", .{p.sections.len});
    for (p.sections, 0..) |s, i| {
        try out.print(
            "  [{d:>3}] {s:<10} vaddr=0x{x:0>8} vsize=0x{x:0>6} raw=0x{x:0>6}\n",
            .{ i, s.name, s.virtual_address, s.virtual_size, s.raw_size },
        );
    }
}

fn runDeps(io: Io, gpa: std.mem.Allocator, out: *Io.Writer, path: []const u8) !void {
    var mapping = try scribe.mmap.open(io, path);
    defer mapping.deinit();

    const list = try scribe.collectDeps(gpa, mapping.bytes());
    defer gpa.free(list);

    if (list.len == 0) {
        try out.writeAll("(no dynamic dependencies)\n");
        return;
    }
    for (list) |d| try out.print("  {s:<24} [{s}]\n", .{ d.name, @tagName(d.kind) });
}

fn runStrings(io: Io, out: *Io.Writer, path: []const u8, min_len: usize) !void {
    var mapping = try scribe.mmap.open(io, path);
    defer mapping.deinit();

    var it = scribe.scanStrings(mapping.bytes(), .{ .min_len = min_len });
    while (it.next()) |s| {
        try out.writeAll(s);
        try out.writeByte('\n');
    }
}

fn runEntropy(io: Io, gpa: std.mem.Allocator, out: *Io.Writer, path: []const u8) !void {
    var mapping = try scribe.mmap.open(io, path);
    defer mapping.deinit();
    const bytes = mapping.bytes();

    const overall = scribe.shannon(bytes);
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
) !void {
    if (std.mem.startsWith(u8, path, "registry://")) {
        var bom = try scribe.registry.pullSbom(gpa, io, path, .{});
        defer bom.deinit(gpa);
        try emitSbom(out, .{ .components = bom.components, .config_issues = bom.config_issues }, plain, style);
        return;
    }

    if (scribe.local_docker.isLocalDockerUri(path)) {
        var bom = try scribe.local_docker.pullSbom(gpa, io, path);
        defer bom.deinit(gpa);
        try emitSbom(out, .{ .components = bom.components, .config_issues = bom.config_issues }, plain, style);
        return;
    }

    var mapping = try scribe.mmap.open(io, path);
    defer mapping.deinit();
    const bytes = mapping.bytes();

    if (scribe.container.isContainer(bytes)) {
        var bom = try scribe.container.collect(gpa, bytes);
        defer bom.deinit(gpa);
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
) !void {
    var db_map = try scribe.mmap.open(io, db_path);
    defer db_map.deinit();
    var db = try scribe.security.vulnerability.load(gpa, db_map.bytes());
    defer db.deinit(gpa);

    // Build an Sbom from the target. Same source-detection as `runSbom` /
    // `runScan` so vuln matching works against binaries, container tars,
    // local docker images, and direct registry pulls.
    var bom: scribe.sbom.Sbom = blk: {
        if (std.mem.startsWith(u8, target_path, "registry://")) {
            var img = try scribe.registry.pullSbom(gpa, io, target_path, .{});
            const s: scribe.sbom.Sbom = .{
                .components = img.components,
                .config_issues = img.config_issues,
            };
            img.components = &.{};
            img.config_issues = &.{};
            break :blk s;
        }
        if (scribe.local_docker.isLocalDockerUri(target_path)) {
            var img = try scribe.local_docker.pullSbom(gpa, io, target_path);
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
            var img = try scribe.container.collect(gpa, bytes);
            const s: scribe.sbom.Sbom = .{
                .components = img.components,
                .config_issues = img.config_issues,
            };
            img.components = &.{};
            img.config_issues = &.{};
            break :blk s;
        }
        break :blk try scribe.sbom.collect(gpa, bytes);
    };
    defer bom.deinit(gpa);

    const refs = try gpa.alloc(scribe.security.vulnerability.ComponentRef, bom.components.len);
    defer gpa.free(refs);
    for (bom.components, 0..) |c, i| {
        refs[i] = .{ .name = c.name, .version = if (c.version) |v| v else null };
    }

    var vulns = try scribe.security.vulnerability.match(gpa, refs, db);
    defer vulns.deinit(gpa);

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
    sec_opts: scribe.security.secrets.ScanOptions,
    plain: bool,
    style: scribe.term.Style,
) !void {
    var target = try scribe.mmap.open(io, target_path);
    defer target.deinit();
    const bytes = target.bytes();

    // Detect container vs binary target. Container path also auto-runs IaC
    // audit on embedded Dockerfiles / *.yaml / *.yml from the squashed layers.
    var bom: scribe.sbom.Sbom = if (scribe.container.isContainer(bytes)) blk: {
        var img = try scribe.container.collect(gpa, bytes);
        const s: scribe.sbom.Sbom = .{
            .components = img.components,
            .config_issues = img.config_issues,
        };
        img.components = &.{};
        img.config_issues = &.{};
        break :blk s;
    } else try scribe.sbom.collect(gpa, bytes);
    defer bom.deinit(gpa);

    // Auto-enable wide-string scanning for PE targets — wide UTF-16LE
    // strings are the primary text-storage convention in Windows binaries.
    var sec_opts_eff = sec_opts;
    if (bytes.len >= 2 and bytes[0] == 'M' and bytes[1] == 'Z') sec_opts_eff.scan_wide = true;
    var findings = try scribe.security.secrets.scan(gpa, bytes, sec_opts_eff);
    bom.findings = findings.items; // ownership moves into Sbom.deinit
    findings.items = &.{};

    // Fingerprint cross-ref: match function-byte fingerprints against the
    // corpus and append unique (lib, version) hits as Components evidenced
    // by `fingerprint`. Downstream vuln matcher then looks them up.
    if (fp_db_path) |fp| try augmentBomWithFingerprint(io, gpa, bytes, fp, &bom);

    if (db_path) |dp| {
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
) !u8 {
    var policy_map = try scribe.mmap.open(io, policy_path);
    defer policy_map.deinit();
    var policy = try scribe.security.policy.Policy.loadJson(gpa, policy_map.bytes());
    defer policy.deinit(gpa);

    var target = try scribe.mmap.open(io, target_path);
    defer target.deinit();
    const bytes = target.bytes();

    var bom: scribe.sbom.Sbom = if (scribe.container.isContainer(bytes)) blk: {
        var img = try scribe.container.collect(gpa, bytes);
        const s: scribe.sbom.Sbom = .{
            .components = img.components,
            .config_issues = img.config_issues,
        };
        img.components = &.{};
        img.config_issues = &.{};
        break :blk s;
    } else try scribe.sbom.collect(gpa, bytes);
    defer bom.deinit(gpa);

    var sec_opts_eff = sec_opts;
    if (bytes.len >= 2 and bytes[0] == 'M' and bytes[1] == 'Z') sec_opts_eff.scan_wide = true;
    var findings = try scribe.security.secrets.scan(gpa, bytes, sec_opts_eff);
    bom.findings = findings.items;
    findings.items = &.{};

    if (db_path) |dp| {
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

    var result = try scribe.security.policy.evaluate(gpa, policy, bom);
    defer result.deinit(gpa);

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
) !void {
    var client: std.http.Client = .{ .allocator = gpa, .io = io };
    defer client.deinit();

    var body: std.Io.Writer.Allocating = .init(gpa);
    defer body.deinit();

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

    const json_bytes = body.writer.buffered();
    var db = scribe.security.vulnerability.load(gpa, json_bytes) catch |err| {
        try out.print("error: advisory JSON parse failed: {s}\n", .{@errorName(err)});
        return err;
    };
    defer db.deinit(gpa);

    var aw: std.Io.Writer.Allocating = .init(gpa);
    defer aw.deinit();
    try scribe.security.vulnerability.writeBinary(db, &aw.writer);
    const out_bytes = aw.written();

    try Io.Dir.cwd().writeFile(io, .{ .sub_path = out_path, .data = out_bytes });
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
