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
    \\  scribe symbols <path>          DWARF function symbols (ELF only)
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
        runSbom(io, gpa, stdout, args[2], plain) catch |err| return dieErr(stderr, err);
        return;
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
) !void {
    if (std.mem.startsWith(u8, path, "registry://")) {
        var bom = try scribe.registry.pullSbom(gpa, io, path, .{});
        defer bom.deinit(gpa);
        try emitSbom(out, .{ .components = bom.components }, plain);
        return;
    }

    if (scribe.local_docker.isLocalDockerUri(path)) {
        var bom = try scribe.local_docker.pullSbom(gpa, io, path);
        defer bom.deinit(gpa);
        try emitSbom(out, .{ .components = bom.components }, plain);
        return;
    }

    var mapping = try scribe.mmap.open(io, path);
    defer mapping.deinit();
    const bytes = mapping.bytes();

    if (scribe.container.isContainer(bytes)) {
        var bom = try scribe.container.collect(gpa, bytes);
        defer bom.deinit(gpa);
        try emitSbom(out, .{ .components = bom.components }, plain);
    } else {
        var bom = try scribe.sbom.collect(gpa, bytes);
        defer bom.deinit(gpa);
        try emitSbom(out, bom, plain);
    }
}

fn emitSbom(out: *Io.Writer, bom: scribe.sbom.Sbom, plain: bool) !void {
    if (plain) {
        if (bom.components.len == 0) {
            try out.writeAll("(no components detected)\n");
            return;
        }
        for (bom.components) |c| {
            try out.print(
                "{s:<13} {s:<28} {s:<16} {s:<14} via={s}",
                .{
                    @tagName(c.kind),
                    c.name,
                    c.version orelse "-",
                    c.platform orelse "-",
                    @tagName(c.evidence),
                },
            );
            if (c.path) |p| try out.print(" @ {s}", .{p});
            try out.writeByte('\n');
        }
    } else {
        try scribe.sbom.writeCycloneDX(out, bom);
    }
}

fn stripHexPrefix(s: []const u8) []const u8 {
    if (s.len >= 2 and s[0] == '0' and (s[1] == 'x' or s[1] == 'X')) return s[2..];
    return s;
}

fn runSymbols(
    io: Io,
    gpa: std.mem.Allocator,
    out: *Io.Writer,
    path: []const u8,
) !void {
    var mapping = try scribe.mmap.open(io, path);
    defer mapping.deinit();

    var sym = try scribe.dwarf.open(gpa, mapping.bytes());
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

    var sym = try scribe.dwarf.open(gpa, mapping.bytes());
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

    const hits = try scribe.fingerprint.match(gpa, target_map.bytes(), db);
    defer gpa.free(hits);

    if (hits.len == 0) {
        try out.writeAll("(no fingerprint matches)\n");
        return;
    }
    for (hits) |h| {
        try out.print(
            "0x{x:0>16}  {s:<32}  ->  {s} {s}{s}{s}\n",
            .{
                h.target_addr,
                h.target_function,
                h.db_entry.lib,
                if (h.db_entry.version) |_| " " else "",
                h.db_entry.version orelse "",
                if (!std.mem.eql(u8, h.db_entry.name, h.target_function))
                    " (renamed)"
                else
                    "",
            },
        );
    }
    try out.print("({d} matches)\n", .{hits.len});
}

test "module imports resolve" {
    _ = scribe;
}
