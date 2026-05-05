//! Hardening flag detection. Each format gets an analyzer that surfaces
//! the binary's exploit-mitigation posture (PIE, NX, RELRO on ELF;
//! MH_PIE, code signing, encryption on Mach-O; ASLR, DEP, GS, CFG on PE).
//!
//! Output mirrors what `checksec --file=` prints for ELF and what
//! `dumpbin /HEADERS` reports for PE — the IDs are stable so downstream
//! consumers (policy gate, TUI) can suppress or grade specific checks.
//!
//! Status semantics:
//! - `enabled`  — protection is on
//! - `disabled` — protection is off (interesting for findings)
//! - `partial`  — partially on (e.g. RELRO without BIND_NOW = partial)
//! - `unknown`  — couldn't determine (e.g. canary check on stripped binary)
//! - `na`       — not applicable to this format

const std = @import("std");
const errors = @import("../errors.zig");
const format = @import("../format.zig");
const elf_mod = @import("../elf.zig");
const macho_mod = @import("../macho.zig");
const config = @import("config.zig");

const ScribeError = errors.ScribeError;

pub const Status = enum {
    enabled,
    disabled,
    partial,
    unknown,
    na,

    pub fn label(self: Status) []const u8 {
        return switch (self) {
            .enabled => "enabled",
            .disabled => "disabled",
            .partial => "partial",
            .unknown => "unknown",
            .na => "n/a",
        };
    }
};

pub const Check = struct {
    id: []const u8,
    name: []const u8,
    status: Status,
    detail: ?[]u8 = null,
};

pub const Report = struct {
    format: format.Kind,
    checks: []Check,

    pub fn deinit(self: *Report, allocator: std.mem.Allocator) void {
        for (self.checks) |c| if (c.detail) |d| allocator.free(d);
        allocator.free(self.checks);
        self.checks = &.{};
    }
};

pub fn analyze(
    allocator: std.mem.Allocator,
    info: format.Info,
    bytes: []const u8,
) ScribeError!Report {
    return switch (info) {
        .elf => |e| analyzeElf(allocator, e, bytes),
        .macho => |m| analyzeMacho(allocator, m, bytes),
        .pe => |p| analyzePe(allocator, p, bytes),
    };
}

// ----------------------------------------------------------------------------
// ELF
// ----------------------------------------------------------------------------

const ET_DYN: u16 = 3;
const PF_X: u32 = 1;
const DF_1_PIE: u32 = 0x08000000;

fn analyzeElf(
    allocator: std.mem.Allocator,
    info: elf_mod.ElfInfo,
    bytes: []const u8,
) ScribeError!Report {
    var checks: std.ArrayList(Check) = .empty;
    errdefer {
        for (checks.items) |c| if (c.detail) |d| allocator.free(d);
        checks.deinit(allocator);
    }

    var hdr_reader: std.Io.Reader = .fixed(bytes);
    const header = std.elf.Header.read(&hdr_reader) catch return error.UnsupportedFormat;

    // PIE: ET_DYN + (DF_1_PIE OR no PT_INTERP). Plain shared libs are also
    // ET_DYN; treat presence of PT_INTERP as "this is an executable" so we
    // can distinguish PIE-exec from a .so. Both report `enabled` under the
    // PIE check — the distinction matters mostly for `static-pie` audits.
    var has_dynamic = false;
    var dyn_off: u64 = 0;
    var dyn_size: u64 = 0;
    var has_relro = false;
    var stack_exec: ?bool = null; // null = no PT_GNU_STACK
    {
        var ph_it = header.iterateProgramHeadersBuffer(bytes);
        while (true) {
            const maybe = ph_it.next() catch break;
            const ph = maybe orelse break;
            switch (ph.p_type) {
                std.elf.PT_DYNAMIC => {
                    has_dynamic = true;
                    dyn_off = ph.p_offset;
                    dyn_size = ph.p_filesz;
                },
                std.elf.PT_GNU_RELRO => has_relro = true,
                std.elf.PT_GNU_STACK => stack_exec = (ph.p_flags & PF_X) != 0,
                else => {},
            }
        }
    }

    // Walk DT_FLAGS / DT_FLAGS_1 / DT_BIND_NOW for full-RELRO + PIE flag.
    var flags1: u64 = 0;
    var df_flags: u64 = 0;
    var bind_now_dt = false;
    var has_runpath = false;
    var has_rpath = false;
    if (has_dynamic and dyn_size > 0 and dyn_off + dyn_size <= bytes.len) {
        var dyn_it = header.iterateDynamicSectionBuffer(bytes, dyn_off, dyn_size);
        while (true) {
            const maybe = dyn_it.next() catch break;
            const d = maybe orelse break;
            switch (d.d_tag) {
                std.elf.DT_NULL => break,
                std.elf.DT_FLAGS => df_flags = d.d_val,
                std.elf.DT_FLAGS_1 => flags1 = d.d_val,
                std.elf.DT_BIND_NOW => bind_now_dt = true,
                std.elf.DT_RPATH => has_rpath = true,
                std.elf.DT_RUNPATH => has_runpath = true,
                else => {},
            }
        }
    }

    const is_dyn = info.e_type == ET_DYN;
    const pie_flag = (flags1 & DF_1_PIE) != 0;
    const pie_status: Status = if (is_dyn and (pie_flag or !has_dynamic))
        .enabled
    else if (is_dyn)
        .enabled // ET_DYN executables are PIE; .so libs also ET_DYN — both flagged enabled
    else
        .disabled;
    try checks.append(allocator, .{ .id = "PIE", .name = "Position-Independent Executable", .status = pie_status });

    const nx_status: Status = blk: {
        if (stack_exec) |x| break :blk if (x) .disabled else .enabled;
        break :blk .unknown;
    };
    try checks.append(allocator, .{ .id = "NX", .name = "Non-executable stack", .status = nx_status });

    const bind_now = bind_now_dt or (df_flags & std.elf.DF_BIND_NOW) != 0 or (flags1 & 0x1) != 0; // DF_1_NOW
    const relro_status: Status = if (has_relro and bind_now)
        .enabled
    else if (has_relro)
        .partial
    else
        .disabled;
    try checks.append(allocator, .{ .id = "RELRO", .name = "Read-only relocations", .status = relro_status });

    // Symbol-name heuristics for canary + FORTIFY. Look in .dynsym + .symtab
    // string tables. Cheap: scan all section names, find STRTAB sections,
    // search them. False-negative-safe: report `unknown` if no string tables
    // were found (e.g. heavily obfuscated input).
    var has_canary: ?bool = null;
    var has_fortify: ?bool = null;
    for (info.sections) |s| {
        if (s.type != std.elf.SHT_STRTAB) continue;
        if (s.offset + s.size > bytes.len) continue;
        const tbl = bytes[@intCast(s.offset)..][0..@intCast(s.size)];
        if (std.mem.indexOf(u8, tbl, "__stack_chk_fail") != null) has_canary = true;
        if (std.mem.indexOf(u8, tbl, "_chk\x00") != null or
            std.mem.indexOf(u8, tbl, "memcpy_chk") != null) has_fortify = true;
        if (has_canary == null) has_canary = false;
        if (has_fortify == null) has_fortify = false;
    }
    try checks.append(allocator, .{
        .id = "CANARY",
        .name = "Stack canary",
        .status = if (has_canary) |v| (if (v) Status.enabled else .disabled) else .unknown,
    });
    try checks.append(allocator, .{
        .id = "FORTIFY",
        .name = "FORTIFY_SOURCE",
        .status = if (has_fortify) |v| (if (v) Status.enabled else .disabled) else .unknown,
    });

    if (has_runpath or has_rpath) {
        const tag = if (has_rpath) "DT_RPATH" else "DT_RUNPATH";
        const detail = try allocator.dupe(u8, tag);
        try checks.append(allocator, .{
            .id = "RPATH",
            .name = "Embedded library search path",
            .status = .enabled,
            .detail = detail,
        });
    }

    var has_symtab = false;
    for (info.sections) |s| {
        if (std.mem.eql(u8, s.name, ".symtab")) has_symtab = true;
    }
    try checks.append(allocator, .{
        .id = "STRIPPED",
        .name = "Symbol table stripped",
        .status = if (has_symtab) Status.disabled else .enabled,
    });

    return .{ .format = .elf, .checks = try checks.toOwnedSlice(allocator) };
}

// ----------------------------------------------------------------------------
// Mach-O
// ----------------------------------------------------------------------------

const MH_PIE: u32 = 0x200000;
const MH_NO_HEAP_EXECUTION: u32 = 0x1000000;
const MH_ALLOW_STACK_EXECUTION: u32 = 0x20000;

const encryption_info_command_64 = extern struct {
    cmd: u32,
    cmdsize: u32,
    cryptoff: u32,
    cryptsize: u32,
    cryptid: u32,
    pad: u32,
};

const encryption_info_command_32 = extern struct {
    cmd: u32,
    cmdsize: u32,
    cryptoff: u32,
    cryptsize: u32,
    cryptid: u32,
};

fn analyzeMacho(
    allocator: std.mem.Allocator,
    info: macho_mod.MachoInfo,
    full_bytes: []const u8,
) ScribeError!Report {
    var checks: std.ArrayList(Check) = .empty;
    errdefer {
        for (checks.items) |c| if (c.detail) |d| allocator.free(d);
        checks.deinit(allocator);
    }

    // For FAT inputs, section + load-command offsets are slice-relative.
    // Rebase here so the analyzer never has to think about the FAT envelope.
    const slice_off: usize = @intCast(info.fat_slice_offset);
    if (slice_off >= full_bytes.len) return error.Truncated;
    const bytes = full_bytes[slice_off..];

    const flags = info.flags;

    const pie_on = (flags & MH_PIE) != 0;
    try checks.append(allocator, .{ .id = "PIE", .name = "Position-Independent Executable", .status = if (pie_on) Status.enabled else .disabled });

    const nx_heap = (flags & MH_NO_HEAP_EXECUTION) != 0;
    try checks.append(allocator, .{ .id = "NX_HEAP", .name = "Non-executable heap", .status = if (nx_heap) Status.enabled else .disabled });

    const stack_exec = (flags & MH_ALLOW_STACK_EXECUTION) != 0;
    try checks.append(allocator, .{ .id = "STACK_EXEC", .name = "Allow stack execution", .status = if (stack_exec) Status.enabled else .disabled });

    // Walk load commands for code-sig / encryption / restricted segment / rpath.
    var has_code_sig = false;
    var encrypted = false;
    var has_rpath = false;
    var has_restrict = false;

    const lc_start: usize = if (info.is_64) @sizeOf(std.macho.mach_header_64) else @sizeOf(std.macho.mach_header);
    if (lc_start <= bytes.len) {
        var off = lc_start;
        var i: u32 = 0;
        const ncmds = readNcmds(info, bytes);
        const sizeofcmds = readSizeofcmds(info, bytes);
        const lc_end = std.math.add(usize, lc_start, sizeofcmds) catch lc_start;
        while (i < ncmds and off + @sizeOf(std.macho.load_command) <= lc_end and lc_end <= bytes.len) : (i += 1) {
            const lc: *align(1) const std.macho.load_command = @ptrCast(bytes[off..].ptr);
            const cmdsize = lc.cmdsize;
            if (cmdsize < @sizeOf(std.macho.load_command)) break;
            if (off + cmdsize > lc_end) break;
            switch (lc.cmd) {
                .CODE_SIGNATURE => has_code_sig = true,
                .RPATH => has_rpath = true,
                .ENCRYPTION_INFO => {
                    if (cmdsize >= @sizeOf(encryption_info_command_32)) {
                        const e: *align(1) const encryption_info_command_32 = @ptrCast(bytes[off..].ptr);
                        if (e.cryptid != 0) encrypted = true;
                    }
                },
                .ENCRYPTION_INFO_64 => {
                    if (cmdsize >= @sizeOf(encryption_info_command_64)) {
                        const e: *align(1) const encryption_info_command_64 = @ptrCast(bytes[off..].ptr);
                        if (e.cryptid != 0) encrypted = true;
                    }
                },
                .SEGMENT_64 => {
                    if (cmdsize >= @sizeOf(std.macho.segment_command_64)) {
                        const seg: *align(1) const std.macho.segment_command_64 = @ptrCast(bytes[off..].ptr);
                        if (std.mem.startsWith(u8, &seg.segname, "__RESTRICT")) has_restrict = true;
                    }
                },
                .SEGMENT => {
                    if (cmdsize >= @sizeOf(std.macho.segment_command)) {
                        const seg: *align(1) const std.macho.segment_command = @ptrCast(bytes[off..].ptr);
                        if (std.mem.startsWith(u8, &seg.segname, "__RESTRICT")) has_restrict = true;
                    }
                },
                else => {},
            }
            off += cmdsize;
        }
    }

    try checks.append(allocator, .{ .id = "CODE_SIG", .name = "Code signature", .status = if (has_code_sig) Status.enabled else .disabled });
    try checks.append(allocator, .{ .id = "ENCRYPTED", .name = "FairPlay encrypted", .status = if (encrypted) Status.enabled else .disabled });
    if (has_restrict)
        try checks.append(allocator, .{ .id = "RESTRICT", .name = "__RESTRICT segment", .status = .enabled });
    if (has_rpath) {
        const detail = try allocator.dupe(u8, "LC_RPATH");
        try checks.append(allocator, .{
            .id = "RPATH",
            .name = "Embedded library search path",
            .status = .enabled,
            .detail = detail,
        });
    }

    // Stack-canary heuristic: the C symbol gets an extra underscore at link
    // time on Mach-O, so we look for `_stack_chk_fail` (matches both
    // `__stack_chk_fail` and the `___stack_chk_fail` name used by some
    // toolchains). Symbol strings live in __LINKEDIT's symbol string table,
    // not __cstring — easier to do a slice-wide substring scan than to
    // walk LC_SYMTAB.
    const has_canary = std.mem.indexOf(u8, bytes, "_stack_chk_fail") != null;
    try checks.append(allocator, .{
        .id = "CANARY",
        .name = "Stack canary",
        .status = if (has_canary) Status.enabled else .disabled,
    });

    return .{ .format = .macho, .checks = try checks.toOwnedSlice(allocator) };
}

fn readNcmds(info: macho_mod.MachoInfo, bytes: []const u8) u32 {
    if (info.is_64) {
        const h: *align(1) const std.macho.mach_header_64 = @ptrCast(bytes.ptr);
        return h.ncmds;
    }
    const h: *align(1) const std.macho.mach_header = @ptrCast(bytes.ptr);
    return h.ncmds;
}

fn readSizeofcmds(info: macho_mod.MachoInfo, bytes: []const u8) u32 {
    if (info.is_64) {
        const h: *align(1) const std.macho.mach_header_64 = @ptrCast(bytes.ptr);
        return h.sizeofcmds;
    }
    const h: *align(1) const std.macho.mach_header = @ptrCast(bytes.ptr);
    return h.sizeofcmds;
}

// ----------------------------------------------------------------------------
// PE
// ----------------------------------------------------------------------------

const IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA: u16 = 0x0020;
const IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE: u16 = 0x0040;
const IMAGE_DLLCHARACTERISTICS_NX_COMPAT: u16 = 0x0100;
const IMAGE_DLLCHARACTERISTICS_GUARD_CF: u16 = 0x4000;

const pe_mod = @import("../pe.zig");

fn analyzePe(
    allocator: std.mem.Allocator,
    info: pe_mod.PeInfo,
    bytes: []const u8,
) ScribeError!Report {
    var checks: std.ArrayList(Check) = .empty;
    errdefer {
        for (checks.items) |c| if (c.detail) |d| allocator.free(d);
        checks.deinit(allocator);
    }

    // Locate the PE optional header. `e_lfanew` is the 4-byte little-endian
    // value at offset 0x3C in the DOS header; that points at the "PE\0\0"
    // signature. The COFF File Header (20 bytes) follows; the optional
    // header begins right after.
    if (bytes.len < 0x40) return error.Truncated;
    const e_lfanew = std.mem.readInt(u32, bytes[0x3C..][0..4], .little);
    const sig_off: usize = e_lfanew;
    if (sig_off + 24 > bytes.len) return error.Truncated;
    if (!std.mem.eql(u8, bytes[sig_off..][0..4], "PE\x00\x00")) return error.UnsupportedFormat;
    // IMAGE_FILE_HEADER ("COFF header") is 20 bytes — fixed by PE/COFF spec.
    const coff_header_size: usize = 20;
    const opt_off = sig_off + 4 + coff_header_size;
    if (opt_off + 0x48 > bytes.len) return error.Truncated;

    // dll_characteristics offset within OptionalHeader: 0x46 for both
    // PE32 and PE32+ (it sits after Subsystem at 0x44 in PE32+, 0x44 in PE32).
    const dll_char_off: usize = if (info.is_64) opt_off + 0x46 else opt_off + 0x46;
    const dll_char = std.mem.readInt(u16, bytes[dll_char_off..][0..2], .little);

    const aslr = (dll_char & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) != 0;
    const high_entropy = (dll_char & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA) != 0;
    const dep = (dll_char & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) != 0;
    const cfg = (dll_char & IMAGE_DLLCHARACTERISTICS_GUARD_CF) != 0;

    try checks.append(allocator, .{ .id = "ASLR", .name = "Address Space Layout Randomization", .status = if (aslr) Status.enabled else .disabled });
    try checks.append(allocator, .{ .id = "HIGH_ENTROPY_VA", .name = "64-bit high-entropy ASLR", .status = if (high_entropy) Status.enabled else .disabled });
    try checks.append(allocator, .{ .id = "DEP", .name = "Data Execution Prevention (NX_COMPAT)", .status = if (dep) Status.enabled else .disabled });
    try checks.append(allocator, .{ .id = "CFG", .name = "Control Flow Guard", .status = if (cfg) Status.enabled else .disabled });

    // Authenticode: certificate table data directory entry (#4) non-empty.
    // Data directories begin at OptionalHeader offset 0x70 (PE32) or 0x88 (PE32+);
    // each entry is 8 bytes (RVA u32 + Size u32).
    const dd_off: usize = opt_off + (if (info.is_64) @as(usize, 0x88) else @as(usize, 0x70));
    const sec_dd_off = dd_off + 4 * 8;
    if (sec_dd_off + 8 <= bytes.len) {
        const sec_size = std.mem.readInt(u32, bytes[sec_dd_off + 4 ..][0..4], .little);
        try checks.append(allocator, .{
            .id = "AUTHENTICODE",
            .name = "Authenticode signature",
            .status = if (sec_size != 0) Status.enabled else .disabled,
        });
    }

    // Load Config directory (#10): GS cookie + SafeSEH (32-bit only).
    // Layout per PE/COFF v8.3 §5.10. Only need a couple of fields; resolve
    // RVA→file offset via section headers.
    const lc_dd_off = dd_off + 10 * 8;
    if (lc_dd_off + 8 <= bytes.len) {
        const lc_rva = std.mem.readInt(u32, bytes[lc_dd_off..][0..4], .little);
        const lc_size = std.mem.readInt(u32, bytes[lc_dd_off + 4 ..][0..4], .little);
        if (lc_rva != 0 and lc_size != 0) {
            if (rvaToFileOffset(info, lc_rva)) |file_off| {
                if (info.is_64 and file_off + 96 <= bytes.len) {
                    const security_cookie = std.mem.readInt(u64, bytes[file_off + 40 ..][0..8], .little);
                    try checks.append(allocator, .{
                        .id = "GS",
                        .name = "Stack buffer-overflow check",
                        .status = if (security_cookie != 0) Status.enabled else .disabled,
                    });
                } else if (!info.is_64 and file_off + 76 <= bytes.len) {
                    const security_cookie = std.mem.readInt(u32, bytes[file_off + 32 ..][0..4], .little);
                    const seh_table = std.mem.readInt(u32, bytes[file_off + 64 ..][0..4], .little);
                    const seh_count = std.mem.readInt(u32, bytes[file_off + 68 ..][0..4], .little);
                    try checks.append(allocator, .{
                        .id = "GS",
                        .name = "Stack buffer-overflow check",
                        .status = if (security_cookie != 0) Status.enabled else .disabled,
                    });
                    try checks.append(allocator, .{
                        .id = "SAFESEH",
                        .name = "Safe Structured Exception Handling",
                        .status = if (seh_table != 0 and seh_count > 0) Status.enabled else .disabled,
                    });
                }
            }
        }
    }

    return .{ .format = .pe, .checks = try checks.toOwnedSlice(allocator) };
}

fn rvaToFileOffset(info: pe_mod.PeInfo, rva: u32) ?u64 {
    for (info.sections) |s| {
        if (rva >= s.virtual_address and rva < s.virtual_address + s.virtual_size)
            return @as(u64, s.raw_offset) + (rva - s.virtual_address);
    }
    return null;
}

// ----------------------------------------------------------------------------
// Folding hardening checks into the existing IaC issue stream so they flow
// through SBOM properties[] / policy / TUI without bespoke wiring.
// ----------------------------------------------------------------------------

pub fn toConfigIssues(
    allocator: std.mem.Allocator,
    report: Report,
    path: []const u8,
) ScribeError![]config.Issue {
    var out: std.ArrayList(config.Issue) = .empty;
    errdefer {
        for (out.items) |it| config.freeIssue(allocator, it);
        out.deinit(allocator);
    }

    for (report.checks) |c| {
        const finding = mapToFinding(c) orelse continue;

        const id_prefix: []const u8 = switch (report.format) {
            .elf => "BIN-ELF-",
            .macho => "BIN-MAC-",
            .pe => "BIN-PE-",
        };
        const rule_id = std.fmt.allocPrint(allocator, "{s}{s}", .{ id_prefix, c.id }) catch return error.OutOfMemory;
        errdefer allocator.free(rule_id);

        const title = std.fmt.allocPrint(
            allocator,
            "{s}: {s}",
            .{ c.name, c.status.label() },
        ) catch return error.OutOfMemory;
        errdefer allocator.free(title);

        const file_copy = allocator.dupe(u8, path) catch return error.OutOfMemory;
        errdefer allocator.free(file_copy);

        const snippet = std.fmt.allocPrint(allocator, "{s}={s}", .{ c.id, c.status.label() }) catch return error.OutOfMemory;
        errdefer allocator.free(snippet);

        const recommendation = allocator.dupe(u8, finding.recommendation) catch return error.OutOfMemory;
        errdefer allocator.free(recommendation);

        try out.append(allocator, .{
            .rule_id = rule_id,
            .title = title,
            .severity = finding.severity,
            .source = .image_config,
            .file = file_copy,
            .line = 0,
            .snippet = snippet,
            .recommendation = recommendation,
        });
    }

    return out.toOwnedSlice(allocator) catch error.OutOfMemory;
}

const Finding = struct { severity: config.Severity, recommendation: []const u8 };

fn mapToFinding(c: Check) ?Finding {
    // Only emit findings for things that are *off* (or interesting-when-on).
    // `enabled` for protective checks → no finding. `enabled` for risk-style
    // checks (STACK_EXEC, ENCRYPTED, RPATH) → info-level finding.
    return switch (c.status) {
        .enabled => switch (matchKind(c.id)) {
            .protective => null,
            .risk => .{ .severity = .info, .recommendation = riskRecommendation(c.id) },
        },
        .disabled => switch (matchKind(c.id)) {
            .protective => .{ .severity = severityFor(c.id), .recommendation = enableRecommendation(c.id) },
            .risk => null,
        },
        .partial => .{ .severity = .low, .recommendation = enableRecommendation(c.id) },
        .unknown, .na => null,
    };
}

const Kind = enum { protective, risk };

fn matchKind(id: []const u8) Kind {
    if (std.mem.eql(u8, id, "STACK_EXEC")) return .risk;
    if (std.mem.eql(u8, id, "ENCRYPTED")) return .risk;
    if (std.mem.eql(u8, id, "RPATH")) return .risk;
    if (std.mem.eql(u8, id, "STRIPPED")) return .risk;
    if (std.mem.eql(u8, id, "RESTRICT")) return .risk;
    return .protective;
}

fn severityFor(id: []const u8) config.Severity {
    if (std.mem.eql(u8, id, "PIE") or
        std.mem.eql(u8, id, "NX") or
        std.mem.eql(u8, id, "RELRO") or
        std.mem.eql(u8, id, "ASLR") or
        std.mem.eql(u8, id, "DEP") or
        std.mem.eql(u8, id, "CODE_SIG"))
        return .medium;
    return .low;
}

fn enableRecommendation(id: []const u8) []const u8 {
    if (std.mem.eql(u8, id, "PIE")) return "Re-link with -pie / -fPIE so the loader can relocate the executable for ASLR.";
    if (std.mem.eql(u8, id, "NX")) return "Mark the stack non-executable (PT_GNU_STACK without PF_X). Re-link with a recent toolchain.";
    if (std.mem.eql(u8, id, "RELRO")) return "Re-link with -Wl,-z,relro,-z,now for full RELRO + immediate binding.";
    if (std.mem.eql(u8, id, "CANARY")) return "Build with -fstack-protector-strong (or -fstack-protector-all for max coverage).";
    if (std.mem.eql(u8, id, "FORTIFY")) return "Build with -D_FORTIFY_SOURCE=2 -O2 so libc *_chk variants get linked in.";
    if (std.mem.eql(u8, id, "ASLR")) return "Link with /DYNAMICBASE so the loader randomizes the image base.";
    if (std.mem.eql(u8, id, "DEP")) return "Link with /NXCOMPAT so the OS marks data pages non-executable.";
    if (std.mem.eql(u8, id, "CFG")) return "Build with /guard:cf to enable Control Flow Guard.";
    if (std.mem.eql(u8, id, "GS")) return "Build with /GS so the compiler injects stack buffer-overflow cookies.";
    if (std.mem.eql(u8, id, "HIGH_ENTROPY_VA")) return "Link 64-bit images with /HIGHENTROPYVA for full 64-bit ASLR.";
    if (std.mem.eql(u8, id, "AUTHENTICODE")) return "Sign the binary with a trusted Authenticode certificate before distribution.";
    if (std.mem.eql(u8, id, "CODE_SIG")) return "Sign the binary with `codesign` (or notarize) before distribution.";
    if (std.mem.eql(u8, id, "NX_HEAP")) return "Re-link with -Wl,-no_heap_execution so heap pages stay non-executable.";
    if (std.mem.eql(u8, id, "SAFESEH")) return "Link 32-bit binaries with /SAFESEH so SEH chains are validated.";
    return "Enable the corresponding compiler/linker flag for this protection.";
}

fn riskRecommendation(id: []const u8) []const u8 {
    if (std.mem.eql(u8, id, "STACK_EXEC")) return "MH_ALLOW_STACK_EXECUTION is dangerous outside legacy interpreters; remove unless required.";
    if (std.mem.eql(u8, id, "ENCRYPTED")) return "Binary is FairPlay-encrypted (cryptid != 0); decrypt slice before re-distribution.";
    if (std.mem.eql(u8, id, "RPATH")) return "Embedded RPATH/RUNPATH can be hijacked when writable; audit search paths.";
    if (std.mem.eql(u8, id, "STRIPPED")) return "Symbol table stripped; impedes triage but is informational.";
    if (std.mem.eql(u8, id, "RESTRICT")) return "Legacy __RESTRICT segment present; superseded by hardened runtime in modern code-sign flow.";
    return "Review the surfaced setting; it may indicate elevated risk.";
}

// ----------------------------------------------------------------------------

test "elf hardening on golden fixture" {
    const allocator = std.testing.allocator;
    const bytes = @embedFile("../testdata/hello_x86_64");
    var info = try elf_mod.parse(allocator, bytes);
    defer info.deinit(allocator);
    const fmt_info: format.Info = .{ .elf = info };
    var report = try analyze(allocator, fmt_info, bytes);
    defer report.deinit(allocator);
    try std.testing.expect(report.checks.len > 0);
    var saw_pie = false;
    for (report.checks) |c| if (std.mem.eql(u8, c.id, "PIE")) {
        saw_pie = true;
    };
    try std.testing.expect(saw_pie);
}

test "macho hardening on golden fixture" {
    const allocator = std.testing.allocator;
    const bytes = @embedFile("../testdata/hello_macho_aarch64");
    var info = try macho_mod.parse(allocator, bytes);
    defer info.deinit(allocator);
    const fmt_info: format.Info = .{ .macho = info };
    var report = try analyze(allocator, fmt_info, bytes);
    defer report.deinit(allocator);
    var saw_pie = false;
    for (report.checks) |c| if (std.mem.eql(u8, c.id, "PIE")) {
        saw_pie = true;
        try std.testing.expectEqual(Status.enabled, c.status);
    };
    try std.testing.expect(saw_pie);
}

test "pe hardening on golden fixture" {
    const allocator = std.testing.allocator;
    const bytes = @embedFile("../testdata/hello_pe_x86_64");
    var info = try pe_mod.parse(allocator, bytes);
    defer info.deinit(allocator);
    const fmt_info: format.Info = .{ .pe = info };
    var report = try analyze(allocator, fmt_info, bytes);
    defer report.deinit(allocator);
    var saw_aslr = false;
    var saw_dep = false;
    for (report.checks) |c| {
        if (std.mem.eql(u8, c.id, "ASLR")) saw_aslr = true;
        if (std.mem.eql(u8, c.id, "DEP")) saw_dep = true;
    }
    try std.testing.expect(saw_aslr);
    try std.testing.expect(saw_dep);
}
