//! Smoke-fuzz harness for parser robustness. Runs each parser against a
//! catalog of malformed / boundary inputs and ensures they return errors
//! cleanly rather than panicking. Not a replacement for proper coverage-
//! guided fuzzing (that requires libfuzzer-style instrumentation that's
//! not yet wired into Zig's build system here), but catches regressions
//! when we bound-check off-by-one or forget to validate a length field.

const std = @import("std");
const format = @import("format.zig");
const elf_mod = @import("elf.zig");
const macho_mod = @import("macho.zig");
const pe_mod = @import("pe.zig");
const wasm_mod = @import("wasm.zig");
const ar_mod = @import("ar.zig");
const yara_mod = @import("security/yara.zig");

fn tryParseElf(allocator: std.mem.Allocator, bytes: []const u8) void {
    var info = elf_mod.parse(allocator, bytes) catch return;
    info.deinit(allocator);
}
fn tryParseMacho(allocator: std.mem.Allocator, bytes: []const u8) void {
    var info = macho_mod.parse(allocator, bytes) catch return;
    info.deinit(allocator);
}
fn tryParsePe(allocator: std.mem.Allocator, bytes: []const u8) void {
    var info = pe_mod.parse(allocator, bytes) catch return;
    info.deinit(allocator);
}
fn tryParseWasm(allocator: std.mem.Allocator, bytes: []const u8) void {
    var info = wasm_mod.parse(allocator, bytes) catch return;
    info.deinit(allocator);
}
fn tryParseAr(allocator: std.mem.Allocator, bytes: []const u8) void {
    var arc = ar_mod.parse(allocator, bytes) catch return;
    arc.deinit(allocator);
}
fn tryParseYara(allocator: std.mem.Allocator, src: []const u8) void {
    var rs = yara_mod.parse(allocator, src) catch return;
    rs.deinit(allocator);
}

test "fuzz: empty input across all parsers" {
    const allocator = std.testing.allocator;
    tryParseElf(allocator, "");
    tryParseMacho(allocator, "");
    tryParsePe(allocator, "");
    tryParseWasm(allocator, "");
    tryParseAr(allocator, "");
    tryParseYara(allocator, "");
}

test "fuzz: single-byte inputs" {
    const allocator = std.testing.allocator;
    var i: u9 = 0;
    while (i < 256) : (i += 1) {
        const b: u8 = @intCast(i);
        const buf = [_]u8{b};
        tryParseElf(allocator, &buf);
        tryParseMacho(allocator, &buf);
        tryParsePe(allocator, &buf);
        tryParseWasm(allocator, &buf);
        tryParseAr(allocator, &buf);
    }
}

test "fuzz: repeating magic prefix doesn't trip parsers" {
    const allocator = std.testing.allocator;
    inline for (.{
        [_]u8{ 0x7F, 'E', 'L', 'F' },
        [_]u8{ 0xCF, 0xFA, 0xED, 0xFE },
        [_]u8{ 0xCA, 0xFE, 0xBA, 0xBE },
        [_]u8{ 'M', 'Z', 0, 0 },
        [_]u8{ 0x00, 0x61, 0x73, 0x6D },
    }) |prefix| {
        var buf: [128]u8 = @splat(0xAA);
        @memcpy(buf[0..prefix.len], &prefix);
        tryParseElf(allocator, &buf);
        tryParseMacho(allocator, &buf);
        tryParsePe(allocator, &buf);
        tryParseWasm(allocator, &buf);
    }
}

test "fuzz: pseudo-random inputs (PRNG-seeded, not coverage-guided)" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x53_43_52_42); // "SCRB"
    const rand = prng.random();
    var i: u32 = 0;
    while (i < 64) : (i += 1) {
        const len = rand.intRangeAtMost(usize, 0, 1024);
        const buf = try allocator.alloc(u8, len);
        defer allocator.free(buf);
        rand.bytes(buf);
        tryParseElf(allocator, buf);
        tryParseMacho(allocator, buf);
        tryParsePe(allocator, buf);
        tryParseWasm(allocator, buf);
        tryParseAr(allocator, buf);
    }
}

test "fuzz: yara malformed rules should error, not panic" {
    const allocator = std.testing.allocator;
    inline for (.{
        "rule",
        "rule {",
        "rule x { strings: $a = }",
        "rule x { condition: $z }", // unknown ref
        "rule x { strings: $a = \"unterminated",
        "rule x { strings: $a = { ZZ } condition: $a }", // bad hex
        "rule a { strings: $a = \"x\" condition: any of them",
        "/* unterminated comment",
    }) |src| {
        tryParseYara(allocator, src);
    }
}

test "fuzz: format.detect handles random small slices" {
    var prng = std.Random.DefaultPrng.init(42);
    const rand = prng.random();
    var i: u32 = 0;
    while (i < 256) : (i += 1) {
        var buf: [16]u8 = undefined;
        rand.bytes(&buf);
        _ = format.detect(&buf) catch {};
    }
}
