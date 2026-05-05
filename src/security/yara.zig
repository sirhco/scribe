//! YARA-subset rule engine. Parses a tractable subset of YARA syntax and
//! scans byte slices for matches.
//!
//! Supported:
//!   rule NAME [: tag ...] { [meta:] [strings:] condition: ... }
//!   $a = "literal" [ascii] [wide] [nocase]
//!   $b = { AA BB ?? CC }
//!   condition expressions:
//!     $a            — string identifier
//!     any of them   — at least one string matches
//!     all of them   — every defined string matches
//!     N of them     — at least N of the strings match
//!     E and E       — boolean AND
//!     E or E        — boolean OR
//!     not E         — boolean NOT
//!     ( E )         — parenthesized
//!
//! Out of scope (deliberate): jumps `[2-5]`, alternates `(AA|BB)`, regex
//! `/.../`, `for`/`at`/`in`/`filesize`, module imports, `$*` set refs.

const std = @import("std");
const errors = @import("../errors.zig");

const ScribeError = errors.ScribeError;

pub const Modifiers = struct {
    wide: bool = false,
    nocase: bool = false,
};

pub const Pattern = union(enum) {
    /// Anchored substring scan. `nocase` lowercases ASCII alphas both sides.
    /// `wide` interleaves the literal with 0x00 (UTF-16LE) before scanning.
    literal: struct { bytes: []u8, modifiers: Modifiers },
    /// Parallel buffers — match when `(b[i] & mask[i]) == value[i]`.
    hex: struct { value: []u8, mask: []u8 },
};

pub const StringDef = struct {
    name: []u8, // owned; without leading "$"
    pattern: Pattern,
};

pub const Cond = union(enum) {
    string_ref: []u8,
    any_of_them,
    all_of_them,
    n_of_them: u32,
    and_op: struct { lhs: *Cond, rhs: *Cond },
    or_op: struct { lhs: *Cond, rhs: *Cond },
    not_op: *Cond,
    bool_lit: bool,
};

pub const Rule = struct {
    name: []u8,
    tags: [][]u8,
    strings: []StringDef,
    condition: *Cond,
};

pub const RuleSet = struct {
    rules: []Rule,

    pub fn deinit(self: *RuleSet, allocator: std.mem.Allocator) void {
        for (self.rules) |*r| freeRule(allocator, r);
        allocator.free(self.rules);
        self.rules = &.{};
    }
};

fn freeRule(allocator: std.mem.Allocator, r: *Rule) void {
    allocator.free(r.name);
    for (r.tags) |t| allocator.free(t);
    allocator.free(r.tags);
    for (r.strings) |s| {
        allocator.free(s.name);
        switch (s.pattern) {
            .literal => |lit| allocator.free(lit.bytes),
            .hex => |h| {
                allocator.free(h.value);
                allocator.free(h.mask);
            },
        }
    }
    allocator.free(r.strings);
    freeCond(allocator, r.condition);
}

fn freeCond(allocator: std.mem.Allocator, c: *Cond) void {
    switch (c.*) {
        .string_ref => |n| allocator.free(n),
        .and_op => |bin| {
            freeCond(allocator, bin.lhs);
            freeCond(allocator, bin.rhs);
        },
        .or_op => |bin| {
            freeCond(allocator, bin.lhs);
            freeCond(allocator, bin.rhs);
        },
        .not_op => |inner| freeCond(allocator, inner),
        else => {},
    }
    allocator.destroy(c);
}

pub const StringHit = struct {
    name: []const u8,
    offset: usize,
};

pub const Match = struct {
    rule: []const u8,
    tags: []const []const u8,
    hits: []StringHit,

    pub fn deinit(self: *Match, allocator: std.mem.Allocator) void {
        allocator.free(self.hits);
        self.hits = &.{};
    }
};

pub fn freeMatches(allocator: std.mem.Allocator, matches: []Match) void {
    for (matches) |*m| m.deinit(allocator);
    allocator.free(matches);
}

// ----------------------------------------------------------------------------
// Lexer
// ----------------------------------------------------------------------------

const TokenKind = enum {
    ident,
    string,
    integer,
    hex_block,
    dollar,
    colon,
    comma,
    lbrace,
    rbrace,
    lparen,
    rparen,
    eq,
    eof,
    kw_rule,
    kw_meta,
    kw_strings,
    kw_condition,
    kw_any,
    kw_all,
    kw_of,
    kw_them,
    kw_and,
    kw_or,
    kw_not,
    kw_ascii,
    kw_wide,
    kw_nocase,
    kw_fullword,
    kw_true,
    kw_false,
};

const Token = struct {
    kind: TokenKind,
    text: []const u8,
};

const Lexer = struct {
    src: []const u8,
    pos: usize = 0,
    /// When true, an upcoming `{` is treated as a hex block (consumed up to
    /// matching `}` and returned as a single `hex_block` token). Otherwise
    /// `{`/`}` are normal punctuation.
    hex_mode: bool = false,

    fn skipWs(self: *Lexer) void {
        while (self.pos < self.src.len) {
            const c = self.src[self.pos];
            if (c == ' ' or c == '\t' or c == '\r' or c == '\n') {
                self.pos += 1;
            } else if (c == '/' and self.pos + 1 < self.src.len and self.src[self.pos + 1] == '/') {
                while (self.pos < self.src.len and self.src[self.pos] != '\n') self.pos += 1;
            } else if (c == '/' and self.pos + 1 < self.src.len and self.src[self.pos + 1] == '*') {
                self.pos += 2;
                while (self.pos + 1 < self.src.len and !(self.src[self.pos] == '*' and self.src[self.pos + 1] == '/'))
                    self.pos += 1;
                if (self.pos + 1 < self.src.len) self.pos += 2;
            } else break;
        }
    }

    fn next(self: *Lexer) ScribeError!Token {
        self.skipWs();
        if (self.pos >= self.src.len) return .{ .kind = .eof, .text = "" };
        const c = self.src[self.pos];

        if (self.hex_mode and c == '{') {
            self.hex_mode = false;
            const start = self.pos;
            self.pos += 1;
            while (self.pos < self.src.len and self.src[self.pos] != '}') self.pos += 1;
            if (self.pos >= self.src.len) return error.NotImplemented;
            self.pos += 1;
            return .{ .kind = .hex_block, .text = self.src[start..self.pos] };
        }

        if (isIdentStart(c)) {
            const start = self.pos;
            while (self.pos < self.src.len and isIdentCont(self.src[self.pos])) self.pos += 1;
            const text = self.src[start..self.pos];
            return .{ .kind = identKind(text), .text = text };
        }
        if (c >= '0' and c <= '9') {
            const start = self.pos;
            while (self.pos < self.src.len and self.src[self.pos] >= '0' and self.src[self.pos] <= '9')
                self.pos += 1;
            return .{ .kind = .integer, .text = self.src[start..self.pos] };
        }
        if (c == '"') {
            self.pos += 1;
            const start = self.pos;
            while (self.pos < self.src.len and self.src[self.pos] != '"') {
                if (self.src[self.pos] == '\\' and self.pos + 1 < self.src.len) self.pos += 2 else self.pos += 1;
            }
            if (self.pos >= self.src.len) return error.NotImplemented;
            const text = self.src[start..self.pos];
            self.pos += 1;
            return .{ .kind = .string, .text = text };
        }
        const single: ?TokenKind = switch (c) {
            '$' => .dollar,
            ':' => .colon,
            ',' => .comma,
            '{' => .lbrace,
            '}' => .rbrace,
            '(' => .lparen,
            ')' => .rparen,
            '=' => .eq,
            else => null,
        };
        if (single) |kind| {
            self.pos += 1;
            return .{ .kind = kind, .text = self.src[self.pos - 1 .. self.pos] };
        }
        return error.NotImplemented;
    }
};

fn isIdentStart(c: u8) bool {
    return (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z') or c == '_';
}

fn isIdentCont(c: u8) bool {
    return isIdentStart(c) or (c >= '0' and c <= '9');
}

fn identKind(text: []const u8) TokenKind {
    const Pair = struct { name: []const u8, kind: TokenKind };
    const map = [_]Pair{
        .{ .name = "rule", .kind = .kw_rule },
        .{ .name = "meta", .kind = .kw_meta },
        .{ .name = "strings", .kind = .kw_strings },
        .{ .name = "condition", .kind = .kw_condition },
        .{ .name = "any", .kind = .kw_any },
        .{ .name = "all", .kind = .kw_all },
        .{ .name = "of", .kind = .kw_of },
        .{ .name = "them", .kind = .kw_them },
        .{ .name = "and", .kind = .kw_and },
        .{ .name = "or", .kind = .kw_or },
        .{ .name = "not", .kind = .kw_not },
        .{ .name = "ascii", .kind = .kw_ascii },
        .{ .name = "wide", .kind = .kw_wide },
        .{ .name = "nocase", .kind = .kw_nocase },
        .{ .name = "fullword", .kind = .kw_fullword },
        .{ .name = "true", .kind = .kw_true },
        .{ .name = "false", .kind = .kw_false },
    };
    for (map) |entry| {
        if (std.mem.eql(u8, text, entry.name)) return entry.kind;
    }
    return .ident;
}

// ----------------------------------------------------------------------------
// Parser
// ----------------------------------------------------------------------------

pub fn parse(allocator: std.mem.Allocator, source: []const u8) ScribeError!RuleSet {
    var p = Parser{ .allocator = allocator, .lex = .{ .src = source }, .cur = undefined };
    p.cur = try p.lex.next();
    return try p.parseRuleSet();
}

const Parser = struct {
    allocator: std.mem.Allocator,
    lex: Lexer,
    cur: Token,

    fn advance(self: *Parser) ScribeError!void {
        self.cur = try self.lex.next();
    }

    fn expect(self: *Parser, kind: TokenKind) ScribeError!Token {
        if (self.cur.kind != kind) return error.NotImplemented;
        const t = self.cur;
        try self.advance();
        return t;
    }

    fn parseRuleSet(self: *Parser) ScribeError!RuleSet {
        var list: std.ArrayList(Rule) = .empty;
        errdefer {
            for (list.items) |*r| freeRule(self.allocator, r);
            list.deinit(self.allocator);
        }
        while (self.cur.kind != .eof) {
            const r = try self.parseRule();
            list.append(self.allocator, r) catch return error.OutOfMemory;
        }
        return .{ .rules = list.toOwnedSlice(self.allocator) catch return error.OutOfMemory };
    }

    fn parseRule(self: *Parser) ScribeError!Rule {
        _ = try self.expect(.kw_rule);
        const name_tok = try self.expect(.ident);
        const name = self.allocator.dupe(u8, name_tok.text) catch return error.OutOfMemory;
        errdefer self.allocator.free(name);

        var tags: std.ArrayList([]u8) = .empty;
        errdefer {
            for (tags.items) |t| self.allocator.free(t);
            tags.deinit(self.allocator);
        }
        if (self.cur.kind == .colon) {
            try self.advance();
            while (self.cur.kind == .ident) {
                const t = self.allocator.dupe(u8, self.cur.text) catch return error.OutOfMemory;
                tags.append(self.allocator, t) catch return error.OutOfMemory;
                try self.advance();
            }
        }

        _ = try self.expect(.lbrace);

        // Optional `meta:` block — read & discard. We don't currently
        // surface metadata, so just walk past the bindings.
        if (self.cur.kind == .kw_meta) {
            try self.advance();
            _ = try self.expect(.colon);
            while (self.cur.kind == .ident) {
                try self.advance();
                _ = try self.expect(.eq);
                switch (self.cur.kind) {
                    .string, .integer, .kw_true, .kw_false => try self.advance(),
                    else => return error.NotImplemented,
                }
            }
        }

        var strings: std.ArrayList(StringDef) = .empty;
        errdefer {
            for (strings.items) |s| {
                self.allocator.free(s.name);
                switch (s.pattern) {
                    .literal => |lit| self.allocator.free(lit.bytes),
                    .hex => |h| {
                        self.allocator.free(h.value);
                        self.allocator.free(h.mask);
                    },
                }
            }
            strings.deinit(self.allocator);
        }

        if (self.cur.kind == .kw_strings) {
            try self.advance();
            _ = try self.expect(.colon);
            while (self.cur.kind == .dollar) {
                try self.advance();
                const sname_tok = try self.expect(.ident);
                const sname = self.allocator.dupe(u8, sname_tok.text) catch return error.OutOfMemory;
                errdefer self.allocator.free(sname);
                // For hex patterns, the lexer needs to know the next `{` is
                // a hex block, not a rule-body opener. Set the flag *before*
                // expect(eq) so its internal advance() picks the right path,
                // then clear it immediately so subsequent `{` (next rule's
                // body opener) tokenizes as `lbrace`.
                self.lex.hex_mode = true;
                _ = try self.expect(.eq);
                self.lex.hex_mode = false;
                switch (self.cur.kind) {
                    .string => {
                        const lit_text = self.cur.text;
                        try self.advance();
                        var mods = Modifiers{};
                        while (true) switch (self.cur.kind) {
                            .kw_ascii => try self.advance(),
                            .kw_wide => { mods.wide = true; try self.advance(); },
                            .kw_nocase => { mods.nocase = true; try self.advance(); },
                            .kw_fullword => try self.advance(),
                            else => break,
                        };
                        const bytes = unescapeString(self.allocator, lit_text) catch return error.OutOfMemory;
                        strings.append(self.allocator, .{
                            .name = sname,
                            .pattern = .{ .literal = .{ .bytes = bytes, .modifiers = mods } },
                        }) catch return error.OutOfMemory;
                    },
                    .hex_block => {
                        const hex_text = self.cur.text;
                        try self.advance();
                        const parsed = try parseHexBlock(self.allocator, hex_text);
                        strings.append(self.allocator, .{
                            .name = sname,
                            .pattern = .{ .hex = .{ .value = parsed.value, .mask = parsed.mask } },
                        }) catch return error.OutOfMemory;
                    },
                    else => return error.NotImplemented,
                }
            }
        }

        _ = try self.expect(.kw_condition);
        _ = try self.expect(.colon);
        const cond = try self.parseExpr(strings.items);

        _ = try self.expect(.rbrace);

        return .{
            .name = name,
            .tags = tags.toOwnedSlice(self.allocator) catch return error.OutOfMemory,
            .strings = strings.toOwnedSlice(self.allocator) catch return error.OutOfMemory,
            .condition = cond,
        };
    }

    // expr = or_expr
    // or_expr = and_expr ("or" and_expr)*
    // and_expr = unary ("and" unary)*
    // unary = "not" unary | primary
    // primary = quantifier | "$" IDENT | "true" | "false" | "(" expr ")"
    // quantifier = ("any" | "all" | INT) "of" "them"
    fn parseExpr(self: *Parser, strs: []StringDef) ScribeError!*Cond {
        return self.parseOr(strs);
    }

    fn parseOr(self: *Parser, strs: []StringDef) ScribeError!*Cond {
        var lhs = try self.parseAnd(strs);
        while (self.cur.kind == .kw_or) {
            try self.advance();
            const rhs = try self.parseAnd(strs);
            const node = self.allocator.create(Cond) catch return error.OutOfMemory;
            node.* = .{ .or_op = .{ .lhs = lhs, .rhs = rhs } };
            lhs = node;
        }
        return lhs;
    }

    fn parseAnd(self: *Parser, strs: []StringDef) ScribeError!*Cond {
        var lhs = try self.parseUnary(strs);
        while (self.cur.kind == .kw_and) {
            try self.advance();
            const rhs = try self.parseUnary(strs);
            const node = self.allocator.create(Cond) catch return error.OutOfMemory;
            node.* = .{ .and_op = .{ .lhs = lhs, .rhs = rhs } };
            lhs = node;
        }
        return lhs;
    }

    fn parseUnary(self: *Parser, strs: []StringDef) ScribeError!*Cond {
        if (self.cur.kind == .kw_not) {
            try self.advance();
            const inner = try self.parseUnary(strs);
            const node = self.allocator.create(Cond) catch return error.OutOfMemory;
            node.* = .{ .not_op = inner };
            return node;
        }
        return self.parsePrimary(strs);
    }

    fn parsePrimary(self: *Parser, strs: []StringDef) ScribeError!*Cond {
        switch (self.cur.kind) {
            .lparen => {
                try self.advance();
                const inner = try self.parseExpr(strs);
                _ = try self.expect(.rparen);
                return inner;
            },
            .dollar => {
                try self.advance();
                const id = try self.expect(.ident);
                const name = self.allocator.dupe(u8, id.text) catch return error.OutOfMemory;
                const node = self.allocator.create(Cond) catch {
                    self.allocator.free(name);
                    return error.OutOfMemory;
                };
                node.* = .{ .string_ref = name };
                return node;
            },
            .kw_any => {
                try self.advance();
                _ = try self.expect(.kw_of);
                _ = try self.expect(.kw_them);
                const node = self.allocator.create(Cond) catch return error.OutOfMemory;
                node.* = .any_of_them;
                return node;
            },
            .kw_all => {
                try self.advance();
                _ = try self.expect(.kw_of);
                _ = try self.expect(.kw_them);
                const node = self.allocator.create(Cond) catch return error.OutOfMemory;
                node.* = .all_of_them;
                return node;
            },
            .integer => {
                const tok = self.cur;
                try self.advance();
                _ = try self.expect(.kw_of);
                _ = try self.expect(.kw_them);
                const n = std.fmt.parseInt(u32, tok.text, 10) catch return error.NotImplemented;
                const node = self.allocator.create(Cond) catch return error.OutOfMemory;
                node.* = .{ .n_of_them = n };
                return node;
            },
            .kw_true => {
                try self.advance();
                const node = self.allocator.create(Cond) catch return error.OutOfMemory;
                node.* = .{ .bool_lit = true };
                return node;
            },
            .kw_false => {
                try self.advance();
                const node = self.allocator.create(Cond) catch return error.OutOfMemory;
                node.* = .{ .bool_lit = false };
                return node;
            },
            else => return error.NotImplemented,
        }
    }
};

fn unescapeString(allocator: std.mem.Allocator, raw: []const u8) ![]u8 {
    var out = try allocator.alloc(u8, raw.len);
    var i: usize = 0;
    var j: usize = 0;
    while (i < raw.len) {
        if (raw[i] == '\\' and i + 1 < raw.len) {
            const c = raw[i + 1];
            out[j] = switch (c) {
                'n' => '\n',
                'r' => '\r',
                't' => '\t',
                '"' => '"',
                '\\' => '\\',
                'x' => blk: {
                    if (i + 3 >= raw.len) break :blk c;
                    const hi = hexDigit(raw[i + 2]) orelse break :blk c;
                    const lo = hexDigit(raw[i + 3]) orelse break :blk c;
                    i += 2;
                    break :blk (hi << 4) | lo;
                },
                else => c,
            };
            i += 2;
        } else {
            out[j] = raw[i];
            i += 1;
        }
        j += 1;
    }
    return allocator.realloc(out, j) catch out[0..j];
}

fn hexDigit(c: u8) ?u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => null,
    };
}

const HexParse = struct { value: []u8, mask: []u8 };

fn parseHexBlock(allocator: std.mem.Allocator, text: []const u8) ScribeError!HexParse {
    // Strip outer braces.
    if (text.len < 2 or text[0] != '{' or text[text.len - 1] != '}') return error.NotImplemented;
    const body = text[1 .. text.len - 1];

    var value: std.ArrayList(u8) = .empty;
    errdefer value.deinit(allocator);
    var mask: std.ArrayList(u8) = .empty;
    errdefer mask.deinit(allocator);

    var i: usize = 0;
    while (i < body.len) {
        const c = body[i];
        if (c == ' ' or c == '\t' or c == '\r' or c == '\n') {
            i += 1;
            continue;
        }
        if (c == '?' and i + 1 < body.len and body[i + 1] == '?') {
            value.append(allocator, 0) catch return error.OutOfMemory;
            mask.append(allocator, 0) catch return error.OutOfMemory;
            i += 2;
            continue;
        }
        // Two-hex-digit byte.
        if (i + 1 >= body.len) return error.NotImplemented;
        const hi = hexDigit(c) orelse return error.NotImplemented;
        const lo = hexDigit(body[i + 1]) orelse return error.NotImplemented;
        value.append(allocator, (hi << 4) | lo) catch return error.OutOfMemory;
        mask.append(allocator, 0xFF) catch return error.OutOfMemory;
        i += 2;
    }

    return .{
        .value = value.toOwnedSlice(allocator) catch return error.OutOfMemory,
        .mask = mask.toOwnedSlice(allocator) catch return error.OutOfMemory,
    };
}

// ----------------------------------------------------------------------------
// Scanner
// ----------------------------------------------------------------------------

pub fn scan(
    allocator: std.mem.Allocator,
    rules: RuleSet,
    bytes: []const u8,
) ScribeError![]Match {
    var matches: std.ArrayList(Match) = .empty;
    errdefer {
        for (matches.items) |*m| m.deinit(allocator);
        matches.deinit(allocator);
    }

    for (rules.rules) |r| {
        // Find every hit for every defined string. Each entry is a list of
        // offsets; an empty list means no match for that string.
        var per_string_hit_count = allocator.alloc(usize, r.strings.len) catch return error.OutOfMemory;
        defer allocator.free(per_string_hit_count);
        @memset(per_string_hit_count, 0);

        var hits: std.ArrayList(StringHit) = .empty;
        errdefer hits.deinit(allocator);

        for (r.strings, 0..) |s, idx| {
            const count = try findHits(allocator, &hits, s, bytes);
            per_string_hit_count[idx] = count;
        }

        const matched_count = countMatched(per_string_hit_count);
        const ok = evalCond(r.condition, r.strings, per_string_hit_count, matched_count);
        if (ok) {
            const tags_const_ptr: [*]const []const u8 = @ptrCast(r.tags.ptr);
            matches.append(allocator, .{
                .rule = r.name,
                .tags = tags_const_ptr[0..r.tags.len],
                .hits = hits.toOwnedSlice(allocator) catch return error.OutOfMemory,
            }) catch return error.OutOfMemory;
        } else {
            hits.deinit(allocator);
        }
    }

    return matches.toOwnedSlice(allocator) catch error.OutOfMemory;
}

fn countMatched(per_string: []const usize) u32 {
    var n: u32 = 0;
    for (per_string) |c| if (c > 0) {
        n += 1;
    };
    return n;
}

fn findHits(
    allocator: std.mem.Allocator,
    out: *std.ArrayList(StringHit),
    s: StringDef,
    bytes: []const u8,
) ScribeError!usize {
    var count: usize = 0;
    switch (s.pattern) {
        .literal => |lit| {
            if (lit.modifiers.wide) {
                // Build wide form (interleave 0x00) and search.
                var wide = allocator.alloc(u8, lit.bytes.len * 2) catch return error.OutOfMemory;
                defer allocator.free(wide);
                for (lit.bytes, 0..) |b, i| {
                    wide[i * 2] = b;
                    wide[i * 2 + 1] = 0;
                }
                count = appendOccurrences(allocator, out, s.name, bytes, wide, lit.modifiers.nocase) catch return error.OutOfMemory;
            } else {
                count = appendOccurrences(allocator, out, s.name, bytes, lit.bytes, lit.modifiers.nocase) catch return error.OutOfMemory;
            }
        },
        .hex => |h| {
            count = appendHexOccurrences(allocator, out, s.name, bytes, h.value, h.mask) catch return error.OutOfMemory;
        },
    }
    return count;
}

fn appendOccurrences(
    allocator: std.mem.Allocator,
    out: *std.ArrayList(StringHit),
    name: []const u8,
    haystack: []const u8,
    needle: []const u8,
    nocase: bool,
) !usize {
    if (needle.len == 0 or needle.len > haystack.len) return 0;
    var count: usize = 0;
    var i: usize = 0;
    const limit = haystack.len - needle.len + 1;
    while (i < limit) : (i += 1) {
        if (matchAt(haystack, i, needle, nocase)) {
            try out.append(allocator, .{ .name = name, .offset = i });
            count += 1;
        }
    }
    return count;
}

fn matchAt(haystack: []const u8, off: usize, needle: []const u8, nocase: bool) bool {
    var i: usize = 0;
    while (i < needle.len) : (i += 1) {
        const a = haystack[off + i];
        const b = needle[i];
        if (nocase) {
            if (asciiLower(a) != asciiLower(b)) return false;
        } else {
            if (a != b) return false;
        }
    }
    return true;
}

fn asciiLower(c: u8) u8 {
    return if (c >= 'A' and c <= 'Z') c + 32 else c;
}

fn appendHexOccurrences(
    allocator: std.mem.Allocator,
    out: *std.ArrayList(StringHit),
    name: []const u8,
    haystack: []const u8,
    value: []const u8,
    mask: []const u8,
) !usize {
    if (value.len == 0 or value.len > haystack.len) return 0;
    var count: usize = 0;
    var i: usize = 0;
    const limit = haystack.len - value.len + 1;
    while (i < limit) : (i += 1) {
        var k: usize = 0;
        var ok = true;
        while (k < value.len) : (k += 1) {
            if ((haystack[i + k] & mask[k]) != value[k]) {
                ok = false;
                break;
            }
        }
        if (ok) {
            try out.append(allocator, .{ .name = name, .offset = i });
            count += 1;
        }
    }
    return count;
}

fn evalCond(cond: *const Cond, strs: []const StringDef, per_string: []const usize, matched: u32) bool {
    return switch (cond.*) {
        .bool_lit => |b| b,
        .any_of_them => matched > 0,
        .all_of_them => matched == strs.len,
        .n_of_them => |n| matched >= n,
        .string_ref => |name| blk: {
            for (strs, 0..) |s, i| {
                if (std.mem.eql(u8, s.name, name)) break :blk per_string[i] > 0;
            }
            break :blk false;
        },
        .and_op => |bin| evalCond(bin.lhs, strs, per_string, matched) and evalCond(bin.rhs, strs, per_string, matched),
        .or_op => |bin| evalCond(bin.lhs, strs, per_string, matched) or evalCond(bin.rhs, strs, per_string, matched),
        .not_op => |inner| !evalCond(inner, strs, per_string, matched),
    };
}

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

test "parse + match literal string" {
    const src =
        \\rule has_hello {
        \\  strings:
        \\    $a = "hello"
        \\  condition:
        \\    $a
        \\}
    ;
    const allocator = std.testing.allocator;
    var rs = try parse(allocator, src);
    defer rs.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), rs.rules.len);
    const matches = try scan(allocator, rs, "say hello world");
    defer freeMatches(allocator, matches);
    try std.testing.expectEqual(@as(usize, 1), matches.len);
    try std.testing.expectEqual(@as(usize, 1), matches[0].hits.len);
    try std.testing.expectEqual(@as(usize, 4), matches[0].hits[0].offset);
}

test "parse + match hex pattern with wildcard" {
    const src =
        \\rule packed_marker {
        \\  strings:
        \\    $sig = { 4D 5A ?? ?? 50 45 }
        \\  condition:
        \\    $sig
        \\}
    ;
    const allocator = std.testing.allocator;
    var rs = try parse(allocator, src);
    defer rs.deinit(allocator);
    const data = [_]u8{ 'M', 'Z', 0x90, 0x00, 'P', 'E', 0, 0 };
    const matches = try scan(allocator, rs, &data);
    defer freeMatches(allocator, matches);
    try std.testing.expectEqual(@as(usize, 1), matches.len);
}

test "any/all/N of them" {
    const src =
        \\rule any_of {
        \\  strings:
        \\    $a = "foo"
        \\    $b = "bar"
        \\    $c = "baz"
        \\  condition:
        \\    2 of them
        \\}
    ;
    const allocator = std.testing.allocator;
    var rs = try parse(allocator, src);
    defer rs.deinit(allocator);
    const matches = try scan(allocator, rs, "this has foo and bar in it");
    defer freeMatches(allocator, matches);
    try std.testing.expectEqual(@as(usize, 1), matches.len);
}

test "wide and nocase modifiers" {
    const src =
        \\rule mixed {
        \\  strings:
        \\    $a = "Secret" nocase
        \\    $b = "Wide" wide
        \\  condition:
        \\    $a and $b
        \\}
    ;
    const allocator = std.testing.allocator;
    var rs = try parse(allocator, src);
    defer rs.deinit(allocator);
    var data: [40]u8 = @splat(0);
    @memcpy(data[0..6], "secret");
    // "Wide" as UTF-16LE: W 00 i 00 d 00 e 00
    data[10] = 'W'; data[12] = 'i'; data[14] = 'd'; data[16] = 'e';
    const matches = try scan(allocator, rs, &data);
    defer freeMatches(allocator, matches);
    try std.testing.expectEqual(@as(usize, 1), matches.len);
}

test "boolean conditions" {
    const src =
        \\rule b {
        \\  strings:
        \\    $a = "alpha"
        \\    $b = "beta"
        \\  condition:
        \\    $a and not $b
        \\}
    ;
    const allocator = std.testing.allocator;
    var rs = try parse(allocator, src);
    defer rs.deinit(allocator);
    const m1 = try scan(allocator, rs, "alpha only");
    defer freeMatches(allocator, m1);
    try std.testing.expectEqual(@as(usize, 1), m1.len);
    const m2 = try scan(allocator, rs, "alpha and beta");
    defer freeMatches(allocator, m2);
    try std.testing.expectEqual(@as(usize, 0), m2.len);
}
