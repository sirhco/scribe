//! Minimal YAML 1.2 subset parser, focused on what Kubernetes manifests
//! actually use. Handles:
//!
//!   - Multi-document streams (`---` separators).
//!   - Block-style mappings and sequences (the dominant style in k8s).
//!   - Flow-style mappings/sequences (`{a: b, c: d}` / `[1, 2, 3]`)
//!     including nested.
//!   - Anchors (`&name`) and aliases (`*name`) — alias resolves to a
//!     deep-cloned copy of the anchored node.
//!   - Quoted strings (`"..."` / `'...'`) with basic escapes.
//!   - Plain scalars (unquoted).
//!   - Block / folded literals (`|`, `>`) treated as opaque multi-line
//!     strings; chomping indicators (`|-`, `|+`, etc) accepted but
//!     ignored beyond the basic strip.
//!   - Comments (`#` to end of line outside strings).
//!   - Helm-style `{{ ... }}` template expressions tolerated as opaque
//!     scalar bytes — we don't expand them, but they no longer break
//!     parsing the way `:` inside templates breaks naive scanners.
//!
//! Out of scope (intentionally — every k8s manifest I've audited is fine
//! without these):
//!
//!   - YAML 1.1 booleans (`yes`/`no`/`on`/`off`); only `true`/`false`.
//!   - Tags (`!!str`, `!!int`, custom `!Foo`) — accepted in input,
//!     dropped from the parsed tree (value-only).
//!   - Complex keys (`?` mapping keys).
//!   - Set type (`!!set`).
//!   - Merge keys (`<<:`).
//!
//! Returns a `Node` tree that owns its strings via the passed allocator.
//! Use `Node.scalar` / `Node.mapping` / etc. accessors for navigation.
//! `findScalar` and friends provide concise lookup helpers.

const std = @import("std");

pub const NodeKind = enum { scalar, sequence, mapping };

pub const Node = struct {
    kind: NodeKind,
    /// One of `scalar` (string bytes) or aggregate (`seq` / `map`),
    /// based on `kind`. Parser leaves the inactive arms empty/null.
    scalar: []u8 = "",
    seq: []Node = &.{},
    map: []KeyValue = &.{},
    /// Source line number (1-based) where this node began. 0 for synthetic.
    line: u32 = 0,

    pub fn deinit(self: *Node, allocator: std.mem.Allocator) void {
        switch (self.kind) {
            .scalar => allocator.free(self.scalar),
            .sequence => {
                for (self.seq) |*n| {
                    var nm = n.*;
                    nm.deinit(allocator);
                }
                if (self.seq.len > 0) allocator.free(self.seq);
            },
            .mapping => {
                for (self.map) |*kv| kv.deinit(allocator);
                if (self.map.len > 0) allocator.free(self.map);
            },
        }
        self.scalar = "";
        self.seq = &.{};
        self.map = &.{};
    }

    /// Lookup a scalar value by key inside a mapping. Returns null when the
    /// node isn't a mapping, key isn't found, or the value isn't a scalar.
    pub fn getScalar(self: Node, key: []const u8) ?[]const u8 {
        if (self.kind != .mapping) return null;
        for (self.map) |kv| {
            if (std.mem.eql(u8, kv.key, key) and kv.value.kind == .scalar) {
                return kv.value.scalar;
            }
        }
        return null;
    }

    /// Lookup any child by key (returns the Node regardless of kind).
    pub fn get(self: Node, key: []const u8) ?*const Node {
        if (self.kind != .mapping) return null;
        for (self.map) |*kv| {
            if (std.mem.eql(u8, kv.key, key)) return &kv.value;
        }
        return null;
    }

    /// Walk a `.`-separated path through nested mappings.
    pub fn getPath(self: Node, path: []const u8) ?*const Node {
        var cur: *const Node = &self;
        var it = std.mem.splitScalar(u8, path, '.');
        while (it.next()) |segment| {
            if (cur.kind != .mapping) return null;
            const child = cur.get(segment) orelse return null;
            cur = child;
        }
        return cur;
    }
};

pub const KeyValue = struct {
    key: []u8, // owned
    value: Node,
    line: u32 = 0,

    pub fn deinit(self: *KeyValue, allocator: std.mem.Allocator) void {
        allocator.free(self.key);
        self.value.deinit(allocator);
    }
};

pub const Document = struct {
    /// Root node of one YAML document. May be any kind.
    root: Node,
    /// 1-based line in the original source where the document began.
    start_line: u32,

    pub fn deinit(self: *Document, allocator: std.mem.Allocator) void {
        self.root.deinit(allocator);
    }
};

pub const Stream = struct {
    documents: []Document,

    pub fn deinit(self: *Stream, allocator: std.mem.Allocator) void {
        for (self.documents) |*d| d.deinit(allocator);
        if (self.documents.len > 0) allocator.free(self.documents);
        self.documents = &.{};
    }
};

pub const Error = error{
    UnexpectedToken,
    UnterminatedString,
    UnterminatedFlow,
    UnknownAnchor,
    BadIndent,
    OutOfMemory,
};

pub fn parse(allocator: std.mem.Allocator, src: []const u8) Error!Stream {
    var p: Parser = .{
        .allocator = allocator,
        .src = src,
        .pos = 0,
        .line = 1,
        .anchors = std.StringHashMap(Node).init(allocator),
    };
    defer p.anchors.deinit();
    errdefer {
        var it = p.anchors.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            var n = entry.value_ptr.*;
            n.deinit(allocator);
        }
    }

    var docs: std.ArrayList(Document) = .empty;
    errdefer {
        for (docs.items) |*d| d.deinit(allocator);
        docs.deinit(allocator);
    }

    while (true) {
        p.skipBlankLinesAndComments();
        if (p.pos >= src.len) break;

        // Optional document-start marker.
        const doc_start_line = p.line;
        if (p.atLineStart() and std.mem.startsWith(u8, p.src[p.pos..], "---")) {
            p.pos += 3;
            p.skipToNewline();
            p.consumeNewline();
        }
        // Optional document-end marker — closes prior doc, no node here.
        if (p.atLineStart() and std.mem.startsWith(u8, p.src[p.pos..], "...")) {
            p.pos += 3;
            p.skipToNewline();
            p.consumeNewline();
            continue;
        }

        p.skipBlankLinesAndComments();
        if (p.pos >= src.len) break;

        // Parse one root node at indent = current column (typically 0).
        const indent = p.currentIndent();
        const root = try p.parseNode(indent);
        try docs.append(allocator, .{ .root = root, .start_line = doc_start_line });
    }

    // Free anchor scratch copies (their content was deep-copied at alias-resolve).
    var it = p.anchors.iterator();
    while (it.next()) |entry| {
        allocator.free(entry.key_ptr.*);
        var n = entry.value_ptr.*;
        n.deinit(allocator);
    }

    const items = docs.toOwnedSlice(allocator) catch return error.OutOfMemory;
    return .{ .documents = items };
}

const Parser = struct {
    allocator: std.mem.Allocator,
    src: []const u8,
    pos: usize,
    line: u32,
    anchors: std.StringHashMap(Node),

    fn atLineStart(self: *Parser) bool {
        return self.pos == 0 or (self.pos > 0 and self.src[self.pos - 1] == '\n');
    }

    fn currentIndent(self: *Parser) usize {
        // Number of leading spaces on the current line.
        var i = self.pos;
        while (i > 0 and self.src[i - 1] != '\n') i -= 1;
        var n: usize = 0;
        while (i + n < self.src.len and self.src[i + n] == ' ') n += 1;
        return n;
    }

    /// Column (0-based) of `self.pos` on the current line. Used when we
    /// want to call into a sub-parser whose "indent" should be the current
    /// caret column rather than the line's leading whitespace.
    fn currentColumn(self: *Parser) usize {
        var i = self.pos;
        while (i > 0 and self.src[i - 1] != '\n') i -= 1;
        return self.pos - i;
    }

    fn skipSpaces(self: *Parser) void {
        while (self.pos < self.src.len and (self.src[self.pos] == ' ' or self.src[self.pos] == '\t'))
            self.pos += 1;
    }

    fn skipToNewline(self: *Parser) void {
        while (self.pos < self.src.len and self.src[self.pos] != '\n') self.pos += 1;
    }

    fn consumeNewline(self: *Parser) void {
        if (self.pos < self.src.len and self.src[self.pos] == '\n') {
            self.pos += 1;
            self.line += 1;
        }
    }

    fn skipBlankLinesAndComments(self: *Parser) void {
        while (self.pos < self.src.len) {
            const start = self.pos;
            self.skipSpaces();
            if (self.pos >= self.src.len) return;
            const ch = self.src[self.pos];
            if (ch == '\n') {
                self.consumeNewline();
                continue;
            }
            if (ch == '#') {
                self.skipToNewline();
                self.consumeNewline();
                continue;
            }
            // Real content — rewind to indent-preserving position and bail.
            self.pos = start;
            return;
        }
    }

    /// Parse a node at base indent `indent`. Decides scalar/sequence/mapping
    /// from the first non-blank token at the current position.
    fn parseNode(self: *Parser, indent: usize) Error!Node {
        self.skipBlankLinesAndComments();
        if (self.pos >= self.src.len) return Node{ .kind = .scalar, .scalar = try self.allocator.dupe(u8, ""), .line = self.line };

        // Optional anchor / tag prefix.
        var anchor_name: ?[]const u8 = null;
        if (self.peek() == '&') {
            anchor_name = try self.parseAnchorName();
            self.skipSpaces();
        }
        if (self.peek() == '!') {
            // Drop tag; advance to whitespace.
            while (self.pos < self.src.len and self.src[self.pos] != ' ' and self.src[self.pos] != '\n') self.pos += 1;
            self.skipSpaces();
        }

        // Alias?
        if (self.peek() == '*') {
            const name = try self.parseAnchorName();
            const stored = self.anchors.get(name) orelse return error.UnknownAnchor;
            const cloned = try cloneNode(self.allocator, stored);
            if (anchor_name) |a| try self.storeAnchor(a, cloned);
            return cloned;
        }

        // Flow-style?
        if (self.peek() == '[') {
            const node = try self.parseFlowSeq();
            if (anchor_name) |a| try self.storeAnchor(a, node);
            return node;
        }
        if (self.peek() == '{') {
            const node = try self.parseFlowMap();
            if (anchor_name) |a| try self.storeAnchor(a, node);
            return node;
        }

        // Block sequence?
        if (self.peek() == '-' and self.peekN(1) != null and (self.peekN(1).? == ' ' or self.peekN(1).? == '\n')) {
            const node = try self.parseBlockSeq(indent);
            if (anchor_name) |a| try self.storeAnchor(a, node);
            return node;
        }
        // Block sequence at this indent (compact style: leading indent spaces
        // followed by `- `, common in Kubernetes manifests where the sequence
        // sits at the same column as its parent key).
        if (self.atLineStart()) {
            const li = self.currentIndent();
            if (li == indent and self.pos + li < self.src.len and self.src[self.pos + li] == '-') {
                const after: u8 = if (self.pos + li + 1 < self.src.len) self.src[self.pos + li + 1] else '\n';
                if (after == ' ' or after == '\n') {
                    const node = try self.parseBlockSeq(indent);
                    if (anchor_name) |a| try self.storeAnchor(a, node);
                    return node;
                }
            }
        }

        // Block / folded literal?
        if (self.peek() == '|' or self.peek() == '>') {
            const node = try self.parseBlockLiteral(indent);
            if (anchor_name) |a| try self.storeAnchor(a, node);
            return node;
        }

        // Could be a mapping (key: value) or a plain scalar. Look ahead for `:`.
        const line_end = self.lineEnd();
        const line_text = self.src[self.pos..line_end];
        if (findMapKeyDelim(line_text)) |_| {
            const node = try self.parseBlockMap(indent);
            if (anchor_name) |a| try self.storeAnchor(a, node);
            return node;
        }

        const node = try self.parsePlainScalar();
        if (anchor_name) |a| try self.storeAnchor(a, node);
        return node;
    }

    fn parseAnchorName(self: *Parser) Error![]const u8 {
        std.debug.assert(self.peek() == '&' or self.peek() == '*');
        self.pos += 1;
        const start = self.pos;
        while (self.pos < self.src.len) : (self.pos += 1) {
            const c = self.src[self.pos];
            if (c == ' ' or c == '\n' or c == ',' or c == ']' or c == '}' or c == '\t') break;
        }
        return self.src[start..self.pos];
    }

    fn storeAnchor(self: *Parser, name: []const u8, node: Node) Error!void {
        // Anchors store DEEP COPIES so that the original tree's lifetime
        // is decoupled from the alias resolution.
        const cloned = try cloneNode(self.allocator, node);
        const key = try self.allocator.dupe(u8, name);
        try self.anchors.put(key, cloned);
    }

    fn lineEnd(self: *Parser) usize {
        var i = self.pos;
        while (i < self.src.len and self.src[i] != '\n') i += 1;
        return i;
    }

    fn peek(self: *Parser) u8 {
        return if (self.pos < self.src.len) self.src[self.pos] else 0;
    }

    fn peekN(self: *Parser, n: usize) ?u8 {
        return if (self.pos + n < self.src.len) self.src[self.pos + n] else null;
    }

    fn parseBlockMap(self: *Parser, indent: usize) Error!Node {
        var entries: std.ArrayList(KeyValue) = .empty;
        errdefer {
            for (entries.items) |*kv| kv.deinit(self.allocator);
            entries.deinit(self.allocator);
        }
        // Merge-key (`<<: *anchor` / `<<: [*a, *b]`) values are deferred to
        // the end of the map so explicit keys — wherever they appear in
        // source order — always override merged ones, per YAML 1.1.
        var merges: std.ArrayList(Node) = .empty;
        defer {
            for (merges.items) |*n| n.deinit(self.allocator);
            merges.deinit(self.allocator);
        }

        const start_line = self.line;
        // The first iteration may begin mid-line (e.g. when a block sequence
        // dispatches `- key: val` directly into the map parser). In that
        // case the caller passes `indent` = column of the first key, and we
        // skip the leading-whitespace machinery for one iteration.
        var first_mid_line = !self.atLineStart();

        while (true) {
            if (!first_mid_line) {
                self.skipBlankLinesAndComments();
                if (self.pos >= self.src.len) break;

                const cur_indent = self.currentIndent();
                if (cur_indent < indent) break;
                if (cur_indent > indent) {
                    // Belongs to a parent value; bail out cleanly.
                    break;
                }

                // Document boundary closes the map.
                if (self.atLineStart()) {
                    if (std.mem.startsWith(u8, self.src[self.pos + cur_indent ..], "---") or
                        std.mem.startsWith(u8, self.src[self.pos + cur_indent ..], "..."))
                    {
                        break;
                    }
                }

                // Skip the indent.
                self.pos += cur_indent;

                // A `-` here means we're not actually a map; let the caller handle it.
                if (self.peek() == '-' and (self.peekN(1) == null or self.peekN(1).? == ' ' or self.peekN(1).? == '\n')) {
                    // Rewind to start-of-line and bail.
                    self.pos -= cur_indent;
                    break;
                }
            }
            first_mid_line = false;

            const line_end = self.lineEnd();
            const line_text = self.src[self.pos..line_end];
            const colon_off = findMapKeyDelim(line_text) orelse break;

            const kv_line = self.line;
            const key_raw = std.mem.trim(u8, line_text[0..colon_off], " \t");
            const key = try parseScalarPiece(self.allocator, key_raw);
            errdefer self.allocator.free(key);

            // Advance past the colon.
            self.pos += colon_off + 1;
            self.skipSpaces();

            // Strip trailing inline comment from the rest of the line.
            const rest_end = stripInlineComment(self.src[self.pos..line_end]);
            var rest = self.src[self.pos .. self.pos + rest_end];

            // A bare `&anchor` on the rest of the line (with no inline
            // value following it) introduces a deferred block value on
            // subsequent lines. Strip the anchor here so the empty-rest
            // path below parses the block, and stash the name so we can
            // register it once we have the real value.
            var pending_anchor: ?[]const u8 = null;
            {
                const trimmed_rest = std.mem.trim(u8, rest, " \t");
                if (trimmed_rest.len > 0 and trimmed_rest[0] == '&') {
                    var j: usize = 1;
                    while (j < trimmed_rest.len and trimmed_rest[j] != ' ' and trimmed_rest[j] != '\t') j += 1;
                    const tail = std.mem.trim(u8, trimmed_rest[j..], " \t");
                    if (tail.len == 0) {
                        pending_anchor = trimmed_rest[1..j];
                        // Consume the anchor token from the source so the
                        // empty-rest branch sees no inline content.
                        self.pos = line_end;
                        rest = self.src[line_end..line_end];
                    }
                }
            }

            var value: Node = undefined;
            if (rest.len == 0) {
                // Value continues on next line(s) at deeper indent — or at
                // the same indent for compact block sequences.
                self.pos = line_end;
                self.consumeNewline();
                self.skipBlankLinesAndComments();
                const child_indent = self.currentIndent();
                if (child_indent < indent) {
                    value = .{ .kind = .scalar, .scalar = try self.allocator.dupe(u8, ""), .line = kv_line };
                } else if (child_indent == indent) {
                    // Compact block sequence at parent indent? `- ` after the indent.
                    const ci = child_indent;
                    if (self.pos + ci < self.src.len and self.src[self.pos + ci] == '-') {
                        const after: u8 = if (self.pos + ci + 1 < self.src.len) self.src[self.pos + ci + 1] else '\n';
                        if (after == ' ' or after == '\n') {
                            value = try self.parseBlockSeq(indent);
                        } else {
                            value = .{ .kind = .scalar, .scalar = try self.allocator.dupe(u8, ""), .line = kv_line };
                        }
                    } else {
                        value = .{ .kind = .scalar, .scalar = try self.allocator.dupe(u8, ""), .line = kv_line };
                    }
                } else {
                    value = try self.parseNode(child_indent);
                }
            } else if (rest.len > 0 and (rest[0] == '|' or rest[0] == '>')) {
                // Block / folded literal scalar — parse out of the standard
                // inline path because it consumes subsequent lines, not just
                // the rest of the key's line.
                self.pos = (@intFromPtr(rest.ptr) - @intFromPtr(self.src.ptr));
                value = try self.parseBlockLiteral(indent);
            } else {
                // Inline value on the same line — could be flow, scalar, or alias.
                value = try self.parseInlineValue(rest, kv_line);
                self.pos = line_end;
                self.consumeNewline();
            }

            if (pending_anchor) |aname| {
                try self.storeAnchor(aname, value);
            }

            if (std.mem.eql(u8, key, "<<")) {
                // YAML 1.1 merge key. Stash the source mapping(s); apply
                // after explicit entries are gathered so source-order
                // overrides win regardless of where `<<` sits.
                self.allocator.free(key);
                merges.append(self.allocator, value) catch return error.OutOfMemory;
                continue;
            }
            entries.append(self.allocator, .{ .key = key, .value = value, .line = kv_line }) catch return error.OutOfMemory;
        }

        // Apply deferred merges: append entries from each merge source
        // whose key isn't already present.
        for (merges.items) |merge_src| {
            try applyMerge(self.allocator, &entries, merge_src);
        }

        const items = entries.toOwnedSlice(self.allocator) catch return error.OutOfMemory;
        return Node{ .kind = .mapping, .map = items, .line = start_line };
    }

    fn parseBlockSeq(self: *Parser, indent: usize) Error!Node {
        var items: std.ArrayList(Node) = .empty;
        errdefer {
            for (items.items) |*n| n.deinit(self.allocator);
            items.deinit(self.allocator);
        }

        const start_line = self.line;

        while (true) {
            self.skipBlankLinesAndComments();
            if (self.pos >= self.src.len) break;
            const cur_indent = self.currentIndent();
            if (cur_indent != indent) break;

            self.pos += cur_indent;
            if (self.peek() != '-') break;
            // Must be `- ` or `-\n`.
            if (self.peekN(1)) |nxt| {
                if (nxt != ' ' and nxt != '\n') break;
            }
            self.pos += 1; // skip `-`
            self.skipSpaces();

            const item_line = self.line;
            if (self.peek() == '\n' or self.pos >= self.src.len) {
                self.consumeNewline();
                self.skipBlankLinesAndComments();
                const child_indent = self.currentIndent();
                if (child_indent <= indent) {
                    items.append(self.allocator, .{ .kind = .scalar, .scalar = try self.allocator.dupe(u8, ""), .line = item_line }) catch return error.OutOfMemory;
                } else {
                    const node = try self.parseNode(child_indent);
                    items.append(self.allocator, node) catch return error.OutOfMemory;
                }
                continue;
            }

            // Inline element: could be a flow node, a one-line mapping
            // ("- key: value"), or a scalar.
            const line_end = self.lineEnd();
            const line_text = self.src[self.pos..line_end];

            // Flow node first — inside `{...}` / `[...]` colons aren't map
            // delimiters at our level, so don't let findMapKeyDelim mis-fire.
            if (line_text.len > 0 and (line_text[0] == '{' or line_text[0] == '[')) {
                const node = try self.parseInlineValue(line_text, item_line);
                self.pos = line_end;
                self.consumeNewline();
                items.append(self.allocator, node) catch return error.OutOfMemory;
                continue;
            }

            if (findMapKeyDelim(line_text)) |_| {
                // Sub-mapping starting on the dash's line. The new map's
                // indent is the column of the first key (the character we
                // are currently positioned at), so subsequent kv lines that
                // align under it are absorbed into the same map.
                const node = try self.parseBlockMap(self.currentColumn());
                items.append(self.allocator, node) catch return error.OutOfMemory;
                continue;
            }

            const node = try self.parseInlineValue(line_text, item_line);
            self.pos = line_end;
            self.consumeNewline();
            items.append(self.allocator, node) catch return error.OutOfMemory;
        }

        const out = items.toOwnedSlice(self.allocator) catch return error.OutOfMemory;
        return Node{ .kind = .sequence, .seq = out, .line = start_line };
    }

    fn parseFlowSeq(self: *Parser) Error!Node {
        std.debug.assert(self.peek() == '[');
        const start_line = self.line;
        self.pos += 1;
        var items: std.ArrayList(Node) = .empty;
        errdefer {
            for (items.items) |*n| n.deinit(self.allocator);
            items.deinit(self.allocator);
        }
        while (true) {
            self.skipFlowWhitespace();
            if (self.pos >= self.src.len) return error.UnterminatedFlow;
            if (self.peek() == ']') {
                self.pos += 1;
                break;
            }
            const node = try self.parseFlowNode();
            items.append(self.allocator, node) catch return error.OutOfMemory;
            self.skipFlowWhitespace();
            if (self.peek() == ',') {
                self.pos += 1;
                continue;
            }
            if (self.peek() == ']') {
                self.pos += 1;
                break;
            }
            return error.UnexpectedToken;
        }
        const out = items.toOwnedSlice(self.allocator) catch return error.OutOfMemory;
        return Node{ .kind = .sequence, .seq = out, .line = start_line };
    }

    fn parseFlowMap(self: *Parser) Error!Node {
        std.debug.assert(self.peek() == '{');
        const start_line = self.line;
        self.pos += 1;
        var entries: std.ArrayList(KeyValue) = .empty;
        errdefer {
            for (entries.items) |*kv| kv.deinit(self.allocator);
            entries.deinit(self.allocator);
        }
        while (true) {
            self.skipFlowWhitespace();
            if (self.pos >= self.src.len) return error.UnterminatedFlow;
            if (self.peek() == '}') {
                self.pos += 1;
                break;
            }
            // Parse key.
            const key_node = try self.parseFlowNode();
            const key_str = if (key_node.kind == .scalar) key_node.scalar else "";
            const key_owned = try self.allocator.dupe(u8, key_str);
            // Free the original key node (we'll reuse the dup'd bytes).
            var key_copy = key_node;
            key_copy.deinit(self.allocator);

            self.skipFlowWhitespace();
            if (self.peek() != ':') {
                self.allocator.free(key_owned);
                return error.UnexpectedToken;
            }
            self.pos += 1;
            self.skipFlowWhitespace();

            const val_node = if (self.peek() == ',' or self.peek() == '}') Node{
                .kind = .scalar,
                .scalar = try self.allocator.dupe(u8, ""),
                .line = start_line,
            } else try self.parseFlowNode();

            entries.append(self.allocator, .{ .key = key_owned, .value = val_node, .line = start_line }) catch return error.OutOfMemory;
            self.skipFlowWhitespace();
            if (self.peek() == ',') {
                self.pos += 1;
                continue;
            }
            if (self.peek() == '}') {
                self.pos += 1;
                break;
            }
            return error.UnexpectedToken;
        }
        const out = entries.toOwnedSlice(self.allocator) catch return error.OutOfMemory;
        return Node{ .kind = .mapping, .map = out, .line = start_line };
    }

    fn parseFlowNode(self: *Parser) Error!Node {
        self.skipFlowWhitespace();
        if (self.peek() == '[') return self.parseFlowSeq();
        if (self.peek() == '{') return self.parseFlowMap();
        if (self.peek() == '*') {
            const name = try self.parseAnchorName();
            const stored = self.anchors.get(name) orelse return error.UnknownAnchor;
            return cloneNode(self.allocator, stored);
        }
        // Quoted or plain scalar inside flow context.
        const start_line = self.line;
        if (self.peek() == '"' or self.peek() == '\'') {
            const s = try self.parseQuotedScalar();
            return Node{ .kind = .scalar, .scalar = s, .line = start_line };
        }
        // Plain scalar bounded by , ] } : or whitespace. Note: a `: ` (colon
        // followed by whitespace) terminates a flow-map key — without that
        // rule "x: 1" inside `{x: 1}` would be eaten as one scalar.
        const start = self.pos;
        var brace_depth: usize = 0;
        var bracket_depth: usize = 0;
        while (self.pos < self.src.len) : (self.pos += 1) {
            const c = self.src[self.pos];
            if (c == '\n') break;
            if (c == '{') brace_depth += 1;
            if (c == '}') {
                if (brace_depth == 0) break;
                brace_depth -= 1;
            }
            if (c == '[') bracket_depth += 1;
            if (c == ']') {
                if (bracket_depth == 0) break;
                bracket_depth -= 1;
            }
            if (c == ',' and brace_depth == 0 and bracket_depth == 0) break;
            if (c == ':' and brace_depth == 0 and bracket_depth == 0) {
                const next: u8 = if (self.pos + 1 < self.src.len) self.src[self.pos + 1] else ' ';
                if (next == ' ' or next == '\t' or next == ',' or next == '}' or next == ']' or next == '\n') break;
            }
        }
        const raw = std.mem.trim(u8, self.src[start..self.pos], " \t");
        const dup = try parseScalarPiece(self.allocator, raw);
        return Node{ .kind = .scalar, .scalar = dup, .line = start_line };
    }

    fn skipFlowWhitespace(self: *Parser) void {
        while (self.pos < self.src.len) {
            const c = self.src[self.pos];
            if (c == ' ' or c == '\t' or c == '\r') {
                self.pos += 1;
            } else if (c == '\n') {
                self.consumeNewline();
            } else if (c == '#') {
                self.skipToNewline();
            } else break;
        }
    }

    fn parsePlainScalar(self: *Parser) Error!Node {
        const line = self.line;
        const line_end = self.lineEnd();
        const line_text = self.src[self.pos..line_end];
        const stripped_end = stripInlineComment(line_text);
        const raw = std.mem.trim(u8, line_text[0..stripped_end], " \t");
        const dup = try parseScalarPiece(self.allocator, raw);
        self.pos = line_end;
        self.consumeNewline();
        return Node{ .kind = .scalar, .scalar = dup, .line = line };
    }

    fn parseQuotedScalar(self: *Parser) Error![]u8 {
        const quote = self.peek();
        self.pos += 1;
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(self.allocator);
        while (self.pos < self.src.len) : (self.pos += 1) {
            const c = self.src[self.pos];
            if (c == quote) {
                self.pos += 1;
                return out.toOwnedSlice(self.allocator) catch error.OutOfMemory;
            }
            if (quote == '"' and c == '\\' and self.pos + 1 < self.src.len) {
                self.pos += 1;
                const esc = self.src[self.pos];
                const decoded: u8 = switch (esc) {
                    'n' => '\n',
                    't' => '\t',
                    'r' => '\r',
                    '"' => '"',
                    '\\' => '\\',
                    '0' => 0,
                    else => esc,
                };
                out.append(self.allocator, decoded) catch return error.OutOfMemory;
                continue;
            }
            if (c == '\n') self.line += 1;
            out.append(self.allocator, c) catch return error.OutOfMemory;
        }
        return error.UnterminatedString;
    }

    fn parseBlockLiteral(self: *Parser, indent: usize) Error!Node {
        const ind_marker = self.peek();
        _ = ind_marker;
        self.pos += 1;
        // Tolerate chomping/keep indicators (- + digit).
        while (self.pos < self.src.len and self.src[self.pos] != '\n' and self.src[self.pos] != ' ') self.pos += 1;
        self.skipToNewline();
        self.consumeNewline();

        const start_line = self.line;
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(self.allocator);

        while (self.pos < self.src.len) {
            const cur_indent = self.currentIndent();
            if (cur_indent <= indent) break;
            // Skip the literal block's own indent.
            self.pos += @min(cur_indent, indent + 2);
            const line_end = self.lineEnd();
            out.appendSlice(self.allocator, self.src[self.pos..line_end]) catch return error.OutOfMemory;
            out.append(self.allocator, '\n') catch return error.OutOfMemory;
            self.pos = line_end;
            self.consumeNewline();
        }

        const dup = out.toOwnedSlice(self.allocator) catch return error.OutOfMemory;
        return Node{ .kind = .scalar, .scalar = dup, .line = start_line };
    }

    fn parseInlineValue(self: *Parser, raw: []const u8, line: u32) Error!Node {
        const trimmed = std.mem.trim(u8, raw, " \t");
        if (trimmed.len == 0) return Node{ .kind = .scalar, .scalar = try self.allocator.dupe(u8, ""), .line = line };
        // Helm / Go-template values like `{{ .Values.x }}` are NOT YAML flow
        // maps — keep the whole rest as an opaque scalar so downstream
        // template expansion sees verbatim bytes.
        if (trimmed.len >= 2 and trimmed[0] == '{' and trimmed[1] == '{') {
            const dup = try parseScalarPiece(self.allocator, trimmed);
            return Node{ .kind = .scalar, .scalar = dup, .line = line };
        }
        if (trimmed[0] == '&') {
            // Anchor + value. `&name <value>` — register anchor, parse the
            // remainder as the inline value, then store the parsed node
            // under the anchor name for later `*name` aliases.
            const saved = self.pos;
            self.pos = (@intFromPtr(trimmed.ptr) - @intFromPtr(self.src.ptr));
            const name = try self.parseAnchorName();
            // Slice of bytes after the anchor name within the original raw.
            const consumed = self.pos - (@intFromPtr(trimmed.ptr) - @intFromPtr(self.src.ptr));
            const remainder = std.mem.trim(u8, trimmed[consumed..], " \t");
            // Restore caller's pos before recursing — parseInlineValue's
            // contract is that it does not move pos itself.
            self.pos = saved;
            const node = if (remainder.len == 0)
                Node{ .kind = .scalar, .scalar = try self.allocator.dupe(u8, ""), .line = line }
            else
                try self.parseInlineValue(remainder, line);
            try self.storeAnchor(name, node);
            return node;
        }
        if (trimmed[0] == '[' or trimmed[0] == '{') {
            // Parse as flow node — restore parser pos.
            const saved = self.pos;
            self.pos = (@intFromPtr(trimmed.ptr) - @intFromPtr(self.src.ptr));
            const node = try self.parseFlowNode();
            self.pos = saved + raw.len;
            return node;
        }
        if (trimmed[0] == '*') {
            // Alias.
            const saved = self.pos;
            self.pos = (@intFromPtr(trimmed.ptr) - @intFromPtr(self.src.ptr));
            const name = try self.parseAnchorName();
            const stored = self.anchors.get(name) orelse return error.UnknownAnchor;
            const cloned = try cloneNode(self.allocator, stored);
            self.pos = saved + raw.len;
            return cloned;
        }
        // Quoted or plain scalar.
        if (trimmed[0] == '"' or trimmed[0] == '\'') {
            const saved = self.pos;
            self.pos = (@intFromPtr(trimmed.ptr) - @intFromPtr(self.src.ptr));
            const dup = try self.parseQuotedScalar();
            self.pos = saved + raw.len;
            return Node{ .kind = .scalar, .scalar = dup, .line = line };
        }
        const dup = try parseScalarPiece(self.allocator, trimmed);
        return Node{ .kind = .scalar, .scalar = dup, .line = line };
    }
};

/// Apply a YAML 1.1 merge-key source to an entry list. Per the merge-key
/// spec, the source may be either a single mapping or a sequence of
/// mappings (right-most wins among the sources, but explicit keys in the
/// outer mapping override every merged source — so we only insert keys
/// that are not already present).
fn applyMerge(
    allocator: std.mem.Allocator,
    entries: *std.ArrayList(KeyValue),
    src: Node,
) Error!void {
    switch (src.kind) {
        .mapping => {
            for (src.map) |inner_kv| {
                if (entryHasKey(entries.items, inner_kv.key)) continue;
                const k_dup = try allocator.dupe(u8, inner_kv.key);
                errdefer allocator.free(k_dup);
                const v_dup = try cloneNode(allocator, inner_kv.value);
                entries.append(allocator, .{ .key = k_dup, .value = v_dup, .line = inner_kv.line }) catch return error.OutOfMemory;
            }
        },
        .sequence => {
            for (src.seq) |item| {
                if (item.kind == .mapping) try applyMerge(allocator, entries, item);
            }
        },
        .scalar => {}, // ignore scalar merge sources (malformed input)
    }
}

fn entryHasKey(items: []const KeyValue, key: []const u8) bool {
    for (items) |kv| {
        if (std.mem.eql(u8, kv.key, key)) return true;
    }
    return false;
}

fn cloneNode(allocator: std.mem.Allocator, node: Node) std.mem.Allocator.Error!Node {
    return switch (node.kind) {
        .scalar => Node{
            .kind = .scalar,
            .scalar = try allocator.dupe(u8, node.scalar),
            .line = node.line,
        },
        .sequence => blk: {
            const out = try allocator.alloc(Node, node.seq.len);
            var built: usize = 0;
            errdefer {
                for (out[0..built]) |*n| {
                    var nm = n.*;
                    nm.deinit(allocator);
                }
                allocator.free(out);
            }
            for (node.seq, 0..) |n, i| {
                out[i] = try cloneNode(allocator, n);
                built += 1;
            }
            break :blk Node{ .kind = .sequence, .seq = out, .line = node.line };
        },
        .mapping => blk: {
            const out = try allocator.alloc(KeyValue, node.map.len);
            var built: usize = 0;
            errdefer {
                for (out[0..built]) |*kv| kv.deinit(allocator);
                allocator.free(out);
            }
            for (node.map, 0..) |kv, i| {
                const key_dup = try allocator.dupe(u8, kv.key);
                errdefer allocator.free(key_dup);
                const val_dup = try cloneNode(allocator, kv.value);
                out[i] = .{ .key = key_dup, .value = val_dup, .line = kv.line };
                built += 1;
            }
            break :blk Node{ .kind = .mapping, .map = out, .line = node.line };
        },
    };
}

/// Find the position of the first `:` that introduces a mapping key in the
/// given line. Returns null when the line is a plain scalar. Honors quotes
/// and Helm `{{ ... }}` template expressions so colons inside them are
/// not treated as map delimiters.
fn findMapKeyDelim(line: []const u8) ?usize {
    var i: usize = 0;
    while (i < line.len) : (i += 1) {
        const c = line[i];
        if (c == '#') return null;
        if (c == '"' or c == '\'') {
            const quote = c;
            i += 1;
            while (i < line.len and line[i] != quote) {
                if (line[i] == '\\' and i + 1 < line.len) i += 1;
                i += 1;
            }
            continue;
        }
        if (c == '{' and i + 1 < line.len and line[i + 1] == '{') {
            // Helm / Go-template — skip until `}}`.
            i += 2;
            while (i + 1 < line.len and !(line[i] == '}' and line[i + 1] == '}')) i += 1;
            if (i + 1 < line.len) i += 1;
            continue;
        }
        if (c == ':') {
            // Map key requires whitespace or end-of-line after the colon.
            const next: u8 = if (i + 1 < line.len) line[i + 1] else ' ';
            if (next == ' ' or next == '\t' or i + 1 >= line.len or next == '\n') return i;
        }
    }
    return null;
}

fn stripInlineComment(line: []const u8) usize {
    // Returns the prefix length up to (but not including) an end-of-line `#`.
    // Honors quotes so `# inside a string` doesn't truncate.
    var i: usize = 0;
    while (i < line.len) : (i += 1) {
        const c = line[i];
        if (c == '"' or c == '\'') {
            const quote = c;
            i += 1;
            while (i < line.len and line[i] != quote) {
                if (line[i] == '\\' and i + 1 < line.len) i += 1;
                i += 1;
            }
            continue;
        }
        if (c == '#') {
            // Require whitespace before # for it to count as a comment.
            if (i == 0 or line[i - 1] == ' ' or line[i - 1] == '\t') return i;
        }
    }
    return line.len;
}

/// Trim and unquote a scalar piece. Plain scalars stay as-is (whitespace-trimmed);
/// quoted strings are unwrapped (basic — full backslash decoding is in
/// `parseQuotedScalar`).
fn parseScalarPiece(allocator: std.mem.Allocator, raw: []const u8) ![]u8 {
    if (raw.len == 0) return allocator.dupe(u8, "");
    if ((raw[0] == '"' and raw[raw.len - 1] == '"') or
        (raw[0] == '\'' and raw[raw.len - 1] == '\''))
    {
        if (raw.len >= 2) return allocator.dupe(u8, raw[1 .. raw.len - 1]);
    }
    return allocator.dupe(u8, raw);
}

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

const testing = std.testing;

test "simple block mapping" {
    var s = try parse(testing.allocator, "a: 1\nb: hello\nc: \"with: colon\"\n");
    defer s.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 1), s.documents.len);
    const root = s.documents[0].root;
    try testing.expectEqual(NodeKind.mapping, root.kind);
    try testing.expectEqualStrings("1", root.getScalar("a").?);
    try testing.expectEqualStrings("hello", root.getScalar("b").?);
    try testing.expectEqualStrings("with: colon", root.getScalar("c").?);
}

test "nested mapping + sequence" {
    const src =
        \\spec:
        \\  containers:
        \\  - name: app
        \\    image: nginx:1.27
        \\    ports:
        \\    - 80
        \\    - 443
    ;
    var s = try parse(testing.allocator, src);
    defer s.deinit(testing.allocator);
    const spec = s.documents[0].root.get("spec").?;
    const containers = spec.get("containers").?;
    try testing.expectEqual(NodeKind.sequence, containers.kind);
    try testing.expectEqual(@as(usize, 1), containers.seq.len);
    const c0 = containers.seq[0];
    try testing.expectEqualStrings("app", c0.getScalar("name").?);
    try testing.expectEqualStrings("nginx:1.27", c0.getScalar("image").?);
    const ports = c0.get("ports").?;
    try testing.expectEqual(@as(usize, 2), ports.seq.len);
}

test "multi-doc separator" {
    const src =
        \\a: 1
        \\---
        \\b: 2
    ;
    var s = try parse(testing.allocator, src);
    defer s.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 2), s.documents.len);
    try testing.expectEqualStrings("1", s.documents[0].root.getScalar("a").?);
    try testing.expectEqualStrings("2", s.documents[1].root.getScalar("b").?);
}

test "anchors and aliases" {
    const src =
        \\base: &b "shared-string"
        \\copy: *b
    ;
    var s = try parse(testing.allocator, src);
    defer s.deinit(testing.allocator);
    try testing.expectEqualStrings("shared-string", s.documents[0].root.getScalar("base").?);
    try testing.expectEqualStrings("shared-string", s.documents[0].root.getScalar("copy").?);
}

test "merge key (`<<:`) inlines anchored mapping with explicit-override precedence" {
    const src =
        \\defaults: &d
        \\  level: high
        \\  retries: 3
        \\  privileged: true
        \\applied:
        \\  <<: *d
        \\  level: critical
    ;
    var s = try parse(testing.allocator, src);
    defer s.deinit(testing.allocator);
    const applied = s.documents[0].root.get("applied").?;
    // Explicit `level: critical` wins over merged `level: high`.
    try testing.expectEqualStrings("critical", applied.getScalar("level").?);
    // Other keys come from the merge.
    try testing.expectEqualStrings("3", applied.getScalar("retries").?);
    try testing.expectEqualStrings("true", applied.getScalar("privileged").?);
    // The synthetic `<<` key itself must not appear in the result.
    try testing.expect(applied.get("<<") == null);
}

test "flow style" {
    const src = "vals: [1, 2, 3]\nobj: {x: 1, y: 2}\n";
    var s = try parse(testing.allocator, src);
    defer s.deinit(testing.allocator);
    const root = s.documents[0].root;
    const vals = root.get("vals").?;
    try testing.expectEqual(@as(usize, 3), vals.seq.len);
    try testing.expectEqualStrings("1", vals.seq[0].scalar);
    const obj = root.get("obj").?;
    try testing.expectEqual(NodeKind.mapping, obj.kind);
    try testing.expectEqualStrings("1", obj.getScalar("x").?);
}

test "comments stripped" {
    const src = "a: 1  # inline\n# full line\nb: 2\n";
    var s = try parse(testing.allocator, src);
    defer s.deinit(testing.allocator);
    try testing.expectEqualStrings("1", s.documents[0].root.getScalar("a").?);
    try testing.expectEqualStrings("2", s.documents[0].root.getScalar("b").?);
}

test "Helm template tolerated as opaque scalar" {
    const src =
        \\image: "{{ .Values.image.repository }}:{{ .Values.image.tag }}"
        \\replicas: {{ .Values.replicaCount }}
    ;
    var s = try parse(testing.allocator, src);
    defer s.deinit(testing.allocator);
    const root = s.documents[0].root;
    // The image string is quoted so it survives.
    try testing.expectEqualStrings("{{ .Values.image.repository }}:{{ .Values.image.tag }}", root.getScalar("image").?);
    // Plain scalar value containing template — stored as raw text.
    try testing.expectEqualStrings("{{ .Values.replicaCount }}", root.getScalar("replicas").?);
}

test "block literal preserves multiline body" {
    const src =
        \\script: |
        \\  echo hello
        \\  echo world
    ;
    var s = try parse(testing.allocator, src);
    defer s.deinit(testing.allocator);
    const body = s.documents[0].root.getScalar("script").?;
    try testing.expect(std.mem.indexOf(u8, body, "echo hello") != null);
    try testing.expect(std.mem.indexOf(u8, body, "echo world") != null);
}

test "getPath walks nested mappings" {
    const src =
        \\spec:
        \\  template:
        \\    spec:
        \\      containers:
        \\      - name: c
    ;
    var s = try parse(testing.allocator, src);
    defer s.deinit(testing.allocator);
    const containers = s.documents[0].root.getPath("spec.template.spec.containers").?;
    try testing.expectEqual(NodeKind.sequence, containers.kind);
}
