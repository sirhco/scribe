//! Interactive scan-results browser. Vertical layout: tab bar on top,
//! split-view below (left = filtered findings list, right = colored detail).
//!
//! Keys:
//!   j/k or ↑/↓     — navigate
//!   1..5           — filter by category (1 all, 2 components, 3 secrets,
//!                                        4 vulns, 5 config)
//!   Tab / Shift-Tab — cycle filter forward / backward
//!   q / Esc / ^C   — quit
//!
//! Built on libvaxis vxfw. All label/detail bytes allocated up front into an
//! arena that lives for the whole UI session.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;

const vaxis = @import("vaxis");
const vxfw = vaxis.vxfw;
const Style = vaxis.Style;
const Color = vaxis.Color;
const Segment = vaxis.Segment;

const scribe = @import("scribe");

// ---- color palette ---------------------------------------------------------

const palette = struct {
    const accent: Color = .{ .index = 6 }; // cyan
    const dim: Color = .{ .index = 8 }; // bright black
    const fg: Color = .default;
    const bg_active: Color = .{ .index = 17 }; // dark blue tint
    const heading: Color = .{ .index = 14 }; // bright cyan
    const sev_critical: Color = .{ .index = 9 }; // bright red
    const sev_high: Color = .{ .index = 1 }; // red
    const sev_medium: Color = .{ .index = 3 }; // yellow
    const sev_low: Color = .{ .index = 6 }; // cyan
    const sev_info: Color = .{ .index = 8 };
    const sev_unknown: Color = .{ .index = 8 };
    const ok: Color = .{ .index = 2 }; // green
    const secret_kind: Color = .{ .index = 11 }; // bright yellow
    const component_kind: Color = .{ .index = 6 };
};

fn severityColor(s: scribe.security.vulnerability.Severity) Color {
    return switch (s) {
        .critical => palette.sev_critical,
        .high => palette.sev_high,
        .medium => palette.sev_medium,
        .low => palette.sev_low,
        .none => palette.sev_info,
    };
}

fn issueSeverityColor(s: scribe.security.config.Severity) Color {
    return switch (s) {
        .critical => palette.sev_critical,
        .high => palette.sev_high,
        .medium => palette.sev_medium,
        .low => palette.sev_low,
        .info => palette.sev_info,
    };
}

// ---- filter ----------------------------------------------------------------

const Filter = enum(u8) {
    all = 0,
    components = 1,
    secrets = 2,
    vulnerabilities = 3,
    config = 4,

    fn label(self: Filter) []const u8 {
        return switch (self) {
            .all => " All ",
            .components => " Components ",
            .secrets => " Secrets ",
            .vulnerabilities => " Vulnerabilities ",
            .config => " Config ",
        };
    }

    fn includes(self: Filter, cat: Category) bool {
        return switch (self) {
            .all => true,
            .components => cat == .summary or cat == .component or cat == .heading_components,
            .secrets => cat == .summary or cat == .secret or cat == .heading_secrets,
            .vulnerabilities => cat == .summary or cat == .vulnerability or cat == .heading_vulnerabilities,
            .config => cat == .summary or cat == .config or cat == .heading_config,
        };
    }
};

const Category = enum {
    summary,
    heading_components,
    component,
    heading_secrets,
    secret,
    heading_vulnerabilities,
    vulnerability,
    heading_config,
    config,
};

// ---- item ------------------------------------------------------------------

const Item = struct {
    /// Pre-built title variants. Picked at render time based on flags.
    title_plain: []const u8,
    title_marked: []const u8, // "★ "
    title_selected: []const u8, // "▸ "
    title_marked_selected: []const u8, // "▸★ "
    title_style: Style,
    detail: []const Segment,
    category: Category,
    bookmarked: bool = false,
    selected: bool = false,

    fn currentTitle(self: *const Item) []const u8 {
        if (self.selected and self.bookmarked) return self.title_marked_selected;
        if (self.selected) return self.title_selected;
        if (self.bookmarked) return self.title_marked;
        return self.title_plain;
    }

    fn currentStyle(self: *const Item) Style {
        if (!self.selected) return self.title_style;
        var s = self.title_style;
        s.bg = palette.bg_active;
        s.bold = true;
        return s;
    }
};

const Mode = enum { normal, search };

// ---- tab bar widget --------------------------------------------------------

const TabBar = struct {
    state: *Root,

    fn widget(self: *TabBar) vxfw.Widget {
        return .{
            .userdata = self,
            .drawFn = drawFn,
        };
    }

    fn drawFn(ptr: *anyopaque, ctx: vxfw.DrawContext) Allocator.Error!vxfw.Surface {
        const self: *TabBar = @ptrCast(@alignCast(ptr));
        const max = ctx.max.size();
        const size: vxfw.Size = .{ .width = max.width, .height = 1 };
        const surface = try vxfw.Surface.init(ctx.arena, self.widget(), size);
        @memset(surface.buffer, .{ .style = .{} });

        const labels = [_]Filter{ .all, .components, .secrets, .vulnerabilities, .config };
        var col: u16 = 0;
        for (labels, 0..) |f, i| {
            const is_active = self.state.filter == f;
            const num_label = switch (i) {
                0 => "1",
                1 => "2",
                2 => "3",
                3 => "4",
                4 => "5",
                else => "?",
            };
            // counter
            const count = self.state.counts[i];
            var count_buf: [16]u8 = undefined;
            const count_str = std.fmt.bufPrint(&count_buf, " ({d})", .{count}) catch " (?)";

            const num_style: Style = .{
                .fg = palette.dim,
                .bold = is_active,
            };
            col = writeRun(surface, col, num_label, num_style);

            const text_style: Style = if (is_active)
                .{ .fg = palette.heading, .bold = true, .reverse = true }
            else
                .{ .fg = palette.fg };
            col = writeRun(surface, col, f.label(), text_style);

            col = writeRun(surface, col, count_str, .{ .fg = palette.dim });
            // separator
            col = writeRun(surface, col, " ", .{});
        }
        return surface;
    }
};

fn writeRun(surface: vxfw.Surface, start_col: u16, text: []const u8, style: Style) u16 {
    var col = start_col;
    for (text) |b| {
        if (col >= surface.size.width) break;
        const buf = [_]u8{b};
        const slice: []const u8 = &buf;
        // We need a stable grapheme pointer. Cell stores []const u8; for
        // ASCII we can rely on the segment we'll render byte by byte using
        // a static lookup table to avoid lifetime issues.
        const grapheme = asciiCell(slice);
        surface.writeCell(col, 0, .{
            .char = .{ .grapheme = grapheme, .width = 1 },
            .style = style,
        });
        col += 1;
    }
    return col;
}

/// Cell.Character.grapheme is `[]const u8`. For ASCII we return a slice
/// from a static 256-entry table so the cell outlives any local buffer.
fn asciiCell(s: []const u8) []const u8 {
    const Static = struct {
        var table: [256][1]u8 = blk: {
            var t: [256][1]u8 = undefined;
            for (0..256) |i| t[i][0] = @intCast(i);
            break :blk t;
        };
    };
    if (s.len == 0) return " ";
    const idx: usize = s[0];
    return Static.table[idx][0..];
}

// ---- status bar widget -----------------------------------------------------

const StatusBar = struct {
    state: *Root,

    fn widget(self: *StatusBar) vxfw.Widget {
        return .{
            .userdata = self,
            .drawFn = drawFn,
        };
    }

    fn drawFn(ptr: *anyopaque, ctx: vxfw.DrawContext) Allocator.Error!vxfw.Surface {
        const self: *StatusBar = @ptrCast(@alignCast(ptr));
        const max = ctx.max.size();
        const size: vxfw.Size = .{ .width = max.width, .height = 1 };
        const surface = try vxfw.Surface.init(ctx.arena, self.widget(), size);
        @memset(surface.buffer, .{ .style = .{} });

        var col: u16 = 0;
        if (self.state.mode == .search) {
            col = writeRun(surface, col, "/", .{ .fg = palette.heading, .bold = true });
            col = writeRun(surface, col, self.state.query_buf[0..self.state.query_len], .{ .fg = palette.fg, .bold = true });
            col = writeRun(surface, col, "_", .{ .fg = palette.heading, .bold = true });
            col = writeRun(surface, col, "  (Enter confirm · Esc cancel)", .{ .fg = palette.dim, .italic = true });
        } else if (self.state.status_len > 0) {
            const msg = self.state.status_buf[0..self.state.status_len];
            col = writeRun(surface, col, msg, .{ .fg = palette.ok, .bold = true });
        } else {
            col = writeRun(surface, col, " q ", .{ .fg = palette.dim });
            col = writeRun(surface, col, "quit  ", .{ .fg = palette.fg });
            col = writeRun(surface, col, "/ ", .{ .fg = palette.dim });
            col = writeRun(surface, col, "search  ", .{ .fg = palette.fg });
            col = writeRun(surface, col, "Sp ", .{ .fg = palette.dim });
            col = writeRun(surface, col, "select  ", .{ .fg = palette.fg });
            col = writeRun(surface, col, "c ", .{ .fg = palette.dim });
            col = writeRun(surface, col, "clear  ", .{ .fg = palette.fg });
            col = writeRun(surface, col, "b ", .{ .fg = palette.dim });
            col = writeRun(surface, col, "bookmark  ", .{ .fg = palette.fg });
            col = writeRun(surface, col, "e ", .{ .fg = palette.dim });
            col = writeRun(surface, col, "export  ", .{ .fg = palette.fg });
            col = writeRun(surface, col, "y ", .{ .fg = palette.dim });
            col = writeRun(surface, col, "yank  ", .{ .fg = palette.fg });
            if (self.state.query_len > 0) {
                col = writeRun(surface, col, "│  ", .{ .fg = palette.dim });
                col = writeRun(surface, col, "filter: /", .{ .fg = palette.heading });
                col = writeRun(surface, col, self.state.query_buf[0..self.state.query_len], .{ .fg = palette.heading, .bold = true });
            }
            const bookmark_count = countBookmarks(self.state.items);
            const sel_count = countSelected(self.state.items);
            if (bookmark_count > 0) {
                var nb: [32]u8 = undefined;
                const s = std.fmt.bufPrint(&nb, "  ★{d}", .{bookmark_count}) catch "";
                col = writeRun(surface, col, s, .{ .fg = palette.heading });
            }
            if (sel_count > 0) {
                var sb: [32]u8 = undefined;
                const s = std.fmt.bufPrint(&sb, "  ▸{d}", .{sel_count}) catch "";
                col = writeRun(surface, col, s, .{ .fg = palette.sev_medium, .bold = true });
            }
        }
        return surface;
    }
};

fn countBookmarks(items: []const Item) usize {
    var n: usize = 0;
    for (items) |it| if (it.bookmarked) {
        n += 1;
    };
    return n;
}

fn countSelected(items: []const Item) usize {
    var n: usize = 0;
    for (items) |it| if (it.selected) {
        n += 1;
    };
    return n;
}

// ---- root widget -----------------------------------------------------------

const Root = struct {
    list: *vxfw.ListView,
    split: *vxfw.SplitView,
    detail: *vxfw.RichText,
    tabbar: *TabBar,
    statusbar: *StatusBar,
    flex: *vxfw.FlexColumn,

    items: []Item,
    /// list_widgets is a buffer sized to items.len; we slice into it when
    /// the filter changes and rebind list.children.
    list_widgets_buf: []vxfw.Widget,
    list_text_buf: []vxfw.Text,
    /// Mapping from filtered-list-index -> items[] index. Same length as
    /// the active list_widgets slice.
    item_index_map: []usize,

    filter: Filter = .all,
    counts: [5]usize,

    mode: Mode = .normal,
    query_buf: [128]u8 = undefined,
    query_len: usize = 0,

    status_buf: [256]u8 = undefined,
    status_len: usize = 0,

    /// Allocator we use to write export files etc.
    gpa: Allocator,
    /// Path the user pointed scribe at — embedded in export header.
    source_path: []const u8,

    fn widget(self: *Root) vxfw.Widget {
        return .{
            .userdata = self,
            .eventHandler = handleEvent,
            .drawFn = drawFn,
        };
    }

    fn handleEvent(ptr: *anyopaque, ctx: *vxfw.EventContext, event: vxfw.Event) anyerror!void {
        const self: *Root = @ptrCast(@alignCast(ptr));
        switch (event) {
            .key_press => |key| {
                if (self.mode == .search) return self.handleSearchKey(ctx, key);

                // Any key in normal mode clears the transient status banner
                // (so the next render shows the regular hint line).
                self.status_len = 0;

                if (key.matches('q', .{}) or
                    key.matches('c', .{ .ctrl = true }) or
                    key.matches(vaxis.Key.escape, .{}))
                {
                    ctx.quit = true;
                    ctx.consume_event = true;
                    return;
                }
                if (key.matches('/', .{})) return self.enterSearch(ctx);
                if (key.matches(' ', .{})) return self.toggleSelection(ctx);
                if (key.matches('c', .{})) return self.clearSelection(ctx);
                if (key.matches('b', .{})) return self.toggleBookmark(ctx);
                if (key.matches('e', .{})) return self.exportBookmarks(ctx);
                if (key.matches('y', .{})) return self.yankDetail(ctx);
                if (key.matches('1', .{})) return self.setFilter(ctx, .all);
                if (key.matches('2', .{})) return self.setFilter(ctx, .components);
                if (key.matches('3', .{})) return self.setFilter(ctx, .secrets);
                if (key.matches('4', .{})) return self.setFilter(ctx, .vulnerabilities);
                if (key.matches('5', .{})) return self.setFilter(ctx, .config);
                if (key.matches(vaxis.Key.tab, .{})) return self.cycleFilter(ctx, 1);
                if (key.matches(vaxis.Key.tab, .{ .shift = true })) return self.cycleFilter(ctx, -1);
                try self.list.handleEvent(ctx, event);
            },
            .init => {
                self.applyFilter();
                ctx.redraw = true;
            },
            else => try self.list.handleEvent(ctx, event),
        }
    }

    fn handleSearchKey(self: *Root, ctx: *vxfw.EventContext, key: vaxis.Key) !void {
        if (key.matches(vaxis.Key.escape, .{})) {
            // Cancel: clear query, exit search mode.
            self.query_len = 0;
            self.mode = .normal;
            self.applyFilter();
            self.list.cursor = 0;
            self.list.scroll = .{};
            ctx.consumeAndRedraw();
            return;
        }
        if (key.matches(vaxis.Key.enter, .{})) {
            // Confirm: keep query, exit search mode.
            self.mode = .normal;
            ctx.consumeAndRedraw();
            return;
        }
        if (key.matches(vaxis.Key.backspace, .{})) {
            if (self.query_len > 0) {
                self.query_len -= 1;
                self.applyFilter();
                self.list.cursor = 0;
                self.list.scroll = .{};
            }
            ctx.consumeAndRedraw();
            return;
        }
        // Take printable text from the key event. Kitty extension reports
        // .text; fall back to the raw codepoint when that's absent.
        const text = key.text orelse blk: {
            if (key.codepoint >= 0x20 and key.codepoint < 0x7F) {
                self.query_buf[0] = @intCast(key.codepoint);
                break :blk self.query_buf[0..1];
            }
            ctx.consume_event = true;
            return;
        };
        for (text) |b| {
            if (b < 0x20 or b == 0x7F) continue;
            if (self.query_len >= self.query_buf.len) break;
            self.query_buf[self.query_len] = b;
            self.query_len += 1;
        }
        self.applyFilter();
        self.list.cursor = 0;
        self.list.scroll = .{};
        ctx.consumeAndRedraw();
    }

    fn enterSearch(self: *Root, ctx: *vxfw.EventContext) void {
        self.mode = .search;
        self.query_len = 0;
        self.applyFilter();
        self.list.cursor = 0;
        ctx.consumeAndRedraw();
    }

    fn toggleBookmark(self: *Root, ctx: *vxfw.EventContext) void {
        // If anything is multi-selected, batch toggle all selected. Otherwise
        // fall back to toggling the cursor row.
        var batch: usize = 0;
        for (self.items) |it| if (it.selected) {
            batch += 1;
        };
        if (batch > 0) {
            for (self.items, 0..) |*it, i| {
                if (!it.selected) continue;
                it.bookmarked = !it.bookmarked;
                self.list_text_buf[i].text = it.currentTitle();
                self.list_text_buf[i].style = it.currentStyle();
            }
            self.setStatus("toggled bookmark on {d} selected", .{batch});
            ctx.consumeAndRedraw();
            return;
        }
        const idx = self.list.cursor;
        if (idx >= self.item_index_map.len) {
            ctx.consume_event = true;
            return;
        }
        const item_idx = self.item_index_map[idx];
        self.items[item_idx].bookmarked = !self.items[item_idx].bookmarked;
        self.list_text_buf[item_idx].text = self.items[item_idx].currentTitle();
        self.list_text_buf[item_idx].style = self.items[item_idx].currentStyle();
        ctx.consumeAndRedraw();
    }

    fn toggleSelection(self: *Root, ctx: *vxfw.EventContext) void {
        const idx = self.list.cursor;
        if (idx >= self.item_index_map.len) {
            ctx.consume_event = true;
            return;
        }
        const item_idx = self.item_index_map[idx];
        const it = &self.items[item_idx];
        // Don't allow selecting summary or section-heading rows (they aren't
        // real findings; bookmarking them is meaningless).
        switch (it.category) {
            .summary,
            .heading_components,
            .heading_secrets,
            .heading_vulnerabilities,
            .heading_config,
            => {
                ctx.consume_event = true;
                return;
            },
            else => {},
        }
        it.selected = !it.selected;
        self.list_text_buf[item_idx].text = it.currentTitle();
        self.list_text_buf[item_idx].style = it.currentStyle();
        // Auto-advance cursor on select-down so multi-select feels fluent.
        if (it.selected) self.list.nextItem(ctx);
        ctx.consumeAndRedraw();
    }

    fn clearSelection(self: *Root, ctx: *vxfw.EventContext) void {
        var n: usize = 0;
        for (self.items, 0..) |*it, i| {
            if (!it.selected) continue;
            it.selected = false;
            self.list_text_buf[i].text = it.currentTitle();
            self.list_text_buf[i].style = it.currentStyle();
            n += 1;
        }
        if (n > 0) self.setStatus("cleared {d} selections", .{n});
        ctx.consumeAndRedraw();
    }

    fn exportBookmarks(self: *Root, ctx: *vxfw.EventContext) void {
        const out_path = ".scribe-bookmarks.md";

        // Read previous bookmarks (if any) so we can compute a diff.
        var prev_arena = std.heap.ArenaAllocator.init(self.gpa);
        defer prev_arena.deinit();
        const prev_titles = readPreviousTitles(ctx.io, prev_arena.allocator(), out_path) catch &.{};

        // Current bookmarked titles, in items order.
        var cur_arena = std.heap.ArenaAllocator.init(self.gpa);
        defer cur_arena.deinit();
        var cur_list: std.ArrayList([]const u8) = .empty;
        var n: usize = 0;
        for (self.items) |it| {
            if (!it.bookmarked) continue;
            n += 1;
            cur_list.append(cur_arena.allocator(), it.title_plain) catch return;
        }
        const cur_titles = cur_list.items;

        // Diff: added = in cur not in prev; removed = in prev not in cur.
        var added: std.ArrayList([]const u8) = .empty;
        var removed: std.ArrayList([]const u8) = .empty;
        for (cur_titles) |t| {
            if (!containsTitle(prev_titles, t)) added.append(cur_arena.allocator(), t) catch return;
        }
        for (prev_titles) |t| {
            if (!containsTitle(cur_titles, t)) removed.append(cur_arena.allocator(), t) catch return;
        }

        var aw: std.Io.Writer.Allocating = .init(self.gpa);
        defer aw.deinit();
        const w = &aw.writer;
        w.print("# scribe bookmarks\n\nsource: `{s}`\n\n", .{self.source_path}) catch {};

        if (prev_titles.len > 0 and (added.items.len > 0 or removed.items.len > 0)) {
            w.writeAll("## Changes since last export\n\n") catch {};
            for (added.items) |t| w.print("- + {s}\n", .{t}) catch {};
            for (removed.items) |t| w.print("- − {s}\n", .{t}) catch {};
            w.writeAll("\n") catch {};
        }

        for (self.items) |it| {
            if (!it.bookmarked) continue;
            w.print("## {s}\n\n", .{it.title_plain}) catch {};
            for (it.detail) |seg| w.writeAll(seg.text) catch {};
            w.writeAll("\n---\n\n") catch {};
        }
        const bytes = aw.written();
        Io.Dir.cwd().writeFile(ctx.io, .{ .sub_path = out_path, .data = bytes }) catch |err| {
            self.setStatus("export failed: {s}", .{@errorName(err)});
            ctx.consumeAndRedraw();
            return;
        };
        if (prev_titles.len == 0) {
            self.setStatus("✓ exported {d} bookmarks → {s}", .{ n, out_path });
        } else {
            self.setStatus(
                "✓ exported {d} → {s}  (+{d} −{d})",
                .{ n, out_path, added.items.len, removed.items.len },
            );
        }
        ctx.consumeAndRedraw();
    }

    fn yankDetail(self: *Root, ctx: *vxfw.EventContext) void {
        const it = self.currentItem() orelse {
            ctx.consume_event = true;
            return;
        };
        // Concatenate spans into a flat plain-text payload and ship it.
        var aw: std.Io.Writer.Allocating = .init(ctx.alloc);
        defer aw.deinit();
        for (it.detail) |seg| aw.writer.writeAll(seg.text) catch {};
        ctx.copyToClipboard(aw.written()) catch |err| {
            self.setStatus("copy failed: {s}", .{@errorName(err)});
            ctx.consumeAndRedraw();
            return;
        };
        self.setStatus("✓ copied detail to clipboard ({d} bytes)", .{aw.written().len});
        ctx.consumeAndRedraw();
    }

    fn setStatus(self: *Root, comptime fmt: []const u8, args: anytype) void {
        const msg = std.fmt.bufPrint(&self.status_buf, fmt, args) catch self.status_buf[0..0];
        self.status_len = msg.len;
    }

    fn cycleFilter(self: *Root, ctx: *vxfw.EventContext, dir: i8) void {
        const cur: i8 = @intCast(@intFromEnum(self.filter));
        const next: i8 = @mod(cur + dir, 5);
        const f: Filter = @enumFromInt(@as(u8, @intCast(next)));
        self.setFilter(ctx, f);
    }

    fn setFilter(self: *Root, ctx: *vxfw.EventContext, f: Filter) void {
        if (self.filter == f) {
            ctx.consume_event = true;
            return;
        }
        self.filter = f;
        self.applyFilter();
        self.list.cursor = 0;
        self.list.scroll = .{};
        ctx.consumeAndRedraw();
    }

    fn applyFilter(self: *Root) void {
        const query = self.query_buf[0..self.query_len];
        var n: usize = 0;
        for (self.items, 0..) |*it, i| {
            if (!self.filter.includes(it.category)) continue;
            if (query.len > 0 and !matchQuery(it.title_plain, query) and it.category != .summary) continue;
            // Refresh title + style (prefix and bg follow bookmark/selection).
            self.list_text_buf[i].text = it.currentTitle();
            self.list_text_buf[i].style = it.currentStyle();
            self.list_widgets_buf[n] = self.list_text_buf[i].widget();
            self.item_index_map[n] = i;
            n += 1;
        }
        self.list.children = .{ .slice = self.list_widgets_buf[0..n] };
        self.list.item_count = @intCast(n);
    }

    fn currentItem(self: *Root) ?*const Item {
        const idx = self.list.cursor;
        if (idx >= self.item_index_map.len) return null;
        const item_idx = self.item_index_map[idx];
        if (item_idx >= self.items.len) return null;
        return &self.items[item_idx];
    }

    fn drawFn(ptr: *anyopaque, ctx: vxfw.DrawContext) Allocator.Error!vxfw.Surface {
        const self: *Root = @ptrCast(@alignCast(ptr));
        // Refresh detail text from current cursor before drawing.
        if (self.currentItem()) |it| {
            self.detail.text = it.detail;
        } else {
            self.detail.text = empty_detail[0..];
        }
        const surface = try self.flex.widget().draw(ctx);
        const children = try ctx.arena.alloc(vxfw.SubSurface, 1);
        children[0] = .{
            .origin = .{ .row = 0, .col = 0 },
            .z_index = 0,
            .surface = surface,
        };
        return try vxfw.Surface.initWithChildren(
            ctx.arena,
            self.widget(),
            surface.size,
            children,
        );
    }
};

/// Read the previous export and pull out `## <title>` headings. Returns
/// an empty slice when the file doesn't exist or can't be parsed; callers
/// treat "no previous file" identically to "no overlap".
fn readPreviousTitles(io: Io, arena: Allocator, path: []const u8) ![][]const u8 {
    var f = Io.Dir.cwd().openFile(io, path, .{}) catch return &.{};
    defer f.close(io);
    var buf: [8192]u8 = undefined;
    var fr: Io.File.Reader = .init(f, io, &buf);

    var aw: std.Io.Writer.Allocating = .init(arena);
    _ = fr.interface.streamRemaining(&aw.writer) catch return &.{};
    const bytes = aw.written();

    var out: std.ArrayList([]const u8) = .empty;
    var line_iter = std.mem.splitScalar(u8, bytes, '\n');
    while (line_iter.next()) |line| {
        if (!std.mem.startsWith(u8, line, "## ")) continue;
        const rest = line[3..];
        if (std.mem.startsWith(u8, rest, "Changes since last export")) continue;
        try out.append(arena, try arena.dupe(u8, rest));
    }
    return out.toOwnedSlice(arena);
}

fn containsTitle(list: []const []const u8, t: []const u8) bool {
    for (list) |x| if (std.mem.eql(u8, x, t)) return true;
    return false;
}

fn matchQuery(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0) return true;
    if (needle.len > haystack.len) return false;
    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += 1) {
        var ok = true;
        for (needle, 0..) |nb, j| {
            if (std.ascii.toLower(haystack[i + j]) != std.ascii.toLower(nb)) {
                ok = false;
                break;
            }
        }
        if (ok) return true;
    }
    return false;
}

const empty_detail = [_]Segment{
    .{ .text = "(no items)", .style = .{ .fg = palette.dim, .italic = true } },
};

// ---- public entry ----------------------------------------------------------

pub const Options = struct {
    db_path: ?[]const u8 = null,
    config_path: ?[]const u8 = null,
    fp_db_path: ?[]const u8 = null,
    sec_opts: scribe.security.secrets.ScanOptions = .{},
};

pub fn run(
    io: Io,
    gpa: Allocator,
    env_map: *std.process.Environ.Map,
    source_path: []const u8,
    opts: Options,
    prog: *scribe.progress.Reporter,
) !void {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const work = arena.allocator();

    // Phase 1: build SBOM + scanners against source.
    var bom_owner = try collectFromSource(io, gpa, source_path, opts, prog);
    defer bom_owner.deinit(gpa);

    // Phase 2: flatten findings into Item array.
    const items = try buildItems(work, &bom_owner.bom, source_path);
    if (items.len == 0) {
        prog.finish("no findings to display");
        return;
    }
    prog.finish(null);

    // Phase 3: build widget arrays.
    const list_text_buf = try work.alloc(vxfw.Text, items.len);
    const list_widgets_buf = try work.alloc(vxfw.Widget, items.len);
    const item_index_map = try work.alloc(usize, items.len);
    for (items, 0..) |it, i| {
        list_text_buf[i] = .{
            .text = it.title_plain,
            .style = it.title_style,
            .softwrap = false,
            .overflow = .ellipsis,
        };
    }

    var list_view: vxfw.ListView = .{ .children = .{ .slice = &.{} } };
    var detail_text: vxfw.RichText = .{ .text = empty_detail[0..], .softwrap = true };
    var detail_view: DetailWrap = .{ .rich = &detail_text };

    const list_border: vxfw.Border = .{
        .child = list_view.widget(),
        .style = .{ .fg = palette.dim },
        .labels = &.{
            .{ .text = " findings ", .alignment = .top_left },
        },
    };
    const detail_border: vxfw.Border = .{
        .child = detail_view.widget(),
        .style = .{ .fg = palette.dim },
        .labels = &.{
            .{ .text = " detail ", .alignment = .top_left },
        },
    };

    var split: vxfw.SplitView = .{
        .lhs = list_border.widget(),
        .rhs = detail_border.widget(),
        .style = .{ .fg = palette.dim },
        .width = 56,
        .min_width = 24,
    };

    var counts: [5]usize = .{ 0, 0, 0, 0, 0 };
    counts[0] = items.len;
    for (items) |it| switch (it.category) {
        .component => counts[1] += 1,
        .secret => counts[2] += 1,
        .vulnerability => counts[3] += 1,
        .config => counts[4] += 1,
        else => {},
    };

    var root: Root = .{
        .list = &list_view,
        .split = &split,
        .detail = &detail_text,
        .tabbar = undefined,
        .statusbar = undefined,
        .flex = undefined,
        .items = items,
        .list_widgets_buf = list_widgets_buf,
        .list_text_buf = list_text_buf,
        .item_index_map = item_index_map,
        .counts = counts,
        .gpa = gpa,
        .source_path = source_path,
    };

    var tabbar: TabBar = .{ .state = &root };
    root.tabbar = &tabbar;
    var statusbar: StatusBar = .{ .state = &root };
    root.statusbar = &statusbar;

    const flex_children = try work.alloc(vxfw.FlexItem, 3);
    flex_children[0] = .{ .widget = tabbar.widget(), .flex = 0 };
    flex_children[1] = .{ .widget = split.widget(), .flex = 1 };
    flex_children[2] = .{ .widget = statusbar.widget(), .flex = 0 };
    var flex: vxfw.FlexColumn = .{ .children = flex_children };
    root.flex = &flex;

    // Initial filter projection so the widget tree has data on first draw.
    root.applyFilter();

    // Phase 4: run the App.
    var tty_buf: [4096]u8 = undefined;
    var app = try vxfw.App.init(io, gpa, env_map, &tty_buf);
    defer app.deinit();

    try app.run(root.widget(), .{});
}

/// Wraps a *RichText so we can plug a userdata-bearing widget into the
/// border without constructing the widget interface inline (lifetime).
const DetailWrap = struct {
    rich: *vxfw.RichText,

    fn widget(self: *DetailWrap) vxfw.Widget {
        return .{
            .userdata = self,
            .drawFn = drawFn,
        };
    }

    fn drawFn(ptr: *anyopaque, ctx: vxfw.DrawContext) Allocator.Error!vxfw.Surface {
        const self: *DetailWrap = @ptrCast(@alignCast(ptr));
        return self.rich.widget().draw(ctx);
    }
};

// ---- collection ------------------------------------------------------------

const BomOwner = struct {
    bom: scribe.sbom.Sbom,
    mapping: ?scribe.mmap.Mapping = null,

    fn deinit(self: *BomOwner, gpa: Allocator) void {
        self.bom.deinit(gpa);
        if (self.mapping) |*m| m.deinit();
    }
};

fn collectFromSource(
    io: Io,
    gpa: Allocator,
    path: []const u8,
    opts: Options,
    prog: *scribe.progress.Reporter,
) !BomOwner {
    var owner: BomOwner = .{ .bom = .{ .components = &.{}, .config_issues = &.{} } };

    if (std.mem.startsWith(u8, path, "registry://")) {
        var img = try scribe.registry.pullSbom(gpa, io, path, .{ .progress = prog });
        owner.bom = .{
            .components = takeComponents(&img),
            .config_issues = takeConfigIssues(&img),
        };
    } else if (scribe.local_docker.isLocalDockerUri(path)) {
        var img = try scribe.local_docker.pullSbomWithProgress(gpa, io, path, prog);
        owner.bom = .{
            .components = takeComponents(&img),
            .config_issues = takeConfigIssues(&img),
        };
    } else {
        var mapping = try scribe.mmap.open(io, path);
        errdefer mapping.deinit();
        const bytes = mapping.bytes();

        if (scribe.container.isContainer(bytes)) {
            prog.step("analyzing image layers");
            var img = try scribe.container.collect(gpa, bytes);
            owner.bom = .{
                .components = takeComponents(&img),
                .config_issues = takeConfigIssues(&img),
            };
        } else {
            prog.step("collecting sbom");
            owner.bom = try scribe.sbom.collect(gpa, bytes);
        }

        // Secret scan (binary-only path; container path skips because layers
        // are already squashed inside container.collect's component scan).
        prog.step("scanning secrets");
        var sec_opts = opts.sec_opts;
        if (bytes.len >= 2 and bytes[0] == 'M' and bytes[1] == 'Z') sec_opts.scan_wide = true;
        var findings = try scribe.security.secrets.scan(gpa, bytes, sec_opts);
        owner.bom.findings = findings.items;
        findings.items = &.{};

        // Fingerprint cross-ref (binary path).
        if (opts.fp_db_path) |fp| {
            prog.step("matching fingerprints");
            try augmentBomWithFingerprint(io, gpa, bytes, fp, &owner.bom);
        }

        owner.mapping = mapping;
    }

    // Vulnerability matching (any source).
    if (opts.db_path) |dp| {
        prog.step("matching advisories");
        var db_map = try scribe.mmap.open(io, dp);
        defer db_map.deinit();
        var db = try scribe.security.vulnerability.load(gpa, db_map.bytes());
        defer db.deinit(gpa);

        const refs = try gpa.alloc(scribe.security.vulnerability.ComponentRef, owner.bom.components.len);
        defer gpa.free(refs);
        for (owner.bom.components, 0..) |c, i| {
            refs[i] = .{ .name = c.name, .version = c.version };
        }
        var vulns = try scribe.security.vulnerability.match(gpa, refs, db);
        owner.bom.vulnerabilities = vulns.items;
        vulns.items = &.{};
    }

    // Explicit --config <path> appends issues alongside auto-discovered ones.
    if (opts.config_path) |cp| {
        prog.step("auditing config");
        var cfg_map = try scribe.mmap.open(io, cp);
        defer cfg_map.deinit();
        var issues = try scribe.security.config.audit(gpa, cfg_map.bytes(), cp, .auto);
        if (owner.bom.config_issues.len == 0) {
            owner.bom.config_issues = issues.items;
            issues.items = &.{};
        } else {
            const merged = try gpa.alloc(
                scribe.security.config.Issue,
                owner.bom.config_issues.len + issues.items.len,
            );
            @memcpy(merged[0..owner.bom.config_issues.len], owner.bom.config_issues);
            @memcpy(merged[owner.bom.config_issues.len..], issues.items);
            gpa.free(owner.bom.config_issues);
            gpa.free(issues.items);
            owner.bom.config_issues = merged;
            issues.items = &.{};
        }
    }

    return owner;
}

fn augmentBomWithFingerprint(
    io: Io,
    gpa: Allocator,
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

fn takeComponents(img: *scribe.container.ImageSbom) []scribe.sbom.Component {
    const out = img.components;
    img.components = &.{};
    return out;
}

fn takeConfigIssues(img: *scribe.container.ImageSbom) []scribe.security.config.Issue {
    const out = img.config_issues;
    img.config_issues = &.{};
    return out;
}

// ---- item construction -----------------------------------------------------

fn buildItems(arena: Allocator, bom: *const scribe.sbom.Sbom, source: []const u8) ![]Item {
    var list: std.ArrayList(Item) = .empty;

    // Summary header (always shown — pinned to top).
    {
        const title = try std.fmt.allocPrint(arena, "▼ {s}", .{source});
        const detail = try arena.dupe(Segment, &[_]Segment{
            .{ .text = "scribe interactive view\n\n", .style = .{ .bold = true, .fg = palette.heading } },
            .{ .text = "source:           ", .style = .{ .fg = palette.dim } },
            .{ .text = source, .style = .{ .fg = palette.fg, .bold = true } },
            .{ .text = "\ncomponents:       ", .style = .{ .fg = palette.dim } },
            .{ .text = try std.fmt.allocPrint(arena, "{d}", .{bom.components.len}), .style = .{ .fg = palette.fg } },
            .{ .text = "\nsecrets:          ", .style = .{ .fg = palette.dim } },
            .{
                .text = try std.fmt.allocPrint(arena, "{d}", .{bom.findings.len}),
                .style = .{ .fg = if (bom.findings.len > 0) palette.sev_high else palette.ok },
            },
            .{ .text = "\nvulnerabilities:  ", .style = .{ .fg = palette.dim } },
            .{
                .text = try std.fmt.allocPrint(arena, "{d}", .{bom.vulnerabilities.len}),
                .style = .{ .fg = if (bom.vulnerabilities.len > 0) palette.sev_high else palette.ok },
            },
            .{ .text = "\nconfig issues:    ", .style = .{ .fg = palette.dim } },
            .{
                .text = try std.fmt.allocPrint(arena, "{d}", .{bom.config_issues.len}),
                .style = .{ .fg = if (bom.config_issues.len > 0) palette.sev_high else palette.ok },
            },
            .{ .text = "\n\n", .style = .{} },
            .{ .text = "Use 1-5 to filter. Tab cycles. q to quit.\n", .style = .{ .fg = palette.dim, .italic = true } },
        });
        try list.append(arena, .{
            .title_plain = title,
            .title_marked = "",
            .title_selected = "",
            .title_marked_selected = "",
            .title_style = .{ .bold = true, .fg = palette.heading },
            .detail = detail,
            .category = .summary,
        });
    }

    if (bom.components.len > 0) {
        try list.append(arena, .{
            .title_plain = try std.fmt.allocPrint(arena, "── components ({d}) ──", .{bom.components.len}),
            .title_marked = "",
            .title_selected = "",
            .title_marked_selected = "",
            .title_style = .{ .bold = true, .fg = palette.accent, .dim = true },
            .detail = try componentsHeaderDetail(arena, bom.components.len),
            .category = .heading_components,
        });
        for (bom.components) |c| {
            const ver = c.version orelse "-";
            const title = try std.fmt.allocPrint(
                arena,
                "  {s:<13} {s:<28} {s}",
                .{ @tagName(c.kind), c.name, ver },
            );
            const detail = try arena.dupe(Segment, &[_]Segment{
                .{ .text = c.name, .style = .{ .bold = true, .fg = palette.heading } },
                .{ .text = "\n\n", .style = .{} },
                .{ .text = "kind:      ", .style = .{ .fg = palette.dim } },
                .{ .text = @tagName(c.kind), .style = .{ .fg = palette.component_kind } },
                .{ .text = "\nversion:   ", .style = .{ .fg = palette.dim } },
                .{ .text = ver, .style = .{ .fg = palette.fg, .bold = true } },
                .{ .text = "\nevidence:  ", .style = .{ .fg = palette.dim } },
                .{ .text = @tagName(c.evidence), .style = .{ .fg = palette.fg } },
                .{ .text = "\nplatform:  ", .style = .{ .fg = palette.dim } },
                .{ .text = c.platform orelse "-", .style = .{ .fg = palette.fg } },
                .{ .text = "\npath:      ", .style = .{ .fg = palette.dim } },
                .{ .text = c.path orelse "-", .style = .{ .fg = palette.fg } },
                .{ .text = "\n", .style = .{} },
            });
            try list.append(arena, .{
                .title_plain = title,
            .title_marked = "",
            .title_selected = "",
            .title_marked_selected = "",
                .title_style = .{ .fg = palette.fg },
                .detail = detail,
                .category = .component,
            });
        }
    }

    if (bom.findings.len > 0) {
        try list.append(arena, .{
            .title_plain = try std.fmt.allocPrint(arena, "── secrets ({d}) ──", .{bom.findings.len}),
            .title_marked = "",
            .title_selected = "",
            .title_marked_selected = "",
            .title_style = .{ .bold = true, .fg = palette.accent, .dim = true },
            .detail = try arena.dupe(Segment, &[_]Segment{
                .{ .text = "secret findings\n\n", .style = .{ .bold = true, .fg = palette.heading } },
                .{ .text = "Substrings detected by anchored regex + entropy.\n", .style = .{ .fg = palette.dim } },
            }),
            .category = .heading_secrets,
        });
        for (bom.findings) |f| {
            const title = try std.fmt.allocPrint(
                arena,
                "  {s:<14} 0x{x:0>8} conf={d}",
                .{ @tagName(f.kind), f.offset, @intFromEnum(f.confidence) },
            );
            const detail = try arena.dupe(Segment, &[_]Segment{
                .{ .text = @tagName(f.kind), .style = .{ .bold = true, .fg = palette.secret_kind } },
                .{ .text = "\n\n", .style = .{} },
                .{ .text = "offset:      ", .style = .{ .fg = palette.dim } },
                .{ .text = try std.fmt.allocPrint(arena, "0x{x:0>8}", .{f.offset}), .style = .{ .fg = palette.fg } },
                .{ .text = "\nlength:      ", .style = .{ .fg = palette.dim } },
                .{ .text = try std.fmt.allocPrint(arena, "{d}", .{f.length}), .style = .{ .fg = palette.fg } },
                .{ .text = "\nentropy:     ", .style = .{ .fg = palette.dim } },
                .{ .text = try std.fmt.allocPrint(arena, "{d:.3}", .{f.entropy}), .style = .{ .fg = palette.fg } },
                .{ .text = "\nconfidence:  ", .style = .{ .fg = palette.dim } },
                .{
                    .text = try std.fmt.allocPrint(arena, "{d}", .{@intFromEnum(f.confidence)}),
                    .style = .{ .fg = if (@intFromEnum(f.confidence) >= 80) palette.sev_high else palette.sev_medium },
                },
                .{ .text = "\npreview:     ", .style = .{ .fg = palette.dim } },
                .{ .text = f.redacted_preview, .style = .{ .fg = palette.fg, .bold = true } },
                .{ .text = "\n", .style = .{} },
            });
            try list.append(arena, .{
                .title_plain = title,
            .title_marked = "",
            .title_selected = "",
            .title_marked_selected = "",
                .title_style = .{ .fg = palette.secret_kind },
                .detail = detail,
                .category = .secret,
            });
        }
    }

    if (bom.vulnerabilities.len > 0) {
        try list.append(arena, .{
            .title_plain = try std.fmt.allocPrint(arena, "── vulnerabilities ({d}) ──", .{bom.vulnerabilities.len}),
            .title_marked = "",
            .title_selected = "",
            .title_marked_selected = "",
            .title_style = .{ .bold = true, .fg = palette.accent, .dim = true },
            .detail = try arena.dupe(Segment, &[_]Segment{
                .{ .text = "vulnerabilities\n\n", .style = .{ .bold = true, .fg = palette.heading } },
                .{ .text = "Advisory matches against the loaded vuln DB.\n", .style = .{ .fg = palette.dim } },
            }),
            .category = .heading_vulnerabilities,
        });
        for (bom.vulnerabilities) |v| {
            const sev_color = severityColor(v.severity);
            const title = try std.fmt.allocPrint(
                arena,
                "  {s:<18} {s:<24} [{s}]",
                .{ v.advisory_id, v.package, @tagName(v.severity) },
            );
            const detail = try arena.dupe(Segment, &[_]Segment{
                .{ .text = v.advisory_id, .style = .{ .bold = true, .fg = palette.heading } },
                .{ .text = "  ", .style = .{} },
                .{ .text = @tagName(v.severity), .style = .{ .bold = true, .fg = sev_color } },
                .{ .text = "\n\n", .style = .{} },
                .{ .text = "package:   ", .style = .{ .fg = palette.dim } },
                .{ .text = v.package, .style = .{ .fg = palette.fg, .bold = true } },
                .{ .text = "\nversion:   ", .style = .{ .fg = palette.dim } },
                .{ .text = v.matched_version orelse "-", .style = .{ .fg = palette.fg } },
                .{ .text = "\nseverity:  ", .style = .{ .fg = palette.dim } },
                .{ .text = @tagName(v.severity), .style = .{ .fg = sev_color, .bold = true } },
                .{ .text = "\nfixed in:  ", .style = .{ .fg = palette.dim } },
                .{
                    .text = v.fixed_version orelse "-",
                    .style = .{ .fg = if (v.fixed_version != null) palette.ok else palette.dim },
                },
                .{ .text = "\n\n", .style = .{} },
                .{ .text = v.summary, .style = .{ .fg = palette.fg } },
                .{ .text = "\n", .style = .{} },
            });
            try list.append(arena, .{
                .title_plain = title,
            .title_marked = "",
            .title_selected = "",
            .title_marked_selected = "",
                .title_style = .{ .fg = sev_color },
                .detail = detail,
                .category = .vulnerability,
            });
        }
    }

    if (bom.config_issues.len > 0) {
        try list.append(arena, .{
            .title_plain = try std.fmt.allocPrint(arena, "── config issues ({d}) ──", .{bom.config_issues.len}),
            .title_marked = "",
            .title_selected = "",
            .title_marked_selected = "",
            .title_style = .{ .bold = true, .fg = palette.accent, .dim = true },
            .detail = try arena.dupe(Segment, &[_]Segment{
                .{ .text = "configuration issues\n\n", .style = .{ .bold = true, .fg = palette.heading } },
                .{ .text = "Misconfigurations from Dockerfile / k8s / OCI image-config.\n", .style = .{ .fg = palette.dim } },
            }),
            .category = .heading_config,
        });
        for (bom.config_issues) |it| {
            const sev_color = issueSeverityColor(it.severity);
            const title = try std.fmt.allocPrint(arena, "  {s:<10} [{s}]  {s}", .{
                it.rule_id,
                @tagName(it.severity),
                it.title,
            });
            const detail = try arena.dupe(Segment, &[_]Segment{
                .{ .text = it.rule_id, .style = .{ .bold = true, .fg = palette.heading } },
                .{ .text = "  ", .style = .{} },
                .{ .text = @tagName(it.severity), .style = .{ .bold = true, .fg = sev_color } },
                .{ .text = "\n", .style = .{} },
                .{ .text = it.title, .style = .{ .fg = palette.fg, .bold = true } },
                .{ .text = "\n\n", .style = .{} },
                .{ .text = "source:    ", .style = .{ .fg = palette.dim } },
                .{ .text = @tagName(it.source), .style = .{ .fg = palette.fg } },
                .{ .text = "\nfile:      ", .style = .{ .fg = palette.dim } },
                .{
                    .text = try std.fmt.allocPrint(arena, "{s}:{d}", .{ it.file, it.line }),
                    .style = .{ .fg = palette.fg },
                },
                .{ .text = "\n\nsnippet:\n", .style = .{ .fg = palette.dim } },
                .{
                    .text = if (it.snippet.len > 0) it.snippet else "(no snippet)",
                    .style = .{ .fg = palette.fg },
                },
                .{ .text = "\n\nfix:       ", .style = .{ .fg = palette.dim } },
                .{
                    .text = if (it.recommendation.len > 0) it.recommendation else "(no recommendation)",
                    .style = .{ .fg = palette.ok },
                },
                .{ .text = "\n", .style = .{} },
            });
            try list.append(arena, .{
                .title_plain = title,
            .title_marked = "",
            .title_selected = "",
            .title_marked_selected = "",
                .title_style = .{ .fg = sev_color },
                .detail = detail,
                .category = .config,
            });
        }
    }

    const items = try list.toOwnedSlice(arena);
    // Pre-build prefix variants. Items render based on (bookmarked, selected).
    for (items) |*it| {
        // Trim leading two-space indent (used in body rows) before adding
        // a prefix glyph so the glyph aligns with the body row's indent.
        const base = it.title_plain;
        const has_indent = base.len >= 2 and base[0] == ' ' and base[1] == ' ';
        const body = if (has_indent) base[2..] else base;
        it.title_marked = try std.fmt.allocPrint(arena, "★ {s}", .{body});
        it.title_selected = try std.fmt.allocPrint(arena, "▸ {s}", .{body});
        it.title_marked_selected = try std.fmt.allocPrint(arena, "▸★ {s}", .{body});
    }
    return items;
}

fn componentsHeaderDetail(arena: Allocator, n: usize) ![]const Segment {
    return try arena.dupe(Segment, &[_]Segment{
        .{ .text = "components\n\n", .style = .{ .bold = true, .fg = palette.heading } },
        .{
            .text = try std.fmt.allocPrint(arena, "{d} components detected.\n\n", .{n}),
            .style = .{ .fg = palette.fg },
        },
        .{
            .text = "Sources: build-id, dynamic links, embedded version strings, fingerprint matches.\n",
            .style = .{ .fg = palette.dim },
        },
    });
}
