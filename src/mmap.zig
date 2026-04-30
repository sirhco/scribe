const std = @import("std");
const Io = std.Io;

pub const OpenError = error{
    NotARegularFile,
    EmptyFile,
} || Io.File.OpenError || Io.File.StatError || Io.File.MemoryMap.CreateError;

pub const Mapping = struct {
    file: Io.File,
    mm: Io.File.MemoryMap,
    io: Io,

    pub fn bytes(self: *const Mapping) []const u8 {
        return self.mm.memory;
    }

    pub fn deinit(self: *Mapping) void {
        self.mm.destroy(self.io);
        self.file.close(self.io);
    }
};

pub fn open(io: Io, path: []const u8) OpenError!Mapping {
    const file = if (std.fs.path.isAbsolute(path))
        try Io.Dir.openFileAbsolute(io, path, .{ .mode = .read_only })
    else
        try Io.Dir.cwd().openFile(io, path, .{ .mode = .read_only });
    errdefer file.close(io);

    const stat = try file.stat(io);
    if (stat.kind != .file) return error.NotARegularFile;
    if (stat.size == 0) return error.EmptyFile;

    var mm = try Io.File.MemoryMap.create(io, file, .{
        .len = @intCast(stat.size),
        .protection = .{ .read = true, .write = false },
        .populate = false,
    });
    errdefer mm.destroy(io);

    return .{ .file = file, .mm = mm, .io = io };
}
