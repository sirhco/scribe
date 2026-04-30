pub const ScribeError = error{
    NotElf,
    Truncated,
    UnsupportedClass,
    UnsupportedEndian,
    UnsupportedVersion,
    InvalidStringTable,
    NotImplemented,
    OutOfMemory,
};
