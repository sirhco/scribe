pub const ScribeError = error{
    UnsupportedFormat,
    Truncated,
    UnsupportedClass,
    UnsupportedEndian,
    UnsupportedVersion,
    InvalidStringTable,
    NotImplemented,
    OutOfMemory,
};
