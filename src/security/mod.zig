//! Security subsystem barrel re-export. v1 ships secret scanning;
//! vulnerability lookup, IaC config audit, and policy gate land in
//! subsequent modules.

pub const secrets = @import("secrets.zig");
pub const vulnerability = @import("vulnerability.zig");
