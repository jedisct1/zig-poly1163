const std = @import("std");

// Re-export the scalar implementation which matches the reference exactly
pub const Poly1163 = @import("scalar.zig").Poly1163Scalar;
pub const authenticate = @import("scalar.zig").authenticateScalar;

// Constants
pub const TAG_SIZE = 16;
pub const KEY_SIZE = 32;