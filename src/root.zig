const std = @import("std");
const builtin = @import("builtin");

// Import and export the unified implementation
const vector = @import("vector.zig");
pub const Poly1163 = vector.Poly1163;
pub const authenticate = vector.authenticate;

// Constants
pub const TAG_SIZE = 16;
pub const KEY_SIZE = 32;
