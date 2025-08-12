const std = @import("std");
const builtin = @import("builtin");

const vector = @import("vector.zig");

pub const Poly1163 = vector.Poly1163;
pub const authenticate = vector.authenticate;

pub const TAG_SIZE = 16;
pub const KEY_SIZE = 32;
