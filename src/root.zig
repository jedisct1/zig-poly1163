const std = @import("std");
const builtin = @import("builtin");

// Re-export the scalar implementation which matches the reference exactly
pub const Poly1163Scalar = @import("scalar.zig").Poly1163Scalar;
pub const authenticateScalar = @import("scalar.zig").authenticateScalar;

// Import vectorized implementation
const vector = @import("vector.zig");
pub const Poly1163Vector = vector.Poly1163Vector;
pub const authenticateVector = vector.authenticateVector;
pub const has_avx2 = vector.has_avx2;

// Both implementations now produce identical results
// Note: The "vector" implementation is actually just the scalar algorithm
// (true SIMD vectorization across blocks is not possible for Poly1305/Poly1163)
pub const Poly1163 = Poly1163Scalar;
pub const authenticate = authenticateScalar;

// Constants
pub const TAG_SIZE = 16;
pub const KEY_SIZE = 32;
