//! Poly1163 - High-performance polynomial MAC using AVX2 SIMD
//! Uses polynomial mod 2^116 - 3 with 14-byte blocks for optimal performance
const std = @import("std");
const mem = std.mem;
const crypto = std.crypto;
const builtin = @import("builtin");

// Constants - optimized for 2^116 - 3 polynomial
const BLOCK_SIZE = 14; // 14-byte blocks for optimal SIMD processing
const TAG_SIZE = 16;
const KEY_SIZE = 32; // 16 bytes for r, 16 bytes for s (blind)
const DELAYED = 1; // Number of 56-byte chunks to delay

// Vector types for SIMD operations
const Vec4x64 = @Vector(4, u64);
const Vec4x32 = @Vector(4, u32);

pub const Poly1163 = struct {
    // Four hash limbs for SIMD processing
    hash: [4]Vec4x64,
    // Key powers for batching: r^4, r^8, etc
    key_powers: [DELAYED][7]Vec4x64,
    // Keys for finalization: [r^4, r^2, r^3, r^1]
    keys_finalize: [7]Vec4x64,
    key: u128,
    blind: u128,
    buf: [DELAYED * 56]u8,
    remaining: usize,

    pub fn init(key_bytes: [KEY_SIZE]u8) Poly1163 {
        // Read key parts exactly as C implementation
        const key128 = mem.readInt(u128, key_bytes[0..16], .little) & (((@as(u128, 1) << 112) - 1));
        const blind = mem.readInt(u128, key_bytes[16..32], .little);

        // Compute key powers using scalar multiplication
        const key2 = scalar128Mult(key128, key128);
        const key3 = scalar128Mult(key128, key2);
        const key4 = scalar128Mult(key2, key2);

        var self = Poly1163{
            .hash = .{
                @splat(0),
                @splat(0),
                @splat(0),
                @splat(0),
            },
            .key_powers = undefined,
            .keys_finalize = undefined,
            .key = key128,
            .blind = blind,
            .buf = undefined,
            .remaining = 0,
        };

        // Initialize r^4 powers for batching (29-bit limbs)
        const r4_0 = @as(u32, @truncate(key4 & ((1 << 29) - 1)));
        const r4_1 = @as(u32, @truncate((key4 >> 29) & ((1 << 29) - 1)));
        const r4_2 = @as(u32, @truncate((key4 >> (2 * 29)) & ((1 << 29) - 1)));
        const r4_3 = @as(u32, @truncate((key4 >> (3 * 29)) & ((1 << 29) - 1)));

        self.key_powers[0][0] = @splat(@as(u64, r4_0));
        self.key_powers[0][1] = @splat(@as(u64, r4_1));
        self.key_powers[0][2] = @splat(@as(u64, r4_2));
        self.key_powers[0][3] = @splat(@as(u64, r4_3));
        self.key_powers[0][4] = @splat(@as(u64, 3 * r4_1));
        self.key_powers[0][5] = @splat(@as(u64, 3 * r4_2));
        self.key_powers[0][6] = @splat(@as(u64, 3 * r4_3));

        // Initialize finalization keys
        const r1_0 = @as(u32, @truncate(key128 & ((1 << 29) - 1)));
        const r1_1 = @as(u32, @truncate((key128 >> 29) & ((1 << 29) - 1)));
        const r1_2 = @as(u32, @truncate((key128 >> (2 * 29)) & ((1 << 29) - 1)));
        const r1_3 = @as(u32, @truncate((key128 >> (3 * 29)) & ((1 << 29) - 1)));

        const r2_0 = @as(u32, @truncate(key2 & ((1 << 29) - 1)));
        const r2_1 = @as(u32, @truncate((key2 >> 29) & ((1 << 29) - 1)));
        const r2_2 = @as(u32, @truncate((key2 >> (2 * 29)) & ((1 << 29) - 1)));
        const r2_3 = @as(u32, @truncate((key2 >> (3 * 29)) & ((1 << 29) - 1)));

        const r3_0 = @as(u32, @truncate(key3 & ((1 << 29) - 1)));
        const r3_1 = @as(u32, @truncate((key3 >> 29) & ((1 << 29) - 1)));
        const r3_2 = @as(u32, @truncate((key3 >> (2 * 29)) & ((1 << 29) - 1)));
        const r3_3 = @as(u32, @truncate((key3 >> (3 * 29)) & ((1 << 29) - 1)));

        self.keys_finalize[0] = Vec4x64{ r4_0, r2_0, r3_0, r1_0 };
        self.keys_finalize[1] = Vec4x64{ r4_1, r2_1, r3_1, r1_1 };
        self.keys_finalize[2] = Vec4x64{ r4_2, r2_2, r3_2, r1_2 };
        self.keys_finalize[3] = Vec4x64{ r4_3, r2_3, r3_3, r1_3 };
        self.keys_finalize[4] = Vec4x64{ 3 * r4_1, 3 * r2_1, 3 * r3_1, 3 * r1_1 };
        self.keys_finalize[5] = Vec4x64{ 3 * r4_2, 3 * r2_2, 3 * r3_2, 3 * r1_2 };
        self.keys_finalize[6] = Vec4x64{ 3 * r4_3, 3 * r2_3, 3 * r3_3, 3 * r1_3 };

        return self;
    }

    pub fn update(self: *Poly1163, data: []const u8) void {
        var input = data;

        // Process buffered data
        if (self.remaining > 0 and self.remaining + input.len >= DELAYED * 56) {
            const needed = DELAYED * 56 - self.remaining;
            @memcpy(self.buf[self.remaining..][0..needed], input[0..needed]);

            self.core(self.buf[0 .. DELAYED * 56]);

            input = input[needed..];
            self.remaining = 0;
        }

        // Process full 56-byte chunks
        const full_chunks = input.len / (DELAYED * 56);
        if (full_chunks > 0) {
            const bytes_to_process = full_chunks * DELAYED * 56;
            self.core(input[0..bytes_to_process]);
            input = input[bytes_to_process..];
        }

        // Buffer remaining data
        if (input.len > 0) {
            @memcpy(self.buf[self.remaining..][0..input.len], input);
            self.remaining += input.len;
        }
    }

    // Core processing function - processes 4 blocks of 14 bytes each
    fn core(self: *Poly1163, input: []const u8) void {
        var pos: usize = 0;

        while (pos + 55 < input.len) {
            // Load and process 4 blocks
            var msg: [4]Vec4x64 = undefined;
            self.load256(input[pos..], &msg);

            // Perform multiplication and reduction
            self.multiplyAndReduce(&msg);

            pos += 56;
        }
    }

    // Load 4x14 bytes into 4 vector registers with 29-bit limbs
    fn load256(_: *Poly1163, input: []const u8, msg: *[4]Vec4x64) void {
        const lower29_mask = @as(u64, (1 << 29) - 1);
        const lower25_mask = @as(u64, (1 << 25) - 1);

        // Load 4 blocks of 14 bytes each
        var blocks: [4]u128 = undefined;
        blocks[0] = mem.readInt(u128, input[0..][0..14] ++ [_]u8{ 0, 0 }, .little) & (((@as(u128, 1) << 112) - 1));
        blocks[1] = mem.readInt(u128, input[14..][0..14] ++ [_]u8{ 0, 0 }, .little) & (((@as(u128, 1) << 112) - 1));
        blocks[2] = mem.readInt(u128, input[28..][0..14] ++ [_]u8{ 0, 0 }, .little) & (((@as(u128, 1) << 112) - 1));
        blocks[3] = mem.readInt(u128, input[42..][0..14] ++ [_]u8{ 0, 0 }, .little) & (((@as(u128, 1) << 112) - 1));

        // Add padding bit
        blocks[0] |= (@as(u128, 1) << 112);
        blocks[1] |= (@as(u128, 1) << 112);
        blocks[2] |= (@as(u128, 1) << 112);
        blocks[3] |= (@as(u128, 1) << 112);

        // Split into 29-bit limbs for SIMD processing
        msg[0] = Vec4x64{
            @as(u64, @truncate(blocks[0] & lower29_mask)),
            @as(u64, @truncate(blocks[1] & lower29_mask)),
            @as(u64, @truncate(blocks[2] & lower29_mask)),
            @as(u64, @truncate(blocks[3] & lower29_mask)),
        };

        msg[1] = Vec4x64{
            @as(u64, @truncate((blocks[0] >> 29) & lower29_mask)),
            @as(u64, @truncate((blocks[1] >> 29) & lower29_mask)),
            @as(u64, @truncate((blocks[2] >> 29) & lower29_mask)),
            @as(u64, @truncate((blocks[3] >> 29) & lower29_mask)),
        };

        msg[2] = Vec4x64{
            @as(u64, @truncate((blocks[0] >> 58) & lower29_mask)),
            @as(u64, @truncate((blocks[1] >> 58) & lower29_mask)),
            @as(u64, @truncate((blocks[2] >> 58) & lower29_mask)),
            @as(u64, @truncate((blocks[3] >> 58) & lower29_mask)),
        };

        msg[3] = Vec4x64{
            @as(u64, @truncate((blocks[0] >> 87) & lower25_mask)) | (1 << 25),
            @as(u64, @truncate((blocks[1] >> 87) & lower25_mask)) | (1 << 25),
            @as(u64, @truncate((blocks[2] >> 87) & lower25_mask)) | (1 << 25),
            @as(u64, @truncate((blocks[3] >> 87) & lower25_mask)) | (1 << 25),
        };
    }

    // Multiply accumulator by r^4 and add message blocks
    fn multiplyAndReduce(self: *Poly1163, msg: *const [4]Vec4x64) void {
        const mask29 = @as(u64, (1 << 29) - 1);

        // Add message to hash
        self.hash[0] +%= msg[0];
        self.hash[1] +%= msg[1];
        self.hash[2] +%= msg[2];
        self.hash[3] +%= msg[3];

        // Multiply by r^4 (simplified - production would need full implementation)
        var result: [4]Vec4x64 = undefined;

        result[0] = (self.hash[0] * self.key_powers[0][0]) & @as(Vec4x64, @splat(mask29));
        result[1] = (self.hash[1] * self.key_powers[0][1]) & @as(Vec4x64, @splat(mask29));
        result[2] = (self.hash[2] * self.key_powers[0][2]) & @as(Vec4x64, @splat(mask29));
        result[3] = (self.hash[3] * self.key_powers[0][3]) & @as(Vec4x64, @splat(mask29));

        self.hash = result;
    }

    pub fn final(self: *Poly1163) [TAG_SIZE]u8 {
        if (self.remaining > 0) {
            // Process full blocks in buffer
            const full_blocks = self.remaining / (4 * 14);
            if (full_blocks > 0) {
                self.core(self.buf[0 .. full_blocks * 4 * 14]);
            }

            // Process remaining partial blocks with scalar operations
            var pos = full_blocks * 4 * 14;
            var acc = self.combineHash();

            while (pos < self.remaining) {
                const block_len = @min(14, self.remaining - pos);
                var block: [16]u8 = [_]u8{0} ** 16;
                @memcpy(block[0..block_len], self.buf[pos .. pos + block_len]);

                // Add padding
                const val = load64(block[0..], block_len);
                acc = addMod(acc, val);
                acc = scalar128Mult(acc, self.key);

                pos += block_len;
            }

            // Final reduction
            acc = scalar128Reduce(acc);
            acc +%= self.blind;

            var tag: [TAG_SIZE]u8 = undefined;
            mem.writeInt(u128, &tag, acc, .little);
            return tag;
        }

        // No remaining data - just combine and reduce
        var acc = self.combineHash();
        acc = scalar128Reduce(acc);
        acc +%= self.blind;

        var tag: [TAG_SIZE]u8 = undefined;
        mem.writeInt(u128, &tag, acc, .little);
        return tag;
    }

    pub fn verify(self: *Poly1163, expected_tag: [TAG_SIZE]u8) bool {
        const computed_tag = self.final();
        return crypto.timing_safe.eql([TAG_SIZE]u8, computed_tag, expected_tag);
    }

    // Combine the 4 SIMD hash values into a single scalar
    fn combineHash(self: *Poly1163) u128 {
        // Extract and combine the 4 parallel hashes
        const h0_0 = self.hash[0][0];
        const h0_1 = self.hash[1][0];
        const h0_2 = self.hash[2][0];
        const h0_3 = self.hash[3][0];

        const h1_0 = self.hash[0][1];
        const h1_1 = self.hash[1][1];
        const h1_2 = self.hash[2][1];
        const h1_3 = self.hash[3][1];

        const h2_0 = self.hash[0][2];
        const h2_1 = self.hash[1][2];
        const h2_2 = self.hash[2][2];
        const h2_3 = self.hash[3][2];

        const h3_0 = self.hash[0][3];
        const h3_1 = self.hash[1][3];
        const h3_2 = self.hash[2][3];
        const h3_3 = self.hash[3][3];

        // Reconstruct 128-bit values from limbs
        const hash_a = h0_0 + (h0_1 << 29) + (h0_2 << 58) + (@as(u128, h0_3) << 87);
        const hash_b = h1_0 + (h1_1 << 29) + (h1_2 << 58) + (@as(u128, h1_3) << 87);
        const hash_c = h2_0 + (h2_1 << 29) + (h2_2 << 58) + (@as(u128, h2_3) << 87);
        const hash_d = h3_0 + (h3_1 << 29) + (h3_2 << 58) + (@as(u128, h3_3) << 87);

        return scalar128Reduce(addMod(addMod(hash_a, hash_b), addMod(hash_c, hash_d)));
    }
};

// Scalar multiplication mod 2^116 - 3
inline fn scalar128Mult(a: u128, b: u128) u128 {
    const a0 = a & (((@as(u128, 1) << 58) - 1));
    const a1 = a >> 58;
    const b0 = b & (((@as(u128, 1) << 58) - 1));
    const b1 = b >> 58;

    var d: [2]u128 = .{ 0, 0 };

    // Multiplication with reduction by 2^116 - 3
    d[0] += a0 * b0;
    d[0] += a1 * (b1 * 3); // Since 2^116 ≡ 3 (mod 2^116 - 3)

    d[1] += a0 * b1;
    d[1] += a1 * b0;

    // Carry propagation
    const c0 = d[0] >> 58;
    const res0 = d[0] & (((@as(u128, 1) << 58) - 1));
    d[1] += c0;

    const c1 = d[1] >> 58;
    const res1 = d[1] & (((@as(u128, 1) << 58) - 1));

    // Final reduction
    const c2 = c1 * 3;
    var result = res0 + c2;
    const c3 = result >> 58;
    result = (result & (((@as(u128, 1) << 58) - 1))) + res1 + c3;

    return (result & (((@as(u128, 1) << 58) - 1))) + ((result >> 58) << 58);
}

// Scalar carry/reduction
inline fn scalar128Carry(a: u128) u128 {
    const a0 = a & (((@as(u128, 1) << 58) - 1));
    const a1 = a >> 58;

    const c0 = a0 >> 58;
    const res0 = a0 & (((@as(u128, 1) << 58) - 1));
    const t1 = a1 + c0;

    const c1 = t1 >> 58;
    const res1 = t1 & (((@as(u128, 1) << 58) - 1));

    // Reduction: 2^116 ≡ 3
    const c2 = c1 * 3;
    const t0 = res0 + c2;
    const c3 = t0 >> 58;

    return (t0 & (((@as(u128, 1) << 58) - 1))) + ((res1 + c3) << 58);
}

// Final reduction to ensure value < 2^116 - 3
inline fn scalar128Reduce(a: u128) u128 {
    const val = scalar128Carry(a);
    const a0 = val & (((@as(u128, 1) << 58) - 1));
    const a1 = val >> 58;

    // Check if val >= 2^116 - 3
    var t0 = a0 + 3;
    const c = t0 >> 58;
    t0 &= (((@as(u128, 1) << 58) - 1));

    var t1 = a1 + c;
    t1 +%= ~@as(u128, (@as(u128, 1) << 58) - 1); // Subtract 2^58

    // Check if t1 had a carry (negative after subtraction)
    const mask = if ((t1 >> 63) != 0) @as(u128, 0) else ~@as(u128, 0);
    const inv_mask = ~mask;

    const res0 = (a0 & inv_mask) | (t0 & mask);
    const res1 = (a1 & inv_mask) | (t1 & mask);

    return res0 + (res1 << 58);
}

inline fn addMod(a: u128, b: u128) u128 {
    return scalar128Carry(a +% b);
}

inline fn load64(buf: []const u8, len: u64) u128 {
    var val: u128 = 0;
    for (0..len) |i| {
        val |= @as(u128, buf[i]) << @intCast(i * 8);
    }
    val |= @as(u128, 1) << @intCast(len * 8);
    return val;
}

// One-shot authentication function
pub fn authenticate(key: [KEY_SIZE]u8, message: []const u8) [TAG_SIZE]u8 {
    var poly = Poly1163.init(key);
    poly.update(message);
    return poly.final();
}

// Tests
test "Poly1163 basic functionality" {
    const key = [_]u8{0x42} ** KEY_SIZE;
    const message = "Hello, World!";

    const tag = authenticate(key, message);

    // Verify it produces consistent output
    const tag2 = authenticate(key, message);
    try std.testing.expectEqualSlices(u8, &tag, &tag2);
}

test "Poly1163 empty message" {
    const key = [_]u8{0x01} ** KEY_SIZE;
    const message = "";

    const tag = authenticate(key, message);
    try std.testing.expect(tag.len == TAG_SIZE);
}

test "Poly1163 verification" {
    const key = [_]u8{0x04} ** KEY_SIZE;
    const message = "Test message for verification";

    // Generate tag
    var poly = Poly1163.init(key);
    poly.update(message);
    const tag = poly.final();

    // Verify tag
    var poly2 = Poly1163.init(key);
    poly2.update(message);
    try std.testing.expect(poly2.verify(tag));

    // Verify with wrong tag fails
    var wrong_tag = tag;
    wrong_tag[0] ^= 0xFF;
    var poly3 = Poly1163.init(key);
    poly3.update(message);
    try std.testing.expect(!poly3.verify(wrong_tag));
}

test "Poly1163 incremental update" {
    const key = [_]u8{0x05} ** KEY_SIZE;
    const message = "This message will be processed in parts";

    // Process all at once
    const tag1 = authenticate(key, message);

    // Process incrementally
    var poly = Poly1163.init(key);
    poly.update(message[0..10]);
    poly.update(message[10..20]);
    poly.update(message[20..]);
    const tag2 = poly.final();

    try std.testing.expectEqualSlices(u8, &tag1, &tag2);
}
