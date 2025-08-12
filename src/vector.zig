const std = @import("std");
const mem = std.mem;
const crypto = std.crypto;

const BLOCK_SIZE = 14;
const TAG_SIZE = 16;
const KEY_SIZE = 32;
const VECTOR_WIDTH = std.simd.suggestVectorLength(u128) orelse 1;

pub const Poly1163 = struct {
    r: u128,
    s: u128,
    acc: u128,
    buf: [BLOCK_SIZE * VECTOR_WIDTH]u8,
    buf_len: usize,
    r_powers: @Vector(VECTOR_WIDTH, u128), // Precomputed powers r^1, r^2, ..., r^VECTOR_WIDTH for parallel processing

    pub fn init(key_bytes: [KEY_SIZE]u8) Poly1163 {
        const r = mem.readInt(u128, key_bytes[0..16], .little) & (((@as(u128, 1) << 112) - 1));
        const s = mem.readInt(u128, key_bytes[16..32], .little);

        // Precompute powers of r in reverse order for Horner's method
        // r_powers[0] = r^VECTOR_WIDTH, r_powers[1] = r^(VECTOR_WIDTH-1), ..., r_powers[VECTOR_WIDTH-1] = r
        var r_powers: @Vector(VECTOR_WIDTH, u128) = undefined;
        r_powers[VECTOR_WIDTH - 1] = r;
        var i: usize = VECTOR_WIDTH - 1;
        while (i > 0) : (i -= 1) {
            r_powers[i - 1] = multiplyMod(r_powers[i], r);
        }

        return Poly1163{
            .r = r,
            .s = s,
            .acc = 0,
            .buf = undefined,
            .buf_len = 0,
            .r_powers = r_powers,
        };
    }

    pub fn update(self: *Poly1163, data: []const u8) void {
        var input = data;

        if (self.buf_len > 0) {
            const needed = @min(BLOCK_SIZE * VECTOR_WIDTH - self.buf_len, input.len);
            @memcpy(self.buf[self.buf_len..][0..needed], input[0..needed]);
            self.buf_len += needed;
            input = input[needed..];

            if (self.buf_len >= BLOCK_SIZE * VECTOR_WIDTH) {
                self.processVectorBlocks(self.buf[0 .. BLOCK_SIZE * VECTOR_WIDTH]);
                self.buf_len = 0;
            } else if (self.buf_len >= BLOCK_SIZE and input.len == 0) {
                const complete_blocks = self.buf_len / BLOCK_SIZE;
                for (0..complete_blocks) |i| {
                    self.processBlock(self.buf[i * BLOCK_SIZE .. (i + 1) * BLOCK_SIZE]);
                }
                const remaining = self.buf_len % BLOCK_SIZE;
                if (remaining > 0) {
                    @memmove(self.buf[0..remaining], self.buf[complete_blocks * BLOCK_SIZE .. self.buf_len]);
                }
                self.buf_len = remaining;
            }
        }

        // Prefetch upcoming data for better cache utilization
        @prefetch(input.ptr + 256, .{ .rw = .read, .locality = 3, .cache = .data });

        while (input.len >= BLOCK_SIZE * VECTOR_WIDTH) {
            @prefetch(input.ptr + BLOCK_SIZE * VECTOR_WIDTH + 256, .{ .rw = .read, .locality = 3, .cache = .data });
            self.processVectorBlocks(input[0 .. BLOCK_SIZE * VECTOR_WIDTH]);
            input = input[BLOCK_SIZE * VECTOR_WIDTH ..];
        }

        while (input.len >= BLOCK_SIZE) {
            self.processBlock(input[0..BLOCK_SIZE]);
            input = input[BLOCK_SIZE..];
        }

        if (input.len > 0) {
            @memcpy(self.buf[self.buf_len..][0..input.len], input);
            self.buf_len += input.len;
        }
    }

    fn processVectorBlocks(self: *Poly1163, blocks: []const u8) void {
        var values: @Vector(VECTOR_WIDTH, u128) = undefined;

        // Load VECTOR_WIDTH blocks in parallel
        inline for (0..VECTOR_WIDTH) |i| {
            const block = blocks[i * BLOCK_SIZE .. (i + 1) * BLOCK_SIZE];
            const low = mem.readInt(u64, block[0..8], .little);
            var high: u64 = 0;
            inline for (0..6) |j| {
                high |= @as(u64, block[8 + j]) << @intCast(j * 8);
            }
            values[i] = @as(u128, low) | (@as(u128, high) << 64) | (@as(u128, 1) << (BLOCK_SIZE * 8));
        }

        // Horner's method: acc = (acc + v0) * r^VECTOR_WIDTH + v1 * r^(VECTOR_WIDTH-1) + ... + v(VECTOR_WIDTH-1) * r
        // Handle v0 separately with accumulator
        self.acc +%= values[0];
        self.acc = multiplyMod(self.acc, self.r_powers[0]);
        
        // Zero out first value for SIMD multiplication since it's already handled
        var values_to_multiply = values;
        values_to_multiply[0] = 0;
        
        // Use SIMD for parallel multiplication of remaining values
        const products = multiplyModVector(values_to_multiply, self.r_powers);
        
        // Sum products using SIMD reduction
        self.acc +%= @reduce(.Add, products);
    }

    fn processBlock(self: *Poly1163, block: []const u8) void {
        const len = @min(block.len, BLOCK_SIZE);
        var val: u128 = 0;

        if (len >= 8) {
            val = mem.readInt(u64, block[0..8], .little);
            for (8..len) |i| {
                val |= @as(u128, block[i]) << @intCast(i * 8);
            }
        } else {
            for (0..len) |i| {
                val |= @as(u128, block[i]) << @intCast(i * 8);
            }
        }

        const shift_amount = @as(u7, @intCast(len)) * 8;
        val |= @as(u128, 1) << shift_amount; // Append 1-bit after message block

        self.acc +%= val;
        self.acc = multiplyMod(self.acc, self.r);
    }

    pub fn verify(self: *Poly1163, expected_tag: [TAG_SIZE]u8) bool {
        const computed_tag = self.final();
        return crypto.timing_safe.eql([TAG_SIZE]u8, computed_tag, expected_tag);
    }

    pub fn final(self: *Poly1163) [TAG_SIZE]u8 {
        if (self.buf_len > 0) {
            const complete_blocks = self.buf_len / BLOCK_SIZE;
            for (0..complete_blocks) |i| {
                self.processBlock(self.buf[i * BLOCK_SIZE .. (i + 1) * BLOCK_SIZE]);
            }

            const remaining = self.buf_len % BLOCK_SIZE;
            if (remaining > 0) {
                self.processBlock(self.buf[complete_blocks * BLOCK_SIZE ..][0..remaining]);
            }
        }

        self.acc = reduce(self.acc);
        self.acc +%= self.s;

        var tag: [TAG_SIZE]u8 = undefined;
        mem.writeInt(u128, &tag, self.acc, .little);
        return tag;
    }

    // Vectorized modular multiplication for multiple independent multiplications
    fn multiplyModVector(a: @Vector(VECTOR_WIDTH, u128), b: @Vector(VECTOR_WIDTH, u128)) @Vector(VECTOR_WIDTH, u128) {
        const mask58: @Vector(VECTOR_WIDTH, u128) = @splat((@as(u128, 1) << 58) - 1);
        const three: @Vector(VECTOR_WIDTH, u128) = @splat(3);
        
        // Split operands into 58-bit limbs using SIMD operations
        const a0 = a & mask58;
        const a1 = a >> @splat(58);
        const b0 = b & mask58;
        const b1 = b >> @splat(58);
        
        // Karatsuba-like multiplication with vectorized operations
        var d0 = a0 * b0;
        d0 += a1 * (b1 * three); // b1 * 3 because 2^116 ≡ 3 (mod p)
        
        var d1 = a0 * b1;
        d1 += a1 * b0;
        
        const c0 = d0 >> @splat(58);
        const res0_tmp = d0 & mask58;
        d1 += c0;
        
        const c1 = d1 >> @splat(58);
        const res1 = d1 & mask58;
        
        const c2 = c1 * three;
        var res0 = res0_tmp + c2;
        const c3 = res0 >> @splat(58);
        res0 = res0 & mask58;
        
        return res0 + ((res1 + c3) << @splat(58));
    }

    // Modular multiplication using 2^116 - 3 prime with 58-bit limbs
    fn multiplyMod(a: u128, b: u128) u128 {
        const mask58 = (@as(u128, 1) << 58) - 1;

        const a0 = a & mask58;
        const a1 = a >> 58;
        const b0 = b & mask58;
        const b1 = b >> 58;

        // Karatsuba-like multiplication with modular reduction
        var d0: u128 = a0 * b0;
        d0 +%= a1 * (b1 * 3); // b1 * 3 because 2^116 ≡ 3 (mod p)

        var d1: u128 = a0 * b1;
        d1 +%= a1 * b0;

        const c0 = d0 >> 58;
        const res0_tmp = d0 & mask58;
        d1 +%= c0;

        const c1 = d1 >> 58;
        const res1 = d1 & mask58;

        const c2 = c1 * 3;
        var res0 = res0_tmp +% c2;
        const c3 = res0 >> 58;
        res0 = res0 & mask58;

        return res0 + ((res1 + c3) << 58);
    }

    fn reduce(a: u128) u128 {
        const val = carry(a);
        const mask58 = (@as(u128, 1) << 58) - 1;
        const a0 = val & mask58;
        const a1 = val >> 58;

        var t0 = a0 +% 3;
        const c = t0 >> 58;
        t0 &= mask58;

        var t1 = a1 +% c;
        t1 +%= ~mask58;

        // Constant-time selection using bitmasking
        const mask = if ((t1 >> 63) != 0) @as(u128, 0) else ~@as(u128, 0);
        const inv_mask = ~mask;

        const res0 = (a0 & inv_mask) | (t0 & mask);
        const res1 = (a1 & inv_mask) | (t1 & mask);

        return res0 + (res1 << 58);
    }

    fn carry(a: u128) u128 {
        const mask58 = (@as(u128, 1) << 58) - 1;
        const a0 = a & mask58;
        const a1 = a >> 58;

        const c0 = a0 >> 58;
        const res0_tmp = a0 & mask58;
        const t1 = a1 + c0;

        const c1 = t1 >> 58;
        const res1 = t1 & mask58;

        const c2 = c1 * 3; // Reduction: 2^116 ≡ 3 (mod p)
        var res0 = res0_tmp + c2;
        const c3 = res0 >> 58;
        res0 = res0 & mask58;

        return res0 + ((res1 + c3) << 58);
    }
};

pub fn authenticate(key: [KEY_SIZE]u8, message: []const u8) [TAG_SIZE]u8 {
    var poly = Poly1163.init(key);
    poly.update(message);
    return poly.final();
}