const std = @import("std");
const mem = std.mem;
const crypto = std.crypto;
const builtin = @import("builtin");

const BLOCK_SIZE = 14;
const TAG_SIZE = 16;
const KEY_SIZE = 32;
const VECTOR_WIDTH = 4; // Process 4 blocks in parallel

pub const has_avx2 = blk: {
    if (builtin.cpu.arch != .x86_64) break :blk false;
    break :blk std.Target.x86.featureSetHas(builtin.cpu.features, .avx2);
};

// Vector type for SIMD operations
const Vec128 = @Vector(VECTOR_WIDTH, u128);

pub const Poly1163Vector = struct {
    r: u128,
    s: u128,
    acc: u128,
    buf: [BLOCK_SIZE * VECTOR_WIDTH]u8,
    buf_len: usize,
    // Precomputed powers of r for Horner's method (vectorized)
    r_powers_vec: Vec128,

    pub fn init(key_bytes: [KEY_SIZE]u8) Poly1163Vector {
        const r = mem.readInt(u128, key_bytes[0..16], .little) & (((@as(u128, 1) << 112) - 1));
        const s = mem.readInt(u128, key_bytes[16..32], .little);

        // Precompute powers of r: r, r^2, r^3, r^4 directly as vector
        var r_powers_vec: Vec128 = undefined;
        r_powers_vec[0] = r;
        for (1..VECTOR_WIDTH) |i| {
            r_powers_vec[i] = multiplyMod(r_powers_vec[i - 1], r);
        }

        return Poly1163Vector{
            .r = r,
            .s = s,
            .acc = 0,
            .buf = undefined,
            .buf_len = 0,
            .r_powers_vec = r_powers_vec,
        };
    }

    pub fn update(self: *Poly1163Vector, data: []const u8) void {
        var input = data;

        // Handle buffered data
        if (self.buf_len > 0) {
            const needed = @min(BLOCK_SIZE * VECTOR_WIDTH - self.buf_len, input.len);
            @memcpy(self.buf[self.buf_len..][0..needed], input[0..needed]);
            self.buf_len += needed;
            input = input[needed..];

            // Process complete vector blocks from buffer
            if (self.buf_len >= BLOCK_SIZE * VECTOR_WIDTH) {
                self.processVectorBlocks(self.buf[0..BLOCK_SIZE * VECTOR_WIDTH]);
                self.buf_len = 0;
            } else if (self.buf_len >= BLOCK_SIZE and input.len == 0) {
                // Process any complete blocks in buffer if no more input
                const complete_blocks = self.buf_len / BLOCK_SIZE;
                self.processPartialVector(self.buf[0..complete_blocks * BLOCK_SIZE], complete_blocks);
                const remaining = self.buf_len % BLOCK_SIZE;
                if (remaining > 0) {
                    std.mem.copyForwards(u8, self.buf[0..remaining], self.buf[complete_blocks * BLOCK_SIZE..self.buf_len]);
                }
                self.buf_len = remaining;
            }
        }

        // Process full vector blocks using optimized loading
        while (input.len >= BLOCK_SIZE * VECTOR_WIDTH) {
            self.processVectorBlocks(input[0..BLOCK_SIZE * VECTOR_WIDTH]);
            input = input[BLOCK_SIZE * VECTOR_WIDTH..];
        }

        // Process remaining complete blocks
        if (input.len >= BLOCK_SIZE) {
            const complete_blocks = input.len / BLOCK_SIZE;
            self.processPartialVector(input[0..complete_blocks * BLOCK_SIZE], complete_blocks);
            input = input[complete_blocks * BLOCK_SIZE..];
        }

        // Buffer remaining bytes
        if (input.len > 0) {
            @memcpy(self.buf[self.buf_len..][0..input.len], input);
            self.buf_len += input.len;
        }
    }

    fn processVectorBlocks(self: *Poly1163Vector, blocks: []const u8) void {
        var values_vec: Vec128 = undefined;
        
        // Load all blocks directly into vector
        inline for (0..VECTOR_WIDTH) |i| {
            const block = blocks[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE];
            var val: u128 = 0;
            
            // Load bytes using vectorized operations where beneficial
            if (BLOCK_SIZE >= 8) {
                // Load first 8 bytes as u64
                val |= mem.readInt(u64, block[0..8], .little);
                // Load remaining 6 bytes
                for (8..BLOCK_SIZE) |j| {
                    val |= @as(u128, block[j]) << @intCast(j * 8);
                }
            } else {
                for (0..BLOCK_SIZE) |j| {
                    val |= @as(u128, block[j]) << @intCast(j * 8);
                }
            }
            val |= @as(u128, 1) << (BLOCK_SIZE * 8);
            values_vec[i] = val;
        }

        // Use vectorized multiplication for parallel processing
        // We need to reorganize for Horner's method with SIMD
        // First, multiply first block with accumulator scalar
        self.acc +%= values_vec[0];
        self.acc = multiplyMod(self.acc, self.r_powers_vec[VECTOR_WIDTH - 1]);
        
        // Process remaining blocks in parallel using SIMD
        // Create a vector with the appropriate powers for blocks 1-3
        var powers_for_mult: Vec128 = undefined;
        powers_for_mult[0] = self.r_powers_vec[2]; // for block 1: r^3
        powers_for_mult[1] = self.r_powers_vec[1]; // for block 2: r^2
        powers_for_mult[2] = self.r_powers_vec[0]; // for block 3: r^1
        powers_for_mult[3] = 0; // unused
        
        // Shift values to align with powers
        var shifted_values: Vec128 = undefined;
        shifted_values[0] = values_vec[1];
        shifted_values[1] = values_vec[2];
        shifted_values[2] = values_vec[3];
        shifted_values[3] = 0;
        
        // Perform vectorized multiplication
        const products = multiplyModVec(shifted_values, powers_for_mult);
        
        // Sum the results (reduction to scalar)
        for (0..3) |i| {
            self.acc +%= products[i];
        }
    }

    fn processPartialVector(self: *Poly1163Vector, blocks: []const u8, num_blocks: usize) void {
        if (num_blocks == 0) return;
        
        var values_vec: Vec128 = @splat(0);
        
        // Load available blocks into vector
        for (0..num_blocks) |i| {
            const block = blocks[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE];
            var val: u128 = 0;
            for (0..BLOCK_SIZE) |j| {
                val |= @as(u128, block[j]) << @intCast(j * 8);
            }
            val |= @as(u128, 1) << (BLOCK_SIZE * 8);
            values_vec[i] = val;
        }

        // Process with Horner's method using only num_blocks powers
        self.acc +%= values_vec[0];
        self.acc = multiplyMod(self.acc, self.r_powers_vec[num_blocks - 1]);
        
        for (1..num_blocks) |i| {
            const power_idx = num_blocks - 1 - i;
            const term = multiplyMod(values_vec[i], self.r_powers_vec[power_idx]);
            self.acc +%= term;
        }
    }

    fn processBlock(self: *Poly1163Vector, block: []const u8) void {
        const len = @min(block.len, BLOCK_SIZE);
        var val: u128 = 0;
        for (0..len) |i| {
            val |= @as(u128, block[i]) << @intCast(i * 8);
        }
        const shift_amount = @as(u7, @intCast(len)) * 8;
        val |= @as(u128, 1) << shift_amount;

        self.acc +%= val;
        self.acc = multiplyMod(self.acc, self.r);
    }

    pub fn verify(self: *Poly1163Vector, expected_tag: [TAG_SIZE]u8) bool {
        const computed_tag = self.final();
        return crypto.timing_safe.eql([TAG_SIZE]u8, computed_tag, expected_tag);
    }

    pub fn final(self: *Poly1163Vector) [TAG_SIZE]u8 {
        // Process any remaining buffered data
        if (self.buf_len > 0) {
            // Process complete blocks first
            const complete_blocks = self.buf_len / BLOCK_SIZE;
            if (complete_blocks > 0) {
                self.processPartialVector(self.buf[0..complete_blocks * BLOCK_SIZE], complete_blocks);
            }
            
            // Process final partial block
            const remaining = self.buf_len % BLOCK_SIZE;
            if (remaining > 0) {
                self.processBlock(self.buf[complete_blocks * BLOCK_SIZE..][0..remaining]);
            }
        }

        self.acc = reduce(self.acc);
        self.acc +%= self.s;

        var tag: [TAG_SIZE]u8 = undefined;
        mem.writeInt(u128, &tag, self.acc, .little);
        return tag;
    }

    fn multiplyMod(a: u128, b: u128) u128 {
        const mask58 = (@as(u128, 1) << 58) - 1;
        const a0 = a & mask58;
        const a1 = a >> 58;
        const b0 = b & mask58;
        const b1 = b >> 58;

        var d0: u128 = a0 * b0;
        d0 +%= a1 * (b1 * 3);

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

        const c2 = c1 * 3;
        var res0 = res0_tmp + c2;
        const c3 = res0 >> 58;
        res0 = res0 & mask58;

        return res0 + ((res1 + c3) << 58);
    }

    // Vectorized versions of the modular arithmetic functions
    fn multiplyModVec(a: Vec128, b: Vec128) Vec128 {
        const mask58: Vec128 = @splat((@as(u128, 1) << 58) - 1);
        const three: Vec128 = @splat(3);
        
        const a0 = a & mask58;
        const a1 = a >> @splat(58);
        const b0 = b & mask58;
        const b1 = b >> @splat(58);

        var d0 = a0 *% b0;
        d0 +%= a1 *% (b1 *% three);

        var d1 = a0 *% b1;
        d1 +%= a1 *% b0;

        const c0 = d0 >> @splat(58);
        const res0_tmp = d0 & mask58;
        d1 +%= c0;

        const c1 = d1 >> @splat(58);
        const res1 = d1 & mask58;

        const c2 = c1 *% three;
        var res0 = res0_tmp +% c2;
        const c3 = res0 >> @splat(58);
        res0 = res0 & mask58;

        return res0 +% ((res1 +% c3) << @splat(58));
    }

    fn carryVec(a: Vec128) Vec128 {
        const mask58: Vec128 = @splat((@as(u128, 1) << 58) - 1);
        const three: Vec128 = @splat(3);
        
        const a0 = a & mask58;
        const a1 = a >> @splat(58);

        const c0 = a0 >> @splat(58);
        const res0_tmp = a0 & mask58;
        const t1 = a1 +% c0;

        const c1 = t1 >> @splat(58);
        const res1 = t1 & mask58;

        const c2 = c1 *% three;
        var res0 = res0_tmp +% c2;
        const c3 = res0 >> @splat(58);
        res0 = res0 & mask58;

        return res0 +% ((res1 +% c3) << @splat(58));
    }

    fn reduceVec(a: Vec128) Vec128 {
        const val = carryVec(a);
        const mask58: Vec128 = @splat((@as(u128, 1) << 58) - 1);
        const three: Vec128 = @splat(3);
        
        const a0 = val & mask58;
        const a1 = val >> @splat(58);

        var t0 = a0 +% three;
        const c = t0 >> @splat(58);
        t0 &= mask58;

        var t1 = a1 +% c;
        t1 +%= @as(Vec128, @splat(~((@as(u128, 1) << 58) - 1)));

        // For the conditional mask, we need to check each lane separately
        // This is the tricky part for SIMD - we need branchless selection
        const sign_bits = t1 >> @splat(63);
        const mask = sign_bits *% @as(Vec128, @splat(~@as(u128, 0)));
        const inv_mask = ~mask;

        const res0 = (a0 & inv_mask) | (t0 & mask);
        const res1 = (a1 & inv_mask) | (t1 & mask);

        return res0 +% (res1 << @splat(58));
    }
};

pub fn authenticateVector(key: [KEY_SIZE]u8, message: []const u8) [TAG_SIZE]u8 {
    var poly = Poly1163Vector.init(key);
    poly.update(message);
    return poly.final();
}