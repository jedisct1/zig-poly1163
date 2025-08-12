const std = @import("std");
const mem = std.mem;
const crypto = std.crypto;

const BLOCK_SIZE = 14;
const TAG_SIZE = 16;
const KEY_SIZE = 32;

pub const Poly1163Scalar = struct {
    r: u128,
    s: u128,
    acc: u128,
    buf: [BLOCK_SIZE]u8,
    buf_len: usize,

    pub fn init(key_bytes: [KEY_SIZE]u8) Poly1163Scalar {
        const r = mem.readInt(u128, key_bytes[0..16], .little) & (((@as(u128, 1) << 112) - 1));
        const s = mem.readInt(u128, key_bytes[16..32], .little);

        return Poly1163Scalar{
            .r = r,
            .s = s,
            .acc = 0,
            .buf = undefined,
            .buf_len = 0,
        };
    }

    pub fn update(self: *Poly1163Scalar, data: []const u8) void {
        var input = data;

        if (self.buf_len > 0) {
            const needed = @min(BLOCK_SIZE - self.buf_len, input.len);
            @memcpy(self.buf[self.buf_len..][0..needed], input[0..needed]);
            self.buf_len += needed;
            input = input[needed..];

            if (self.buf_len == BLOCK_SIZE) {
                self.processBlock(self.buf[0..]);
                self.buf_len = 0;
            }
        }

        while (input.len >= BLOCK_SIZE) {
            self.processBlock(input[0..BLOCK_SIZE]);
            input = input[BLOCK_SIZE..];
        }

        if (input.len > 0) {
            @memcpy(self.buf[0..input.len], input);
            self.buf_len = input.len;
        }
    }

    fn processBlock(self: *Poly1163Scalar, block: []const u8) void {
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

    pub fn verify(self: *Poly1163Scalar, expected_tag: [TAG_SIZE]u8) bool {
        const computed_tag = self.final();
        return crypto.timing_safe.eql([TAG_SIZE]u8, computed_tag, expected_tag);
    }

    pub fn final(self: *Poly1163Scalar) [TAG_SIZE]u8 {
        if (self.buf_len > 0) {
            self.processBlock(self.buf[0..self.buf_len]);
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
};

pub fn authenticateScalar(key: [KEY_SIZE]u8, message: []const u8) [TAG_SIZE]u8 {
    var poly = Poly1163Scalar.init(key);
    poly.update(message);
    return poly.final();
}
