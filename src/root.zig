const std = @import("std");
const mem = std.mem;
const crypto = std.crypto;

const BLOCK_SIZE = 14;
const TAG_SIZE = 16;
const KEY_SIZE = 32;
const DELAYED = 1;

const Vec4x64 = @Vector(4, u64);

pub const Poly1163 = struct {
    hash: [4]Vec4x64,
    key_powers: [DELAYED][7]Vec4x64,
    keys_finalize: [7]Vec4x64,
    key: u128,
    blind: u128,
    buf: [DELAYED * 56]u8,
    remaining: usize,

    pub fn init(key_bytes: [KEY_SIZE]u8) Poly1163 {
        const key128 = mem.readInt(u128, key_bytes[0..16], .little) & (((@as(u128, 1) << 112) - 1));
        const blind = mem.readInt(u128, key_bytes[16..32], .little);

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

        if (self.remaining > 0 and self.remaining + input.len >= DELAYED * 56) {
            const needed = DELAYED * 56 - self.remaining;
            @memcpy(self.buf[self.remaining..][0..needed], input[0..needed]);
            self.core(self.buf[0 .. DELAYED * 56]);
            input = input[needed..];
            self.remaining = 0;
        }

        const full_chunks = input.len / (DELAYED * 56);
        if (full_chunks > 0) {
            const bytes_to_process = full_chunks * DELAYED * 56;
            self.core(input[0..bytes_to_process]);
            input = input[bytes_to_process..];
        }

        if (input.len > 0) {
            @memcpy(self.buf[self.remaining..][0..input.len], input);
            self.remaining += input.len;
        }
    }

    fn core(self: *Poly1163, input: []const u8) void {
        var pos: usize = 0;
        while (pos + 55 < input.len) {
            var msg: [4]Vec4x64 = undefined;
            self.load256(input[pos..], &msg);
            self.multiplyAndReduce(&msg);
            pos += 56;
        }
    }

    fn load256(_: *Poly1163, input: []const u8, msg: *[4]Vec4x64) void {
        const lower29_mask = @as(u64, (1 << 29) - 1);
        const lower25_mask = @as(u64, (1 << 25) - 1);
        const block_mask = (@as(u128, 1) << 112) - 1;
        const pad_bit = @as(u128, 1) << 112;

        var blocks: [4]u128 = undefined;
        inline for (0..4) |i| {
            blocks[i] = (mem.readInt(u128, input[i * 14 ..][0..14] ++ [_]u8{ 0, 0 }, .little) & block_mask) | pad_bit;
        }

        msg[0] = Vec4x64{ @as(u64, @truncate(blocks[0] & lower29_mask)), @as(u64, @truncate(blocks[1] & lower29_mask)), @as(u64, @truncate(blocks[2] & lower29_mask)), @as(u64, @truncate(blocks[3] & lower29_mask)) };
        msg[1] = Vec4x64{ @as(u64, @truncate((blocks[0] >> 29) & lower29_mask)), @as(u64, @truncate((blocks[1] >> 29) & lower29_mask)), @as(u64, @truncate((blocks[2] >> 29) & lower29_mask)), @as(u64, @truncate((blocks[3] >> 29) & lower29_mask)) };
        msg[2] = Vec4x64{ @as(u64, @truncate((blocks[0] >> 58) & lower29_mask)), @as(u64, @truncate((blocks[1] >> 58) & lower29_mask)), @as(u64, @truncate((blocks[2] >> 58) & lower29_mask)), @as(u64, @truncate((blocks[3] >> 58) & lower29_mask)) };
        msg[3] = Vec4x64{ @as(u64, @truncate((blocks[0] >> 87) & lower25_mask)) | (1 << 25), @as(u64, @truncate((blocks[1] >> 87) & lower25_mask)) | (1 << 25), @as(u64, @truncate((blocks[2] >> 87) & lower25_mask)) | (1 << 25), @as(u64, @truncate((blocks[3] >> 87) & lower25_mask)) | (1 << 25) };
    }

    fn multiplyAndReduce(self: *Poly1163, msg: *const [4]Vec4x64) void {
        const mask29 = @as(Vec4x64, @splat((1 << 29) - 1));

        inline for (0..4) |i| {
            self.hash[i] +%= msg[i];
        }

        var t: [4]Vec4x64 = undefined;

        t[0] = self.hash[0] * self.key_powers[0][0] +%
            self.hash[1] * self.key_powers[0][6] +%
            self.hash[2] * self.key_powers[0][5] +%
            self.hash[3] * self.key_powers[0][4];

        t[1] = self.hash[0] * self.key_powers[0][1] +%
            self.hash[1] * self.key_powers[0][0] +%
            self.hash[2] * self.key_powers[0][6] +%
            self.hash[3] * self.key_powers[0][5];

        t[2] = self.hash[0] * self.key_powers[0][2] +%
            self.hash[1] * self.key_powers[0][1] +%
            self.hash[2] * self.key_powers[0][0] +%
            self.hash[3] * self.key_powers[0][6];

        t[3] = self.hash[0] * self.key_powers[0][3] +%
            self.hash[1] * self.key_powers[0][2] +%
            self.hash[2] * self.key_powers[0][1] +%
            self.hash[3] * self.key_powers[0][0];

        var carry = t[0] >> @splat(29);
        self.hash[0] = t[0] & mask29;

        t[1] +%= carry;
        carry = t[1] >> @splat(29);
        self.hash[1] = t[1] & mask29;

        t[2] +%= carry;
        carry = t[2] >> @splat(29);
        self.hash[2] = t[2] & mask29;

        t[3] +%= carry;
        carry = t[3] >> @splat(29);
        self.hash[3] = t[3] & mask29;

        self.hash[0] +%= carry +% carry +% carry;
        carry = self.hash[0] >> @splat(29);
        self.hash[0] &= mask29;
        self.hash[1] +%= carry;
    }

    pub fn final(self: *Poly1163) [TAG_SIZE]u8 {
        if (self.remaining > 0) {
            const full_blocks = self.remaining / (4 * 14);
            if (full_blocks > 0) {
                self.core(self.buf[0 .. full_blocks * 4 * 14]);
            }

            var acc = self.combineHash();

            var pos = full_blocks * 4 * 14;
            while (pos < self.remaining) {
                const block_len = @min(14, self.remaining - pos);
                acc +%= load64(self.buf[pos..], block_len);
                acc = scalar128Mult(acc, self.key);
                pos += 14;
            }

            acc = scalar128Reduce(acc);
            acc +%= self.blind;

            var tag: [TAG_SIZE]u8 = undefined;
            mem.writeInt(u128, &tag, acc, .little);
            return tag;
        }

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

    fn combineHash(self: *Poly1163) u128 {
        const hash_a = self.hash[0][0] + (self.hash[1][0] << 29) + (self.hash[2][0] << 58) + (@as(u128, self.hash[3][0]) << 87);
        const hash_b = self.hash[0][2] + (self.hash[1][2] << 29) + (self.hash[2][2] << 58) + (@as(u128, self.hash[3][2]) << 87);
        const hash_c = self.hash[0][1] + (self.hash[1][1] << 29) + (self.hash[2][1] << 58) + (@as(u128, self.hash[3][1]) << 87);
        const hash_d = self.hash[0][3] + (self.hash[1][3] << 29) + (self.hash[2][3] << 58) + (@as(u128, self.hash[3][3]) << 87);

        return scalar128Reduce(hash_a +% hash_b +% hash_c +% hash_d);
    }
};

inline fn scalar128Mult(a: u128, b: u128) u128 {
    const mask58 = (@as(u128, 1) << 58) - 1;
    const a0 = a & mask58;
    const a1 = a >> 58;
    const b0 = b & mask58;
    const b1 = b >> 58;

    var d: [2]u128 = .{ 0, 0 };

    d[0] = a0 * b0;
    d[0] += a1 * (b1 * 3);

    d[1] = a0 * b1;
    d[1] += a1 * b0;

    const c0 = d[0] >> 58;
    const res0_tmp = d[0] & mask58;
    d[1] += c0;

    const c1 = d[1] >> 58;
    const res1 = d[1] & mask58;

    const c2 = c1 * 3;
    var res0 = res0_tmp + c2;
    const c3 = res0 >> 58;
    res0 = res0 & mask58;

    return res0 + ((res1 + c3) << 58);
}

inline fn scalar128Carry(a: u128) u128 {
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

inline fn scalar128Reduce(a: u128) u128 {
    const mask58 = (@as(u128, 1) << 58) - 1;
    const val = scalar128Carry(a);
    const a0 = val & mask58;
    const a1 = val >> 58;

    var t0 = a0 + 3;
    const c = t0 >> 58;
    t0 &= mask58;

    var t1 = a1 + c;
    t1 +%= ~mask58;

    const mask = if ((t1 >> 63) != 0) @as(u128, 0) else ~@as(u128, 0);
    const inv_mask = ~mask;

    const res0 = (a0 & inv_mask) | (t0 & mask);
    const res1 = (a1 & inv_mask) | (t1 & mask);

    return res0 + (res1 << 58);
}

inline fn addMod(a: u128, b: u128) u128 {
    return scalar128Carry(a +% b);
}

inline fn load64(buf: []const u8, len: usize) u128 {
    var val: u128 = 0;
    for (0..len) |i| {
        val |= @as(u128, buf[i]) << @intCast(i * 8);
    }
    val |= @as(u128, 1) << @intCast(len * 8);
    return val;
}

pub fn authenticate(key: [KEY_SIZE]u8, message: []const u8) [TAG_SIZE]u8 {
    var poly = Poly1163.init(key);
    poly.update(message);
    return poly.final();
}

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
