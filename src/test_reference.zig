const std = @import("std");
const Poly1163 = @import("root.zig").Poly1163;
const authenticate = @import("root.zig").authenticate;

fn expectTag(key: [32]u8, data: []const u8, expected_hex: []const u8) !void {
    const tag = authenticate(key, data);

    var expected_tag: [16]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_tag, expected_hex);

    if (!std.mem.eql(u8, &tag, &expected_tag)) {
        std.debug.print("MISMATCH for data len {}\n", .{data.len});
        std.debug.print("Expected: {s}\n", .{expected_hex});
        std.debug.print("Got:      ", .{});
        for (tag) |b| {
            std.debug.print("{x:0>2}", .{b});
        }
        std.debug.print("\n", .{});
        return error.TagMismatch;
    }
}

test "reference compatibility tests" {
    const key1 = [32]u8{
        0x3A, 0x7F, 0xC2, 0x1D, 0x55, 0x9B, 0xE0, 0x4C,
        0x8A, 0x2E, 0x73, 0x6D, 0xF1, 0x90, 0x12, 0x38,
        0xA4, 0xB6, 0x05, 0xE9, 0xD7, 0x30, 0x19, 0xCB,
        0x84, 0xFE, 0x6A, 0x41, 0x97, 0x20, 0xDA, 0x11,
    };

    try expectTag(key1, "Hello World!", "8b4e6c3ba3ca72e64c29402a382ae611");
    try expectTag(key1, "", "a4b605e9d73019cb84fe6a419720da11");
    try expectTag(key1, &[_]u8{0x42}, "b9bda957e7919c7d79884bec4270e011");

    const data4 = [_]u8{0xAA} ** 14;
    try expectTag(key1, &data4, "ea7e7b6ed4f9decfb388a76aec97da11");

    const data5 = [_]u8{0xBB} ** 15;
    try expectTag(key1, &data5, "aaedd02acf33a866dfca83012468db11");

    const data6 = [_]u8{0xCC} ** 28;
    try expectTag(key1, &data6, "1503cea2b6673406135a97f2842ae711");

    const data7 = [_]u8{0xDD} ** 56;
    try expectTag(key1, &data7, "e162ac436bd9efd55620212d8f51e611");

    const data8 = [_]u8{0xEE} ** 57;
    try expectTag(key1, &data8, "39e980628d1ad4c23a359ff810dce911");

    var data9: [100]u8 = undefined;
    for (0..100) |i| {
        data9[i] = @as(u8, @intCast(i));
    }
    try expectTag(key1, &data9, "ef62449a7573c1e9fb367552d875da11");

    const key2 = [_]u8{0} ** 32;
    try expectTag(key2, "Hello World!", "00000000000000000000000000000000");

    const key3 = [_]u8{0x42} ** 32;
    try expectTag(key3, "Hello World!", "6a22576dc4ef8f229bd27b1a57574742");

    var data12: [1024]u8 = undefined;
    for (0..1024) |i| {
        data12[i] = @as(u8, @intCast(i & 0xFF));
    }
    try expectTag(key1, &data12, "fd0ab9dc05662e55e59303845a10e311");
}

test "incremental update matches single update" {
    const key = [32]u8{
        0x3A, 0x7F, 0xC2, 0x1D, 0x55, 0x9B, 0xE0, 0x4C,
        0x8A, 0x2E, 0x73, 0x6D, 0xF1, 0x90, 0x12, 0x38,
        0xA4, 0xB6, 0x05, 0xE9, 0xD7, 0x30, 0x19, 0xCB,
        0x84, 0xFE, 0x6A, 0x41, 0x97, 0x20, 0xDA, 0x11,
    };

    var data: [1024]u8 = undefined;
    for (0..1024) |i| {
        data[i] = @as(u8, @intCast(i & 0xFF));
    }

    const tag1 = authenticate(key, &data);

    var poly = Poly1163.init(key);
    poly.update(data[0..100]);
    poly.update(data[100..500]);
    poly.update(data[500..1024]);
    const tag2 = poly.final();

    try std.testing.expectEqualSlices(u8, &tag1, &tag2);
}
