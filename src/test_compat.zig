const std = @import("std");
const root = @import("root.zig");

pub fn main() !void {
    var stdout = std.fs.File.stdout().writer(&[_]u8{}).interface;

    // Use the same test key as the C example
    const key = [_]u8{ 0x3A, 0x7F, 0xC2, 0x1D, 0x55, 0x9B, 0xE0, 0x4C, 0x8A, 0x2E, 0x73, 0x6D, 0xF1, 0x90, 0x12, 0x38, 0xA4, 0xB6, 0x05, 0xE9, 0xD7, 0x30, 0x19, 0xCB, 0x84, 0xFE, 0x6A, 0x41, 0x97, 0x20, 0xDA, 0x11 };

    const data = "Hello World!";

    try stdout.print("Test Zig Poly1163 Output:\n", .{});

    try stdout.print("Key: ", .{});
    for (key) |byte| {
        try stdout.print("{x:0>2}", .{byte});
    }
    try stdout.print("\n", .{});

    try stdout.print("Data: {s} (len={})\n", .{ data, data.len });
    try stdout.print("Data (hex): ", .{});
    for (data) |byte| {
        try stdout.print("{x:0>2}", .{byte});
    }
    try stdout.print("\n", .{});

    // Compute the tag using Poly1163
    var poly = root.Poly1163.init(key);
    poly.update(data);
    const tag = poly.final();

    try stdout.print("Tag: ", .{});
    for (tag) |byte| {
        try stdout.print("{x:0>2}", .{byte});
    }
    try stdout.print("\n", .{});

    // Also test with the C example's 1024 byte update (even though data is only 12 bytes)
    try stdout.print("\nTest with 1024 byte buffer (matching C example):\n", .{});
    var poly2 = root.Poly1163.init(key);

    // Create a 1024 byte buffer with "Hello World!" at the start and zeros after
    var buf: [1024]u8 = [_]u8{0} ** 1024;
    @memcpy(buf[0..data.len], data);

    poly2.update(&buf);
    const tag2 = poly2.final();

    try stdout.print("Tag (1024 bytes): ", .{});
    for (tag2) |byte| {
        try stdout.print("{x:0>2}", .{byte});
    }
    try stdout.print("\n", .{});
}
