const std = @import("std");
const root = @import("root.zig");

pub fn main() !void {
    var stdout = std.fs.File.stdout().writer(&[_]u8{}).interface;

    try stdout.print("=== Poly1163 Test Vectors ===\n\n", .{});

    // Test 1: Empty message
    {
        const key = [_]u8{0} ** 32;
        const data = "";

        var poly = root.Poly1163.init(key);
        poly.update(data);
        const tag = poly.final();

        try stdout.print("Test 1: Empty message\n", .{});
        try stdout.print("Key: all zeros\n", .{});
        try stdout.print("Data: empty\n", .{});
        try stdout.print("Tag: ", .{});
        for (tag) |byte| {
            try stdout.print("{x:0>2}", .{byte});
        }
        try stdout.print("\n\n", .{});
    }

    // Test 2: Single block
    {
        const key = [_]u8{1} ** 32;
        const data = "Hello World!";

        var poly = root.Poly1163.init(key);
        poly.update(data);
        const tag = poly.final();

        try stdout.print("Test 2: Single block\n", .{});
        try stdout.print("Key: all 0x01\n", .{});
        try stdout.print("Data: {s} (len={})\n", .{ data, data.len });
        try stdout.print("Tag: ", .{});
        for (tag) |byte| {
            try stdout.print("{x:0>2}", .{byte});
        }
        try stdout.print("\n\n", .{});
    }

    // Test 3: Multiple blocks
    {
        const key = [_]u8{0xFF} ** 32;
        const data = "The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog.";

        var poly = root.Poly1163.init(key);
        poly.update(data);
        const tag = poly.final();

        try stdout.print("Test 3: Multiple blocks\n", .{});
        try stdout.print("Key: all 0xFF\n", .{});
        try stdout.print("Data: {s} (len={})\n", .{ data, data.len });
        try stdout.print("Tag: ", .{});
        for (tag) |byte| {
            try stdout.print("{x:0>2}", .{byte});
        }
        try stdout.print("\n\n", .{});
    }

    // Test 4: Incremental update
    {
        const key = [_]u8{0x42} ** 32;
        const part1 = "Hello ";
        const part2 = "World";
        const part3 = "!";

        var poly = root.Poly1163.init(key);
        poly.update(part1);
        poly.update(part2);
        poly.update(part3);
        const tag = poly.final();

        // Compare with single update
        var poly2 = root.Poly1163.init(key);
        const full_msg = "Hello World!";
        poly2.update(full_msg);
        const tag2 = poly2.final();

        try stdout.print("Test 4: Incremental update\n", .{});
        try stdout.print("Key: all 0x42\n", .{});
        try stdout.print("Data (parts): \"{s}\", \"{s}\", \"{s}\"\n", .{ part1, part2, part3 });
        try stdout.print("Tag (incremental): ", .{});
        for (tag) |byte| {
            try stdout.print("{x:0>2}", .{byte});
        }
        try stdout.print("\n", .{});
        try stdout.print("Tag (single):      ", .{});
        for (tag2) |byte| {
            try stdout.print("{x:0>2}", .{byte});
        }
        try stdout.print("\n", .{});
        try stdout.print("Match: {}\n\n", .{std.mem.eql(u8, &tag, &tag2)});
    }

    // Test 5: Exactly 56 bytes (4 blocks of 14 bytes)
    {
        const key = [_]u8{0xAA} ** 32;
        const data = "1234567890123456789012345678901234567890123456789012345"; // 56 bytes

        var poly = root.Poly1163.init(key);
        poly.update(data);
        const tag = poly.final();

        try stdout.print("Test 5: Exactly 56 bytes (4 blocks)\n", .{});
        try stdout.print("Key: all 0xAA\n", .{});
        try stdout.print("Data: 56 bytes\n", .{});
        try stdout.print("Tag: ", .{});
        for (tag) |byte| {
            try stdout.print("{x:0>2}", .{byte});
        }
        try stdout.print("\n\n", .{});
    }

    try stdout.print("=== Test Vectors Complete ===\n", .{});
}
