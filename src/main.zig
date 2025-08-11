const std = @import("std");
const poly1163 = @import("poly1163");
const Poly1163 = poly1163.Poly1163;

pub fn main() !void {
    // Get stdout for writing
    var stdout_buffer: [4096]u8 = undefined;
    const stdout_file = std.fs.File.stdout();
    var stdout_writer = stdout_file.writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    try stdout.print("=== Poly1163 Message Authentication Code Demo ===\n\n", .{});

    // Generate a random key
    var key: [32]u8 = undefined;
    std.crypto.random.bytes(&key);

    try stdout.print("Generated random 256-bit key\n", .{});
    try stdout.print("Key (hex): ", .{});
    for (key) |byte| {
        try stdout.print("{x:0>2}", .{byte});
    }
    try stdout.print("\n\n", .{});

    // Demo 1: Simple message authentication
    {
        const message = "Hello, Poly1163!";
        try stdout.print("Demo 1: Authenticating message: \"{s}\"\n", .{message});

        const tag = poly1163.authenticate(key, message);

        try stdout.print("Authentication tag (hex): ", .{});
        for (tag) |byte| {
            try stdout.print("{x:0>2}", .{byte});
        }
        try stdout.print("\n\n", .{});
    }

    // Demo 2: Incremental processing
    {
        try stdout.print("Demo 2: Incremental message processing\n", .{});
        const part1 = "This is ";
        const part2 = "a message ";
        const part3 = "in three parts!";

        var poly = Poly1163.init(key);
        poly.update(part1);
        poly.update(part2);
        poly.update(part3);
        const tag = poly.final();

        try stdout.print("Message parts: \"{s}\", \"{s}\", \"{s}\"\n", .{ part1, part2, part3 });
        try stdout.print("Final tag (hex): ", .{});
        for (tag) |byte| {
            try stdout.print("{x:0>2}", .{byte});
        }
        try stdout.print("\n\n", .{});
    }

    // Demo 3: Tag verification
    {
        try stdout.print("Demo 3: Tag verification\n", .{});
        const message = "Verify this message";

        // Generate correct tag
        var poly = Poly1163.init(key);
        poly.update(message);
        const correct_tag = poly.final();

        // Verify correct tag
        var poly2 = Poly1163.init(key);
        poly2.update(message);
        const is_valid = poly2.verify(correct_tag);
        try stdout.print("Correct tag verification: {}\n", .{is_valid});

        // Try to verify with tampered tag
        var tampered_tag = correct_tag;
        tampered_tag[0] ^= 0x01;
        var poly3 = Poly1163.init(key);
        poly3.update(message);
        const is_invalid = poly3.verify(tampered_tag);
        try stdout.print("Tampered tag verification: {}\n\n", .{is_invalid});
    }

    // Demo 4: Performance benchmark
    {
        try stdout.print("Demo 4: Performance benchmark\n", .{});
        const iterations = 10000;
        const test_message = "Performance test message with some data to process";

        const start = std.time.nanoTimestamp();

        var i: usize = 0;
        while (i < iterations) : (i += 1) {
            _ = poly1163.authenticate(key, test_message);
        }

        const end = std.time.nanoTimestamp();
        const elapsed_ns = @as(u64, @intCast(end - start));
        const elapsed_ms = @as(f64, @floatFromInt(elapsed_ns)) / 1_000_000.0;
        const ops_per_sec = @as(f64, @floatFromInt(iterations)) / (elapsed_ms / 1000.0);

        try stdout.print("Processed {} messages in {d:.2} ms\n", .{ iterations, elapsed_ms });
        try stdout.print("Throughput: {d:.0} operations/second\n", .{ops_per_sec});
        try stdout.print("Average time per operation: {d:.3} microseconds\n\n", .{elapsed_ms * 1000.0 / @as(f64, @floatFromInt(iterations))});
    }

    // Demo 5: Different message sizes
    {
        try stdout.print("Demo 5: Testing different message sizes\n", .{});

        // Empty message
        const empty_tag = poly1163.authenticate(key, "");
        try stdout.print("Empty message tag: ", .{});
        for (empty_tag[0..8]) |byte| {
            try stdout.print("{x:0>2}", .{byte});
        }
        try stdout.print("...\n", .{});

        // Single block (16 bytes)
        const single_block = "Exactly16bytes!!";
        const single_tag = poly1163.authenticate(key, single_block);
        try stdout.print("16-byte message tag: ", .{});
        for (single_tag[0..8]) |byte| {
            try stdout.print("{x:0>2}", .{byte});
        }
        try stdout.print("...\n", .{});

        // Multiple blocks
        const multi_block = "This message is longer than 16 bytes and will span multiple blocks";
        const multi_tag = poly1163.authenticate(key, multi_block);
        try stdout.print("{}-byte message tag: ", .{multi_block.len});
        for (multi_tag[0..8]) |byte| {
            try stdout.print("{x:0>2}", .{byte});
        }
        try stdout.print("...\n\n", .{});
    }

    try stdout.print("=== Demo Complete ===\n", .{});
    try stdout.flush();
}

test "simple test" {
    var list = std.ArrayList(i32).init(std.testing.allocator);
    defer list.deinit();
    try list.append(42);
    try std.testing.expectEqual(@as(i32, 42), list.pop());
}
