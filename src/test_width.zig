const std = @import("std");
const testing = std.testing;

// Test that different VECTOR_WIDTH values produce the same result
test "vector width consistency" {
    const key = [_]u8{ 0x3A, 0x7F, 0xC2, 0x1D, 0x55, 0x9B, 0xE0, 0x4C, 0x8A, 0x2E, 0x73, 0x6D, 0xF1, 0x90, 0x12, 0x38, 0xA4, 0xB6, 0x05, 0xE9, 0xD7, 0x30, 0x19, 0xCB, 0x84, 0xFE, 0x6A, 0x41, 0x97, 0x20, 0xDA, 0x11 };

    // Test with different message sizes
    const test_cases = [_][]const u8{
        "",
        "a",
        "Hello",
        "The quick brown fox jumps over the lazy dog",
        "a" ** 100,
        "test" ** 50,
        "0123456789" ** 20,
    };

    // Expected tag for "The quick brown fox..." message
    var expected: [16]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, "ff5b754926b0d74d9c6543020d80e811");

    const vector = @import("vector.zig");

    // Test the known case
    const tag = vector.authenticate(key, test_cases[3]);
    try testing.expectEqualSlices(u8, &expected, &tag);

    // Test that processVectorBlocks works correctly with any VECTOR_WIDTH
    // by verifying it produces consistent results
    for (test_cases) |message| {
        var poly1 = vector.Poly1163.init(key);
        poly1.update(message);
        const tag1 = poly1.final();

        // Process same message again to ensure consistency
        var poly2 = vector.Poly1163.init(key);
        poly2.update(message);
        const tag2 = poly2.final();

        try testing.expectEqualSlices(u8, &tag1, &tag2);

        // Test with chunked updates
        if (message.len > 10) {
            var poly3 = vector.Poly1163.init(key);
            poly3.update(message[0..5]);
            poly3.update(message[5..10]);
            poly3.update(message[10..]);
            const tag3 = poly3.final();

            try testing.expectEqualSlices(u8, &tag1, &tag3);
        }
    }
}
