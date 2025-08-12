const std = @import("std");
const poly1163 = @import("root.zig");
const Poly1305 = std.crypto.onetimeauth.Poly1305;

const KB = 1024;
const MB = 1024 * KB;

const BenchmarkConfig = struct {
    name: []const u8,
    data_size: usize,
    iterations: u32,
};

const configs = [_]BenchmarkConfig{
    .{ .name = "16 bytes", .data_size = 16, .iterations = 100_000 },
    .{ .name = "64 bytes", .data_size = 64, .iterations = 100_000 },
    .{ .name = "256 bytes", .data_size = 256, .iterations = 50_000 },
    .{ .name = "1 KB", .data_size = KB, .iterations = 20_000 },
    .{ .name = "4 KB", .data_size = 4 * KB, .iterations = 5_000 },
    .{ .name = "16 KB", .data_size = 16 * KB, .iterations = 1_500 },
    .{ .name = "64 KB", .data_size = 64 * KB, .iterations = 400 },
    .{ .name = "256 KB", .data_size = 256 * KB, .iterations = 100 },
    .{ .name = "1 MB", .data_size = MB, .iterations = 25 },
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const stdout = std.fs.File.stdout().deprecatedWriter();

    try stdout.print("\n=== Poly1163 vs Poly1305 Performance Comparison ===\n", .{});
    try stdout.print("Build mode: ReleaseFast\n", .{});
    try stdout.print("\n", .{});

    var prng = std.Random.DefaultPrng.init(0x12345678);
    const random = prng.random();

    const key_1163 = blk: {
        var key: [32]u8 = undefined;
        random.bytes(&key);
        break :blk key;
    };

    const key_1305 = blk: {
        var key: [32]u8 = undefined;
        random.bytes(&key);
        break :blk key;
    };

    try stdout.print("{s:<12} | {s:>12} | {s:>12} | {s:>10}\n", .{
        "Size", "Poly1163", "Poly1305", "vs 1305",
    });
    try stdout.print("{s:-<12}-+-{s:->12}-+-{s:->12}-+-{s:->10}\n", .{ "", "", "", "" });

    for (configs) |config| {
        const data = try allocator.alloc(u8, config.data_size);
        defer allocator.free(data);
        random.bytes(data);

        const poly1163_ns = try benchmarkPoly1163(key_1163, data, config.iterations);
        const poly1305_ns = try benchmarkPoly1305(key_1305, data, config.iterations);

        const vs_1305 = @as(f64, @floatFromInt(poly1305_ns)) / @as(f64, @floatFromInt(poly1163_ns));

        try stdout.print("{s:<12} | {d:>12.1} | {d:>12.1} | {d:>9.2}x\n", .{
            config.name,
            @as(f64, @floatFromInt(poly1163_ns)),
            @as(f64, @floatFromInt(poly1305_ns)),
            vs_1305,
        });
    }

    try stdout.print("\nOptimizations:\n", .{});
    try stdout.print("- Horner's method for parallel block processing\n", .{});
    try stdout.print("- Efficient 58-bit limb arithmetic\n", .{});
}

fn benchmarkPoly1163(key: [32]u8, data: []const u8, iterations: u32) !u64 {
    var timer = try std.time.Timer.start();

    var i: u32 = 0;
    while (i < iterations) : (i += 1) {
        var poly = poly1163.Poly1163.init(key);
        poly.update(data);
        const tag = poly.final();
        std.mem.doNotOptimizeAway(&tag);
    }

    const elapsed = timer.read();
    return elapsed / iterations;
}

fn benchmarkPoly1305(key: [32]u8, data: []const u8, iterations: u32) !u64 {
    var timer = try std.time.Timer.start();

    var i: u32 = 0;
    while (i < iterations) : (i += 1) {
        var tag: [16]u8 = undefined;
        Poly1305.create(&tag, data, &key);
        std.mem.doNotOptimizeAway(&tag);
    }

    const elapsed = timer.read();
    return elapsed / iterations;
}

fn calculateThroughput(data_size: usize, nanoseconds: u64) f64 {
    const seconds = @as(f64, @floatFromInt(nanoseconds)) / 1_000_000_000.0;
    const megabytes = @as(f64, @floatFromInt(data_size)) / (1024.0 * 1024.0);
    return megabytes / seconds;
}
