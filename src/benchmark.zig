const std = @import("std");
const Poly1163 = @import("root.zig").Poly1163;
const Poly1305 = std.crypto.onetimeauth.Poly1305;

const KB = 1024;
const MB = 1024 * KB;

const BenchmarkConfig = struct {
    name: []const u8,
    data_size: usize,
    iterations: u32,
};

const configs = [_]BenchmarkConfig{
    .{ .name = "16 bytes", .data_size = 16, .iterations = 1_000_000 },
    .{ .name = "64 bytes", .data_size = 64, .iterations = 1_000_000 },
    .{ .name = "256 bytes", .data_size = 256, .iterations = 500_000 },
    .{ .name = "1 KB", .data_size = KB, .iterations = 200_000 },
    .{ .name = "4 KB", .data_size = 4 * KB, .iterations = 50_000 },
    .{ .name = "16 KB", .data_size = 16 * KB, .iterations = 15_000 },
    .{ .name = "64 KB", .data_size = 64 * KB, .iterations = 4_000 },
    .{ .name = "256 KB", .data_size = 256 * KB, .iterations = 1_000 },
    .{ .name = "1 MB", .data_size = MB, .iterations = 250 },
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const stdout = std.fs.File.stdout().deprecatedWriter();

    try stdout.print("\n=== Poly1163 vs Poly1305 Performance Comparison ===\n", .{});
    try stdout.print("Build mode: ReleaseFast\n\n", .{});

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

    try stdout.print("{s:<12} | {s:>14} | {s:>14} | {s:>12} | {s:>12} | {s:>8}\n", .{
        "Size", "Poly1163 (ns)", "Poly1305 (ns)", "1163 MB/s", "1305 MB/s", "Speedup",
    });
    try stdout.print("{s:-<12}-+-{s:->14}-+-{s:->14}-+-{s:->12}-+-{s:->12}-+-{s:->8}\n", .{ "", "", "", "", "", "" });

    for (configs) |config| {
        const data = try allocator.alloc(u8, config.data_size);
        defer allocator.free(data);
        random.bytes(data);

        const poly1163_ns = try benchmarkPoly1163(key_1163, data, config.iterations);
        const poly1305_ns = try benchmarkPoly1305(key_1305, data, config.iterations);

        const poly1163_mbps = calculateThroughput(config.data_size, poly1163_ns);
        const poly1305_mbps = calculateThroughput(config.data_size, poly1305_ns);

        const speedup = @as(f64, @floatFromInt(poly1305_ns)) / @as(f64, @floatFromInt(poly1163_ns));

        try stdout.print("{s:<12} | {d:>14.1} | {d:>14.1} | {d:>12.1} | {d:>12.1} | {d:>7.2}x\n", .{
            config.name,   @as(f64, @floatFromInt(poly1163_ns)), @as(f64, @floatFromInt(poly1305_ns)),
            poly1163_mbps, poly1305_mbps,                        speedup,
        });
    }

    try stdout.print("\nNote: Poly1163 uses optimized 2^116-3 polynomial with SIMD processing\n", .{});
    try stdout.print("Speedup > 1 means Poly1163 is faster than Poly1305\n", .{});
}

fn benchmarkPoly1163(key: [32]u8, data: []const u8, iterations: u32) !u64 {
    var timer = try std.time.Timer.start();

    var i: u32 = 0;
    while (i < iterations) : (i += 1) {
        var poly = Poly1163.init(key);
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
