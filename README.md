# Poly1163

A high-performance polynomial-based message authentication code (MAC) implementation in Zig, based on polynomial evaluation modulo prime 2^130 - 1163.

## Features

- **Cryptographic MAC**: Provides message authentication using polynomial evaluation
- **Simple API**: Easy-to-use interface for authentication and verification
- **Incremental processing**: Support for streaming large messages
- **Zero dependencies**: Pure Zig implementation using only the standard library

## Algorithm Overview

Poly1163 uses polynomial evaluation over a large prime field (2^130 - 1163) to compute authentication tags:

1. **Key derivation**: 256-bit key split into:
   - `r`: 128-bit polynomial evaluation key (clamped for security)
   - `s`: 128-bit final masking key

2. **Message processing**: Messages are processed in 16-byte blocks, with each block:
   - Converted to a 128-bit integer (little-endian)
   - Added with a high bit set for domain separation
   - Accumulated using polynomial evaluation: `acc = (acc + block) * r mod p`

3. **Finalization**: The accumulator is masked with `s` to produce the final 128-bit tag

## Installation

Add to your `build.zig.zon`:

```zig
.dependencies = .{
    .poly1163 = .{
        .path = "path/to/zig-poly1163",
    },
},
```

## Usage

### Basic Authentication

```zig
const std = @import("std");
const poly1163 = @import("poly1163");

// Generate or load a 256-bit secret key
var key: [32]u8 = undefined;
std.crypto.random.bytes(&key);

// Authenticate a message
const message = "Hello, World!";
const tag = poly1163.authenticate(key, message);

// Tag is a 16-byte authentication code
std.debug.print("Tag: {x}\n", .{std.fmt.fmtSliceHexLower(&tag)});
```

### Incremental Processing

For large messages or streaming data:

```zig
var poly = poly1163.Poly1163.init(key);

// Process data in chunks
poly.update(chunk1);
poly.update(chunk2);
poly.update(chunk3);

// Get the final tag
const tag = poly.final();
```

### Tag Verification

```zig
// Verify a received tag
var poly = poly1163.Poly1163.init(key);
poly.update(message);

if (poly.verify(received_tag)) {
    // Message is authentic
} else {
    // Authentication failed - message may be tampered
}
```

## API Reference

### Types

- `Poly1163`: Main struct for incremental MAC computation
- `KEY_SIZE = 32`: Size of the secret key in bytes
- `TAG_SIZE = 16`: Size of the authentication tag in bytes

### Functions

#### `Poly1163.init(key: [32]u8) Poly1163`
Initialize a new Poly1163 instance with a secret key.

#### `Poly1163.update(self: *Poly1163, data: []const u8) void`
Process message data incrementally. Can be called multiple times.

#### `Poly1163.final(self: *Poly1163) [16]u8`
Finalize and return the authentication tag.

#### `Poly1163.verify(self: *Poly1163, expected_tag: [16]u8) bool`
Verify an authentication tag against the expected value.

#### `authenticate(key: [32]u8, message: []const u8) [16]u8`
One-shot function to authenticate a complete message.

## Security Considerations

- **Key management**: Keys must be kept secret and generated using a cryptographically secure random number generator
- **Tag truncation**: Never truncate tags; always use the full 16 bytes
- **Nonce/sequence numbers**: For protection against replay attacks, include a nonce or sequence number in the authenticated message
- **Not encryption**: Poly1163 provides authentication only, not confidentiality. Combine with encryption for full protection

## Building and Testing

### Build the project
```bash
zig build
```

### Run tests
```bash
zig build test
```

### Run demo
```bash
zig build run
```

## Implementation Details

- **Prime modulus**: 2^130 - 1163 (chosen for efficient reduction)
- **Block size**: 16 bytes (128 bits)
- **Key clamping**: Specific bits cleared in `r` to ensure uniform distribution and prevent weak keys
- **Padding**: Each block includes a high bit to prevent extension attacks
- **Arithmetic**: Uses Barrett reduction for efficient modular multiplication
