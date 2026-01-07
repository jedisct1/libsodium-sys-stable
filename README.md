# libsodium-sys

A patched version of the `libsodium-sys` crate that installs stable
versions of libsodium instead of point releases.

## Cargo Features

- `fetch-latest`: Download the latest stable version of libsodium
- `optimized`: Build a version optimized for the current platform
- `minimal`: Do not build deprecated APIs
- `use-pkg-config`: Force the use of pkg-config to find libsodium
- `wasi-component`: Build as a WASI component exposing libsodium functions
- `wasmer-wai`: Build with WAI (WebAssembly Interfaces) support for Wasmer runtime

## Build Configuration

The build process can be controlled through several environment variables:

### Using an Existing libsodium Installation

- **`SODIUM_LIB_DIR`**: Path to a directory containing a pre-built libsodium library. When set, the build will use this library instead of building from source.
- **`SODIUM_SHARED`**: When set (any value), links dynamically to libsodium instead of statically. Only works with `SODIUM_LIB_DIR`.
- **`SODIUM_USE_PKG_CONFIG`**: When set (any value), uses pkg-config to find libsodium. Incompatible with `SODIUM_LIB_DIR`.

### Building from Source

When building libsodium from source, these variables apply:

- **`SODIUM_DIST_DIR`**: Path to a local directory containing libsodium distribution archives (`.tar.gz` files with `.minisig` signatures). Useful for offline builds or using specific versions.
- **`SODIUM_DISABLE_PIE`**: When set (any value), disables Position Independent Executable during compilation.
- **`SODIUM_LDFLAGS`**: Additional linker flags to pass when building libsodium.
- **`NUM_JOBS`**: Number of parallel jobs to use during compilation (passed to `make -j`).

### Platform-Specific Notes

#### Windows
On Windows, if libsodium is not found via environment variables or pkg-config, pre-compiled binaries are automatically downloaded for:
- MSVC targets: `i686-pc-windows-msvc`, `x86_64-pc-windows-msvc`, `aarch64-pc-windows-msvc`
- MinGW targets: `i686-pc-windows-gnu`, `x86_64-pc-windows-gnu`

#### WebAssembly/WASI
Compiling to WebAssembly/WASI targets requires the Zig compiler to be installed. The build automatically configures the appropriate flags for WASI compilation.

#### iOS
iOS builds are supported for multiple architectures:
- `aarch64-apple-ios`: ARM64 iOS devices
- `armv7-apple-ios`: ARMv7 iOS devices
- `armv7s-apple-ios`: ARMv7s iOS devices
- `x86_64-apple-ios`: x86_64 iOS simulator
- `aarch64-apple-ios-sim`: ARM64 iOS simulator

The build automatically detects Xcode paths and configures the appropriate SDK and deployment targets.

#### Cross-Compilation
For cross-compilation to non-WebAssembly targets, consider using `cargo zigbuild` which handles C dependencies more easily.

### WASI Component Model

The `wasi-component` feature enables building libsodium as a WASI component. This provides a high-level, type-safe interface for WebAssembly hosts.

**Requirements:**
- Rust 1.82 or later (for native `wasm32-wasip2` target support)
- Zig compiler (for building libsodium C code)

**Build command:**
```bash
cargo build --target wasm32-wasip2 --features wasi-component
```

The WIT interface is defined in `wit/libsodium.wit` (package `libsodium:crypto@1.0.21`) and exposes the same comprehensive API as the WAI interface, organized into separate interfaces for each cryptographic primitive.

### Wasmer WAI Support

The `wasmer-wai` feature enables building libsodium with WAI (WebAssembly Interfaces) support for the Wasmer runtime with WASIX. This provides an alternative interface format for Wasmer's ecosystem.

**Requirements:**
- Zig compiler (for building libsodium C code)

**Build command:**
```bash
cargo build --target wasm32-wasip1 --features wasmer-wai
```

The WAI interface is defined in `wai/libsodium.wai` and exposes nearly all of libsodium's functionality:

**Core:**
- Library initialization and version info
- Random number generation (including deterministic)

**Symmetric encryption:**
- Secretbox (XSalsa20-Poly1305, XChaCha20-Poly1305)
- AEAD (XChaCha20-Poly1305, ChaCha20-Poly1305-IETF, AEGIS-128L, AEGIS-256, AES-256-GCM)
- Stream ciphers (Salsa20, XSalsa20, ChaCha20, XChaCha20)
- Secret stream (chunked streaming encryption)

**Public-key cryptography:**
- Box (X25519-XSalsa20-Poly1305, X25519-XChaCha20-Poly1305)
- Sealed boxes (anonymous encryption)
- Digital signatures (Ed25519, Ed25519ph)
- Key exchange (X25519)

**Hashing and authentication:**
- Generic hashing (BLAKE2b, streaming)
- SHA-256, SHA-512 (one-shot and streaming)
- Short-input hashing (SipHash)
- HMAC (SHA-256, SHA-512, SHA-512-256)
- One-time authentication (Poly1305)
- XOF (SHAKE128, SHAKE256, TurboSHAKE128, TurboSHAKE256)

**Key derivation:**
- KDF (BLAKE2b-based)
- HKDF (SHA-256, SHA-512)
- Password hashing (Argon2, scrypt)

**Low-level primitives:**
- Scalar multiplication (Curve25519, Ed25519, Ristretto255)
- Ristretto255 and Ed25519 group operations
- Constant-time comparison

**Utilities:**
- Hex and Base64 encoding/decoding
- IP address encryption (ipcrypt)

## Build Priority

The build system searches for libsodium in the following order:

1. If `SODIUM_LIB_DIR` is set, use the specified library directory
2. If `SODIUM_USE_PKG_CONFIG` is set or the `use-pkg-config` feature is enabled, try pkg-config
3. If on Windows and vcpkg is available, try vcpkg
4. Build from source (downloading if needed, unless archives are in `SODIUM_DIST_DIR`)
5. On Windows MSVC/MinGW targets only: download pre-compiled binaries

## Security

All downloaded archives are verified using minisign signatures to ensure authenticity.
