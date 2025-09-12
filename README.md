# libsodium-sys

A patched version of the `libsodium-sys` crate that installs stable
versions of libsodium instead of point releases.

## Cargo Features

- `fetch-latest`: Download the latest stable version of libsodium
- `optimized`: Build a version optimized for the current platform
- `minimal`: Do not build deprecated APIs
- `use-pkg-config`: Force the use of pkg-config to find libsodium

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

## Build Priority

The build system searches for libsodium in the following order:

1. If `SODIUM_LIB_DIR` is set, use the specified library directory
2. If `SODIUM_USE_PKG_CONFIG` is set or the `use-pkg-config` feature is enabled, try pkg-config
3. If on Windows and vcpkg is available, try vcpkg
4. Build from source (downloading if needed, unless archives are in `SODIUM_DIST_DIR`)
5. On Windows MSVC/MinGW targets only: download pre-compiled binaries

## Security

All downloaded archives are verified using minisign signatures to ensure authenticity.
