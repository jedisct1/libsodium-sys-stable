> libsodium-sys

A patched version of the `libsodium-sys` crate that installs stable
versions of libsodium instead of point releases.

Cargo features:

- `fetch-latest`: download the latest stable version.
- `optimized`: build a version optimized for the current platform.
- `minimal`: do not build deprecated APIs.

On Windows, if a libsodium Visual Studio package is not installed,
pre-compiled binaries are downloaded. Alternatively, they can be fetched
from an arbitrary local directory, whose path is defined in a
`SODIUM_DIST_DIR` environment variable.

Compiling libsodium to WebAssembly/WASI-core requires the Zig compiler
to be installed.
