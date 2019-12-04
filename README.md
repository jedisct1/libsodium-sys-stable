> libsodium-sys

A patched version of the `libsodium-sys` crate that installs stable
versions of libsodium instead of point releases.

Cargo features:

- `fetch-latest`: download the latest stable version.
- `optimized`: build a version optimized for the current platform.
- `minimal`: do not build deprecated APIs.
