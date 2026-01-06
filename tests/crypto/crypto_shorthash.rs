// shorthash.h

use libsodium_sys::*;

#[test]
fn test_crypto_shorthash_bytes() {
    assert_eq!(
        unsafe { crypto_shorthash_bytes() } as usize,
        crypto_shorthash_BYTES as usize
    );
}

#[test]
fn test_crypto_shorthash_keybytes() {
    assert_eq!(
        unsafe { crypto_shorthash_keybytes() } as usize,
        crypto_shorthash_KEYBYTES as usize
    );
}
