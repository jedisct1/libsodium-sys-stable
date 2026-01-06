// shorthash_siphashx24.h

use libsodium_sys::*;

#[test]
fn test_crypto_shorthash_siphashx24_bytes() {
    assert_eq!(
        unsafe { crypto_shorthash_siphashx24_bytes() } as usize,
        crypto_shorthash_siphashx24_BYTES as usize
    );
}

#[test]
fn test_crypto_shorthash_siphashx24_keybytes() {
    assert_eq!(
        unsafe { crypto_shorthash_siphashx24_keybytes() } as usize,
        crypto_shorthash_siphashx24_KEYBYTES as usize
    );
}
