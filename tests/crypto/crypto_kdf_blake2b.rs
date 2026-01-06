// kdf_blake2b.h

use libsodium_sys::*;

#[test]
fn test_crypto_kdf_blake2b_contextbytes() {
    assert_eq!(
        unsafe { crypto_kdf_blake2b_contextbytes() } as usize,
        crypto_kdf_blake2b_CONTEXTBYTES as usize
    );
}

#[test]
fn test_crypto_kdf_blake2b_keybytes() {
    assert_eq!(
        unsafe { crypto_kdf_blake2b_keybytes() } as usize,
        crypto_kdf_blake2b_KEYBYTES as usize
    );
}
