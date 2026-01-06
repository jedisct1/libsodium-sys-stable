// kdf.h

use libsodium_sys::*;

#[test]
fn test_crypto_kdf_contextbytes() {
    assert_eq!(
        unsafe { crypto_kdf_contextbytes() } as usize,
        crypto_kdf_CONTEXTBYTES as usize
    );
}

#[test]
fn test_crypto_kdf_keybytes() {
    assert_eq!(
        unsafe { crypto_kdf_keybytes() } as usize,
        crypto_kdf_KEYBYTES as usize
    );
}
