// kdf_hkdf_sha256.h

use libsodium_sys::*;

#[test]
fn test_crypto_kdf_hkdf_sha256_keybytes() {
    assert_eq!(
        unsafe { crypto_kdf_hkdf_sha256_keybytes() } as usize,
        crypto_kdf_hkdf_sha256_KEYBYTES as usize
    );
}
