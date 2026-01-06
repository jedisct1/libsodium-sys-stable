// kdf_hkdf_sha512.h

use libsodium_sys::*;

#[test]
fn test_crypto_kdf_hkdf_sha512_keybytes() {
    assert_eq!(
        unsafe { crypto_kdf_hkdf_sha512_keybytes() } as usize,
        crypto_kdf_hkdf_sha512_KEYBYTES as usize
    );
}
