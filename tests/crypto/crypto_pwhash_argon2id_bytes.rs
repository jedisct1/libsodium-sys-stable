// pwhash_argon2id_bytes.h

use libsodium_sys::*;

#[test]
fn test_crypto_pwhash_argon2id_bytes_min() {
    assert_eq!(
        unsafe { crypto_pwhash_argon2id_bytes_min() } as usize,
        crypto_pwhash_argon2id_BYTES_MIN as usize
    );
}
