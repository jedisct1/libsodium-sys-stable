// pwhash_argon2id.h

use libsodium_sys::*;

#[test]
fn test_crypto_pwhash_argon2id_saltbytes() {
    assert_eq!(
        unsafe { crypto_pwhash_argon2id_saltbytes() } as usize,
        crypto_pwhash_argon2id_SALTBYTES as usize
    );
}

#[test]
fn test_crypto_pwhash_argon2id_strbytes() {
    assert_eq!(
        unsafe { crypto_pwhash_argon2id_strbytes() } as usize,
        crypto_pwhash_argon2id_STRBYTES as usize
    );
}
