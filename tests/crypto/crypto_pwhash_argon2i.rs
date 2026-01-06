// pwhash_argon2i.h

use libsodium_sys::*;

#[test]
fn test_crypto_pwhash_argon2i_saltbytes() {
    assert_eq!(
        unsafe { crypto_pwhash_argon2i_saltbytes() } as usize,
        crypto_pwhash_argon2i_SALTBYTES as usize
    );
}

#[test]
fn test_crypto_pwhash_argon2i_strbytes() {
    assert_eq!(
        unsafe { crypto_pwhash_argon2i_strbytes() } as usize,
        crypto_pwhash_argon2i_STRBYTES as usize
    );
}
