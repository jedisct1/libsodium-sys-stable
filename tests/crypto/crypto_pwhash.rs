// pwhash.h

use libsodium_sys::*;

#[test]
fn test_crypto_pwhash_saltbytes() {
    assert_eq!(
        unsafe { crypto_pwhash_saltbytes() } as usize,
        crypto_pwhash_SALTBYTES as usize
    );
}

#[test]
fn test_crypto_pwhash_strbytes() {
    assert_eq!(
        unsafe { crypto_pwhash_strbytes() } as usize,
        crypto_pwhash_STRBYTES as usize
    );
}
