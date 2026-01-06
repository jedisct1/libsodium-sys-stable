// sign.h

use libsodium_sys::*;

#[test]
fn test_crypto_sign_bytes() {
    assert_eq!(
        unsafe { crypto_sign_bytes() } as usize,
        crypto_sign_BYTES as usize
    );
}

#[test]
fn test_crypto_sign_publickeybytes() {
    assert_eq!(
        unsafe { crypto_sign_publickeybytes() } as usize,
        crypto_sign_PUBLICKEYBYTES as usize
    );
}

#[test]
fn test_crypto_sign_secretkeybytes() {
    assert_eq!(
        unsafe { crypto_sign_secretkeybytes() } as usize,
        crypto_sign_SECRETKEYBYTES as usize
    );
}

#[test]
fn test_crypto_sign_seedbytes() {
    assert_eq!(
        unsafe { crypto_sign_seedbytes() } as usize,
        crypto_sign_SEEDBYTES as usize
    );
}
