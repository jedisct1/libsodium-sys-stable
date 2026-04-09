// crypto_kem_xwing.h

use libsodium_sys::*;

#[test]
fn test_crypto_kem_xwing_publickeybytes() {
    assert!(
        unsafe { crypto_kem_xwing_publickeybytes() } == crypto_kem_xwing_PUBLICKEYBYTES as usize
    )
}

#[test]
fn test_crypto_kem_xwing_secretkeybytes() {
    assert!(
        unsafe { crypto_kem_xwing_secretkeybytes() } == crypto_kem_xwing_SECRETKEYBYTES as usize
    )
}

#[test]
fn test_crypto_kem_xwing_ciphertextbytes() {
    assert!(
        unsafe { crypto_kem_xwing_ciphertextbytes() } == crypto_kem_xwing_CIPHERTEXTBYTES as usize
    )
}

#[test]
fn test_crypto_kem_xwing_sharedsecretbytes() {
    assert!(
        unsafe { crypto_kem_xwing_sharedsecretbytes() }
            == crypto_kem_xwing_SHAREDSECRETBYTES as usize
    )
}

#[test]
fn test_crypto_kem_xwing_seedbytes() {
    assert!(unsafe { crypto_kem_xwing_seedbytes() } == crypto_kem_xwing_SEEDBYTES as usize)
}
