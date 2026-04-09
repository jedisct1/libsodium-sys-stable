// crypto_kem_mlkem768.h

use libsodium_sys::*;

#[test]
fn test_crypto_kem_mlkem768_publickeybytes() {
    assert!(
        unsafe { crypto_kem_mlkem768_publickeybytes() }
            == crypto_kem_mlkem768_PUBLICKEYBYTES as usize
    )
}

#[test]
fn test_crypto_kem_mlkem768_secretkeybytes() {
    assert!(
        unsafe { crypto_kem_mlkem768_secretkeybytes() }
            == crypto_kem_mlkem768_SECRETKEYBYTES as usize
    )
}

#[test]
fn test_crypto_kem_mlkem768_ciphertextbytes() {
    assert!(
        unsafe { crypto_kem_mlkem768_ciphertextbytes() }
            == crypto_kem_mlkem768_CIPHERTEXTBYTES as usize
    )
}

#[test]
fn test_crypto_kem_mlkem768_sharedsecretbytes() {
    assert!(
        unsafe { crypto_kem_mlkem768_sharedsecretbytes() }
            == crypto_kem_mlkem768_SHAREDSECRETBYTES as usize
    )
}

#[test]
fn test_crypto_kem_mlkem768_seedbytes() {
    assert!(unsafe { crypto_kem_mlkem768_seedbytes() } == crypto_kem_mlkem768_SEEDBYTES as usize)
}
