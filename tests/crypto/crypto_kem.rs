// crypto_kem.h

use libsodium_sys::*;
use std::ffi::CStr;

#[test]
fn test_crypto_kem_publickeybytes() {
    assert!(unsafe { crypto_kem_publickeybytes() } == crypto_kem_PUBLICKEYBYTES as usize)
}

#[test]
fn test_crypto_kem_secretkeybytes() {
    assert!(unsafe { crypto_kem_secretkeybytes() } == crypto_kem_SECRETKEYBYTES as usize)
}

#[test]
fn test_crypto_kem_ciphertextbytes() {
    assert!(unsafe { crypto_kem_ciphertextbytes() } == crypto_kem_CIPHERTEXTBYTES as usize)
}

#[test]
fn test_crypto_kem_sharedsecretbytes() {
    assert!(unsafe { crypto_kem_sharedsecretbytes() } == crypto_kem_SHAREDSECRETBYTES as usize)
}

#[test]
fn test_crypto_kem_seedbytes() {
    assert!(unsafe { crypto_kem_seedbytes() } == crypto_kem_SEEDBYTES as usize)
}

#[test]
fn test_crypto_kem_primitive() {
    unsafe {
        let s = crypto_kem_primitive();
        let s = CStr::from_ptr(s);
        let p = CStr::from_bytes_with_nul(crypto_kem_PRIMITIVE).unwrap();
        assert_eq!(s, p);
    }
}
