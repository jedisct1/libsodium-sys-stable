// box_curve25519xchacha20poly1305.h

use libsodium_sys::*;

#[test]
fn test_crypto_box_curve25519xchacha20poly1305_beforenmbytes() {
    assert_eq!(
        unsafe { crypto_box_curve25519xchacha20poly1305_beforenmbytes() } as usize,
        crypto_box_curve25519xchacha20poly1305_BEFORENMBYTES as usize
    );
}

#[test]
fn test_crypto_box_curve25519xchacha20poly1305_macbytes() {
    assert_eq!(
        unsafe { crypto_box_curve25519xchacha20poly1305_macbytes() } as usize,
        crypto_box_curve25519xchacha20poly1305_MACBYTES as usize
    );
}

#[test]
fn test_crypto_box_curve25519xchacha20poly1305_noncebytes() {
    assert_eq!(
        unsafe { crypto_box_curve25519xchacha20poly1305_noncebytes() } as usize,
        crypto_box_curve25519xchacha20poly1305_NONCEBYTES as usize
    );
}

#[test]
fn test_crypto_box_curve25519xchacha20poly1305_publickeybytes() {
    assert_eq!(
        unsafe { crypto_box_curve25519xchacha20poly1305_publickeybytes() } as usize,
        crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES as usize
    );
}

#[test]
fn test_crypto_box_curve25519xchacha20poly1305_sealbytes() {
    assert_eq!(
        unsafe { crypto_box_curve25519xchacha20poly1305_sealbytes() } as usize,
        crypto_box_curve25519xchacha20poly1305_SEALBYTES as usize
    );
}

#[test]
fn test_crypto_box_curve25519xchacha20poly1305_secretkeybytes() {
    assert_eq!(
        unsafe { crypto_box_curve25519xchacha20poly1305_secretkeybytes() } as usize,
        crypto_box_curve25519xchacha20poly1305_SECRETKEYBYTES as usize
    );
}

#[test]
fn test_crypto_box_curve25519xchacha20poly1305_seedbytes() {
    assert_eq!(
        unsafe { crypto_box_curve25519xchacha20poly1305_seedbytes() } as usize,
        crypto_box_curve25519xchacha20poly1305_SEEDBYTES as usize
    );
}
