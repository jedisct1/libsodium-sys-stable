// crypto_aead_xchacha20poly1305.h

use libsodium_sys::*;

#[test]
fn test_crypto_aead_xchacha20poly1305_ietf_keybytes() {
    assert_eq!(
        unsafe { crypto_aead_xchacha20poly1305_ietf_keybytes() } as usize,
        crypto_aead_xchacha20poly1305_ietf_KEYBYTES as usize
    );
}

#[test]
fn test_crypto_aead_xchacha20poly1305_ietf_nsecbytes() {
    assert_eq!(
        unsafe { crypto_aead_xchacha20poly1305_ietf_nsecbytes() } as usize,
        crypto_aead_xchacha20poly1305_ietf_NSECBYTES as usize
    );
}

#[test]
fn test_crypto_aead_xchacha20poly1305_ietf_npubbytes() {
    assert_eq!(
        unsafe { crypto_aead_xchacha20poly1305_ietf_npubbytes() } as usize,
        crypto_aead_xchacha20poly1305_ietf_NPUBBYTES as usize
    );
}

#[test]
fn test_crypto_aead_xchacha20poly1305_ietf_abytes() {
    assert_eq!(
        unsafe { crypto_aead_xchacha20poly1305_ietf_abytes() } as usize,
        crypto_aead_xchacha20poly1305_ietf_ABYTES as usize
    );
}
