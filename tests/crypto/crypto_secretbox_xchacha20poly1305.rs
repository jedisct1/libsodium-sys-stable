// secretbox_xchacha20poly1305.h

use libsodium_sys::*;

#[test]
fn test_crypto_secretbox_xchacha20poly1305_keybytes() {
    assert_eq!(
        unsafe { crypto_secretbox_xchacha20poly1305_keybytes() } as usize,
        crypto_secretbox_xchacha20poly1305_KEYBYTES as usize
    );
}

#[test]
fn test_crypto_secretbox_xchacha20poly1305_macbytes() {
    assert_eq!(
        unsafe { crypto_secretbox_xchacha20poly1305_macbytes() } as usize,
        crypto_secretbox_xchacha20poly1305_MACBYTES as usize
    );
}

#[test]
fn test_crypto_secretbox_xchacha20poly1305_noncebytes() {
    assert_eq!(
        unsafe { crypto_secretbox_xchacha20poly1305_noncebytes() } as usize,
        crypto_secretbox_xchacha20poly1305_NONCEBYTES as usize
    );
}
