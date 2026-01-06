// secretstream_xchacha20poly1305.h

use libsodium_sys::*;

#[test]
fn test_crypto_secretstream_xchacha20poly1305_abytes() {
    assert_eq!(
        unsafe { crypto_secretstream_xchacha20poly1305_abytes() } as usize,
        crypto_secretstream_xchacha20poly1305_ABYTES as usize
    );
}

#[test]
fn test_crypto_secretstream_xchacha20poly1305_headerbytes() {
    assert_eq!(
        unsafe { crypto_secretstream_xchacha20poly1305_headerbytes() } as usize,
        crypto_secretstream_xchacha20poly1305_HEADERBYTES as usize
    );
}

#[test]
fn test_crypto_secretstream_xchacha20poly1305_keybytes() {
    assert_eq!(
        unsafe { crypto_secretstream_xchacha20poly1305_keybytes() } as usize,
        crypto_secretstream_xchacha20poly1305_KEYBYTES as usize
    );
}
