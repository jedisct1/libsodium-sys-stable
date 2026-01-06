// crypto_stream_chacha20.h (ietf variant)

use libsodium_sys::*;

#[test]
fn test_crypto_stream_chacha20_ietf_keybytes() {
    assert_eq!(
        unsafe { crypto_stream_chacha20_ietf_keybytes() } as usize,
        crypto_stream_chacha20_ietf_KEYBYTES as usize
    );
}

#[test]
fn test_crypto_stream_chacha20_ietf_noncebytes() {
    assert_eq!(
        unsafe { crypto_stream_chacha20_ietf_noncebytes() } as usize,
        crypto_stream_chacha20_ietf_NONCEBYTES as usize
    );
}
