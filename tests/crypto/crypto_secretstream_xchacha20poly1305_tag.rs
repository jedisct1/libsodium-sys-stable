// secretstream_xchacha20poly1305_tag.h

use libsodium_sys::*;

#[test]
fn test_crypto_secretstream_xchacha20poly1305_tag_final() {
    assert_eq!(
        unsafe { crypto_secretstream_xchacha20poly1305_tag_final() } as usize,
        crypto_secretstream_xchacha20poly1305_TAG_FINAL as usize
    );
}

#[test]
fn test_crypto_secretstream_xchacha20poly1305_tag_message() {
    assert_eq!(
        unsafe { crypto_secretstream_xchacha20poly1305_tag_message() } as usize,
        crypto_secretstream_xchacha20poly1305_TAG_MESSAGE as usize
    );
}

#[test]
fn test_crypto_secretstream_xchacha20poly1305_tag_push() {
    assert_eq!(
        unsafe { crypto_secretstream_xchacha20poly1305_tag_push() } as usize,
        crypto_secretstream_xchacha20poly1305_TAG_PUSH as usize
    );
}

#[test]
fn test_crypto_secretstream_xchacha20poly1305_tag_rekey() {
    assert_eq!(
        unsafe { crypto_secretstream_xchacha20poly1305_tag_rekey() } as usize,
        crypto_secretstream_xchacha20poly1305_TAG_REKEY as usize
    );
}
