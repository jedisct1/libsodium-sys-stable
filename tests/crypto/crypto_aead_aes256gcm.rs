// aead_aes256gcm.h

use libsodium_sys::*;

#[test]
fn test_crypto_aead_aes256gcm_abytes() {
    assert_eq!(
        unsafe { crypto_aead_aes256gcm_abytes() } as usize,
        crypto_aead_aes256gcm_ABYTES as usize
    );
}

#[test]
fn test_crypto_aead_aes256gcm_keybytes() {
    assert_eq!(
        unsafe { crypto_aead_aes256gcm_keybytes() } as usize,
        crypto_aead_aes256gcm_KEYBYTES as usize
    );
}

#[test]
fn test_crypto_aead_aes256gcm_npubbytes() {
    assert_eq!(
        unsafe { crypto_aead_aes256gcm_npubbytes() } as usize,
        crypto_aead_aes256gcm_NPUBBYTES as usize
    );
}

#[test]
fn test_crypto_aead_aes256gcm_nsecbytes() {
    assert_eq!(
        unsafe { crypto_aead_aes256gcm_nsecbytes() } as usize,
        crypto_aead_aes256gcm_NSECBYTES as usize
    );
}
