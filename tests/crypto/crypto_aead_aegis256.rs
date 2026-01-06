// aead_aegis256.h

use libsodium_sys::*;

#[test]
fn test_crypto_aead_aegis256_abytes() {
    assert_eq!(
        unsafe { crypto_aead_aegis256_abytes() } as usize,
        crypto_aead_aegis256_ABYTES as usize
    );
}

#[test]
fn test_crypto_aead_aegis256_keybytes() {
    assert_eq!(
        unsafe { crypto_aead_aegis256_keybytes() } as usize,
        crypto_aead_aegis256_KEYBYTES as usize
    );
}

#[test]
fn test_crypto_aead_aegis256_npubbytes() {
    assert_eq!(
        unsafe { crypto_aead_aegis256_npubbytes() } as usize,
        crypto_aead_aegis256_NPUBBYTES as usize
    );
}

#[test]
fn test_crypto_aead_aegis256_nsecbytes() {
    assert_eq!(
        unsafe { crypto_aead_aegis256_nsecbytes() } as usize,
        crypto_aead_aegis256_NSECBYTES as usize
    );
}
