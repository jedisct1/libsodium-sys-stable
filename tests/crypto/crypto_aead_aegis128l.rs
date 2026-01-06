// aead_aegis128l.h

use libsodium_sys::*;

#[test]
fn test_crypto_aead_aegis128l_abytes() {
    assert_eq!(
        unsafe { crypto_aead_aegis128l_abytes() } as usize,
        crypto_aead_aegis128l_ABYTES as usize
    );
}

#[test]
fn test_crypto_aead_aegis128l_keybytes() {
    assert_eq!(
        unsafe { crypto_aead_aegis128l_keybytes() } as usize,
        crypto_aead_aegis128l_KEYBYTES as usize
    );
}

#[test]
fn test_crypto_aead_aegis128l_npubbytes() {
    assert_eq!(
        unsafe { crypto_aead_aegis128l_npubbytes() } as usize,
        crypto_aead_aegis128l_NPUBBYTES as usize
    );
}

#[test]
fn test_crypto_aead_aegis128l_nsecbytes() {
    assert_eq!(
        unsafe { crypto_aead_aegis128l_nsecbytes() } as usize,
        crypto_aead_aegis128l_NSECBYTES as usize
    );
}
