// core_ed25519.h

use libsodium_sys::*;

#[test]
fn test_crypto_core_ed25519_bytes() {
    assert_eq!(
        unsafe { crypto_core_ed25519_bytes() } as usize,
        crypto_core_ed25519_BYTES as usize
    );
}

#[test]
fn test_crypto_core_ed25519_hashbytes() {
    assert_eq!(
        unsafe { crypto_core_ed25519_hashbytes() } as usize,
        crypto_core_ed25519_HASHBYTES as usize
    );
}

#[test]
fn test_crypto_core_ed25519_nonreducedscalarbytes() {
    assert_eq!(
        unsafe { crypto_core_ed25519_nonreducedscalarbytes() } as usize,
        crypto_core_ed25519_NONREDUCEDSCALARBYTES as usize
    );
}

#[test]
fn test_crypto_core_ed25519_scalarbytes() {
    assert_eq!(
        unsafe { crypto_core_ed25519_scalarbytes() } as usize,
        crypto_core_ed25519_SCALARBYTES as usize
    );
}

#[test]
fn test_crypto_core_ed25519_uniformbytes() {
    assert_eq!(
        unsafe { crypto_core_ed25519_uniformbytes() } as usize,
        crypto_core_ed25519_UNIFORMBYTES as usize
    );
}
