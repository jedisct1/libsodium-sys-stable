// core_ristretto255.h

use libsodium_sys::*;

#[test]
fn test_crypto_core_ristretto255_bytes() {
    assert_eq!(
        unsafe { crypto_core_ristretto255_bytes() } as usize,
        crypto_core_ristretto255_BYTES as usize
    );
}

#[test]
fn test_crypto_core_ristretto255_hashbytes() {
    assert_eq!(
        unsafe { crypto_core_ristretto255_hashbytes() } as usize,
        crypto_core_ristretto255_HASHBYTES as usize
    );
}

#[test]
fn test_crypto_core_ristretto255_nonreducedscalarbytes() {
    assert_eq!(
        unsafe { crypto_core_ristretto255_nonreducedscalarbytes() } as usize,
        crypto_core_ristretto255_NONREDUCEDSCALARBYTES as usize
    );
}

#[test]
fn test_crypto_core_ristretto255_scalarbytes() {
    assert_eq!(
        unsafe { crypto_core_ristretto255_scalarbytes() } as usize,
        crypto_core_ristretto255_SCALARBYTES as usize
    );
}
