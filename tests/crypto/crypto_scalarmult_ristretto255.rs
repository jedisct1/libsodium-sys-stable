// scalarmult_ristretto255.h

use libsodium_sys::*;

#[test]
fn test_crypto_scalarmult_ristretto255_bytes() {
    assert_eq!(
        unsafe { crypto_scalarmult_ristretto255_bytes() } as usize,
        crypto_scalarmult_ristretto255_BYTES as usize
    );
}

#[test]
fn test_crypto_scalarmult_ristretto255_scalarbytes() {
    assert_eq!(
        unsafe { crypto_scalarmult_ristretto255_scalarbytes() } as usize,
        crypto_scalarmult_ristretto255_SCALARBYTES as usize
    );
}
