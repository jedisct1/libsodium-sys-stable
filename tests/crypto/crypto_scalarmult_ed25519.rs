// scalarmult_ed25519.h

use libsodium_sys::*;

#[test]
fn test_crypto_scalarmult_ed25519_bytes() {
    assert_eq!(
        unsafe { crypto_scalarmult_ed25519_bytes() } as usize,
        crypto_scalarmult_ed25519_BYTES as usize
    );
}

#[test]
fn test_crypto_scalarmult_ed25519_scalarbytes() {
    assert_eq!(
        unsafe { crypto_scalarmult_ed25519_scalarbytes() } as usize,
        crypto_scalarmult_ed25519_SCALARBYTES as usize
    );
}
