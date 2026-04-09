// crypto_hash_sha3512.h

use libsodium_sys::*;

#[test]
fn test_crypto_hash_sha3512_bytes() {
    assert!(unsafe { crypto_hash_sha3512_bytes() } == crypto_hash_sha3512_BYTES as usize)
}
