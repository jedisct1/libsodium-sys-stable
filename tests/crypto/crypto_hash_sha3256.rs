// crypto_hash_sha3256.h

use libsodium_sys::*;

#[test]
fn test_crypto_hash_sha3256_bytes() {
    assert!(unsafe { crypto_hash_sha3256_bytes() } == crypto_hash_sha3256_BYTES as usize)
}
