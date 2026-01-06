// kdf_blake2b_bytes.h

use libsodium_sys::*;

#[test]
fn test_crypto_kdf_blake2b_bytes_max() {
    assert_eq!(
        unsafe { crypto_kdf_blake2b_bytes_max() } as usize,
        crypto_kdf_blake2b_BYTES_MAX as usize
    );
}

#[test]
fn test_crypto_kdf_blake2b_bytes_min() {
    assert_eq!(
        unsafe { crypto_kdf_blake2b_bytes_min() } as usize,
        crypto_kdf_blake2b_BYTES_MIN as usize
    );
}
