// pwhash_scryptsalsa208sha256_bytes.h

use libsodium_sys::*;

#[test]
fn test_crypto_pwhash_scryptsalsa208sha256_bytes_min() {
    assert_eq!(
        unsafe { crypto_pwhash_scryptsalsa208sha256_bytes_min() } as usize,
        crypto_pwhash_scryptsalsa208sha256_BYTES_MIN as usize
    );
}
