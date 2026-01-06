// pwhash_scryptsalsa208sha256_opslimit.h

use libsodium_sys::*;

#[test]
fn test_crypto_pwhash_scryptsalsa208sha256_opslimit_max() {
    assert_eq!(
        unsafe { crypto_pwhash_scryptsalsa208sha256_opslimit_max() } as usize,
        crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MAX as usize
    );
}

#[test]
fn test_crypto_pwhash_scryptsalsa208sha256_opslimit_min() {
    assert_eq!(
        unsafe { crypto_pwhash_scryptsalsa208sha256_opslimit_min() } as usize,
        crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MIN as usize
    );
}
