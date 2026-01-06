// pwhash_scryptsalsa208sha256_memlimit.h

use libsodium_sys::*;

#[test]
fn test_crypto_pwhash_scryptsalsa208sha256_memlimit_min() {
    assert_eq!(
        unsafe { crypto_pwhash_scryptsalsa208sha256_memlimit_min() } as usize,
        crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MIN as usize
    );
}
