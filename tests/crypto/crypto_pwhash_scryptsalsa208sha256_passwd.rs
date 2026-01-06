// pwhash_scryptsalsa208sha256_passwd.h

use libsodium_sys::*;

#[test]
fn test_crypto_pwhash_scryptsalsa208sha256_passwd_min() {
    assert_eq!(
        unsafe { crypto_pwhash_scryptsalsa208sha256_passwd_min() } as usize,
        crypto_pwhash_scryptsalsa208sha256_PASSWD_MIN as usize
    );
}
