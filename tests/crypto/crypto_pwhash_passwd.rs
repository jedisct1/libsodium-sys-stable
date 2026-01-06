// pwhash_passwd.h

use libsodium_sys::*;

#[test]
fn test_crypto_pwhash_passwd_max() {
    assert_eq!(
        unsafe { crypto_pwhash_passwd_max() } as usize,
        crypto_pwhash_PASSWD_MAX as usize
    );
}

#[test]
fn test_crypto_pwhash_passwd_min() {
    assert_eq!(
        unsafe { crypto_pwhash_passwd_min() } as usize,
        crypto_pwhash_PASSWD_MIN as usize
    );
}
