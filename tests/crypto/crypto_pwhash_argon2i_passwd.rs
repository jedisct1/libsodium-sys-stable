// pwhash_argon2i_passwd.h

use libsodium_sys::*;

#[test]
fn test_crypto_pwhash_argon2i_passwd_max() {
    assert_eq!(
        unsafe { crypto_pwhash_argon2i_passwd_max() } as usize,
        crypto_pwhash_argon2i_PASSWD_MAX as usize
    );
}

#[test]
fn test_crypto_pwhash_argon2i_passwd_min() {
    assert_eq!(
        unsafe { crypto_pwhash_argon2i_passwd_min() } as usize,
        crypto_pwhash_argon2i_PASSWD_MIN as usize
    );
}
