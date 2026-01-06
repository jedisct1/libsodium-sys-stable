// pwhash_argon2id_passwd.h

use libsodium_sys::*;

#[test]
fn test_crypto_pwhash_argon2id_passwd_max() {
    assert_eq!(
        unsafe { crypto_pwhash_argon2id_passwd_max() } as usize,
        crypto_pwhash_argon2id_PASSWD_MAX as usize
    );
}

#[test]
fn test_crypto_pwhash_argon2id_passwd_min() {
    assert_eq!(
        unsafe { crypto_pwhash_argon2id_passwd_min() } as usize,
        crypto_pwhash_argon2id_PASSWD_MIN as usize
    );
}
