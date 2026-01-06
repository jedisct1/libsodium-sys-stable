// pwhash_argon2i_opslimit.h

use libsodium_sys::*;

#[test]
fn test_crypto_pwhash_argon2i_opslimit_interactive() {
    assert_eq!(
        unsafe { crypto_pwhash_argon2i_opslimit_interactive() } as usize,
        crypto_pwhash_argon2i_OPSLIMIT_INTERACTIVE as usize
    );
}

#[test]
fn test_crypto_pwhash_argon2i_opslimit_max() {
    assert_eq!(
        unsafe { crypto_pwhash_argon2i_opslimit_max() } as usize,
        crypto_pwhash_argon2i_OPSLIMIT_MAX as usize
    );
}

#[test]
fn test_crypto_pwhash_argon2i_opslimit_min() {
    assert_eq!(
        unsafe { crypto_pwhash_argon2i_opslimit_min() } as usize,
        crypto_pwhash_argon2i_OPSLIMIT_MIN as usize
    );
}

#[test]
fn test_crypto_pwhash_argon2i_opslimit_moderate() {
    assert_eq!(
        unsafe { crypto_pwhash_argon2i_opslimit_moderate() } as usize,
        crypto_pwhash_argon2i_OPSLIMIT_MODERATE as usize
    );
}

#[test]
fn test_crypto_pwhash_argon2i_opslimit_sensitive() {
    assert_eq!(
        unsafe { crypto_pwhash_argon2i_opslimit_sensitive() } as usize,
        crypto_pwhash_argon2i_OPSLIMIT_SENSITIVE as usize
    );
}
