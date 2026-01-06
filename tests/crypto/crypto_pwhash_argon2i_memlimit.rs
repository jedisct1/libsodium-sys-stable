// pwhash_argon2i_memlimit.h

use libsodium_sys::*;

#[test]
fn test_crypto_pwhash_argon2i_memlimit_interactive() {
    assert_eq!(
        unsafe { crypto_pwhash_argon2i_memlimit_interactive() } as usize,
        crypto_pwhash_argon2i_MEMLIMIT_INTERACTIVE as usize
    );
}

#[test]
fn test_crypto_pwhash_argon2i_memlimit_min() {
    assert_eq!(
        unsafe { crypto_pwhash_argon2i_memlimit_min() } as usize,
        crypto_pwhash_argon2i_MEMLIMIT_MIN as usize
    );
}

#[test]
fn test_crypto_pwhash_argon2i_memlimit_moderate() {
    assert_eq!(
        unsafe { crypto_pwhash_argon2i_memlimit_moderate() } as usize,
        crypto_pwhash_argon2i_MEMLIMIT_MODERATE as usize
    );
}

#[test]
fn test_crypto_pwhash_argon2i_memlimit_sensitive() {
    assert_eq!(
        unsafe { crypto_pwhash_argon2i_memlimit_sensitive() } as usize,
        crypto_pwhash_argon2i_MEMLIMIT_SENSITIVE as usize
    );
}
