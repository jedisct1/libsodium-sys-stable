// pwhash_alg.h

use libsodium_sys::*;

#[test]
fn test_crypto_pwhash_alg_argon2i13() {
    assert_eq!(
        unsafe { crypto_pwhash_alg_argon2i13() } as usize,
        crypto_pwhash_ALG_ARGON2I13 as usize
    );
}

#[test]
fn test_crypto_pwhash_alg_argon2id13() {
    assert_eq!(
        unsafe { crypto_pwhash_alg_argon2id13() } as usize,
        crypto_pwhash_ALG_ARGON2ID13 as usize
    );
}

#[test]
fn test_crypto_pwhash_alg_default() {
    assert_eq!(
        unsafe { crypto_pwhash_alg_default() } as usize,
        crypto_pwhash_ALG_DEFAULT as usize
    );
}
