// pwhash_argon2id_alg.h

use libsodium_sys::*;

#[test]
fn test_crypto_pwhash_argon2id_alg_argon2id13() {
    assert_eq!(
        unsafe { crypto_pwhash_argon2id_alg_argon2id13() } as usize,
        crypto_pwhash_argon2id_ALG_ARGON2ID13 as usize
    );
}
