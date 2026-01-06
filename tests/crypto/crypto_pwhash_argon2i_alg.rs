// pwhash_argon2i_alg.h

use libsodium_sys::*;

#[test]
fn test_crypto_pwhash_argon2i_alg_argon2i13() {
    assert_eq!(
        unsafe { crypto_pwhash_argon2i_alg_argon2i13() } as usize,
        crypto_pwhash_argon2i_ALG_ARGON2I13 as usize
    );
}
