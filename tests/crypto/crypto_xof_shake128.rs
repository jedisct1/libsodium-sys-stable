// xof_shake128.h

use libsodium_sys::*;

#[test]
fn test_crypto_xof_shake128_blockbytes() {
    assert_eq!(
        unsafe { crypto_xof_shake128_blockbytes() } as usize,
        crypto_xof_shake128_BLOCKBYTES as usize
    );
}

#[test]
fn test_crypto_xof_shake128_statebytes() {
    assert_eq!(
        unsafe { crypto_xof_shake128_statebytes() } as usize,
        crypto_xof_shake128_STATEBYTES as usize
    );
}
