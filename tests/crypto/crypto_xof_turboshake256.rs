// xof_turboshake256.h

use libsodium_sys::*;

#[test]
fn test_crypto_xof_turboshake256_blockbytes() {
    assert_eq!(
        unsafe { crypto_xof_turboshake256_blockbytes() } as usize,
        crypto_xof_turboshake256_BLOCKBYTES as usize
    );
}

#[test]
fn test_crypto_xof_turboshake256_statebytes() {
    assert_eq!(
        unsafe { crypto_xof_turboshake256_statebytes() } as usize,
        crypto_xof_turboshake256_STATEBYTES as usize
    );
}
