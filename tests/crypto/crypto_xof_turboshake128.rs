// xof_turboshake128.h

use libsodium_sys::*;

#[test]
fn test_crypto_xof_turboshake128_blockbytes() {
    assert_eq!(
        unsafe { crypto_xof_turboshake128_blockbytes() } as usize,
        crypto_xof_turboshake128_BLOCKBYTES as usize
    );
}

#[test]
fn test_crypto_xof_turboshake128_statebytes() {
    assert_eq!(
        unsafe { crypto_xof_turboshake128_statebytes() } as usize,
        crypto_xof_turboshake128_STATEBYTES as usize
    );
}
