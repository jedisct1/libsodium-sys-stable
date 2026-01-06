// xof_turboshake256_domain.h

use libsodium_sys::*;

#[test]
fn test_crypto_xof_turboshake256_domain_standard() {
    assert_eq!(
        unsafe { crypto_xof_turboshake256_domain_standard() } as usize,
        crypto_xof_turboshake256_DOMAIN_STANDARD as usize
    );
}
