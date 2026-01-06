// ipcrypt_pfx.h

use libsodium_sys::*;

#[test]
fn test_crypto_ipcrypt_pfx_bytes() {
    assert_eq!(
        unsafe { crypto_ipcrypt_pfx_bytes() } as usize,
        crypto_ipcrypt_PFX_BYTES as usize
    );
}

#[test]
fn test_crypto_ipcrypt_pfx_keybytes() {
    assert_eq!(
        unsafe { crypto_ipcrypt_pfx_keybytes() } as usize,
        crypto_ipcrypt_PFX_KEYBYTES as usize
    );
}
