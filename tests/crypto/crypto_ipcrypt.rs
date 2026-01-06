// ipcrypt.h

use libsodium_sys::*;

#[test]
fn test_crypto_ipcrypt_bytes() {
    assert_eq!(
        unsafe { crypto_ipcrypt_bytes() } as usize,
        crypto_ipcrypt_BYTES as usize
    );
}

#[test]
fn test_crypto_ipcrypt_keybytes() {
    assert_eq!(
        unsafe { crypto_ipcrypt_keybytes() } as usize,
        crypto_ipcrypt_KEYBYTES as usize
    );
}
