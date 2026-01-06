// ipcrypt_nd.h

use libsodium_sys::*;

#[test]
fn test_crypto_ipcrypt_nd_inputbytes() {
    assert_eq!(
        unsafe { crypto_ipcrypt_nd_inputbytes() } as usize,
        crypto_ipcrypt_ND_INPUTBYTES as usize
    );
}

#[test]
fn test_crypto_ipcrypt_nd_keybytes() {
    assert_eq!(
        unsafe { crypto_ipcrypt_nd_keybytes() } as usize,
        crypto_ipcrypt_ND_KEYBYTES as usize
    );
}

#[test]
fn test_crypto_ipcrypt_nd_outputbytes() {
    assert_eq!(
        unsafe { crypto_ipcrypt_nd_outputbytes() } as usize,
        crypto_ipcrypt_ND_OUTPUTBYTES as usize
    );
}

#[test]
fn test_crypto_ipcrypt_nd_tweakbytes() {
    assert_eq!(
        unsafe { crypto_ipcrypt_nd_tweakbytes() } as usize,
        crypto_ipcrypt_ND_TWEAKBYTES as usize
    );
}
