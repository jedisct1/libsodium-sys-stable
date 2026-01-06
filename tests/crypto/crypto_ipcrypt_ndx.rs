// ipcrypt_ndx.h

use libsodium_sys::*;

#[test]
fn test_crypto_ipcrypt_ndx_inputbytes() {
    assert_eq!(
        unsafe { crypto_ipcrypt_ndx_inputbytes() } as usize,
        crypto_ipcrypt_NDX_INPUTBYTES as usize
    );
}

#[test]
fn test_crypto_ipcrypt_ndx_keybytes() {
    assert_eq!(
        unsafe { crypto_ipcrypt_ndx_keybytes() } as usize,
        crypto_ipcrypt_NDX_KEYBYTES as usize
    );
}

#[test]
fn test_crypto_ipcrypt_ndx_outputbytes() {
    assert_eq!(
        unsafe { crypto_ipcrypt_ndx_outputbytes() } as usize,
        crypto_ipcrypt_NDX_OUTPUTBYTES as usize
    );
}

#[test]
fn test_crypto_ipcrypt_ndx_tweakbytes() {
    assert_eq!(
        unsafe { crypto_ipcrypt_ndx_tweakbytes() } as usize,
        crypto_ipcrypt_NDX_TWEAKBYTES as usize
    );
}
