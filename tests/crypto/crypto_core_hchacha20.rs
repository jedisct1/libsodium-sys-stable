// core_hchacha20.h

use libsodium_sys::*;

#[test]
fn test_crypto_core_hchacha20_constbytes() {
    assert_eq!(
        unsafe { crypto_core_hchacha20_constbytes() } as usize,
        crypto_core_hchacha20_CONSTBYTES as usize
    );
}

#[test]
fn test_crypto_core_hchacha20_inputbytes() {
    assert_eq!(
        unsafe { crypto_core_hchacha20_inputbytes() } as usize,
        crypto_core_hchacha20_INPUTBYTES as usize
    );
}

#[test]
fn test_crypto_core_hchacha20_keybytes() {
    assert_eq!(
        unsafe { crypto_core_hchacha20_keybytes() } as usize,
        crypto_core_hchacha20_KEYBYTES as usize
    );
}

#[test]
fn test_crypto_core_hchacha20_outputbytes() {
    assert_eq!(
        unsafe { crypto_core_hchacha20_outputbytes() } as usize,
        crypto_core_hchacha20_OUTPUTBYTES as usize
    );
}
