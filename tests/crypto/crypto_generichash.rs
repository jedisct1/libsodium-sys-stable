// crypto_generichash.h

use libsodium_sys::*;
use std::ffi::CStr;

const EXPECTED_GENERICHASH_64_ZEROES: [u8; crypto_generichash_BYTES as usize] = [
    0x14, 0xa7, 0xcf, 0x66, 0x1b, 0xae, 0x90, 0x65, 0xe3, 0xee, 0x20, 0x9e, 0xb5, 0x7f, 0xca, 0x64,
    0x64, 0x60, 0xeb, 0x72, 0xb4, 0xea, 0xcd, 0x9a, 0x15, 0x10, 0x8c, 0x2c, 0x5c, 0xd2, 0x15, 0x4b,
];
const EXPECTED_GENERICHASH_128_ZEROES: [u8; crypto_generichash_BYTES as usize] = [
    0xfb, 0x96, 0x3c, 0x28, 0x4b, 0x6b, 0x01, 0x92, 0xed, 0xd8, 0xb5, 0x83, 0x54, 0x01, 0xfe, 0xee,
    0x39, 0x8f, 0x29, 0xc4, 0xfd, 0xd2, 0xcf, 0x37, 0x55, 0x7a, 0x8d, 0x49, 0xbd, 0x71, 0x42, 0x46,
];

#[test]
fn test_crypto_generichash_bytes_min() {
    assert_eq!(
        unsafe { crypto_generichash_bytes_min() },
        crypto_generichash_BYTES_MIN as usize
    )
}

#[test]
fn test_crypto_generichash_bytes_max() {
    assert_eq!(
        unsafe { crypto_generichash_bytes_max() },
        crypto_generichash_BYTES_MAX as usize
    )
}

#[test]
fn test_crypto_generichash_bytes() {
    assert_eq!(
        unsafe { crypto_generichash_bytes() },
        crypto_generichash_BYTES as usize
    )
}

#[test]
fn test_crypto_generichash_keybytes_min() {
    assert_eq!(
        unsafe { crypto_generichash_keybytes_min() },
        crypto_generichash_KEYBYTES_MIN as usize
    )
}

#[test]
fn test_crypto_generichash_keybytes_max() {
    assert_eq!(
        unsafe { crypto_generichash_keybytes_max() },
        crypto_generichash_KEYBYTES_MAX as usize
    )
}

#[test]
fn test_crypto_generichash_keybytes() {
    assert_eq!(
        unsafe { crypto_generichash_keybytes() },
        crypto_generichash_KEYBYTES as usize
    )
}
#[test]
fn test_crypto_generichash_primitive() {
    unsafe {
        let s = crypto_generichash_primitive();
        let s = CStr::from_ptr(s);
        let p = CStr::from_bytes_with_nul(crypto_generichash_PRIMITIVE).unwrap();
        assert_eq!(s, p);
    }
}

#[test]
fn test_crypto_generichash_statebytes() {
    assert!(unsafe { crypto_generichash_statebytes() } > 0);
}

#[test]
fn test_crypto_generichash() {
    let mut out = [0u8; crypto_generichash_BYTES as usize];
    let m = [0u8; 64];
    let key = [0u8; crypto_generichash_KEYBYTES as usize];

    assert_eq!(
        unsafe {
            crypto_generichash(
                out.as_mut_ptr(),
                out.len(),
                m.as_ptr(),
                m.len() as u64,
                key.as_ptr(),
                key.len(),
            )
        },
        0
    );
    assert_eq!(out, EXPECTED_GENERICHASH_64_ZEROES);
}

#[cfg(test)]
use std::mem;

#[test]
fn test_crypto_generichash_multipart() {
    let mut out = [0u8; crypto_generichash_BYTES as usize];
    let m = [0u8; 64];
    let key = [0u8; crypto_generichash_KEYBYTES as usize];

    let mut pst = mem::MaybeUninit::<crypto_generichash_state>::uninit();

    assert_eq!(
        unsafe { crypto_generichash_init(pst.as_mut_ptr(), key.as_ptr(), key.len(), out.len()) },
        0
    );

    let mut pst = unsafe { pst.assume_init() };

    assert_eq!(
        unsafe { crypto_generichash_update(&mut pst, m.as_ptr(), m.len() as u64) },
        0
    );

    assert_eq!(
        unsafe { crypto_generichash_update(&mut pst, m.as_ptr(), m.len() as u64) },
        0
    );

    assert_eq!(
        unsafe { crypto_generichash_final(&mut pst, out.as_mut_ptr(), out.len()) },
        0
    );
    assert_eq!(out, EXPECTED_GENERICHASH_128_ZEROES);
}
