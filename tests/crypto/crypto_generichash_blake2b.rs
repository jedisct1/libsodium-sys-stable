// crypto_generichash_blake2b.h

use libsodium_sys::*;

const EXPECTED_GENERICHASH_BLAKE2B_64_ZEROES: [u8; crypto_generichash_blake2b_BYTES as usize] = [
    0x14, 0xa7, 0xcf, 0x66, 0x1b, 0xae, 0x90, 0x65, 0xe3, 0xee, 0x20, 0x9e, 0xb5, 0x7f, 0xca, 0x64,
    0x64, 0x60, 0xeb, 0x72, 0xb4, 0xea, 0xcd, 0x9a, 0x15, 0x10, 0x8c, 0x2c, 0x5c, 0xd2, 0x15, 0x4b,
];

#[test]
fn test_crypto_generichash_blake2b_state_alignment() {
    // this asserts the alignment applied that was broken with old
    // versions of bindgen
    assert_eq!(64, std::mem::align_of::<crypto_generichash_blake2b_state>());
}

#[test]
fn test_crypto_generichash_blake2b_bytes_min() {
    assert_eq!(
        unsafe { crypto_generichash_blake2b_bytes_min() },
        crypto_generichash_blake2b_BYTES_MIN as usize
    )
}

#[test]
fn test_crypto_generichash_blake2b_bytes_max() {
    assert_eq!(
        unsafe { crypto_generichash_blake2b_bytes_max() },
        crypto_generichash_blake2b_BYTES_MAX as usize
    )
}

#[test]
fn test_crypto_generichash_blake2b_bytes() {
    assert_eq!(
        unsafe { crypto_generichash_blake2b_bytes() },
        crypto_generichash_blake2b_BYTES as usize
    )
}

#[test]
fn test_crypto_generichash_blake2b_keybytes_min() {
    assert_eq!(
        unsafe { crypto_generichash_blake2b_keybytes_min() },
        crypto_generichash_blake2b_KEYBYTES_MIN as usize
    )
}

#[test]
fn test_crypto_generichash_blake2b_keybytes_max() {
    assert_eq!(
        unsafe { crypto_generichash_blake2b_keybytes_max() },
        crypto_generichash_blake2b_KEYBYTES_MAX as usize
    )
}

#[test]
fn test_crypto_generichash_blake2b_keybytes() {
    assert_eq!(
        unsafe { crypto_generichash_blake2b_keybytes() },
        crypto_generichash_blake2b_KEYBYTES as usize
    )
}

#[test]
fn test_crypto_generichash_blake2b_saltbytes() {
    assert_eq!(
        unsafe { crypto_generichash_blake2b_saltbytes() },
        crypto_generichash_blake2b_SALTBYTES as usize
    )
}

#[test]
fn test_crypto_generichash_blake2b_personalbytes() {
    assert_eq!(
        unsafe { crypto_generichash_blake2b_personalbytes() },
        crypto_generichash_blake2b_PERSONALBYTES as usize
    )
}

#[test]
fn test_crypto_generichash_blake2b() {
    let mut out = [0u8; crypto_generichash_blake2b_BYTES as usize];
    let m = [0u8; 64];
    let key = [0u8; crypto_generichash_blake2b_KEYBYTES as usize];

    assert_eq!(
        unsafe {
            crypto_generichash_blake2b(
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
    assert_eq!(out, EXPECTED_GENERICHASH_BLAKE2B_64_ZEROES);
}

#[test]
fn test_crypto_generichash_blake2b_salt_personal() {
    let mut out = [0u8; crypto_generichash_blake2b_BYTES as usize];
    let m = [0u8; 64];
    let key = [0u8; crypto_generichash_blake2b_KEYBYTES as usize];
    let salt = [0u8; crypto_generichash_blake2b_SALTBYTES as usize];
    let personal = [0u8; crypto_generichash_blake2b_PERSONALBYTES as usize];

    assert_eq!(
        unsafe {
            crypto_generichash_blake2b_salt_personal(
                out.as_mut_ptr(),
                out.len(),
                m.as_ptr(),
                m.len() as u64,
                key.as_ptr(),
                key.len(),
                salt.as_ptr(),
                personal.as_ptr(),
            )
        },
        0
    );
    assert_eq!(out, EXPECTED_GENERICHASH_BLAKE2B_64_ZEROES);
}
