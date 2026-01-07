//! WASI Component Model implementation for libsodium
//!
//! This module provides safe wrappers around libsodium's FFI that are exported
//! as a WASI component using the Component Model.

#![allow(unused_unsafe)]

use crate::sodium_bindings::*;
use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

// State management for streaming operations
static NEXT_STATE_ID: AtomicU64 = AtomicU64::new(1);

fn next_state_id() -> u64 {
    NEXT_STATE_ID.fetch_add(1, Ordering::SeqCst)
}

// Generic hash states
static GENERICHASH_STATES: Mutex<Option<HashMap<u64, (crypto_generichash_state, usize)>>> = Mutex::new(None);

fn generichash_states() -> std::sync::MutexGuard<'static, Option<HashMap<u64, (crypto_generichash_state, usize)>>> {
    let mut guard = GENERICHASH_STATES.lock().unwrap();
    if guard.is_none() {
        *guard = Some(HashMap::new());
    }
    guard
}

// SHA-256 states
static SHA256_STATES: Mutex<Option<HashMap<u64, crypto_hash_sha256_state>>> = Mutex::new(None);

fn sha256_states() -> std::sync::MutexGuard<'static, Option<HashMap<u64, crypto_hash_sha256_state>>> {
    let mut guard = SHA256_STATES.lock().unwrap();
    if guard.is_none() {
        *guard = Some(HashMap::new());
    }
    guard
}

// SHA-512 states
static SHA512_STATES: Mutex<Option<HashMap<u64, crypto_hash_sha512_state>>> = Mutex::new(None);

fn sha512_states() -> std::sync::MutexGuard<'static, Option<HashMap<u64, crypto_hash_sha512_state>>> {
    let mut guard = SHA512_STATES.lock().unwrap();
    if guard.is_none() {
        *guard = Some(HashMap::new());
    }
    guard
}

// Auth HMAC-SHA512-256 states
static AUTH_STATES: Mutex<Option<HashMap<u64, crypto_auth_hmacsha512256_state>>> = Mutex::new(None);

fn auth_states() -> std::sync::MutexGuard<'static, Option<HashMap<u64, crypto_auth_hmacsha512256_state>>> {
    let mut guard = AUTH_STATES.lock().unwrap();
    if guard.is_none() {
        *guard = Some(HashMap::new());
    }
    guard
}

// Onetimeauth Poly1305 states
static ONETIMEAUTH_STATES: Mutex<Option<HashMap<u64, crypto_onetimeauth_state>>> = Mutex::new(None);

fn onetimeauth_states() -> std::sync::MutexGuard<'static, Option<HashMap<u64, crypto_onetimeauth_state>>> {
    let mut guard = ONETIMEAUTH_STATES.lock().unwrap();
    if guard.is_none() {
        *guard = Some(HashMap::new());
    }
    guard
}

// Secret stream states
static SECRETSTREAM_STATES: Mutex<Option<HashMap<u64, crypto_secretstream_xchacha20poly1305_state>>> = Mutex::new(None);

fn secretstream_states() -> std::sync::MutexGuard<'static, Option<HashMap<u64, crypto_secretstream_xchacha20poly1305_state>>> {
    let mut guard = SECRETSTREAM_STATES.lock().unwrap();
    if guard.is_none() {
        *guard = Some(HashMap::new());
    }
    guard
}

// SHAKE128 states
static SHAKE128_STATES: Mutex<Option<HashMap<u64, crypto_xof_shake128_state>>> = Mutex::new(None);

fn shake128_states() -> std::sync::MutexGuard<'static, Option<HashMap<u64, crypto_xof_shake128_state>>> {
    let mut guard = SHAKE128_STATES.lock().unwrap();
    if guard.is_none() {
        *guard = Some(HashMap::new());
    }
    guard
}

// SHAKE256 states
static SHAKE256_STATES: Mutex<Option<HashMap<u64, crypto_xof_shake256_state>>> = Mutex::new(None);

fn shake256_states() -> std::sync::MutexGuard<'static, Option<HashMap<u64, crypto_xof_shake256_state>>> {
    let mut guard = SHAKE256_STATES.lock().unwrap();
    if guard.is_none() {
        *guard = Some(HashMap::new());
    }
    guard
}

// TurboSHAKE128 states
static TURBOSHAKE128_STATES: Mutex<Option<HashMap<u64, crypto_xof_turboshake128_state>>> = Mutex::new(None);

fn turboshake128_states() -> std::sync::MutexGuard<'static, Option<HashMap<u64, crypto_xof_turboshake128_state>>> {
    let mut guard = TURBOSHAKE128_STATES.lock().unwrap();
    if guard.is_none() {
        *guard = Some(HashMap::new());
    }
    guard
}

// TurboSHAKE256 states
static TURBOSHAKE256_STATES: Mutex<Option<HashMap<u64, crypto_xof_turboshake256_state>>> = Mutex::new(None);

fn turboshake256_states() -> std::sync::MutexGuard<'static, Option<HashMap<u64, crypto_xof_turboshake256_state>>> {
    let mut guard = TURBOSHAKE256_STATES.lock().unwrap();
    if guard.is_none() {
        *guard = Some(HashMap::new());
    }
    guard
}

// HMAC-SHA256 states
static HMACSHA256_STATES: Mutex<Option<HashMap<u64, crypto_auth_hmacsha256_state>>> = Mutex::new(None);

fn hmacsha256_states() -> std::sync::MutexGuard<'static, Option<HashMap<u64, crypto_auth_hmacsha256_state>>> {
    let mut guard = HMACSHA256_STATES.lock().unwrap();
    if guard.is_none() {
        *guard = Some(HashMap::new());
    }
    guard
}

// HMAC-SHA512 states
static HMACSHA512_STATES: Mutex<Option<HashMap<u64, crypto_auth_hmacsha512_state>>> = Mutex::new(None);

fn hmacsha512_states() -> std::sync::MutexGuard<'static, Option<HashMap<u64, crypto_auth_hmacsha512_state>>> {
    let mut guard = HMACSHA512_STATES.lock().unwrap();
    if guard.is_none() {
        *guard = Some(HashMap::new());
    }
    guard
}

// Sign Ed25519ph states
static SIGN_STATES: Mutex<Option<HashMap<u64, crypto_sign_ed25519ph_state>>> = Mutex::new(None);

fn sign_states() -> std::sync::MutexGuard<'static, Option<HashMap<u64, crypto_sign_ed25519ph_state>>> {
    let mut guard = SIGN_STATES.lock().unwrap();
    if guard.is_none() {
        *guard = Some(HashMap::new());
    }
    guard
}

// HKDF-SHA256 extraction states
static HKDF_SHA256_STATES: Mutex<Option<HashMap<u64, crypto_kdf_hkdf_sha256_state>>> = Mutex::new(None);

fn hkdf_sha256_states() -> std::sync::MutexGuard<'static, Option<HashMap<u64, crypto_kdf_hkdf_sha256_state>>> {
    let mut guard = HKDF_SHA256_STATES.lock().unwrap();
    if guard.is_none() {
        *guard = Some(HashMap::new());
    }
    guard
}

// HKDF-SHA512 extraction states
static HKDF_SHA512_STATES: Mutex<Option<HashMap<u64, crypto_kdf_hkdf_sha512_state>>> = Mutex::new(None);

fn hkdf_sha512_states() -> std::sync::MutexGuard<'static, Option<HashMap<u64, crypto_kdf_hkdf_sha512_state>>> {
    let mut guard = HKDF_SHA512_STATES.lock().unwrap();
    if guard.is_none() {
        *guard = Some(HashMap::new());
    }
    guard
}

// HMAC-SHA512-256 states (uses the same state type as hmacsha512256)
static HMACSHA512256_STATES: Mutex<Option<HashMap<u64, crypto_auth_hmacsha512256_state>>> = Mutex::new(None);

fn hmacsha512256_states() -> std::sync::MutexGuard<'static, Option<HashMap<u64, crypto_auth_hmacsha512256_state>>> {
    let mut guard = HMACSHA512256_STATES.lock().unwrap();
    if guard.is_none() {
        *guard = Some(HashMap::new());
    }
    guard
}

wit_bindgen::generate!({
    world: "libsodium",
    path: "wit",
    pub_export_macro: true,
    export_macro_name: "export_libsodium",
});

// Error conversion helper
fn to_crypto_error() -> exports::libsodium::crypto::types::CryptoError {
    exports::libsodium::crypto::types::CryptoError::OperationFailed
}

fn invalid_key() -> exports::libsodium::crypto::types::CryptoError {
    exports::libsodium::crypto::types::CryptoError::InvalidKeySize
}

fn invalid_nonce() -> exports::libsodium::crypto::types::CryptoError {
    exports::libsodium::crypto::types::CryptoError::InvalidNonceSize
}

fn verification_failed() -> exports::libsodium::crypto::types::CryptoError {
    exports::libsodium::crypto::types::CryptoError::VerificationFailed
}

// ============================================================================
// Core
// ============================================================================

impl exports::libsodium::crypto::core::Guest for Component {
    fn init() -> i32 {
        unsafe { sodium_init() }
    }

    fn version_string() -> String {
        unsafe {
            let ptr = sodium_version_string();
            let mut len = 0;
            while *ptr.add(len) != 0 {
                len += 1;
            }
            let slice = core::slice::from_raw_parts(ptr as *const u8, len);
            String::from_utf8_lossy(slice).into_owned()
        }
    }

    fn library_version_major() -> i32 {
        unsafe { sodium_library_version_major() }
    }

    fn library_version_minor() -> i32 {
        unsafe { sodium_library_version_minor() }
    }
}

// ============================================================================
// Random
// ============================================================================

impl exports::libsodium::crypto::random::Guest for Component {
    fn random_bytes(len: u32) -> Vec<u8> {
        let mut buf = vec![0u8; len as usize];
        unsafe {
            randombytes_buf(buf.as_mut_ptr() as *mut libc::c_void, len as usize);
        }
        buf
    }

    fn random_u32() -> u32 {
        unsafe { randombytes_random() }
    }

    fn random_uniform(upper_bound: u32) -> u32 {
        unsafe { randombytes_uniform(upper_bound) }
    }
}

// ============================================================================
// Secretbox
// ============================================================================

impl exports::libsodium::crypto::secretbox::Guest for Component {
    fn key_bytes() -> u32 {
        crypto_secretbox_KEYBYTES
    }

    fn nonce_bytes() -> u32 {
        crypto_secretbox_NONCEBYTES
    }

    fn mac_bytes() -> u32 {
        crypto_secretbox_MACBYTES
    }

    fn keygen() -> Vec<u8> {
        let mut key = vec![0u8; crypto_secretbox_KEYBYTES as usize];
        unsafe {
            crypto_secretbox_keygen(key.as_mut_ptr());
        }
        key
    }

    fn easy(
        message: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if key.len() != crypto_secretbox_KEYBYTES as usize {
            return Err(invalid_key());
        }
        if nonce.len() != crypto_secretbox_NONCEBYTES as usize {
            return Err(invalid_nonce());
        }

        let mut ciphertext = vec![0u8; message.len() + crypto_secretbox_MACBYTES as usize];
        let ret = unsafe {
            crypto_secretbox_easy(
                ciphertext.as_mut_ptr(),
                message.as_ptr(),
                message.len() as u64,
                nonce.as_ptr(),
                key.as_ptr(),
            )
        };

        if ret == 0 {
            Ok(ciphertext)
        } else {
            Err(to_crypto_error())
        }
    }

    fn open_easy(
        ciphertext: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if key.len() != crypto_secretbox_KEYBYTES as usize {
            return Err(invalid_key());
        }
        if nonce.len() != crypto_secretbox_NONCEBYTES as usize {
            return Err(invalid_nonce());
        }
        if ciphertext.len() < crypto_secretbox_MACBYTES as usize {
            return Err(verification_failed());
        }

        let mut message = vec![0u8; ciphertext.len() - crypto_secretbox_MACBYTES as usize];
        let ret = unsafe {
            crypto_secretbox_open_easy(
                message.as_mut_ptr(),
                ciphertext.as_ptr(),
                ciphertext.len() as u64,
                nonce.as_ptr(),
                key.as_ptr(),
            )
        };

        if ret == 0 {
            Ok(message)
        } else {
            Err(verification_failed())
        }
    }

    fn detached(
        message: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<(Vec<u8>, Vec<u8>), exports::libsodium::crypto::types::CryptoError> {
        if key.len() != crypto_secretbox_KEYBYTES as usize {
            return Err(invalid_key());
        }
        if nonce.len() != crypto_secretbox_NONCEBYTES as usize {
            return Err(invalid_nonce());
        }

        let mut ciphertext = vec![0u8; message.len()];
        let mut mac = vec![0u8; crypto_secretbox_MACBYTES as usize];
        let ret = unsafe {
            crypto_secretbox_detached(
                ciphertext.as_mut_ptr(),
                mac.as_mut_ptr(),
                message.as_ptr(),
                message.len() as u64,
                nonce.as_ptr(),
                key.as_ptr(),
            )
        };

        if ret == 0 {
            Ok((ciphertext, mac))
        } else {
            Err(to_crypto_error())
        }
    }

    fn open_detached(
        ciphertext: Vec<u8>,
        mac: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if key.len() != crypto_secretbox_KEYBYTES as usize {
            return Err(invalid_key());
        }
        if nonce.len() != crypto_secretbox_NONCEBYTES as usize {
            return Err(invalid_nonce());
        }
        if mac.len() != crypto_secretbox_MACBYTES as usize {
            return Err(verification_failed());
        }

        let mut message = vec![0u8; ciphertext.len()];
        let ret = unsafe {
            crypto_secretbox_open_detached(
                message.as_mut_ptr(),
                ciphertext.as_ptr(),
                mac.as_ptr(),
                ciphertext.len() as u64,
                nonce.as_ptr(),
                key.as_ptr(),
            )
        };

        if ret == 0 {
            Ok(message)
        } else {
            Err(verification_failed())
        }
    }
}

// ============================================================================
// Crypto Box
// ============================================================================

impl exports::libsodium::crypto::crypto_box::Guest for Component {
    fn public_key_bytes() -> u32 {
        crypto_box_PUBLICKEYBYTES
    }

    fn secret_key_bytes() -> u32 {
        crypto_box_SECRETKEYBYTES
    }

    fn nonce_bytes() -> u32 {
        crypto_box_NONCEBYTES
    }

    fn mac_bytes() -> u32 {
        crypto_box_MACBYTES
    }

    fn seed_bytes() -> u32 {
        crypto_box_SEEDBYTES
    }

    fn keypair() -> exports::libsodium::crypto::types::KeyPair {
        let mut pk = vec![0u8; crypto_box_PUBLICKEYBYTES as usize];
        let mut sk = vec![0u8; crypto_box_SECRETKEYBYTES as usize];
        unsafe {
            crypto_box_keypair(pk.as_mut_ptr(), sk.as_mut_ptr());
        }
        exports::libsodium::crypto::types::KeyPair {
            public_key: pk,
            secret_key: sk,
        }
    }

    fn seed_keypair(
        seed: Vec<u8>,
    ) -> Result<exports::libsodium::crypto::types::KeyPair, exports::libsodium::crypto::types::CryptoError>
    {
        if seed.len() != crypto_box_SEEDBYTES as usize {
            return Err(invalid_key());
        }

        let mut pk = vec![0u8; crypto_box_PUBLICKEYBYTES as usize];
        let mut sk = vec![0u8; crypto_box_SECRETKEYBYTES as usize];
        let ret = unsafe {
            crypto_box_seed_keypair(pk.as_mut_ptr(), sk.as_mut_ptr(), seed.as_ptr())
        };

        if ret == 0 {
            Ok(exports::libsodium::crypto::types::KeyPair {
                public_key: pk,
                secret_key: sk,
            })
        } else {
            Err(to_crypto_error())
        }
    }

    fn easy(
        message: Vec<u8>,
        nonce: Vec<u8>,
        recipient_pk: Vec<u8>,
        sender_sk: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if recipient_pk.len() != crypto_box_PUBLICKEYBYTES as usize {
            return Err(invalid_key());
        }
        if sender_sk.len() != crypto_box_SECRETKEYBYTES as usize {
            return Err(invalid_key());
        }
        if nonce.len() != crypto_box_NONCEBYTES as usize {
            return Err(invalid_nonce());
        }

        let mut ciphertext = vec![0u8; message.len() + crypto_box_MACBYTES as usize];
        let ret = unsafe {
            crypto_box_easy(
                ciphertext.as_mut_ptr(),
                message.as_ptr(),
                message.len() as u64,
                nonce.as_ptr(),
                recipient_pk.as_ptr(),
                sender_sk.as_ptr(),
            )
        };

        if ret == 0 {
            Ok(ciphertext)
        } else {
            Err(to_crypto_error())
        }
    }

    fn open_easy(
        ciphertext: Vec<u8>,
        nonce: Vec<u8>,
        sender_pk: Vec<u8>,
        recipient_sk: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if sender_pk.len() != crypto_box_PUBLICKEYBYTES as usize {
            return Err(invalid_key());
        }
        if recipient_sk.len() != crypto_box_SECRETKEYBYTES as usize {
            return Err(invalid_key());
        }
        if nonce.len() != crypto_box_NONCEBYTES as usize {
            return Err(invalid_nonce());
        }
        if ciphertext.len() < crypto_box_MACBYTES as usize {
            return Err(verification_failed());
        }

        let mut message = vec![0u8; ciphertext.len() - crypto_box_MACBYTES as usize];
        let ret = unsafe {
            crypto_box_open_easy(
                message.as_mut_ptr(),
                ciphertext.as_ptr(),
                ciphertext.len() as u64,
                nonce.as_ptr(),
                sender_pk.as_ptr(),
                recipient_sk.as_ptr(),
            )
        };

        if ret == 0 {
            Ok(message)
        } else {
            Err(verification_failed())
        }
    }

    fn detached(
        message: Vec<u8>,
        nonce: Vec<u8>,
        recipient_pk: Vec<u8>,
        sender_sk: Vec<u8>,
    ) -> Result<(Vec<u8>, Vec<u8>), exports::libsodium::crypto::types::CryptoError> {
        if recipient_pk.len() != crypto_box_PUBLICKEYBYTES as usize {
            return Err(invalid_key());
        }
        if sender_sk.len() != crypto_box_SECRETKEYBYTES as usize {
            return Err(invalid_key());
        }
        if nonce.len() != crypto_box_NONCEBYTES as usize {
            return Err(invalid_nonce());
        }

        let mut ciphertext = vec![0u8; message.len()];
        let mut mac = vec![0u8; crypto_box_MACBYTES as usize];
        let ret = unsafe {
            crypto_box_detached(
                ciphertext.as_mut_ptr(),
                mac.as_mut_ptr(),
                message.as_ptr(),
                message.len() as u64,
                nonce.as_ptr(),
                recipient_pk.as_ptr(),
                sender_sk.as_ptr(),
            )
        };

        if ret == 0 {
            Ok((ciphertext, mac))
        } else {
            Err(to_crypto_error())
        }
    }

    fn open_detached(
        ciphertext: Vec<u8>,
        mac: Vec<u8>,
        nonce: Vec<u8>,
        sender_pk: Vec<u8>,
        recipient_sk: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if sender_pk.len() != crypto_box_PUBLICKEYBYTES as usize {
            return Err(invalid_key());
        }
        if recipient_sk.len() != crypto_box_SECRETKEYBYTES as usize {
            return Err(invalid_key());
        }
        if nonce.len() != crypto_box_NONCEBYTES as usize {
            return Err(invalid_nonce());
        }
        if mac.len() != crypto_box_MACBYTES as usize {
            return Err(verification_failed());
        }

        let mut message = vec![0u8; ciphertext.len()];
        let ret = unsafe {
            crypto_box_open_detached(
                message.as_mut_ptr(),
                ciphertext.as_ptr(),
                mac.as_ptr(),
                ciphertext.len() as u64,
                nonce.as_ptr(),
                sender_pk.as_ptr(),
                recipient_sk.as_ptr(),
            )
        };

        if ret == 0 {
            Ok(message)
        } else {
            Err(verification_failed())
        }
    }

    fn beforenm(
        recipient_pk: Vec<u8>,
        sender_sk: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if recipient_pk.len() != crypto_box_PUBLICKEYBYTES as usize {
            return Err(invalid_key());
        }
        if sender_sk.len() != crypto_box_SECRETKEYBYTES as usize {
            return Err(invalid_key());
        }

        let mut shared_key = vec![0u8; crypto_box_BEFORENMBYTES as usize];
        let ret = unsafe {
            crypto_box_beforenm(
                shared_key.as_mut_ptr(),
                recipient_pk.as_ptr(),
                sender_sk.as_ptr(),
            )
        };

        if ret == 0 {
            Ok(shared_key)
        } else {
            Err(to_crypto_error())
        }
    }

    fn easy_afternm(
        message: Vec<u8>,
        nonce: Vec<u8>,
        shared_key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if shared_key.len() != crypto_box_BEFORENMBYTES as usize {
            return Err(invalid_key());
        }
        if nonce.len() != crypto_box_NONCEBYTES as usize {
            return Err(invalid_nonce());
        }

        let mut ciphertext = vec![0u8; message.len() + crypto_box_MACBYTES as usize];
        let ret = unsafe {
            crypto_box_easy_afternm(
                ciphertext.as_mut_ptr(),
                message.as_ptr(),
                message.len() as u64,
                nonce.as_ptr(),
                shared_key.as_ptr(),
            )
        };

        if ret == 0 {
            Ok(ciphertext)
        } else {
            Err(to_crypto_error())
        }
    }

    fn open_easy_afternm(
        ciphertext: Vec<u8>,
        nonce: Vec<u8>,
        shared_key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if shared_key.len() != crypto_box_BEFORENMBYTES as usize {
            return Err(invalid_key());
        }
        if nonce.len() != crypto_box_NONCEBYTES as usize {
            return Err(invalid_nonce());
        }
        if ciphertext.len() < crypto_box_MACBYTES as usize {
            return Err(verification_failed());
        }

        let mut message = vec![0u8; ciphertext.len() - crypto_box_MACBYTES as usize];
        let ret = unsafe {
            crypto_box_open_easy_afternm(
                message.as_mut_ptr(),
                ciphertext.as_ptr(),
                ciphertext.len() as u64,
                nonce.as_ptr(),
                shared_key.as_ptr(),
            )
        };

        if ret == 0 {
            Ok(message)
        } else {
            Err(verification_failed())
        }
    }

    fn beforenm_bytes() -> u32 {
        crypto_box_BEFORENMBYTES
    }

    fn detached_afternm(
        message: Vec<u8>,
        nonce: Vec<u8>,
        shared_key: Vec<u8>,
    ) -> Result<(Vec<u8>, Vec<u8>), exports::libsodium::crypto::types::CryptoError> {
        if shared_key.len() != crypto_box_BEFORENMBYTES as usize {
            return Err(invalid_key());
        }
        if nonce.len() != crypto_box_NONCEBYTES as usize {
            return Err(invalid_nonce());
        }

        let mut ciphertext = vec![0u8; message.len()];
        let mut mac = vec![0u8; crypto_box_MACBYTES as usize];
        let ret = unsafe {
            crypto_box_detached_afternm(
                ciphertext.as_mut_ptr(),
                mac.as_mut_ptr(),
                message.as_ptr(),
                message.len() as u64,
                nonce.as_ptr(),
                shared_key.as_ptr(),
            )
        };

        if ret == 0 {
            Ok((ciphertext, mac))
        } else {
            Err(to_crypto_error())
        }
    }

    fn open_detached_afternm(
        ciphertext: Vec<u8>,
        mac: Vec<u8>,
        nonce: Vec<u8>,
        shared_key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if shared_key.len() != crypto_box_BEFORENMBYTES as usize {
            return Err(invalid_key());
        }
        if nonce.len() != crypto_box_NONCEBYTES as usize {
            return Err(invalid_nonce());
        }
        if mac.len() != crypto_box_MACBYTES as usize {
            return Err(verification_failed());
        }

        let mut message = vec![0u8; ciphertext.len()];
        let ret = unsafe {
            crypto_box_open_detached_afternm(
                message.as_mut_ptr(),
                ciphertext.as_ptr(),
                mac.as_ptr(),
                ciphertext.len() as u64,
                nonce.as_ptr(),
                shared_key.as_ptr(),
            )
        };

        if ret == 0 {
            Ok(message)
        } else {
            Err(verification_failed())
        }
    }
}

// ============================================================================
// Seal
// ============================================================================

impl exports::libsodium::crypto::seal::Guest for Component {
    fn seal_bytes() -> u32 {
        crypto_box_SEALBYTES
    }

    fn seal(
        message: Vec<u8>,
        recipient_pk: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if recipient_pk.len() != crypto_box_PUBLICKEYBYTES as usize {
            return Err(invalid_key());
        }

        let mut ciphertext = vec![0u8; message.len() + crypto_box_SEALBYTES as usize];
        let ret = unsafe {
            crypto_box_seal(
                ciphertext.as_mut_ptr(),
                message.as_ptr(),
                message.len() as u64,
                recipient_pk.as_ptr(),
            )
        };

        if ret == 0 {
            Ok(ciphertext)
        } else {
            Err(to_crypto_error())
        }
    }

    fn seal_open(
        ciphertext: Vec<u8>,
        recipient_pk: Vec<u8>,
        recipient_sk: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if recipient_pk.len() != crypto_box_PUBLICKEYBYTES as usize {
            return Err(invalid_key());
        }
        if recipient_sk.len() != crypto_box_SECRETKEYBYTES as usize {
            return Err(invalid_key());
        }
        if ciphertext.len() < crypto_box_SEALBYTES as usize {
            return Err(verification_failed());
        }

        let mut message = vec![0u8; ciphertext.len() - crypto_box_SEALBYTES as usize];
        let ret = unsafe {
            crypto_box_seal_open(
                message.as_mut_ptr(),
                ciphertext.as_ptr(),
                ciphertext.len() as u64,
                recipient_pk.as_ptr(),
                recipient_sk.as_ptr(),
            )
        };

        if ret == 0 {
            Ok(message)
        } else {
            Err(verification_failed())
        }
    }
}

// ============================================================================
// Sign
// ============================================================================

impl exports::libsodium::crypto::sign::Guest for Component {
    fn public_key_bytes() -> u32 {
        crypto_sign_PUBLICKEYBYTES
    }

    fn secret_key_bytes() -> u32 {
        crypto_sign_SECRETKEYBYTES
    }

    fn signature_bytes() -> u32 {
        crypto_sign_BYTES
    }

    fn seed_bytes() -> u32 {
        crypto_sign_SEEDBYTES
    }

    fn keypair() -> exports::libsodium::crypto::types::SignKeyPair {
        let mut pk = vec![0u8; crypto_sign_PUBLICKEYBYTES as usize];
        let mut sk = vec![0u8; crypto_sign_SECRETKEYBYTES as usize];
        unsafe {
            crypto_sign_keypair(pk.as_mut_ptr(), sk.as_mut_ptr());
        }
        exports::libsodium::crypto::types::SignKeyPair {
            public_key: pk,
            secret_key: sk,
        }
    }

    fn seed_keypair(
        seed: Vec<u8>,
    ) -> Result<exports::libsodium::crypto::types::SignKeyPair, exports::libsodium::crypto::types::CryptoError>
    {
        if seed.len() != crypto_sign_SEEDBYTES as usize {
            return Err(invalid_key());
        }

        let mut pk = vec![0u8; crypto_sign_PUBLICKEYBYTES as usize];
        let mut sk = vec![0u8; crypto_sign_SECRETKEYBYTES as usize];
        let ret = unsafe {
            crypto_sign_seed_keypair(pk.as_mut_ptr(), sk.as_mut_ptr(), seed.as_ptr())
        };

        if ret == 0 {
            Ok(exports::libsodium::crypto::types::SignKeyPair {
                public_key: pk,
                secret_key: sk,
            })
        } else {
            Err(to_crypto_error())
        }
    }

    fn sign(
        message: Vec<u8>,
        secret_key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if secret_key.len() != crypto_sign_SECRETKEYBYTES as usize {
            return Err(invalid_key());
        }

        let mut signed_message = vec![0u8; message.len() + crypto_sign_BYTES as usize];
        let mut signed_len: u64 = 0;
        let ret = unsafe {
            crypto_sign(
                signed_message.as_mut_ptr(),
                &mut signed_len,
                message.as_ptr(),
                message.len() as u64,
                secret_key.as_ptr(),
            )
        };

        if ret == 0 {
            signed_message.truncate(signed_len as usize);
            Ok(signed_message)
        } else {
            Err(to_crypto_error())
        }
    }

    fn open(
        signed_message: Vec<u8>,
        public_key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if public_key.len() != crypto_sign_PUBLICKEYBYTES as usize {
            return Err(invalid_key());
        }
        if signed_message.len() < crypto_sign_BYTES as usize {
            return Err(verification_failed());
        }

        let mut message = vec![0u8; signed_message.len() - crypto_sign_BYTES as usize];
        let mut message_len: u64 = 0;
        let ret = unsafe {
            crypto_sign_open(
                message.as_mut_ptr(),
                &mut message_len,
                signed_message.as_ptr(),
                signed_message.len() as u64,
                public_key.as_ptr(),
            )
        };

        if ret == 0 {
            message.truncate(message_len as usize);
            Ok(message)
        } else {
            Err(verification_failed())
        }
    }

    fn detached(
        message: Vec<u8>,
        secret_key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if secret_key.len() != crypto_sign_SECRETKEYBYTES as usize {
            return Err(invalid_key());
        }

        let mut signature = vec![0u8; crypto_sign_BYTES as usize];
        let mut sig_len: u64 = 0;
        let ret = unsafe {
            crypto_sign_detached(
                signature.as_mut_ptr(),
                &mut sig_len,
                message.as_ptr(),
                message.len() as u64,
                secret_key.as_ptr(),
            )
        };

        if ret == 0 {
            Ok(signature)
        } else {
            Err(to_crypto_error())
        }
    }

    fn verify_detached(
        signature: Vec<u8>,
        message: Vec<u8>,
        public_key: Vec<u8>,
    ) -> Result<(), exports::libsodium::crypto::types::CryptoError> {
        if public_key.len() != crypto_sign_PUBLICKEYBYTES as usize {
            return Err(invalid_key());
        }
        if signature.len() != crypto_sign_BYTES as usize {
            return Err(verification_failed());
        }

        let ret = unsafe {
            crypto_sign_verify_detached(
                signature.as_ptr(),
                message.as_ptr(),
                message.len() as u64,
                public_key.as_ptr(),
            )
        };

        if ret == 0 {
            Ok(())
        } else {
            Err(verification_failed())
        }
    }

    fn ed25519_sk_to_pk(
        secret_key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if secret_key.len() != crypto_sign_SECRETKEYBYTES as usize {
            return Err(invalid_key());
        }

        let mut pk = vec![0u8; crypto_sign_PUBLICKEYBYTES as usize];
        let ret = unsafe {
            crypto_sign_ed25519_sk_to_pk(pk.as_mut_ptr(), secret_key.as_ptr())
        };

        if ret == 0 {
            Ok(pk)
        } else {
            Err(to_crypto_error())
        }
    }

    fn ed25519_sk_to_seed(
        secret_key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if secret_key.len() != crypto_sign_SECRETKEYBYTES as usize {
            return Err(invalid_key());
        }

        let mut seed = vec![0u8; crypto_sign_SEEDBYTES as usize];
        let ret = unsafe {
            crypto_sign_ed25519_sk_to_seed(seed.as_mut_ptr(), secret_key.as_ptr())
        };

        if ret == 0 {
            Ok(seed)
        } else {
            Err(to_crypto_error())
        }
    }

    fn ed25519_pk_to_curve25519(
        ed25519_pk: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if ed25519_pk.len() != crypto_sign_PUBLICKEYBYTES as usize {
            return Err(invalid_key());
        }

        let mut curve25519_pk = vec![0u8; crypto_scalarmult_curve25519_BYTES as usize];
        let ret = unsafe {
            crypto_sign_ed25519_pk_to_curve25519(curve25519_pk.as_mut_ptr(), ed25519_pk.as_ptr())
        };

        if ret == 0 {
            Ok(curve25519_pk)
        } else {
            Err(to_crypto_error())
        }
    }

    fn ed25519_sk_to_curve25519(
        ed25519_sk: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if ed25519_sk.len() != crypto_sign_SECRETKEYBYTES as usize {
            return Err(invalid_key());
        }

        let mut curve25519_sk = vec![0u8; crypto_scalarmult_curve25519_SCALARBYTES as usize];
        let ret = unsafe {
            crypto_sign_ed25519_sk_to_curve25519(curve25519_sk.as_mut_ptr(), ed25519_sk.as_ptr())
        };

        if ret == 0 {
            Ok(curve25519_sk)
        } else {
            Err(to_crypto_error())
        }
    }

    fn state_bytes() -> u32 {
        core::mem::size_of::<crypto_sign_ed25519ph_state>() as u32
    }

    fn init() -> Result<u64, exports::libsodium::crypto::types::CryptoError> {
        let mut state: crypto_sign_ed25519ph_state = unsafe { core::mem::zeroed() };
        let ret = unsafe { crypto_sign_ed25519ph_init(&mut state) };

        if ret == 0 {
            let id = next_state_id();
            sign_states().as_mut().unwrap().insert(id, state);
            Ok(id)
        } else {
            Err(to_crypto_error())
        }
    }

    fn update(
        state_id: u64,
        message: Vec<u8>,
    ) -> Result<(), exports::libsodium::crypto::types::CryptoError> {
        let mut guard = sign_states();
        let states = guard.as_mut().unwrap();
        let state = states.get_mut(&state_id).ok_or(to_crypto_error())?;

        let ret = unsafe {
            crypto_sign_ed25519ph_update(state, message.as_ptr(), message.len() as u64)
        };

        if ret == 0 {
            Ok(())
        } else {
            Err(to_crypto_error())
        }
    }

    fn final_create(
        state_id: u64,
        secret_key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if secret_key.len() != crypto_sign_SECRETKEYBYTES as usize {
            return Err(invalid_key());
        }

        let mut guard = sign_states();
        let states = guard.as_mut().unwrap();
        let state = states.get_mut(&state_id).ok_or(to_crypto_error())?;

        let mut signature = vec![0u8; crypto_sign_BYTES as usize];
        let mut sig_len: u64 = 0;
        let ret = unsafe {
            crypto_sign_ed25519ph_final_create(
                state,
                signature.as_mut_ptr(),
                &mut sig_len,
                secret_key.as_ptr(),
            )
        };

        // Remove state after finalizing
        states.remove(&state_id);

        if ret == 0 {
            Ok(signature)
        } else {
            Err(to_crypto_error())
        }
    }

    fn final_verify(
        state_id: u64,
        signature: Vec<u8>,
        public_key: Vec<u8>,
    ) -> Result<(), exports::libsodium::crypto::types::CryptoError> {
        if public_key.len() != crypto_sign_PUBLICKEYBYTES as usize {
            return Err(invalid_key());
        }
        if signature.len() != crypto_sign_BYTES as usize {
            return Err(verification_failed());
        }

        let mut guard = sign_states();
        let states = guard.as_mut().unwrap();
        let state = states.get_mut(&state_id).ok_or(to_crypto_error())?;

        let ret = unsafe {
            crypto_sign_ed25519ph_final_verify(
                state,
                signature.as_ptr(),
                public_key.as_ptr(),
            )
        };

        // Remove state after finalizing
        states.remove(&state_id);

        if ret == 0 {
            Ok(())
        } else {
            Err(verification_failed())
        }
    }

    fn destroy(state_id: u64) {
        let mut guard = sign_states();
        if let Some(states) = guard.as_mut() {
            states.remove(&state_id);
        }
    }
}

// ============================================================================
// Generic Hash
// ============================================================================

impl exports::libsodium::crypto::generichash::Guest for Component {
    fn bytes() -> u32 {
        crypto_generichash_BYTES
    }

    fn bytes_min() -> u32 {
        crypto_generichash_BYTES_MIN
    }

    fn bytes_max() -> u32 {
        crypto_generichash_BYTES_MAX
    }

    fn key_bytes() -> u32 {
        crypto_generichash_KEYBYTES
    }

    fn key_bytes_min() -> u32 {
        crypto_generichash_KEYBYTES_MIN
    }

    fn key_bytes_max() -> u32 {
        crypto_generichash_KEYBYTES_MAX
    }

    fn keygen() -> Vec<u8> {
        let mut key = vec![0u8; crypto_generichash_KEYBYTES as usize];
        unsafe {
            crypto_generichash_keygen(key.as_mut_ptr());
        }
        key
    }

    fn hash(
        message: Vec<u8>,
        out_len: u32,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if out_len < crypto_generichash_BYTES_MIN || out_len > crypto_generichash_BYTES_MAX {
            return Err(to_crypto_error());
        }

        let mut hash = vec![0u8; out_len as usize];
        let ret = unsafe {
            crypto_generichash(
                hash.as_mut_ptr(),
                out_len as usize,
                message.as_ptr(),
                message.len() as u64,
                core::ptr::null(),
                0,
            )
        };

        if ret == 0 {
            Ok(hash)
        } else {
            Err(to_crypto_error())
        }
    }

    fn hash_keyed(
        message: Vec<u8>,
        out_len: u32,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if out_len < crypto_generichash_BYTES_MIN || out_len > crypto_generichash_BYTES_MAX {
            return Err(to_crypto_error());
        }
        if !key.is_empty()
            && (key.len() < crypto_generichash_KEYBYTES_MIN as usize
                || key.len() > crypto_generichash_KEYBYTES_MAX as usize)
        {
            return Err(invalid_key());
        }

        let mut hash = vec![0u8; out_len as usize];
        let ret = unsafe {
            crypto_generichash(
                hash.as_mut_ptr(),
                out_len as usize,
                message.as_ptr(),
                message.len() as u64,
                key.as_ptr(),
                key.len(),
            )
        };

        if ret == 0 {
            Ok(hash)
        } else {
            Err(to_crypto_error())
        }
    }
}

// ============================================================================
// SHA-256
// ============================================================================

impl exports::libsodium::crypto::sha256::Guest for Component {
    fn bytes() -> u32 {
        crypto_hash_sha256_BYTES
    }

    fn hash(message: Vec<u8>) -> Vec<u8> {
        let mut hash = vec![0u8; crypto_hash_sha256_BYTES as usize];
        unsafe {
            crypto_hash_sha256(hash.as_mut_ptr(), message.as_ptr(), message.len() as u64);
        }
        hash
    }
}

// ============================================================================
// SHA-512
// ============================================================================

impl exports::libsodium::crypto::sha512::Guest for Component {
    fn bytes() -> u32 {
        crypto_hash_sha512_BYTES
    }

    fn hash(message: Vec<u8>) -> Vec<u8> {
        let mut hash = vec![0u8; crypto_hash_sha512_BYTES as usize];
        unsafe {
            crypto_hash_sha512(hash.as_mut_ptr(), message.as_ptr(), message.len() as u64);
        }
        hash
    }
}

// ============================================================================
// Auth
// ============================================================================

impl exports::libsodium::crypto::auth::Guest for Component {
    fn bytes() -> u32 {
        crypto_auth_BYTES
    }

    fn key_bytes() -> u32 {
        crypto_auth_KEYBYTES
    }

    fn keygen() -> Vec<u8> {
        let mut key = vec![0u8; crypto_auth_KEYBYTES as usize];
        unsafe {
            crypto_auth_keygen(key.as_mut_ptr());
        }
        key
    }

    fn auth(
        message: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if key.len() != crypto_auth_KEYBYTES as usize {
            return Err(invalid_key());
        }

        let mut tag = vec![0u8; crypto_auth_BYTES as usize];
        let ret = unsafe {
            crypto_auth(
                tag.as_mut_ptr(),
                message.as_ptr(),
                message.len() as u64,
                key.as_ptr(),
            )
        };

        if ret == 0 {
            Ok(tag)
        } else {
            Err(to_crypto_error())
        }
    }

    fn verify(
        tag: Vec<u8>,
        message: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<(), exports::libsodium::crypto::types::CryptoError> {
        if key.len() != crypto_auth_KEYBYTES as usize {
            return Err(invalid_key());
        }
        if tag.len() != crypto_auth_BYTES as usize {
            return Err(verification_failed());
        }

        let ret = unsafe {
            crypto_auth_verify(tag.as_ptr(), message.as_ptr(), message.len() as u64, key.as_ptr())
        };

        if ret == 0 {
            Ok(())
        } else {
            Err(verification_failed())
        }
    }
}

// ============================================================================
// AEAD XChaCha20-Poly1305
// ============================================================================

impl exports::libsodium::crypto::aead_xchacha20poly1305::Guest for Component {
    fn key_bytes() -> u32 {
        crypto_aead_xchacha20poly1305_ietf_KEYBYTES
    }

    fn nonce_bytes() -> u32 {
        crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
    }

    fn a_bytes() -> u32 {
        crypto_aead_xchacha20poly1305_ietf_ABYTES
    }

    fn keygen() -> Vec<u8> {
        let mut key = vec![0u8; crypto_aead_xchacha20poly1305_ietf_KEYBYTES as usize];
        unsafe {
            crypto_aead_xchacha20poly1305_ietf_keygen(key.as_mut_ptr());
        }
        key
    }

    fn encrypt(
        message: Vec<u8>,
        additional_data: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if key.len() != crypto_aead_xchacha20poly1305_ietf_KEYBYTES as usize {
            return Err(invalid_key());
        }
        if nonce.len() != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES as usize {
            return Err(invalid_nonce());
        }

        let mut ciphertext =
            vec![0u8; message.len() + crypto_aead_xchacha20poly1305_ietf_ABYTES as usize];
        let mut clen: u64 = 0;

        let ad_ptr = if additional_data.is_empty() {
            core::ptr::null()
        } else {
            additional_data.as_ptr()
        };

        let ret = unsafe {
            crypto_aead_xchacha20poly1305_ietf_encrypt(
                ciphertext.as_mut_ptr(),
                &mut clen,
                message.as_ptr(),
                message.len() as u64,
                ad_ptr,
                additional_data.len() as u64,
                core::ptr::null(),
                nonce.as_ptr(),
                key.as_ptr(),
            )
        };

        if ret == 0 {
            ciphertext.truncate(clen as usize);
            Ok(ciphertext)
        } else {
            Err(to_crypto_error())
        }
    }

    fn decrypt(
        ciphertext: Vec<u8>,
        additional_data: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if key.len() != crypto_aead_xchacha20poly1305_ietf_KEYBYTES as usize {
            return Err(invalid_key());
        }
        if nonce.len() != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES as usize {
            return Err(invalid_nonce());
        }
        if ciphertext.len() < crypto_aead_xchacha20poly1305_ietf_ABYTES as usize {
            return Err(verification_failed());
        }

        let mut message =
            vec![0u8; ciphertext.len() - crypto_aead_xchacha20poly1305_ietf_ABYTES as usize];
        let mut mlen: u64 = 0;

        let ad_ptr = if additional_data.is_empty() {
            core::ptr::null()
        } else {
            additional_data.as_ptr()
        };

        let ret = unsafe {
            crypto_aead_xchacha20poly1305_ietf_decrypt(
                message.as_mut_ptr(),
                &mut mlen,
                core::ptr::null_mut(),
                ciphertext.as_ptr(),
                ciphertext.len() as u64,
                ad_ptr,
                additional_data.len() as u64,
                nonce.as_ptr(),
                key.as_ptr(),
            )
        };

        if ret == 0 {
            message.truncate(mlen as usize);
            Ok(message)
        } else {
            Err(verification_failed())
        }
    }

    fn encrypt_detached(
        message: Vec<u8>,
        additional_data: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<(Vec<u8>, Vec<u8>), exports::libsodium::crypto::types::CryptoError> {
        if key.len() != crypto_aead_xchacha20poly1305_ietf_KEYBYTES as usize {
            return Err(invalid_key());
        }
        if nonce.len() != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES as usize {
            return Err(invalid_nonce());
        }

        let mut ciphertext = vec![0u8; message.len()];
        let mut mac = vec![0u8; crypto_aead_xchacha20poly1305_ietf_ABYTES as usize];
        let mut maclen: u64 = 0;

        let ad_ptr = if additional_data.is_empty() {
            core::ptr::null()
        } else {
            additional_data.as_ptr()
        };

        let ret = unsafe {
            crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
                ciphertext.as_mut_ptr(),
                mac.as_mut_ptr(),
                &mut maclen,
                message.as_ptr(),
                message.len() as u64,
                ad_ptr,
                additional_data.len() as u64,
                core::ptr::null(),
                nonce.as_ptr(),
                key.as_ptr(),
            )
        };

        if ret == 0 {
            Ok((ciphertext, mac))
        } else {
            Err(to_crypto_error())
        }
    }

    fn decrypt_detached(
        ciphertext: Vec<u8>,
        mac: Vec<u8>,
        additional_data: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if key.len() != crypto_aead_xchacha20poly1305_ietf_KEYBYTES as usize {
            return Err(invalid_key());
        }
        if nonce.len() != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES as usize {
            return Err(invalid_nonce());
        }
        if mac.len() != crypto_aead_xchacha20poly1305_ietf_ABYTES as usize {
            return Err(verification_failed());
        }

        let mut message = vec![0u8; ciphertext.len()];

        let ad_ptr = if additional_data.is_empty() {
            core::ptr::null()
        } else {
            additional_data.as_ptr()
        };

        let ret = unsafe {
            crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
                message.as_mut_ptr(),
                core::ptr::null_mut(),
                ciphertext.as_ptr(),
                ciphertext.len() as u64,
                mac.as_ptr(),
                ad_ptr,
                additional_data.len() as u64,
                nonce.as_ptr(),
                key.as_ptr(),
            )
        };

        if ret == 0 {
            Ok(message)
        } else {
            Err(verification_failed())
        }
    }
}

// ============================================================================
// AEAD ChaCha20-Poly1305-IETF
// ============================================================================

impl exports::libsodium::crypto::aead_chacha20poly1305_ietf::Guest for Component {
    fn key_bytes() -> u32 {
        crypto_aead_chacha20poly1305_ietf_KEYBYTES
    }

    fn nonce_bytes() -> u32 {
        crypto_aead_chacha20poly1305_ietf_NPUBBYTES
    }

    fn a_bytes() -> u32 {
        crypto_aead_chacha20poly1305_ietf_ABYTES
    }

    fn keygen() -> Vec<u8> {
        let mut key = vec![0u8; crypto_aead_chacha20poly1305_ietf_KEYBYTES as usize];
        unsafe {
            crypto_aead_chacha20poly1305_ietf_keygen(key.as_mut_ptr());
        }
        key
    }

    fn encrypt(
        message: Vec<u8>,
        additional_data: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if key.len() != crypto_aead_chacha20poly1305_ietf_KEYBYTES as usize {
            return Err(invalid_key());
        }
        if nonce.len() != crypto_aead_chacha20poly1305_ietf_NPUBBYTES as usize {
            return Err(invalid_nonce());
        }

        let mut ciphertext =
            vec![0u8; message.len() + crypto_aead_chacha20poly1305_ietf_ABYTES as usize];
        let mut clen: u64 = 0;

        let ad_ptr = if additional_data.is_empty() {
            core::ptr::null()
        } else {
            additional_data.as_ptr()
        };

        let ret = unsafe {
            crypto_aead_chacha20poly1305_ietf_encrypt(
                ciphertext.as_mut_ptr(),
                &mut clen,
                message.as_ptr(),
                message.len() as u64,
                ad_ptr,
                additional_data.len() as u64,
                core::ptr::null(),
                nonce.as_ptr(),
                key.as_ptr(),
            )
        };

        if ret == 0 {
            ciphertext.truncate(clen as usize);
            Ok(ciphertext)
        } else {
            Err(to_crypto_error())
        }
    }

    fn decrypt(
        ciphertext: Vec<u8>,
        additional_data: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if key.len() != crypto_aead_chacha20poly1305_ietf_KEYBYTES as usize {
            return Err(invalid_key());
        }
        if nonce.len() != crypto_aead_chacha20poly1305_ietf_NPUBBYTES as usize {
            return Err(invalid_nonce());
        }
        if ciphertext.len() < crypto_aead_chacha20poly1305_ietf_ABYTES as usize {
            return Err(verification_failed());
        }

        let mut message =
            vec![0u8; ciphertext.len() - crypto_aead_chacha20poly1305_ietf_ABYTES as usize];
        let mut mlen: u64 = 0;

        let ad_ptr = if additional_data.is_empty() {
            core::ptr::null()
        } else {
            additional_data.as_ptr()
        };

        let ret = unsafe {
            crypto_aead_chacha20poly1305_ietf_decrypt(
                message.as_mut_ptr(),
                &mut mlen,
                core::ptr::null_mut(),
                ciphertext.as_ptr(),
                ciphertext.len() as u64,
                ad_ptr,
                additional_data.len() as u64,
                nonce.as_ptr(),
                key.as_ptr(),
            )
        };

        if ret == 0 {
            message.truncate(mlen as usize);
            Ok(message)
        } else {
            Err(verification_failed())
        }
    }

    fn encrypt_detached(
        message: Vec<u8>,
        additional_data: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<(Vec<u8>, Vec<u8>), exports::libsodium::crypto::types::CryptoError> {
        if key.len() != crypto_aead_chacha20poly1305_ietf_KEYBYTES as usize {
            return Err(invalid_key());
        }
        if nonce.len() != crypto_aead_chacha20poly1305_ietf_NPUBBYTES as usize {
            return Err(invalid_nonce());
        }

        let mut ciphertext = vec![0u8; message.len()];
        let mut mac = vec![0u8; crypto_aead_chacha20poly1305_ietf_ABYTES as usize];
        let mut mac_len: u64 = 0;

        let ad_ptr = if additional_data.is_empty() {
            core::ptr::null()
        } else {
            additional_data.as_ptr()
        };

        let ret = unsafe {
            crypto_aead_chacha20poly1305_ietf_encrypt_detached(
                ciphertext.as_mut_ptr(),
                mac.as_mut_ptr(),
                &mut mac_len,
                message.as_ptr(),
                message.len() as u64,
                ad_ptr,
                additional_data.len() as u64,
                core::ptr::null(),
                nonce.as_ptr(),
                key.as_ptr(),
            )
        };

        if ret == 0 {
            Ok((ciphertext, mac))
        } else {
            Err(to_crypto_error())
        }
    }

    fn decrypt_detached(
        ciphertext: Vec<u8>,
        mac: Vec<u8>,
        additional_data: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if key.len() != crypto_aead_chacha20poly1305_ietf_KEYBYTES as usize {
            return Err(invalid_key());
        }
        if nonce.len() != crypto_aead_chacha20poly1305_ietf_NPUBBYTES as usize {
            return Err(invalid_nonce());
        }
        if mac.len() != crypto_aead_chacha20poly1305_ietf_ABYTES as usize {
            return Err(verification_failed());
        }

        let mut message = vec![0u8; ciphertext.len()];

        let ad_ptr = if additional_data.is_empty() {
            core::ptr::null()
        } else {
            additional_data.as_ptr()
        };

        let ret = unsafe {
            crypto_aead_chacha20poly1305_ietf_decrypt_detached(
                message.as_mut_ptr(),
                core::ptr::null_mut(),
                ciphertext.as_ptr(),
                ciphertext.len() as u64,
                mac.as_ptr(),
                ad_ptr,
                additional_data.len() as u64,
                nonce.as_ptr(),
                key.as_ptr(),
            )
        };

        if ret == 0 {
            Ok(message)
        } else {
            Err(verification_failed())
        }
    }
}

// ============================================================================
// AEAD ChaCha20-Poly1305 (original, 8-byte nonce)
// ============================================================================

impl exports::libsodium::crypto::aead_chacha20poly1305::Guest for Component {
    fn key_bytes() -> u32 {
        crypto_aead_chacha20poly1305_KEYBYTES
    }

    fn nonce_bytes() -> u32 {
        crypto_aead_chacha20poly1305_NPUBBYTES
    }

    fn a_bytes() -> u32 {
        crypto_aead_chacha20poly1305_ABYTES
    }

    fn keygen() -> Vec<u8> {
        let mut key = vec![0u8; crypto_aead_chacha20poly1305_KEYBYTES as usize];
        unsafe {
            crypto_aead_chacha20poly1305_keygen(key.as_mut_ptr());
        }
        key
    }

    fn encrypt(
        message: Vec<u8>,
        additional_data: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if key.len() != crypto_aead_chacha20poly1305_KEYBYTES as usize {
            return Err(invalid_key());
        }
        if nonce.len() != crypto_aead_chacha20poly1305_NPUBBYTES as usize {
            return Err(invalid_nonce());
        }

        let mut ciphertext =
            vec![0u8; message.len() + crypto_aead_chacha20poly1305_ABYTES as usize];
        let mut clen: u64 = 0;

        let ad_ptr = if additional_data.is_empty() {
            core::ptr::null()
        } else {
            additional_data.as_ptr()
        };

        let ret = unsafe {
            crypto_aead_chacha20poly1305_encrypt(
                ciphertext.as_mut_ptr(),
                &mut clen,
                message.as_ptr(),
                message.len() as u64,
                ad_ptr,
                additional_data.len() as u64,
                core::ptr::null(),
                nonce.as_ptr(),
                key.as_ptr(),
            )
        };

        if ret == 0 {
            ciphertext.truncate(clen as usize);
            Ok(ciphertext)
        } else {
            Err(to_crypto_error())
        }
    }

    fn decrypt(
        ciphertext: Vec<u8>,
        additional_data: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if key.len() != crypto_aead_chacha20poly1305_KEYBYTES as usize {
            return Err(invalid_key());
        }
        if nonce.len() != crypto_aead_chacha20poly1305_NPUBBYTES as usize {
            return Err(invalid_nonce());
        }
        if ciphertext.len() < crypto_aead_chacha20poly1305_ABYTES as usize {
            return Err(verification_failed());
        }

        let mut message =
            vec![0u8; ciphertext.len() - crypto_aead_chacha20poly1305_ABYTES as usize];
        let mut mlen: u64 = 0;

        let ad_ptr = if additional_data.is_empty() {
            core::ptr::null()
        } else {
            additional_data.as_ptr()
        };

        let ret = unsafe {
            crypto_aead_chacha20poly1305_decrypt(
                message.as_mut_ptr(),
                &mut mlen,
                core::ptr::null_mut(),
                ciphertext.as_ptr(),
                ciphertext.len() as u64,
                ad_ptr,
                additional_data.len() as u64,
                nonce.as_ptr(),
                key.as_ptr(),
            )
        };

        if ret == 0 {
            message.truncate(mlen as usize);
            Ok(message)
        } else {
            Err(verification_failed())
        }
    }

    fn encrypt_detached(
        message: Vec<u8>,
        additional_data: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<(Vec<u8>, Vec<u8>), exports::libsodium::crypto::types::CryptoError> {
        if key.len() != crypto_aead_chacha20poly1305_KEYBYTES as usize {
            return Err(invalid_key());
        }
        if nonce.len() != crypto_aead_chacha20poly1305_NPUBBYTES as usize {
            return Err(invalid_nonce());
        }

        let mut ciphertext = vec![0u8; message.len()];
        let mut mac = vec![0u8; crypto_aead_chacha20poly1305_ABYTES as usize];
        let mut mac_len: u64 = 0;

        let ad_ptr = if additional_data.is_empty() {
            core::ptr::null()
        } else {
            additional_data.as_ptr()
        };

        let ret = unsafe {
            crypto_aead_chacha20poly1305_encrypt_detached(
                ciphertext.as_mut_ptr(),
                mac.as_mut_ptr(),
                &mut mac_len,
                message.as_ptr(),
                message.len() as u64,
                ad_ptr,
                additional_data.len() as u64,
                core::ptr::null(),
                nonce.as_ptr(),
                key.as_ptr(),
            )
        };

        if ret == 0 {
            Ok((ciphertext, mac))
        } else {
            Err(to_crypto_error())
        }
    }

    fn decrypt_detached(
        ciphertext: Vec<u8>,
        mac: Vec<u8>,
        additional_data: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if key.len() != crypto_aead_chacha20poly1305_KEYBYTES as usize {
            return Err(invalid_key());
        }
        if nonce.len() != crypto_aead_chacha20poly1305_NPUBBYTES as usize {
            return Err(invalid_nonce());
        }
        if mac.len() != crypto_aead_chacha20poly1305_ABYTES as usize {
            return Err(verification_failed());
        }

        let mut message = vec![0u8; ciphertext.len()];

        let ad_ptr = if additional_data.is_empty() {
            core::ptr::null()
        } else {
            additional_data.as_ptr()
        };

        let ret = unsafe {
            crypto_aead_chacha20poly1305_decrypt_detached(
                message.as_mut_ptr(),
                core::ptr::null_mut(),
                ciphertext.as_ptr(),
                ciphertext.len() as u64,
                mac.as_ptr(),
                ad_ptr,
                additional_data.len() as u64,
                nonce.as_ptr(),
                key.as_ptr(),
            )
        };

        if ret == 0 {
            Ok(message)
        } else {
            Err(verification_failed())
        }
    }
}

// ============================================================================
// AEAD AEGIS-128L
// ============================================================================

impl exports::libsodium::crypto::aead_aegis128l::Guest for Component {
    fn key_bytes() -> u32 {
        crypto_aead_aegis128l_KEYBYTES
    }

    fn nonce_bytes() -> u32 {
        crypto_aead_aegis128l_NPUBBYTES
    }

    fn a_bytes() -> u32 {
        crypto_aead_aegis128l_ABYTES
    }

    fn keygen() -> Vec<u8> {
        let mut key = vec![0u8; crypto_aead_aegis128l_KEYBYTES as usize];
        unsafe {
            crypto_aead_aegis128l_keygen(key.as_mut_ptr());
        }
        key
    }

    fn encrypt(
        message: Vec<u8>,
        additional_data: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if key.len() != crypto_aead_aegis128l_KEYBYTES as usize {
            return Err(invalid_key());
        }
        if nonce.len() != crypto_aead_aegis128l_NPUBBYTES as usize {
            return Err(invalid_nonce());
        }

        let mut ciphertext = vec![0u8; message.len() + crypto_aead_aegis128l_ABYTES as usize];
        let mut clen: u64 = 0;

        let ad_ptr = if additional_data.is_empty() {
            core::ptr::null()
        } else {
            additional_data.as_ptr()
        };

        let ret = unsafe {
            crypto_aead_aegis128l_encrypt(
                ciphertext.as_mut_ptr(),
                &mut clen,
                message.as_ptr(),
                message.len() as u64,
                ad_ptr,
                additional_data.len() as u64,
                core::ptr::null(),
                nonce.as_ptr(),
                key.as_ptr(),
            )
        };

        if ret == 0 {
            ciphertext.truncate(clen as usize);
            Ok(ciphertext)
        } else {
            Err(to_crypto_error())
        }
    }

    fn decrypt(
        ciphertext: Vec<u8>,
        additional_data: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if key.len() != crypto_aead_aegis128l_KEYBYTES as usize {
            return Err(invalid_key());
        }
        if nonce.len() != crypto_aead_aegis128l_NPUBBYTES as usize {
            return Err(invalid_nonce());
        }
        if ciphertext.len() < crypto_aead_aegis128l_ABYTES as usize {
            return Err(verification_failed());
        }

        let mut message = vec![0u8; ciphertext.len() - crypto_aead_aegis128l_ABYTES as usize];
        let mut mlen: u64 = 0;

        let ad_ptr = if additional_data.is_empty() {
            core::ptr::null()
        } else {
            additional_data.as_ptr()
        };

        let ret = unsafe {
            crypto_aead_aegis128l_decrypt(
                message.as_mut_ptr(),
                &mut mlen,
                core::ptr::null_mut(),
                ciphertext.as_ptr(),
                ciphertext.len() as u64,
                ad_ptr,
                additional_data.len() as u64,
                nonce.as_ptr(),
                key.as_ptr(),
            )
        };

        if ret == 0 {
            message.truncate(mlen as usize);
            Ok(message)
        } else {
            Err(verification_failed())
        }
    }

    fn encrypt_detached(
        message: Vec<u8>,
        additional_data: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<(Vec<u8>, Vec<u8>), exports::libsodium::crypto::types::CryptoError> {
        if key.len() != crypto_aead_aegis128l_KEYBYTES as usize {
            return Err(invalid_key());
        }
        if nonce.len() != crypto_aead_aegis128l_NPUBBYTES as usize {
            return Err(invalid_nonce());
        }

        let mut ciphertext = vec![0u8; message.len()];
        let mut mac = vec![0u8; crypto_aead_aegis128l_ABYTES as usize];
        let mut mac_len: u64 = 0;

        let ad_ptr = if additional_data.is_empty() {
            core::ptr::null()
        } else {
            additional_data.as_ptr()
        };

        let ret = unsafe {
            crypto_aead_aegis128l_encrypt_detached(
                ciphertext.as_mut_ptr(),
                mac.as_mut_ptr(),
                &mut mac_len,
                message.as_ptr(),
                message.len() as u64,
                ad_ptr,
                additional_data.len() as u64,
                core::ptr::null(),
                nonce.as_ptr(),
                key.as_ptr(),
            )
        };

        if ret == 0 {
            Ok((ciphertext, mac))
        } else {
            Err(to_crypto_error())
        }
    }

    fn decrypt_detached(
        ciphertext: Vec<u8>,
        mac: Vec<u8>,
        additional_data: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if key.len() != crypto_aead_aegis128l_KEYBYTES as usize {
            return Err(invalid_key());
        }
        if nonce.len() != crypto_aead_aegis128l_NPUBBYTES as usize {
            return Err(invalid_nonce());
        }
        if mac.len() != crypto_aead_aegis128l_ABYTES as usize {
            return Err(verification_failed());
        }

        let mut message = vec![0u8; ciphertext.len()];

        let ad_ptr = if additional_data.is_empty() {
            core::ptr::null()
        } else {
            additional_data.as_ptr()
        };

        let ret = unsafe {
            crypto_aead_aegis128l_decrypt_detached(
                message.as_mut_ptr(),
                core::ptr::null_mut(),
                ciphertext.as_ptr(),
                ciphertext.len() as u64,
                mac.as_ptr(),
                ad_ptr,
                additional_data.len() as u64,
                nonce.as_ptr(),
                key.as_ptr(),
            )
        };

        if ret == 0 {
            Ok(message)
        } else {
            Err(verification_failed())
        }
    }
}

// ============================================================================
// AEAD AEGIS-256
// ============================================================================

impl exports::libsodium::crypto::aead_aegis256::Guest for Component {
    fn key_bytes() -> u32 {
        crypto_aead_aegis256_KEYBYTES
    }

    fn nonce_bytes() -> u32 {
        crypto_aead_aegis256_NPUBBYTES
    }

    fn a_bytes() -> u32 {
        crypto_aead_aegis256_ABYTES
    }

    fn keygen() -> Vec<u8> {
        let mut key = vec![0u8; crypto_aead_aegis256_KEYBYTES as usize];
        unsafe {
            crypto_aead_aegis256_keygen(key.as_mut_ptr());
        }
        key
    }

    fn encrypt(
        message: Vec<u8>,
        additional_data: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if key.len() != crypto_aead_aegis256_KEYBYTES as usize {
            return Err(invalid_key());
        }
        if nonce.len() != crypto_aead_aegis256_NPUBBYTES as usize {
            return Err(invalid_nonce());
        }

        let mut ciphertext = vec![0u8; message.len() + crypto_aead_aegis256_ABYTES as usize];
        let mut clen: u64 = 0;

        let ad_ptr = if additional_data.is_empty() {
            core::ptr::null()
        } else {
            additional_data.as_ptr()
        };

        let ret = unsafe {
            crypto_aead_aegis256_encrypt(
                ciphertext.as_mut_ptr(),
                &mut clen,
                message.as_ptr(),
                message.len() as u64,
                ad_ptr,
                additional_data.len() as u64,
                core::ptr::null(),
                nonce.as_ptr(),
                key.as_ptr(),
            )
        };

        if ret == 0 {
            ciphertext.truncate(clen as usize);
            Ok(ciphertext)
        } else {
            Err(to_crypto_error())
        }
    }

    fn decrypt(
        ciphertext: Vec<u8>,
        additional_data: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if key.len() != crypto_aead_aegis256_KEYBYTES as usize {
            return Err(invalid_key());
        }
        if nonce.len() != crypto_aead_aegis256_NPUBBYTES as usize {
            return Err(invalid_nonce());
        }
        if ciphertext.len() < crypto_aead_aegis256_ABYTES as usize {
            return Err(verification_failed());
        }

        let mut message = vec![0u8; ciphertext.len() - crypto_aead_aegis256_ABYTES as usize];
        let mut mlen: u64 = 0;

        let ad_ptr = if additional_data.is_empty() {
            core::ptr::null()
        } else {
            additional_data.as_ptr()
        };

        let ret = unsafe {
            crypto_aead_aegis256_decrypt(
                message.as_mut_ptr(),
                &mut mlen,
                core::ptr::null_mut(),
                ciphertext.as_ptr(),
                ciphertext.len() as u64,
                ad_ptr,
                additional_data.len() as u64,
                nonce.as_ptr(),
                key.as_ptr(),
            )
        };

        if ret == 0 {
            message.truncate(mlen as usize);
            Ok(message)
        } else {
            Err(verification_failed())
        }
    }

    fn encrypt_detached(
        message: Vec<u8>,
        additional_data: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<(Vec<u8>, Vec<u8>), exports::libsodium::crypto::types::CryptoError> {
        if key.len() != crypto_aead_aegis256_KEYBYTES as usize {
            return Err(invalid_key());
        }
        if nonce.len() != crypto_aead_aegis256_NPUBBYTES as usize {
            return Err(invalid_nonce());
        }

        let mut ciphertext = vec![0u8; message.len()];
        let mut mac = vec![0u8; crypto_aead_aegis256_ABYTES as usize];
        let mut mac_len: u64 = 0;

        let ad_ptr = if additional_data.is_empty() {
            core::ptr::null()
        } else {
            additional_data.as_ptr()
        };

        let ret = unsafe {
            crypto_aead_aegis256_encrypt_detached(
                ciphertext.as_mut_ptr(),
                mac.as_mut_ptr(),
                &mut mac_len,
                message.as_ptr(),
                message.len() as u64,
                ad_ptr,
                additional_data.len() as u64,
                core::ptr::null(),
                nonce.as_ptr(),
                key.as_ptr(),
            )
        };

        if ret == 0 {
            Ok((ciphertext, mac))
        } else {
            Err(to_crypto_error())
        }
    }

    fn decrypt_detached(
        ciphertext: Vec<u8>,
        mac: Vec<u8>,
        additional_data: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if key.len() != crypto_aead_aegis256_KEYBYTES as usize {
            return Err(invalid_key());
        }
        if nonce.len() != crypto_aead_aegis256_NPUBBYTES as usize {
            return Err(invalid_nonce());
        }
        if mac.len() != crypto_aead_aegis256_ABYTES as usize {
            return Err(verification_failed());
        }

        let mut message = vec![0u8; ciphertext.len()];

        let ad_ptr = if additional_data.is_empty() {
            core::ptr::null()
        } else {
            additional_data.as_ptr()
        };

        let ret = unsafe {
            crypto_aead_aegis256_decrypt_detached(
                message.as_mut_ptr(),
                core::ptr::null_mut(),
                ciphertext.as_ptr(),
                ciphertext.len() as u64,
                mac.as_ptr(),
                ad_ptr,
                additional_data.len() as u64,
                nonce.as_ptr(),
                key.as_ptr(),
            )
        };

        if ret == 0 {
            Ok(message)
        } else {
            Err(verification_failed())
        }
    }
}

// ============================================================================
// Password Hashing
// ============================================================================

impl exports::libsodium::crypto::pwhash::Guest for Component {
    fn salt_bytes() -> u32 {
        crypto_pwhash_SALTBYTES
    }

    fn str_bytes() -> u32 {
        crypto_pwhash_STRBYTES
    }

    fn bytes_min() -> u32 {
        crypto_pwhash_BYTES_MIN
    }

    fn bytes_max() -> u32 {
        unsafe { crypto_pwhash_bytes_max() as u32 }
    }

    fn passwd_min() -> u32 {
        crypto_pwhash_PASSWD_MIN
    }

    fn passwd_max() -> u32 {
        crypto_pwhash_PASSWD_MAX
    }

    fn opslimit_min() -> u64 {
        crypto_pwhash_OPSLIMIT_MIN as u64
    }

    fn opslimit_max() -> u64 {
        crypto_pwhash_OPSLIMIT_MAX as u64
    }

    fn opslimit_interactive() -> u64 {
        crypto_pwhash_OPSLIMIT_INTERACTIVE as u64
    }

    fn opslimit_moderate() -> u64 {
        crypto_pwhash_OPSLIMIT_MODERATE as u64
    }

    fn opslimit_sensitive() -> u64 {
        crypto_pwhash_OPSLIMIT_SENSITIVE as u64
    }

    fn memlimit_min() -> u64 {
        crypto_pwhash_MEMLIMIT_MIN as u64
    }

    fn memlimit_interactive() -> u64 {
        crypto_pwhash_MEMLIMIT_INTERACTIVE as u64
    }

    fn memlimit_moderate() -> u64 {
        crypto_pwhash_MEMLIMIT_MODERATE as u64
    }

    fn memlimit_sensitive() -> u64 {
        crypto_pwhash_MEMLIMIT_SENSITIVE as u64
    }

    fn memlimit_max() -> u64 {
        unsafe { crypto_pwhash_memlimit_max() as u64 }
    }

    fn alg_argon2i13() -> i32 {
        crypto_pwhash_ALG_ARGON2I13 as i32
    }

    fn alg_argon2id13() -> i32 {
        crypto_pwhash_ALG_ARGON2ID13 as i32
    }

    fn alg_default() -> i32 {
        crypto_pwhash_ALG_DEFAULT as i32
    }

    fn strprefix() -> String {
        unsafe {
            let ptr = crypto_pwhash_strprefix();
            let mut len = 0;
            while *ptr.add(len) != 0 {
                len += 1;
            }
            let slice = core::slice::from_raw_parts(ptr as *const u8, len);
            String::from_utf8_lossy(slice).into_owned()
        }
    }

    fn derive(
        out_len: u32,
        password: Vec<u8>,
        salt: Vec<u8>,
        opslimit: u64,
        memlimit: u64,
        alg: i32,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if salt.len() != crypto_pwhash_SALTBYTES as usize {
            return Err(to_crypto_error());
        }

        let mut out = vec![0u8; out_len as usize];
        let ret = unsafe {
            crypto_pwhash(
                out.as_mut_ptr(),
                out_len as u64,
                password.as_ptr() as *const i8,
                password.len() as u64,
                salt.as_ptr(),
                opslimit,
                memlimit as usize,
                alg,
            )
        };

        if ret == 0 {
            Ok(out)
        } else {
            Err(to_crypto_error())
        }
    }

    fn str(
        password: Vec<u8>,
        opslimit: u64,
        memlimit: u64,
    ) -> Result<String, exports::libsodium::crypto::types::CryptoError> {
        let mut out = vec![0u8; crypto_pwhash_STRBYTES as usize];
        let ret = unsafe {
            crypto_pwhash_str(
                out.as_mut_ptr() as *mut i8,
                password.as_ptr() as *const i8,
                password.len() as u64,
                opslimit,
                memlimit as usize,
            )
        };

        if ret == 0 {
            // Find the null terminator
            let len = out.iter().position(|&c| c == 0).unwrap_or(out.len());
            Ok(String::from_utf8_lossy(&out[..len]).into_owned())
        } else {
            Err(to_crypto_error())
        }
    }

    fn str_verify(
        hash: String,
        password: Vec<u8>,
    ) -> Result<(), exports::libsodium::crypto::types::CryptoError> {
        let hash_bytes = hash.as_bytes();
        if hash_bytes.len() >= crypto_pwhash_STRBYTES as usize {
            return Err(verification_failed());
        }

        // Create null-terminated string
        let mut hash_buf = vec![0u8; crypto_pwhash_STRBYTES as usize];
        hash_buf[..hash_bytes.len()].copy_from_slice(hash_bytes);

        let ret = unsafe {
            crypto_pwhash_str_verify(
                hash_buf.as_ptr() as *const i8,
                password.as_ptr() as *const i8,
                password.len() as u64,
            )
        };

        if ret == 0 {
            Ok(())
        } else {
            Err(verification_failed())
        }
    }

    fn str_needs_rehash(
        hash: String,
        opslimit: u64,
        memlimit: u64,
    ) -> Result<bool, exports::libsodium::crypto::types::CryptoError> {
        let hash_bytes = hash.as_bytes();
        if hash_bytes.len() >= crypto_pwhash_STRBYTES as usize {
            return Err(to_crypto_error());
        }

        // Create null-terminated string
        let mut hash_buf = vec![0u8; crypto_pwhash_STRBYTES as usize];
        hash_buf[..hash_bytes.len()].copy_from_slice(hash_bytes);

        let ret = unsafe {
            crypto_pwhash_str_needs_rehash(
                hash_buf.as_ptr() as *const i8,
                opslimit,
                memlimit as usize,
            )
        };

        match ret {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(to_crypto_error()),
        }
    }
}

// ============================================================================
// KDF
// ============================================================================

impl exports::libsodium::crypto::kdf::Guest for Component {
    fn key_bytes() -> u32 {
        crypto_kdf_KEYBYTES
    }

    fn context_bytes() -> u32 {
        crypto_kdf_CONTEXTBYTES
    }

    fn bytes_min() -> u32 {
        crypto_kdf_BYTES_MIN
    }

    fn bytes_max() -> u32 {
        crypto_kdf_BYTES_MAX
    }

    fn keygen() -> Vec<u8> {
        let mut key = vec![0u8; crypto_kdf_KEYBYTES as usize];
        unsafe {
            crypto_kdf_keygen(key.as_mut_ptr());
        }
        key
    }

    fn derive_from_key(
        subkey_len: u32,
        subkey_id: u64,
        context: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if key.len() != crypto_kdf_KEYBYTES as usize {
            return Err(invalid_key());
        }
        if context.len() != crypto_kdf_CONTEXTBYTES as usize {
            return Err(to_crypto_error());
        }
        if subkey_len < crypto_kdf_BYTES_MIN || subkey_len > crypto_kdf_BYTES_MAX {
            return Err(to_crypto_error());
        }

        let mut subkey = vec![0u8; subkey_len as usize];
        let ret = unsafe {
            crypto_kdf_derive_from_key(
                subkey.as_mut_ptr(),
                subkey_len as usize,
                subkey_id,
                context.as_ptr() as *const i8,
                key.as_ptr(),
            )
        };

        if ret == 0 {
            Ok(subkey)
        } else {
            Err(to_crypto_error())
        }
    }

    fn primitive() -> String {
        unsafe {
            let ptr = crypto_kdf_primitive();
            let mut len = 0;
            while *ptr.add(len) != 0 {
                len += 1;
            }
            let slice = core::slice::from_raw_parts(ptr as *const u8, len);
            String::from_utf8_lossy(slice).into_owned()
        }
    }
}

// ============================================================================
// KDF HKDF-SHA256
// ============================================================================

impl exports::libsodium::crypto::kdf_hkdf_sha256::Guest for Component {
    fn key_bytes() -> u32 {
        crypto_kdf_hkdf_sha256_KEYBYTES
    }

    fn extract(salt: Vec<u8>, ikm: Vec<u8>) -> Vec<u8> {
        let mut prk = vec![0u8; crypto_kdf_hkdf_sha256_KEYBYTES as usize];
        let salt_ptr = if salt.is_empty() {
            core::ptr::null()
        } else {
            salt.as_ptr()
        };
        unsafe {
            crypto_kdf_hkdf_sha256_extract(
                prk.as_mut_ptr(),
                salt_ptr,
                salt.len(),
                ikm.as_ptr(),
                ikm.len(),
            );
        }
        prk
    }

    fn expand(
        out_len: u32,
        prk: Vec<u8>,
        info: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if prk.len() != crypto_kdf_hkdf_sha256_KEYBYTES as usize {
            return Err(invalid_key());
        }
        if out_len > crypto_kdf_hkdf_sha256_BYTES_MAX {
            return Err(to_crypto_error());
        }

        let mut out = vec![0u8; out_len as usize];
        let info_ptr = if info.is_empty() {
            core::ptr::null()
        } else {
            info.as_ptr()
        };

        let ret = unsafe {
            crypto_kdf_hkdf_sha256_expand(
                out.as_mut_ptr(),
                out_len as usize,
                info_ptr as *const i8,
                info.len(),
                prk.as_ptr(),
            )
        };

        if ret == 0 {
            Ok(out)
        } else {
            Err(to_crypto_error())
        }
    }

    fn bytes_min() -> u32 {
        0
    }

    fn bytes_max() -> u32 {
        crypto_kdf_hkdf_sha256_BYTES_MAX
    }

    fn keygen() -> Vec<u8> {
        let mut key = vec![0u8; crypto_kdf_hkdf_sha256_KEYBYTES as usize];
        unsafe {
            crypto_kdf_hkdf_sha256_keygen(key.as_mut_ptr());
        }
        key
    }

    fn extract_init(salt: Vec<u8>) -> Result<u64, exports::libsodium::crypto::types::CryptoError> {
        let mut state: crypto_kdf_hkdf_sha256_state = unsafe { core::mem::zeroed() };
        let salt_ptr = if salt.is_empty() {
            core::ptr::null()
        } else {
            salt.as_ptr()
        };
        let ret = unsafe { crypto_kdf_hkdf_sha256_extract_init(&mut state, salt_ptr, salt.len()) };

        if ret == 0 {
            let id = next_state_id();
            hkdf_sha256_states().as_mut().unwrap().insert(id, state);
            Ok(id)
        } else {
            Err(to_crypto_error())
        }
    }

    fn extract_update(state_id: u64, ikm: Vec<u8>) -> Result<(), exports::libsodium::crypto::types::CryptoError> {
        let mut guard = hkdf_sha256_states();
        let states = guard.as_mut().unwrap();
        let state = states.get_mut(&state_id).ok_or(to_crypto_error())?;

        let ret = unsafe { crypto_kdf_hkdf_sha256_extract_update(state, ikm.as_ptr(), ikm.len()) };

        if ret == 0 {
            Ok(())
        } else {
            Err(to_crypto_error())
        }
    }

    fn extract_final(state_id: u64) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        let mut guard = hkdf_sha256_states();
        let states = guard.as_mut().unwrap();
        let state = states.get_mut(&state_id).ok_or(to_crypto_error())?;

        let mut prk = vec![0u8; crypto_kdf_hkdf_sha256_KEYBYTES as usize];
        let ret = unsafe { crypto_kdf_hkdf_sha256_extract_final(state, prk.as_mut_ptr()) };

        states.remove(&state_id);

        if ret == 0 {
            Ok(prk)
        } else {
            Err(to_crypto_error())
        }
    }
}

// ============================================================================
// Key Exchange
// ============================================================================

impl exports::libsodium::crypto::kx::Guest for Component {
    fn public_key_bytes() -> u32 {
        crypto_kx_PUBLICKEYBYTES
    }

    fn secret_key_bytes() -> u32 {
        crypto_kx_SECRETKEYBYTES
    }

    fn seed_bytes() -> u32 {
        crypto_kx_SEEDBYTES
    }

    fn session_key_bytes() -> u32 {
        crypto_kx_SESSIONKEYBYTES
    }

    fn keypair() -> exports::libsodium::crypto::types::KxKeyPair {
        let mut pk = vec![0u8; crypto_kx_PUBLICKEYBYTES as usize];
        let mut sk = vec![0u8; crypto_kx_SECRETKEYBYTES as usize];
        unsafe {
            crypto_kx_keypair(pk.as_mut_ptr(), sk.as_mut_ptr());
        }
        exports::libsodium::crypto::types::KxKeyPair {
            public_key: pk,
            secret_key: sk,
        }
    }

    fn seed_keypair(
        seed: Vec<u8>,
    ) -> Result<exports::libsodium::crypto::types::KxKeyPair, exports::libsodium::crypto::types::CryptoError>
    {
        if seed.len() != crypto_kx_SEEDBYTES as usize {
            return Err(invalid_key());
        }

        let mut pk = vec![0u8; crypto_kx_PUBLICKEYBYTES as usize];
        let mut sk = vec![0u8; crypto_kx_SECRETKEYBYTES as usize];
        let ret = unsafe {
            crypto_kx_seed_keypair(pk.as_mut_ptr(), sk.as_mut_ptr(), seed.as_ptr())
        };

        if ret == 0 {
            Ok(exports::libsodium::crypto::types::KxKeyPair {
                public_key: pk,
                secret_key: sk,
            })
        } else {
            Err(to_crypto_error())
        }
    }

    fn client_session_keys(
        client_pk: Vec<u8>,
        client_sk: Vec<u8>,
        server_pk: Vec<u8>,
    ) -> Result<exports::libsodium::crypto::types::SessionKeys, exports::libsodium::crypto::types::CryptoError>
    {
        if client_pk.len() != crypto_kx_PUBLICKEYBYTES as usize {
            return Err(invalid_key());
        }
        if client_sk.len() != crypto_kx_SECRETKEYBYTES as usize {
            return Err(invalid_key());
        }
        if server_pk.len() != crypto_kx_PUBLICKEYBYTES as usize {
            return Err(invalid_key());
        }

        let mut rx = vec![0u8; crypto_kx_SESSIONKEYBYTES as usize];
        let mut tx = vec![0u8; crypto_kx_SESSIONKEYBYTES as usize];
        let ret = unsafe {
            crypto_kx_client_session_keys(
                rx.as_mut_ptr(),
                tx.as_mut_ptr(),
                client_pk.as_ptr(),
                client_sk.as_ptr(),
                server_pk.as_ptr(),
            )
        };

        if ret == 0 {
            Ok(exports::libsodium::crypto::types::SessionKeys { rx, tx })
        } else {
            Err(to_crypto_error())
        }
    }

    fn server_session_keys(
        server_pk: Vec<u8>,
        server_sk: Vec<u8>,
        client_pk: Vec<u8>,
    ) -> Result<exports::libsodium::crypto::types::SessionKeys, exports::libsodium::crypto::types::CryptoError>
    {
        if server_pk.len() != crypto_kx_PUBLICKEYBYTES as usize {
            return Err(invalid_key());
        }
        if server_sk.len() != crypto_kx_SECRETKEYBYTES as usize {
            return Err(invalid_key());
        }
        if client_pk.len() != crypto_kx_PUBLICKEYBYTES as usize {
            return Err(invalid_key());
        }

        let mut rx = vec![0u8; crypto_kx_SESSIONKEYBYTES as usize];
        let mut tx = vec![0u8; crypto_kx_SESSIONKEYBYTES as usize];
        let ret = unsafe {
            crypto_kx_server_session_keys(
                rx.as_mut_ptr(),
                tx.as_mut_ptr(),
                server_pk.as_ptr(),
                server_sk.as_ptr(),
                client_pk.as_ptr(),
            )
        };

        if ret == 0 {
            Ok(exports::libsodium::crypto::types::SessionKeys { rx, tx })
        } else {
            Err(to_crypto_error())
        }
    }

    fn primitive() -> String {
        unsafe {
            let ptr = crypto_kx_primitive();
            let mut len = 0;
            while *ptr.add(len) != 0 {
                len += 1;
            }
            let slice = core::slice::from_raw_parts(ptr as *const u8, len);
            String::from_utf8_lossy(slice).into_owned()
        }
    }
}

// ============================================================================
// Scalar Multiplication
// ============================================================================

impl exports::libsodium::crypto::scalarmult::Guest for Component {
    fn scalar_bytes() -> u32 {
        crypto_scalarmult_SCALARBYTES
    }

    fn bytes() -> u32 {
        crypto_scalarmult_BYTES
    }

    fn scalarmult(
        n: Vec<u8>,
        p: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if n.len() != crypto_scalarmult_SCALARBYTES as usize {
            return Err(invalid_key());
        }
        if p.len() != crypto_scalarmult_BYTES as usize {
            return Err(to_crypto_error());
        }

        let mut q = vec![0u8; crypto_scalarmult_BYTES as usize];
        let ret = unsafe { crypto_scalarmult(q.as_mut_ptr(), n.as_ptr(), p.as_ptr()) };

        if ret == 0 {
            Ok(q)
        } else {
            Err(to_crypto_error())
        }
    }

    fn base(n: Vec<u8>) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if n.len() != crypto_scalarmult_SCALARBYTES as usize {
            return Err(invalid_key());
        }

        let mut q = vec![0u8; crypto_scalarmult_BYTES as usize];
        let ret = unsafe { crypto_scalarmult_base(q.as_mut_ptr(), n.as_ptr()) };

        if ret == 0 {
            Ok(q)
        } else {
            Err(to_crypto_error())
        }
    }
}

// ============================================================================
// Utils
// ============================================================================

impl exports::libsodium::crypto::utils::Guest for Component {
    fn memzero(mut data: Vec<u8>) -> Vec<u8> {
        unsafe {
            sodium_memzero(data.as_mut_ptr() as *mut libc::c_void, data.len());
        }
        data
    }

    fn memcmp(a: Vec<u8>, b: Vec<u8>) -> Result<bool, exports::libsodium::crypto::types::CryptoError> {
        if a.len() != b.len() {
            return Err(to_crypto_error());
        }

        let ret = unsafe {
            sodium_memcmp(
                a.as_ptr() as *const libc::c_void,
                b.as_ptr() as *const libc::c_void,
                a.len(),
            )
        };

        Ok(ret == 0)
    }

    fn increment(mut data: Vec<u8>) -> Vec<u8> {
        unsafe {
            sodium_increment(data.as_mut_ptr(), data.len());
        }
        data
    }

    fn add(mut a: Vec<u8>, b: Vec<u8>) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if a.len() != b.len() {
            return Err(to_crypto_error());
        }

        unsafe {
            sodium_add(a.as_mut_ptr(), b.as_ptr(), a.len());
        }
        Ok(a)
    }

    fn sub(mut a: Vec<u8>, b: Vec<u8>) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if a.len() != b.len() {
            return Err(to_crypto_error());
        }

        unsafe {
            sodium_sub(a.as_mut_ptr(), b.as_ptr(), a.len());
        }
        Ok(a)
    }

    fn compare(a: Vec<u8>, b: Vec<u8>) -> i32 {
        if a.len() != b.len() {
            return if a.len() < b.len() { -1 } else { 1 };
        }

        unsafe { sodium_compare(a.as_ptr(), b.as_ptr(), a.len()) }
    }

    fn is_zero(data: Vec<u8>) -> bool {
        unsafe { sodium_is_zero(data.as_ptr(), data.len()) == 1 }
    }

    fn bin2hex(data: Vec<u8>) -> String {
        let hex_len = data.len() * 2 + 1;
        let mut hex = vec![0u8; hex_len];
        unsafe {
            sodium_bin2hex(
                hex.as_mut_ptr() as *mut i8,
                hex_len,
                data.as_ptr(),
                data.len(),
            );
        }
        // Remove null terminator
        hex.pop();
        String::from_utf8_lossy(&hex).into_owned()
    }

    fn hex2bin(hex: String) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        let hex_bytes = hex.as_bytes();
        let max_bin_len = hex_bytes.len() / 2;
        let mut bin = vec![0u8; max_bin_len];
        let mut bin_len: usize = 0;

        let ret = unsafe {
            sodium_hex2bin(
                bin.as_mut_ptr(),
                max_bin_len,
                hex_bytes.as_ptr() as *const i8,
                hex_bytes.len(),
                core::ptr::null(),
                &mut bin_len,
                core::ptr::null_mut(),
            )
        };

        if ret == 0 {
            bin.truncate(bin_len);
            Ok(bin)
        } else {
            Err(to_crypto_error())
        }
    }

    fn bin2base64(data: Vec<u8>) -> String {
        // Calculate base64 length (standard variant, no line breaks)
        let b64_len = unsafe { sodium_base64_encoded_len(data.len(), sodium_base64_VARIANT_ORIGINAL as i32) };
        let mut b64 = vec![0u8; b64_len];
        unsafe {
            sodium_bin2base64(
                b64.as_mut_ptr() as *mut i8,
                b64_len,
                data.as_ptr(),
                data.len(),
                sodium_base64_VARIANT_ORIGINAL as i32,
            );
        }
        // Remove null terminator
        while b64.last() == Some(&0) {
            b64.pop();
        }
        String::from_utf8_lossy(&b64).into_owned()
    }

    fn base642bin(base64: String) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        let b64_bytes = base64.as_bytes();
        // Max decoded size is roughly 3/4 of encoded size
        let max_bin_len = b64_bytes.len() * 3 / 4 + 3;
        let mut bin = vec![0u8; max_bin_len];
        let mut bin_len: usize = 0;

        let ret = unsafe {
            sodium_base642bin(
                bin.as_mut_ptr(),
                max_bin_len,
                b64_bytes.as_ptr() as *const i8,
                b64_bytes.len(),
                core::ptr::null(),
                &mut bin_len,
                core::ptr::null_mut(),
                sodium_base64_VARIANT_ORIGINAL as i32,
            )
        };

        if ret == 0 {
            bin.truncate(bin_len);
            Ok(bin)
        } else {
            Err(to_crypto_error())
        }
    }

    fn hex2bin_ignore(hex: String, ignore: String) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        let hex_bytes = hex.as_bytes();
        let max_bin_len = hex_bytes.len() / 2;
        let mut bin = vec![0u8; max_bin_len];
        let mut bin_len: usize = 0;

        let ignore_ptr = if ignore.is_empty() {
            core::ptr::null()
        } else {
            ignore.as_ptr() as *const i8
        };

        let ret = unsafe {
            sodium_hex2bin(
                bin.as_mut_ptr(),
                max_bin_len,
                hex_bytes.as_ptr() as *const i8,
                hex_bytes.len(),
                ignore_ptr,
                &mut bin_len,
                core::ptr::null_mut(),
            )
        };

        if ret == 0 {
            bin.truncate(bin_len);
            Ok(bin)
        } else {
            Err(to_crypto_error())
        }
    }

    fn base64_variant_original() -> u32 {
        sodium_base64_VARIANT_ORIGINAL
    }

    fn base64_variant_original_no_padding() -> u32 {
        sodium_base64_VARIANT_ORIGINAL_NO_PADDING
    }

    fn base64_variant_urlsafe() -> u32 {
        sodium_base64_VARIANT_URLSAFE
    }

    fn base64_variant_urlsafe_no_padding() -> u32 {
        sodium_base64_VARIANT_URLSAFE_NO_PADDING
    }

    fn bin2base64_variant(data: Vec<u8>, encoding: u32) -> String {
        let b64_maxlen = unsafe { sodium_base64_encoded_len(data.len(), encoding as i32) };
        let mut b64 = vec![0u8; b64_maxlen];
        unsafe {
            sodium_bin2base64(
                b64.as_mut_ptr() as *mut i8,
                b64_maxlen,
                data.as_ptr(),
                data.len(),
                encoding as i32,
            );
        }
        // Find null terminator
        let len = b64.iter().position(|&c| c == 0).unwrap_or(b64.len());
        String::from_utf8_lossy(&b64[..len]).into_owned()
    }

    fn base642bin_variant(base64: String, encoding: u32) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        let b64_bytes = base64.as_bytes();
        let max_bin_len = b64_bytes.len() * 3 / 4 + 1;
        let mut bin = vec![0u8; max_bin_len];
        let mut bin_len: usize = 0;

        let ret = unsafe {
            sodium_base642bin(
                bin.as_mut_ptr(),
                max_bin_len,
                b64_bytes.as_ptr() as *const i8,
                b64_bytes.len(),
                core::ptr::null(),
                &mut bin_len,
                core::ptr::null_mut(),
                encoding as i32,
            )
        };

        if ret == 0 {
            bin.truncate(bin_len);
            Ok(bin)
        } else {
            Err(to_crypto_error())
        }
    }

    fn base642bin_variant_ignore(base64: String, encoding: u32, ignore: String) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        let b64_bytes = base64.as_bytes();
        let max_bin_len = b64_bytes.len() * 3 / 4 + 1;
        let mut bin = vec![0u8; max_bin_len];
        let mut bin_len: usize = 0;

        let ignore_ptr = if ignore.is_empty() {
            core::ptr::null()
        } else {
            ignore.as_ptr() as *const i8
        };

        let ret = unsafe {
            sodium_base642bin(
                bin.as_mut_ptr(),
                max_bin_len,
                b64_bytes.as_ptr() as *const i8,
                b64_bytes.len(),
                ignore_ptr,
                &mut bin_len,
                core::ptr::null_mut(),
                encoding as i32,
            )
        };

        if ret == 0 {
            bin.truncate(bin_len);
            Ok(bin)
        } else {
            Err(to_crypto_error())
        }
    }

    fn pad(mut data: Vec<u8>, block_size: u32) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        let unpadded_len = data.len();
        // Allocate space for padding (max additional bytes = block_size)
        data.resize(unpadded_len + block_size as usize, 0);
        let mut padded_len: usize = 0;

        let ret = unsafe {
            sodium_pad(
                &mut padded_len,
                data.as_mut_ptr(),
                unpadded_len,
                block_size as usize,
                data.len(),
            )
        };

        if ret == 0 {
            data.truncate(padded_len);
            Ok(data)
        } else {
            Err(to_crypto_error())
        }
    }

    fn unpad(data: Vec<u8>, block_size: u32) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        let mut unpadded_len: usize = 0;

        let ret = unsafe {
            sodium_unpad(
                &mut unpadded_len,
                data.as_ptr(),
                data.len(),
                block_size as usize,
            )
        };

        if ret == 0 {
            let mut result = data;
            result.truncate(unpadded_len);
            Ok(result)
        } else {
            Err(to_crypto_error())
        }
    }
}

// ============================================================================
// Short Hash
// ============================================================================

impl exports::libsodium::crypto::shorthash::Guest for Component {
    fn bytes() -> u32 {
        crypto_shorthash_BYTES
    }

    fn key_bytes() -> u32 {
        crypto_shorthash_KEYBYTES
    }

    fn keygen() -> Vec<u8> {
        let mut key = vec![0u8; crypto_shorthash_KEYBYTES as usize];
        unsafe {
            crypto_shorthash_keygen(key.as_mut_ptr());
        }
        key
    }

    fn hash(
        message: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if key.len() != crypto_shorthash_KEYBYTES as usize {
            return Err(invalid_key());
        }

        let mut hash = vec![0u8; crypto_shorthash_BYTES as usize];
        let ret = unsafe {
            crypto_shorthash(hash.as_mut_ptr(), message.as_ptr(), message.len() as u64, key.as_ptr())
        };

        if ret == 0 {
            Ok(hash)
        } else {
            Err(to_crypto_error())
        }
    }

    fn siphashx24_bytes() -> u32 {
        crypto_shorthash_siphashx24_BYTES
    }

    fn siphashx24_key_bytes() -> u32 {
        crypto_shorthash_siphashx24_KEYBYTES
    }

    fn hashx24(
        message: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if key.len() != crypto_shorthash_siphashx24_KEYBYTES as usize {
            return Err(invalid_key());
        }

        let mut hash = vec![0u8; crypto_shorthash_siphashx24_BYTES as usize];
        let ret = unsafe {
            crypto_shorthash_siphashx24(hash.as_mut_ptr(), message.as_ptr(), message.len() as u64, key.as_ptr())
        };

        if ret == 0 {
            Ok(hash)
        } else {
            Err(to_crypto_error())
        }
    }
}

// ============================================================================
// One-Time Auth
// ============================================================================

impl exports::libsodium::crypto::onetimeauth::Guest for Component {
    fn bytes() -> u32 {
        crypto_onetimeauth_BYTES
    }

    fn key_bytes() -> u32 {
        crypto_onetimeauth_KEYBYTES
    }

    fn keygen() -> Vec<u8> {
        let mut key = vec![0u8; crypto_onetimeauth_KEYBYTES as usize];
        unsafe {
            crypto_onetimeauth_keygen(key.as_mut_ptr());
        }
        key
    }

    fn auth(
        message: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if key.len() != crypto_onetimeauth_KEYBYTES as usize {
            return Err(invalid_key());
        }

        let mut tag = vec![0u8; crypto_onetimeauth_BYTES as usize];
        let ret = unsafe {
            crypto_onetimeauth(
                tag.as_mut_ptr(),
                message.as_ptr(),
                message.len() as u64,
                key.as_ptr(),
            )
        };

        if ret == 0 {
            Ok(tag)
        } else {
            Err(to_crypto_error())
        }
    }

    fn verify(
        tag: Vec<u8>,
        message: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<(), exports::libsodium::crypto::types::CryptoError> {
        if key.len() != crypto_onetimeauth_KEYBYTES as usize {
            return Err(invalid_key());
        }
        if tag.len() != crypto_onetimeauth_BYTES as usize {
            return Err(verification_failed());
        }

        let ret = unsafe {
            crypto_onetimeauth_verify(
                tag.as_ptr(),
                message.as_ptr(),
                message.len() as u64,
                key.as_ptr(),
            )
        };

        if ret == 0 {
            Ok(())
        } else {
            Err(verification_failed())
        }
    }
}

// ============================================================================
// Cipher XSalsa20
// ============================================================================

impl exports::libsodium::crypto::cipher_xsalsa20::Guest for Component {
    fn key_bytes() -> u32 {
        crypto_stream_xsalsa20_KEYBYTES
    }

    fn nonce_bytes() -> u32 {
        crypto_stream_xsalsa20_NONCEBYTES
    }

    fn keygen() -> Vec<u8> {
        let mut key = vec![0u8; crypto_stream_xsalsa20_KEYBYTES as usize];
        unsafe {
            crypto_stream_xsalsa20_keygen(key.as_mut_ptr());
        }
        key
    }

    fn keystream(
        len: u32,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if key.len() != crypto_stream_xsalsa20_KEYBYTES as usize {
            return Err(invalid_key());
        }
        if nonce.len() != crypto_stream_xsalsa20_NONCEBYTES as usize {
            return Err(invalid_nonce());
        }

        let mut keystream = vec![0u8; len as usize];
        let ret = unsafe {
            crypto_stream_xsalsa20(
                keystream.as_mut_ptr(),
                len as u64,
                nonce.as_ptr(),
                key.as_ptr(),
            )
        };

        if ret == 0 {
            Ok(keystream)
        } else {
            Err(to_crypto_error())
        }
    }

    fn xor(
        message: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if key.len() != crypto_stream_xsalsa20_KEYBYTES as usize {
            return Err(invalid_key());
        }
        if nonce.len() != crypto_stream_xsalsa20_NONCEBYTES as usize {
            return Err(invalid_nonce());
        }

        let mut output = vec![0u8; message.len()];
        let ret = unsafe {
            crypto_stream_xsalsa20_xor(
                output.as_mut_ptr(),
                message.as_ptr(),
                message.len() as u64,
                nonce.as_ptr(),
                key.as_ptr(),
            )
        };

        if ret == 0 {
            Ok(output)
        } else {
            Err(to_crypto_error())
        }
    }
}

// ============================================================================
// Cipher XChaCha20
// ============================================================================

impl exports::libsodium::crypto::cipher_xchacha20::Guest for Component {
    fn key_bytes() -> u32 {
        crypto_stream_xchacha20_KEYBYTES
    }

    fn nonce_bytes() -> u32 {
        crypto_stream_xchacha20_NONCEBYTES
    }

    fn keygen() -> Vec<u8> {
        let mut key = vec![0u8; crypto_stream_xchacha20_KEYBYTES as usize];
        unsafe {
            crypto_stream_xchacha20_keygen(key.as_mut_ptr());
        }
        key
    }

    fn keystream(
        len: u32,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if key.len() != crypto_stream_xchacha20_KEYBYTES as usize {
            return Err(invalid_key());
        }
        if nonce.len() != crypto_stream_xchacha20_NONCEBYTES as usize {
            return Err(invalid_nonce());
        }

        let mut keystream = vec![0u8; len as usize];
        let ret = unsafe {
            crypto_stream_xchacha20(
                keystream.as_mut_ptr(),
                len as u64,
                nonce.as_ptr(),
                key.as_ptr(),
            )
        };

        if ret == 0 {
            Ok(keystream)
        } else {
            Err(to_crypto_error())
        }
    }

    fn xor(
        message: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if key.len() != crypto_stream_xchacha20_KEYBYTES as usize {
            return Err(invalid_key());
        }
        if nonce.len() != crypto_stream_xchacha20_NONCEBYTES as usize {
            return Err(invalid_nonce());
        }

        let mut output = vec![0u8; message.len()];
        let ret = unsafe {
            crypto_stream_xchacha20_xor(
                output.as_mut_ptr(),
                message.as_ptr(),
                message.len() as u64,
                nonce.as_ptr(),
                key.as_ptr(),
            )
        };

        if ret == 0 {
            Ok(output)
        } else {
            Err(to_crypto_error())
        }
    }

    fn xor_ic(
        message: Vec<u8>,
        nonce: Vec<u8>,
        ic: u64,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if key.len() != crypto_stream_xchacha20_KEYBYTES as usize {
            return Err(invalid_key());
        }
        if nonce.len() != crypto_stream_xchacha20_NONCEBYTES as usize {
            return Err(invalid_nonce());
        }

        let mut output = vec![0u8; message.len()];
        let ret = unsafe {
            crypto_stream_xchacha20_xor_ic(
                output.as_mut_ptr(),
                message.as_ptr(),
                message.len() as u64,
                nonce.as_ptr(),
                ic,
                key.as_ptr(),
            )
        };

        if ret == 0 {
            Ok(output)
        } else {
            Err(to_crypto_error())
        }
    }
}

// ============================================================================
// Secret Stream (XChaCha20-Poly1305 streaming)
// ============================================================================

impl exports::libsodium::crypto::secret_stream::Guest for Component {
    fn key_bytes() -> u32 {
        crypto_secretstream_xchacha20poly1305_KEYBYTES
    }

    fn header_bytes() -> u32 {
        crypto_secretstream_xchacha20poly1305_HEADERBYTES
    }

    fn a_bytes() -> u32 {
        crypto_secretstream_xchacha20poly1305_ABYTES
    }

    fn tag_message() -> u8 {
        crypto_secretstream_xchacha20poly1305_TAG_MESSAGE as u8
    }

    fn tag_push() -> u8 {
        crypto_secretstream_xchacha20poly1305_TAG_PUSH as u8
    }

    fn tag_rekey() -> u8 {
        crypto_secretstream_xchacha20poly1305_TAG_REKEY as u8
    }

    fn tag_final() -> u8 {
        crypto_secretstream_xchacha20poly1305_TAG_FINAL as u8
    }

    fn messagebytes_max() -> u64 {
        unsafe { crypto_secretstream_xchacha20poly1305_messagebytes_max() as u64 }
    }

    fn keygen() -> Vec<u8> {
        let mut key = vec![0u8; crypto_secretstream_xchacha20poly1305_KEYBYTES as usize];
        unsafe {
            crypto_secretstream_xchacha20poly1305_keygen(key.as_mut_ptr());
        }
        key
    }

    fn init_push(key: Vec<u8>) -> Result<(u64, Vec<u8>), exports::libsodium::crypto::types::CryptoError> {
        if key.len() != crypto_secretstream_xchacha20poly1305_KEYBYTES as usize {
            return Err(invalid_key());
        }

        let mut state = crypto_secretstream_xchacha20poly1305_state {
            k: [0; 32],
            nonce: [0; 12],
            _pad: [0; 8],
        };
        let mut header = vec![0u8; crypto_secretstream_xchacha20poly1305_HEADERBYTES as usize];

        let ret = unsafe {
            crypto_secretstream_xchacha20poly1305_init_push(
                &mut state,
                header.as_mut_ptr(),
                key.as_ptr(),
            )
        };

        if ret == 0 {
            let id = next_state_id();
            secretstream_states().as_mut().unwrap().insert(id, state);
            Ok((id, header))
        } else {
            Err(to_crypto_error())
        }
    }

    fn push(state_id: u64, message: Vec<u8>, additional_data: Vec<u8>, tag: u8) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        let mut states = secretstream_states();
        let state = states.as_mut().unwrap().get_mut(&state_id).ok_or(to_crypto_error())?;

        let mut ciphertext = vec![0u8; message.len() + crypto_secretstream_xchacha20poly1305_ABYTES as usize];
        let mut clen: u64 = 0;

        let ad_ptr = if additional_data.is_empty() {
            core::ptr::null()
        } else {
            additional_data.as_ptr()
        };

        let ret = unsafe {
            crypto_secretstream_xchacha20poly1305_push(
                state,
                ciphertext.as_mut_ptr(),
                &mut clen,
                message.as_ptr(),
                message.len() as u64,
                ad_ptr,
                additional_data.len() as u64,
                tag,
            )
        };

        if ret == 0 {
            ciphertext.truncate(clen as usize);
            Ok(ciphertext)
        } else {
            Err(to_crypto_error())
        }
    }

    fn init_pull(header: Vec<u8>, key: Vec<u8>) -> Result<u64, exports::libsodium::crypto::types::CryptoError> {
        if key.len() != crypto_secretstream_xchacha20poly1305_KEYBYTES as usize {
            return Err(invalid_key());
        }
        if header.len() != crypto_secretstream_xchacha20poly1305_HEADERBYTES as usize {
            return Err(to_crypto_error());
        }

        let mut state = crypto_secretstream_xchacha20poly1305_state {
            k: [0; 32],
            nonce: [0; 12],
            _pad: [0; 8],
        };

        let ret = unsafe {
            crypto_secretstream_xchacha20poly1305_init_pull(
                &mut state,
                header.as_ptr(),
                key.as_ptr(),
            )
        };

        if ret == 0 {
            let id = next_state_id();
            secretstream_states().as_mut().unwrap().insert(id, state);
            Ok(id)
        } else {
            Err(to_crypto_error())
        }
    }

    fn pull(state_id: u64, ciphertext: Vec<u8>, additional_data: Vec<u8>) -> Result<(Vec<u8>, u8), exports::libsodium::crypto::types::CryptoError> {
        let mut states = secretstream_states();
        let state = states.as_mut().unwrap().get_mut(&state_id).ok_or(to_crypto_error())?;

        if ciphertext.len() < crypto_secretstream_xchacha20poly1305_ABYTES as usize {
            return Err(verification_failed());
        }

        let mut message = vec![0u8; ciphertext.len() - crypto_secretstream_xchacha20poly1305_ABYTES as usize];
        let mut mlen: u64 = 0;
        let mut tag: u8 = 0;

        let ad_ptr = if additional_data.is_empty() {
            core::ptr::null()
        } else {
            additional_data.as_ptr()
        };

        let ret = unsafe {
            crypto_secretstream_xchacha20poly1305_pull(
                state,
                message.as_mut_ptr(),
                &mut mlen,
                &mut tag,
                ciphertext.as_ptr(),
                ciphertext.len() as u64,
                ad_ptr,
                additional_data.len() as u64,
            )
        };

        if ret == 0 {
            message.truncate(mlen as usize);
            Ok((message, tag))
        } else {
            Err(verification_failed())
        }
    }

    fn rekey(state_id: u64) -> Result<(), exports::libsodium::crypto::types::CryptoError> {
        let mut states = secretstream_states();
        let state = states.as_mut().unwrap().get_mut(&state_id).ok_or(to_crypto_error())?;
        unsafe {
            crypto_secretstream_xchacha20poly1305_rekey(state);
        }
        Ok(())
    }

    fn destroy(state_id: u64) {
        secretstream_states().as_mut().unwrap().remove(&state_id);
    }
}

// ============================================================================
// Generichash State (streaming BLAKE2b)
// ============================================================================

impl exports::libsodium::crypto::generichash_state::Guest for Component {
    fn state_bytes() -> u32 {
        unsafe { crypto_generichash_statebytes() as u32 }
    }

    fn init(out_len: u32, key: Vec<u8>) -> Result<u64, exports::libsodium::crypto::types::CryptoError> {
        if out_len < crypto_generichash_BYTES_MIN || out_len > crypto_generichash_BYTES_MAX {
            return Err(to_crypto_error());
        }
        if !key.is_empty() && (key.len() < crypto_generichash_KEYBYTES_MIN as usize || key.len() > crypto_generichash_KEYBYTES_MAX as usize) {
            return Err(invalid_key());
        }

        let mut state: crypto_generichash_state = unsafe { core::mem::zeroed() };
        let key_ptr = if key.is_empty() { core::ptr::null() } else { key.as_ptr() };

        let ret = unsafe {
            crypto_generichash_init(&mut state, key_ptr, key.len(), out_len as usize)
        };

        if ret == 0 {
            let id = next_state_id();
            generichash_states().as_mut().unwrap().insert(id, (state, out_len as usize));
            Ok(id)
        } else {
            Err(to_crypto_error())
        }
    }

    fn update(state_id: u64, data: Vec<u8>) -> Result<(), exports::libsodium::crypto::types::CryptoError> {
        let mut states = generichash_states();
        let (state, _) = states.as_mut().unwrap().get_mut(&state_id).ok_or(to_crypto_error())?;

        let ret = unsafe {
            crypto_generichash_update(state, data.as_ptr(), data.len() as u64)
        };

        if ret == 0 {
            Ok(())
        } else {
            Err(to_crypto_error())
        }
    }

    fn final_(state_id: u64) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        let mut states = generichash_states();
        let (state, out_len) = states.as_mut().unwrap().remove(&state_id).ok_or(to_crypto_error())?;
        let mut state = state;

        let mut hash = vec![0u8; out_len];
        let ret = unsafe {
            crypto_generichash_final(&mut state, hash.as_mut_ptr(), out_len)
        };

        if ret == 0 {
            Ok(hash)
        } else {
            Err(to_crypto_error())
        }
    }

    fn destroy(state_id: u64) {
        generichash_states().as_mut().unwrap().remove(&state_id);
    }
}

// ============================================================================
// SHA-256 State (streaming)
// ============================================================================

impl exports::libsodium::crypto::sha256_state::Guest for Component {
    fn state_bytes() -> u32 {
        unsafe { crypto_hash_sha256_statebytes() as u32 }
    }

    fn init() -> Result<u64, exports::libsodium::crypto::types::CryptoError> {
        let mut state: crypto_hash_sha256_state = unsafe { core::mem::zeroed() };

        let ret = unsafe { crypto_hash_sha256_init(&mut state) };

        if ret == 0 {
            let id = next_state_id();
            sha256_states().as_mut().unwrap().insert(id, state);
            Ok(id)
        } else {
            Err(to_crypto_error())
        }
    }

    fn update(state_id: u64, data: Vec<u8>) -> Result<(), exports::libsodium::crypto::types::CryptoError> {
        let mut states = sha256_states();
        let state = states.as_mut().unwrap().get_mut(&state_id).ok_or(to_crypto_error())?;

        let ret = unsafe {
            crypto_hash_sha256_update(state, data.as_ptr(), data.len() as u64)
        };

        if ret == 0 {
            Ok(())
        } else {
            Err(to_crypto_error())
        }
    }

    fn final_(state_id: u64) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        let mut states = sha256_states();
        let mut state = states.as_mut().unwrap().remove(&state_id).ok_or(to_crypto_error())?;

        let mut hash = vec![0u8; crypto_hash_sha256_BYTES as usize];
        let ret = unsafe {
            crypto_hash_sha256_final(&mut state, hash.as_mut_ptr())
        };

        if ret == 0 {
            Ok(hash)
        } else {
            Err(to_crypto_error())
        }
    }

    fn destroy(state_id: u64) {
        sha256_states().as_mut().unwrap().remove(&state_id);
    }
}

// ============================================================================
// SHA-512 State (streaming)
// ============================================================================

impl exports::libsodium::crypto::sha512_state::Guest for Component {
    fn state_bytes() -> u32 {
        unsafe { crypto_hash_sha512_statebytes() as u32 }
    }

    fn init() -> Result<u64, exports::libsodium::crypto::types::CryptoError> {
        let mut state: crypto_hash_sha512_state = unsafe { core::mem::zeroed() };

        let ret = unsafe { crypto_hash_sha512_init(&mut state) };

        if ret == 0 {
            let id = next_state_id();
            sha512_states().as_mut().unwrap().insert(id, state);
            Ok(id)
        } else {
            Err(to_crypto_error())
        }
    }

    fn update(state_id: u64, data: Vec<u8>) -> Result<(), exports::libsodium::crypto::types::CryptoError> {
        let mut states = sha512_states();
        let state = states.as_mut().unwrap().get_mut(&state_id).ok_or(to_crypto_error())?;

        let ret = unsafe {
            crypto_hash_sha512_update(state, data.as_ptr(), data.len() as u64)
        };

        if ret == 0 {
            Ok(())
        } else {
            Err(to_crypto_error())
        }
    }

    fn final_(state_id: u64) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        let mut states = sha512_states();
        let mut state = states.as_mut().unwrap().remove(&state_id).ok_or(to_crypto_error())?;

        let mut hash = vec![0u8; crypto_hash_sha512_BYTES as usize];
        let ret = unsafe {
            crypto_hash_sha512_final(&mut state, hash.as_mut_ptr())
        };

        if ret == 0 {
            Ok(hash)
        } else {
            Err(to_crypto_error())
        }
    }

    fn destroy(state_id: u64) {
        sha512_states().as_mut().unwrap().remove(&state_id);
    }
}

// ============================================================================
// Auth State (streaming HMAC-SHA512-256)
// ============================================================================

impl exports::libsodium::crypto::auth_state::Guest for Component {
    fn state_bytes() -> u32 {
        unsafe { crypto_auth_hmacsha512256_statebytes() as u32 }
    }

    fn init(key: Vec<u8>) -> Result<u64, exports::libsodium::crypto::types::CryptoError> {
        if key.len() != crypto_auth_KEYBYTES as usize {
            return Err(invalid_key());
        }

        let mut state: crypto_auth_hmacsha512256_state = unsafe { core::mem::zeroed() };

        let ret = unsafe { crypto_auth_hmacsha512256_init(&mut state, key.as_ptr(), key.len()) };

        if ret == 0 {
            let id = next_state_id();
            auth_states().as_mut().unwrap().insert(id, state);
            Ok(id)
        } else {
            Err(to_crypto_error())
        }
    }

    fn update(state_id: u64, data: Vec<u8>) -> Result<(), exports::libsodium::crypto::types::CryptoError> {
        let mut states = auth_states();
        let state = states.as_mut().unwrap().get_mut(&state_id).ok_or(to_crypto_error())?;

        let ret = unsafe {
            crypto_auth_hmacsha512256_update(state, data.as_ptr(), data.len() as u64)
        };

        if ret == 0 {
            Ok(())
        } else {
            Err(to_crypto_error())
        }
    }

    fn final_(state_id: u64) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        let mut states = auth_states();
        let mut state = states.as_mut().unwrap().remove(&state_id).ok_or(to_crypto_error())?;

        let mut tag = vec![0u8; crypto_auth_BYTES as usize];
        let ret = unsafe {
            crypto_auth_hmacsha512256_final(&mut state, tag.as_mut_ptr())
        };

        if ret == 0 {
            Ok(tag)
        } else {
            Err(to_crypto_error())
        }
    }

    fn destroy(state_id: u64) {
        auth_states().as_mut().unwrap().remove(&state_id);
    }
}

// ============================================================================
// Onetimeauth State (streaming Poly1305)
// ============================================================================

impl exports::libsodium::crypto::onetimeauth_state::Guest for Component {
    fn state_bytes() -> u32 {
        unsafe { crypto_onetimeauth_statebytes() as u32 }
    }

    fn init(key: Vec<u8>) -> Result<u64, exports::libsodium::crypto::types::CryptoError> {
        if key.len() != crypto_onetimeauth_KEYBYTES as usize {
            return Err(invalid_key());
        }

        let mut state: crypto_onetimeauth_state = unsafe { core::mem::zeroed() };

        let ret = unsafe { crypto_onetimeauth_init(&mut state, key.as_ptr()) };

        if ret == 0 {
            let id = next_state_id();
            onetimeauth_states().as_mut().unwrap().insert(id, state);
            Ok(id)
        } else {
            Err(to_crypto_error())
        }
    }

    fn update(state_id: u64, data: Vec<u8>) -> Result<(), exports::libsodium::crypto::types::CryptoError> {
        let mut states = onetimeauth_states();
        let state = states.as_mut().unwrap().get_mut(&state_id).ok_or(to_crypto_error())?;

        let ret = unsafe {
            crypto_onetimeauth_update(state, data.as_ptr(), data.len() as u64)
        };

        if ret == 0 {
            Ok(())
        } else {
            Err(to_crypto_error())
        }
    }

    fn final_(state_id: u64) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        let mut states = onetimeauth_states();
        let mut state = states.as_mut().unwrap().remove(&state_id).ok_or(to_crypto_error())?;

        let mut tag = vec![0u8; crypto_onetimeauth_BYTES as usize];
        let ret = unsafe {
            crypto_onetimeauth_final(&mut state, tag.as_mut_ptr())
        };

        if ret == 0 {
            Ok(tag)
        } else {
            Err(to_crypto_error())
        }
    }

    fn destroy(state_id: u64) {
        onetimeauth_states().as_mut().unwrap().remove(&state_id);
    }
}

// ============================================================================
// AEAD AES-256-GCM
// ============================================================================

impl exports::libsodium::crypto::aead_aes256gcm::Guest for Component {
    fn is_available() -> bool {
        unsafe { crypto_aead_aes256gcm_is_available() == 1 }
    }

    fn key_bytes() -> u32 {
        crypto_aead_aes256gcm_KEYBYTES
    }

    fn nonce_bytes() -> u32 {
        crypto_aead_aes256gcm_NPUBBYTES
    }

    fn a_bytes() -> u32 {
        crypto_aead_aes256gcm_ABYTES
    }

    fn keygen() -> Vec<u8> {
        let mut key = vec![0u8; crypto_aead_aes256gcm_KEYBYTES as usize];
        unsafe {
            crypto_aead_aes256gcm_keygen(key.as_mut_ptr());
        }
        key
    }

    fn encrypt(
        message: Vec<u8>,
        additional_data: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if key.len() != crypto_aead_aes256gcm_KEYBYTES as usize {
            return Err(invalid_key());
        }
        if nonce.len() != crypto_aead_aes256gcm_NPUBBYTES as usize {
            return Err(invalid_nonce());
        }

        let mut ciphertext = vec![0u8; message.len() + crypto_aead_aes256gcm_ABYTES as usize];
        let mut clen: u64 = 0;

        let ad_ptr = if additional_data.is_empty() { core::ptr::null() } else { additional_data.as_ptr() };

        let ret = unsafe {
            crypto_aead_aes256gcm_encrypt(
                ciphertext.as_mut_ptr(),
                &mut clen,
                message.as_ptr(),
                message.len() as u64,
                ad_ptr,
                additional_data.len() as u64,
                core::ptr::null(),
                nonce.as_ptr(),
                key.as_ptr(),
            )
        };

        if ret == 0 {
            ciphertext.truncate(clen as usize);
            Ok(ciphertext)
        } else {
            Err(to_crypto_error())
        }
    }

    fn decrypt(
        ciphertext: Vec<u8>,
        additional_data: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if key.len() != crypto_aead_aes256gcm_KEYBYTES as usize {
            return Err(invalid_key());
        }
        if nonce.len() != crypto_aead_aes256gcm_NPUBBYTES as usize {
            return Err(invalid_nonce());
        }
        if ciphertext.len() < crypto_aead_aes256gcm_ABYTES as usize {
            return Err(verification_failed());
        }

        let mut message = vec![0u8; ciphertext.len() - crypto_aead_aes256gcm_ABYTES as usize];
        let mut mlen: u64 = 0;

        let ad_ptr = if additional_data.is_empty() { core::ptr::null() } else { additional_data.as_ptr() };

        let ret = unsafe {
            crypto_aead_aes256gcm_decrypt(
                message.as_mut_ptr(),
                &mut mlen,
                core::ptr::null_mut(),
                ciphertext.as_ptr(),
                ciphertext.len() as u64,
                ad_ptr,
                additional_data.len() as u64,
                nonce.as_ptr(),
                key.as_ptr(),
            )
        };

        if ret == 0 {
            message.truncate(mlen as usize);
            Ok(message)
        } else {
            Err(verification_failed())
        }
    }

    fn encrypt_detached(
        message: Vec<u8>,
        additional_data: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<(Vec<u8>, Vec<u8>), exports::libsodium::crypto::types::CryptoError> {
        if key.len() != crypto_aead_aes256gcm_KEYBYTES as usize {
            return Err(invalid_key());
        }
        if nonce.len() != crypto_aead_aes256gcm_NPUBBYTES as usize {
            return Err(invalid_nonce());
        }

        let mut ciphertext = vec![0u8; message.len()];
        let mut mac = vec![0u8; crypto_aead_aes256gcm_ABYTES as usize];
        let mut maclen: u64 = 0;

        let ad_ptr = if additional_data.is_empty() { core::ptr::null() } else { additional_data.as_ptr() };

        let ret = unsafe {
            crypto_aead_aes256gcm_encrypt_detached(
                ciphertext.as_mut_ptr(),
                mac.as_mut_ptr(),
                &mut maclen,
                message.as_ptr(),
                message.len() as u64,
                ad_ptr,
                additional_data.len() as u64,
                core::ptr::null(),
                nonce.as_ptr(),
                key.as_ptr(),
            )
        };

        if ret == 0 {
            Ok((ciphertext, mac))
        } else {
            Err(to_crypto_error())
        }
    }

    fn decrypt_detached(
        ciphertext: Vec<u8>,
        mac: Vec<u8>,
        additional_data: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if key.len() != crypto_aead_aes256gcm_KEYBYTES as usize {
            return Err(invalid_key());
        }
        if nonce.len() != crypto_aead_aes256gcm_NPUBBYTES as usize {
            return Err(invalid_nonce());
        }
        if mac.len() != crypto_aead_aes256gcm_ABYTES as usize {
            return Err(verification_failed());
        }

        let mut message = vec![0u8; ciphertext.len()];

        let ad_ptr = if additional_data.is_empty() { core::ptr::null() } else { additional_data.as_ptr() };

        let ret = unsafe {
            crypto_aead_aes256gcm_decrypt_detached(
                message.as_mut_ptr(),
                core::ptr::null_mut(),
                ciphertext.as_ptr(),
                ciphertext.len() as u64,
                mac.as_ptr(),
                ad_ptr,
                additional_data.len() as u64,
                nonce.as_ptr(),
                key.as_ptr(),
            )
        };

        if ret == 0 {
            Ok(message)
        } else {
            Err(verification_failed())
        }
    }
}

// ============================================================================
// Verify (constant-time comparison)
// ============================================================================

impl exports::libsodium::crypto::verify::Guest for Component {
    fn verify16(x: Vec<u8>, y: Vec<u8>) -> bool {
        if x.len() != 16 || y.len() != 16 {
            return false;
        }
        unsafe { crypto_verify_16(x.as_ptr(), y.as_ptr()) == 0 }
    }

    fn verify32(x: Vec<u8>, y: Vec<u8>) -> bool {
        if x.len() != 32 || y.len() != 32 {
            return false;
        }
        unsafe { crypto_verify_32(x.as_ptr(), y.as_ptr()) == 0 }
    }

    fn verify64(x: Vec<u8>, y: Vec<u8>) -> bool {
        if x.len() != 64 || y.len() != 64 {
            return false;
        }
        unsafe { crypto_verify_64(x.as_ptr(), y.as_ptr()) == 0 }
    }
}

// ============================================================================
// Ristretto255 group operations
// ============================================================================

impl exports::libsodium::crypto::ristretto255::Guest for Component {
    fn bytes() -> u32 {
        crypto_core_ristretto255_BYTES
    }

    fn hash_bytes() -> u32 {
        crypto_core_ristretto255_HASHBYTES
    }

    fn scalar_bytes() -> u32 {
        crypto_core_ristretto255_SCALARBYTES
    }

    fn non_reduced_scalar_bytes() -> u32 {
        crypto_core_ristretto255_NONREDUCEDSCALARBYTES
    }

    fn is_valid_point(p: Vec<u8>) -> bool {
        if p.len() != crypto_core_ristretto255_BYTES as usize {
            return false;
        }
        unsafe { crypto_core_ristretto255_is_valid_point(p.as_ptr()) == 1 }
    }

    fn add(p: Vec<u8>, q: Vec<u8>) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if p.len() != crypto_core_ristretto255_BYTES as usize || q.len() != crypto_core_ristretto255_BYTES as usize {
            return Err(to_crypto_error());
        }
        let mut r = vec![0u8; crypto_core_ristretto255_BYTES as usize];
        let ret = unsafe { crypto_core_ristretto255_add(r.as_mut_ptr(), p.as_ptr(), q.as_ptr()) };
        if ret == 0 { Ok(r) } else { Err(to_crypto_error()) }
    }

    fn sub(p: Vec<u8>, q: Vec<u8>) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if p.len() != crypto_core_ristretto255_BYTES as usize || q.len() != crypto_core_ristretto255_BYTES as usize {
            return Err(to_crypto_error());
        }
        let mut r = vec![0u8; crypto_core_ristretto255_BYTES as usize];
        let ret = unsafe { crypto_core_ristretto255_sub(r.as_mut_ptr(), p.as_ptr(), q.as_ptr()) };
        if ret == 0 { Ok(r) } else { Err(to_crypto_error()) }
    }

    fn from_hash(h: Vec<u8>) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if h.len() != crypto_core_ristretto255_HASHBYTES as usize {
            return Err(to_crypto_error());
        }
        let mut p = vec![0u8; crypto_core_ristretto255_BYTES as usize];
        let ret = unsafe { crypto_core_ristretto255_from_hash(p.as_mut_ptr(), h.as_ptr()) };
        if ret == 0 { Ok(p) } else { Err(to_crypto_error()) }
    }

    fn random() -> Vec<u8> {
        let mut p = vec![0u8; crypto_core_ristretto255_BYTES as usize];
        unsafe { crypto_core_ristretto255_random(p.as_mut_ptr()) };
        p
    }

    fn scalar_random() -> Vec<u8> {
        let mut s = vec![0u8; crypto_core_ristretto255_SCALARBYTES as usize];
        unsafe { crypto_core_ristretto255_scalar_random(s.as_mut_ptr()) };
        s
    }

    fn scalar_invert(s: Vec<u8>) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if s.len() != crypto_core_ristretto255_SCALARBYTES as usize {
            return Err(to_crypto_error());
        }
        let mut r = vec![0u8; crypto_core_ristretto255_SCALARBYTES as usize];
        let ret = unsafe { crypto_core_ristretto255_scalar_invert(r.as_mut_ptr(), s.as_ptr()) };
        if ret == 0 { Ok(r) } else { Err(to_crypto_error()) }
    }

    fn scalar_negate(s: Vec<u8>) -> Vec<u8> {
        let mut r = vec![0u8; crypto_core_ristretto255_SCALARBYTES as usize];
        if s.len() == crypto_core_ristretto255_SCALARBYTES as usize {
            unsafe { crypto_core_ristretto255_scalar_negate(r.as_mut_ptr(), s.as_ptr()) };
        }
        r
    }

    fn scalar_complement(s: Vec<u8>) -> Vec<u8> {
        let mut r = vec![0u8; crypto_core_ristretto255_SCALARBYTES as usize];
        if s.len() == crypto_core_ristretto255_SCALARBYTES as usize {
            unsafe { crypto_core_ristretto255_scalar_complement(r.as_mut_ptr(), s.as_ptr()) };
        }
        r
    }

    fn scalar_add(x: Vec<u8>, y: Vec<u8>) -> Vec<u8> {
        let mut r = vec![0u8; crypto_core_ristretto255_SCALARBYTES as usize];
        if x.len() == crypto_core_ristretto255_SCALARBYTES as usize && y.len() == crypto_core_ristretto255_SCALARBYTES as usize {
            unsafe { crypto_core_ristretto255_scalar_add(r.as_mut_ptr(), x.as_ptr(), y.as_ptr()) };
        }
        r
    }

    fn scalar_sub(x: Vec<u8>, y: Vec<u8>) -> Vec<u8> {
        let mut r = vec![0u8; crypto_core_ristretto255_SCALARBYTES as usize];
        if x.len() == crypto_core_ristretto255_SCALARBYTES as usize && y.len() == crypto_core_ristretto255_SCALARBYTES as usize {
            unsafe { crypto_core_ristretto255_scalar_sub(r.as_mut_ptr(), x.as_ptr(), y.as_ptr()) };
        }
        r
    }

    fn scalar_mul(x: Vec<u8>, y: Vec<u8>) -> Vec<u8> {
        let mut r = vec![0u8; crypto_core_ristretto255_SCALARBYTES as usize];
        if x.len() == crypto_core_ristretto255_SCALARBYTES as usize && y.len() == crypto_core_ristretto255_SCALARBYTES as usize {
            unsafe { crypto_core_ristretto255_scalar_mul(r.as_mut_ptr(), x.as_ptr(), y.as_ptr()) };
        }
        r
    }

    fn scalar_reduce(s: Vec<u8>) -> Vec<u8> {
        let mut r = vec![0u8; crypto_core_ristretto255_SCALARBYTES as usize];
        if s.len() == crypto_core_ristretto255_NONREDUCEDSCALARBYTES as usize {
            unsafe { crypto_core_ristretto255_scalar_reduce(r.as_mut_ptr(), s.as_ptr()) };
        }
        r
    }
}

// ============================================================================
// Ed25519 group operations
// ============================================================================

impl exports::libsodium::crypto::ed25519::Guest for Component {
    fn bytes() -> u32 {
        crypto_core_ed25519_BYTES
    }

    fn uniform_bytes() -> u32 {
        crypto_core_ed25519_UNIFORMBYTES
    }

    fn hash_bytes() -> u32 {
        crypto_core_ed25519_HASHBYTES
    }

    fn scalar_bytes() -> u32 {
        crypto_core_ed25519_SCALARBYTES
    }

    fn non_reduced_scalar_bytes() -> u32 {
        crypto_core_ed25519_NONREDUCEDSCALARBYTES
    }

    fn is_valid_point(p: Vec<u8>) -> bool {
        if p.len() != crypto_core_ed25519_BYTES as usize {
            return false;
        }
        unsafe { crypto_core_ed25519_is_valid_point(p.as_ptr()) == 1 }
    }

    fn add(p: Vec<u8>, q: Vec<u8>) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if p.len() != crypto_core_ed25519_BYTES as usize || q.len() != crypto_core_ed25519_BYTES as usize {
            return Err(to_crypto_error());
        }
        let mut r = vec![0u8; crypto_core_ed25519_BYTES as usize];
        let ret = unsafe { crypto_core_ed25519_add(r.as_mut_ptr(), p.as_ptr(), q.as_ptr()) };
        if ret == 0 { Ok(r) } else { Err(to_crypto_error()) }
    }

    fn sub(p: Vec<u8>, q: Vec<u8>) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if p.len() != crypto_core_ed25519_BYTES as usize || q.len() != crypto_core_ed25519_BYTES as usize {
            return Err(to_crypto_error());
        }
        let mut r = vec![0u8; crypto_core_ed25519_BYTES as usize];
        let ret = unsafe { crypto_core_ed25519_sub(r.as_mut_ptr(), p.as_ptr(), q.as_ptr()) };
        if ret == 0 { Ok(r) } else { Err(to_crypto_error()) }
    }

    fn from_uniform(u: Vec<u8>) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if u.len() != crypto_core_ed25519_UNIFORMBYTES as usize {
            return Err(to_crypto_error());
        }
        let mut p = vec![0u8; crypto_core_ed25519_BYTES as usize];
        let ret = unsafe { crypto_core_ed25519_from_uniform(p.as_mut_ptr(), u.as_ptr()) };
        if ret == 0 { Ok(p) } else { Err(to_crypto_error()) }
    }

    fn from_hash(h: Vec<u8>) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if h.len() != crypto_core_ed25519_HASHBYTES as usize {
            return Err(to_crypto_error());
        }
        let mut p = vec![0u8; crypto_core_ed25519_BYTES as usize];
        let ret = unsafe { crypto_core_ed25519_from_hash(p.as_mut_ptr(), h.as_ptr()) };
        if ret == 0 { Ok(p) } else { Err(to_crypto_error()) }
    }

    fn random() -> Vec<u8> {
        let mut p = vec![0u8; crypto_core_ed25519_BYTES as usize];
        unsafe { crypto_core_ed25519_random(p.as_mut_ptr()) };
        p
    }

    fn scalar_random() -> Vec<u8> {
        let mut s = vec![0u8; crypto_core_ed25519_SCALARBYTES as usize];
        unsafe { crypto_core_ed25519_scalar_random(s.as_mut_ptr()) };
        s
    }

    fn scalar_invert(s: Vec<u8>) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if s.len() != crypto_core_ed25519_SCALARBYTES as usize {
            return Err(to_crypto_error());
        }
        let mut r = vec![0u8; crypto_core_ed25519_SCALARBYTES as usize];
        let ret = unsafe { crypto_core_ed25519_scalar_invert(r.as_mut_ptr(), s.as_ptr()) };
        if ret == 0 { Ok(r) } else { Err(to_crypto_error()) }
    }

    fn scalar_negate(s: Vec<u8>) -> Vec<u8> {
        let mut r = vec![0u8; crypto_core_ed25519_SCALARBYTES as usize];
        if s.len() == crypto_core_ed25519_SCALARBYTES as usize {
            unsafe { crypto_core_ed25519_scalar_negate(r.as_mut_ptr(), s.as_ptr()) };
        }
        r
    }

    fn scalar_complement(s: Vec<u8>) -> Vec<u8> {
        let mut r = vec![0u8; crypto_core_ed25519_SCALARBYTES as usize];
        if s.len() == crypto_core_ed25519_SCALARBYTES as usize {
            unsafe { crypto_core_ed25519_scalar_complement(r.as_mut_ptr(), s.as_ptr()) };
        }
        r
    }

    fn scalar_add(x: Vec<u8>, y: Vec<u8>) -> Vec<u8> {
        let mut r = vec![0u8; crypto_core_ed25519_SCALARBYTES as usize];
        if x.len() == crypto_core_ed25519_SCALARBYTES as usize && y.len() == crypto_core_ed25519_SCALARBYTES as usize {
            unsafe { crypto_core_ed25519_scalar_add(r.as_mut_ptr(), x.as_ptr(), y.as_ptr()) };
        }
        r
    }

    fn scalar_sub(x: Vec<u8>, y: Vec<u8>) -> Vec<u8> {
        let mut r = vec![0u8; crypto_core_ed25519_SCALARBYTES as usize];
        if x.len() == crypto_core_ed25519_SCALARBYTES as usize && y.len() == crypto_core_ed25519_SCALARBYTES as usize {
            unsafe { crypto_core_ed25519_scalar_sub(r.as_mut_ptr(), x.as_ptr(), y.as_ptr()) };
        }
        r
    }

    fn scalar_mul(x: Vec<u8>, y: Vec<u8>) -> Vec<u8> {
        let mut r = vec![0u8; crypto_core_ed25519_SCALARBYTES as usize];
        if x.len() == crypto_core_ed25519_SCALARBYTES as usize && y.len() == crypto_core_ed25519_SCALARBYTES as usize {
            unsafe { crypto_core_ed25519_scalar_mul(r.as_mut_ptr(), x.as_ptr(), y.as_ptr()) };
        }
        r
    }

    fn scalar_reduce(s: Vec<u8>) -> Vec<u8> {
        let mut r = vec![0u8; crypto_core_ed25519_SCALARBYTES as usize];
        if s.len() == crypto_core_ed25519_NONREDUCEDSCALARBYTES as usize {
            unsafe { crypto_core_ed25519_scalar_reduce(r.as_mut_ptr(), s.as_ptr()) };
        }
        r
    }
}

// ============================================================================
// Scalarmult Ed25519
// ============================================================================

impl exports::libsodium::crypto::scalarmult_ed25519::Guest for Component {
    fn bytes() -> u32 {
        crypto_scalarmult_ed25519_BYTES
    }

    fn scalar_bytes() -> u32 {
        crypto_scalarmult_ed25519_SCALARBYTES
    }

    fn scalarmult(n: Vec<u8>, p: Vec<u8>) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if n.len() != crypto_scalarmult_ed25519_SCALARBYTES as usize || p.len() != crypto_scalarmult_ed25519_BYTES as usize {
            return Err(to_crypto_error());
        }
        let mut q = vec![0u8; crypto_scalarmult_ed25519_BYTES as usize];
        let ret = unsafe { crypto_scalarmult_ed25519(q.as_mut_ptr(), n.as_ptr(), p.as_ptr()) };
        if ret == 0 { Ok(q) } else { Err(to_crypto_error()) }
    }

    fn scalarmult_noclamp(n: Vec<u8>, p: Vec<u8>) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if n.len() != crypto_scalarmult_ed25519_SCALARBYTES as usize || p.len() != crypto_scalarmult_ed25519_BYTES as usize {
            return Err(to_crypto_error());
        }
        let mut q = vec![0u8; crypto_scalarmult_ed25519_BYTES as usize];
        let ret = unsafe { crypto_scalarmult_ed25519_noclamp(q.as_mut_ptr(), n.as_ptr(), p.as_ptr()) };
        if ret == 0 { Ok(q) } else { Err(to_crypto_error()) }
    }

    fn base(n: Vec<u8>) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if n.len() != crypto_scalarmult_ed25519_SCALARBYTES as usize {
            return Err(to_crypto_error());
        }
        let mut q = vec![0u8; crypto_scalarmult_ed25519_BYTES as usize];
        let ret = unsafe { crypto_scalarmult_ed25519_base(q.as_mut_ptr(), n.as_ptr()) };
        if ret == 0 { Ok(q) } else { Err(to_crypto_error()) }
    }

    fn base_noclamp(n: Vec<u8>) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if n.len() != crypto_scalarmult_ed25519_SCALARBYTES as usize {
            return Err(to_crypto_error());
        }
        let mut q = vec![0u8; crypto_scalarmult_ed25519_BYTES as usize];
        let ret = unsafe { crypto_scalarmult_ed25519_base_noclamp(q.as_mut_ptr(), n.as_ptr()) };
        if ret == 0 { Ok(q) } else { Err(to_crypto_error()) }
    }
}

// ============================================================================
// Scalarmult Ristretto255
// ============================================================================

impl exports::libsodium::crypto::scalarmult_ristretto255::Guest for Component {
    fn bytes() -> u32 {
        crypto_scalarmult_ristretto255_BYTES
    }

    fn scalar_bytes() -> u32 {
        crypto_scalarmult_ristretto255_SCALARBYTES
    }

    fn scalarmult(n: Vec<u8>, p: Vec<u8>) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if n.len() != crypto_scalarmult_ristretto255_SCALARBYTES as usize || p.len() != crypto_scalarmult_ristretto255_BYTES as usize {
            return Err(to_crypto_error());
        }
        let mut q = vec![0u8; crypto_scalarmult_ristretto255_BYTES as usize];
        let ret = unsafe { crypto_scalarmult_ristretto255(q.as_mut_ptr(), n.as_ptr(), p.as_ptr()) };
        if ret == 0 { Ok(q) } else { Err(to_crypto_error()) }
    }

    fn base(n: Vec<u8>) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if n.len() != crypto_scalarmult_ristretto255_SCALARBYTES as usize {
            return Err(to_crypto_error());
        }
        let mut q = vec![0u8; crypto_scalarmult_ristretto255_BYTES as usize];
        let ret = unsafe { crypto_scalarmult_ristretto255_base(q.as_mut_ptr(), n.as_ptr()) };
        if ret == 0 { Ok(q) } else { Err(to_crypto_error()) }
    }
}

// ============================================================================
// KDF HKDF-SHA512
// ============================================================================

impl exports::libsodium::crypto::kdf_hkdf_sha512::Guest for Component {
    fn key_bytes() -> u32 {
        crypto_kdf_hkdf_sha512_KEYBYTES
    }

    fn extract(salt: Vec<u8>, ikm: Vec<u8>) -> Vec<u8> {
        let mut prk = vec![0u8; crypto_kdf_hkdf_sha512_KEYBYTES as usize];
        let salt_ptr = if salt.is_empty() { core::ptr::null() } else { salt.as_ptr() };
        unsafe {
            crypto_kdf_hkdf_sha512_extract(prk.as_mut_ptr(), salt_ptr, salt.len(), ikm.as_ptr(), ikm.len());
        }
        prk
    }

    fn expand(out_len: u32, prk: Vec<u8>, info: Vec<u8>) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if prk.len() != crypto_kdf_hkdf_sha512_KEYBYTES as usize {
            return Err(invalid_key());
        }
        if out_len > crypto_kdf_hkdf_sha512_BYTES_MAX {
            return Err(to_crypto_error());
        }

        let mut out = vec![0u8; out_len as usize];
        let info_ptr = if info.is_empty() { core::ptr::null() } else { info.as_ptr() };

        let ret = unsafe {
            crypto_kdf_hkdf_sha512_expand(out.as_mut_ptr(), out_len as usize, info_ptr as *const i8, info.len(), prk.as_ptr())
        };

        if ret == 0 { Ok(out) } else { Err(to_crypto_error()) }
    }

    fn bytes_min() -> u32 {
        0
    }

    fn bytes_max() -> u32 {
        crypto_kdf_hkdf_sha512_BYTES_MAX
    }

    fn keygen() -> Vec<u8> {
        let mut key = vec![0u8; crypto_kdf_hkdf_sha512_KEYBYTES as usize];
        unsafe {
            crypto_kdf_hkdf_sha512_keygen(key.as_mut_ptr());
        }
        key
    }

    fn extract_init(salt: Vec<u8>) -> Result<u64, exports::libsodium::crypto::types::CryptoError> {
        let mut state: crypto_kdf_hkdf_sha512_state = unsafe { core::mem::zeroed() };
        let salt_ptr = if salt.is_empty() {
            core::ptr::null()
        } else {
            salt.as_ptr()
        };
        let ret = unsafe { crypto_kdf_hkdf_sha512_extract_init(&mut state, salt_ptr, salt.len()) };

        if ret == 0 {
            let id = next_state_id();
            hkdf_sha512_states().as_mut().unwrap().insert(id, state);
            Ok(id)
        } else {
            Err(to_crypto_error())
        }
    }

    fn extract_update(state_id: u64, ikm: Vec<u8>) -> Result<(), exports::libsodium::crypto::types::CryptoError> {
        let mut guard = hkdf_sha512_states();
        let states = guard.as_mut().unwrap();
        let state = states.get_mut(&state_id).ok_or(to_crypto_error())?;

        let ret = unsafe { crypto_kdf_hkdf_sha512_extract_update(state, ikm.as_ptr(), ikm.len()) };

        if ret == 0 {
            Ok(())
        } else {
            Err(to_crypto_error())
        }
    }

    fn extract_final(state_id: u64) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        let mut guard = hkdf_sha512_states();
        let states = guard.as_mut().unwrap();
        let state = states.get_mut(&state_id).ok_or(to_crypto_error())?;

        let mut prk = vec![0u8; crypto_kdf_hkdf_sha512_KEYBYTES as usize];
        let ret = unsafe { crypto_kdf_hkdf_sha512_extract_final(state, prk.as_mut_ptr()) };

        states.remove(&state_id);

        if ret == 0 {
            Ok(prk)
        } else {
            Err(to_crypto_error())
        }
    }
}

// ============================================================================
// Password Hashing (scrypt)
// ============================================================================

impl exports::libsodium::crypto::pwhash_scrypt::Guest for Component {
    fn salt_bytes() -> u32 {
        crypto_pwhash_scryptsalsa208sha256_SALTBYTES
    }

    fn str_bytes() -> u32 {
        crypto_pwhash_scryptsalsa208sha256_STRBYTES
    }

    fn opslimit_min() -> u64 {
        crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MIN as u64
    }

    fn opslimit_max() -> u64 {
        crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MAX as u64
    }

    fn opslimit_interactive() -> u64 {
        crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE as u64
    }

    fn opslimit_sensitive() -> u64 {
        crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE as u64
    }

    fn memlimit_min() -> u64 {
        crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MIN as u64
    }

    fn memlimit_interactive() -> u64 {
        crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE as u64
    }

    fn memlimit_sensitive() -> u64 {
        crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE as u64
    }

    fn derive(out_len: u32, password: Vec<u8>, salt: Vec<u8>, opslimit: u64, memlimit: u64) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if salt.len() != crypto_pwhash_scryptsalsa208sha256_SALTBYTES as usize {
            return Err(to_crypto_error());
        }

        let mut out = vec![0u8; out_len as usize];
        let ret = unsafe {
            crypto_pwhash_scryptsalsa208sha256(
                out.as_mut_ptr(),
                out_len as u64,
                password.as_ptr() as *const i8,
                password.len() as u64,
                salt.as_ptr(),
                opslimit,
                memlimit as usize,
            )
        };

        if ret == 0 { Ok(out) } else { Err(to_crypto_error()) }
    }

    fn str(password: Vec<u8>, opslimit: u64, memlimit: u64) -> Result<String, exports::libsodium::crypto::types::CryptoError> {
        let mut out = vec![0u8; crypto_pwhash_scryptsalsa208sha256_STRBYTES as usize];
        let ret = unsafe {
            crypto_pwhash_scryptsalsa208sha256_str(
                out.as_mut_ptr() as *mut i8,
                password.as_ptr() as *const i8,
                password.len() as u64,
                opslimit,
                memlimit as usize,
            )
        };

        if ret == 0 {
            let len = out.iter().position(|&c| c == 0).unwrap_or(out.len());
            Ok(String::from_utf8_lossy(&out[..len]).into_owned())
        } else {
            Err(to_crypto_error())
        }
    }

    fn str_verify(hash: String, password: Vec<u8>) -> Result<(), exports::libsodium::crypto::types::CryptoError> {
        let hash_bytes = hash.as_bytes();
        if hash_bytes.len() >= crypto_pwhash_scryptsalsa208sha256_STRBYTES as usize {
            return Err(verification_failed());
        }

        let mut hash_buf = vec![0u8; crypto_pwhash_scryptsalsa208sha256_STRBYTES as usize];
        hash_buf[..hash_bytes.len()].copy_from_slice(hash_bytes);

        let ret = unsafe {
            crypto_pwhash_scryptsalsa208sha256_str_verify(
                hash_buf.as_ptr() as *const i8,
                password.as_ptr() as *const i8,
                password.len() as u64,
            )
        };

        if ret == 0 { Ok(()) } else { Err(verification_failed()) }
    }

    fn str_needs_rehash(hash: String, opslimit: u64, memlimit: u64) -> Result<bool, exports::libsodium::crypto::types::CryptoError> {
        let hash_bytes = hash.as_bytes();
        if hash_bytes.len() >= crypto_pwhash_scryptsalsa208sha256_STRBYTES as usize {
            return Err(to_crypto_error());
        }

        let mut hash_buf = vec![0u8; crypto_pwhash_scryptsalsa208sha256_STRBYTES as usize];
        hash_buf[..hash_bytes.len()].copy_from_slice(hash_bytes);

        let ret = unsafe {
            crypto_pwhash_scryptsalsa208sha256_str_needs_rehash(
                hash_buf.as_ptr() as *const i8,
                opslimit,
                memlimit as usize,
            )
        };

        match ret {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(to_crypto_error()),
        }
    }

    fn bytes_min() -> u32 {
        crypto_pwhash_scryptsalsa208sha256_BYTES_MIN
    }

    fn bytes_max() -> u32 {
        unsafe { crypto_pwhash_scryptsalsa208sha256_bytes_max() as u32 }
    }

    fn passwd_min() -> u32 {
        crypto_pwhash_scryptsalsa208sha256_PASSWD_MIN
    }

    fn passwd_max() -> u32 {
        unsafe { crypto_pwhash_scryptsalsa208sha256_passwd_max() as u32 }
    }

    fn memlimit_max() -> u64 {
        unsafe { crypto_pwhash_scryptsalsa208sha256_memlimit_max() as u64 }
    }

    fn strprefix() -> String {
        unsafe {
            let ptr = crypto_pwhash_scryptsalsa208sha256_strprefix();
            let mut len = 0;
            while *ptr.add(len) != 0 {
                len += 1;
            }
            let slice = core::slice::from_raw_parts(ptr as *const u8, len);
            String::from_utf8_lossy(slice).into_owned()
        }
    }

    fn derive_ll(out_len: u32, password: Vec<u8>, salt: Vec<u8>, n: u64, r: u32, p: u32) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        let mut out = vec![0u8; out_len as usize];
        let ret = unsafe {
            crypto_pwhash_scryptsalsa208sha256_ll(
                password.as_ptr(),
                password.len(),
                salt.as_ptr(),
                salt.len(),
                n,
                r,
                p,
                out.as_mut_ptr(),
                out_len as usize,
            )
        };

        if ret == 0 { Ok(out) } else { Err(to_crypto_error()) }
    }
}

// ============================================================================
// Cipher Salsa20
// ============================================================================

impl exports::libsodium::crypto::cipher_salsa20::Guest for Component {
    fn key_bytes() -> u32 {
        crypto_stream_salsa20_KEYBYTES
    }

    fn nonce_bytes() -> u32 {
        crypto_stream_salsa20_NONCEBYTES
    }

    fn keygen() -> Vec<u8> {
        let mut key = vec![0u8; crypto_stream_salsa20_KEYBYTES as usize];
        unsafe { crypto_stream_salsa20_keygen(key.as_mut_ptr()) };
        key
    }

    fn keystream(len: u32, nonce: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if key.len() != crypto_stream_salsa20_KEYBYTES as usize { return Err(invalid_key()); }
        if nonce.len() != crypto_stream_salsa20_NONCEBYTES as usize { return Err(invalid_nonce()); }

        let mut out = vec![0u8; len as usize];
        let ret = unsafe { crypto_stream_salsa20(out.as_mut_ptr(), len as u64, nonce.as_ptr(), key.as_ptr()) };
        if ret == 0 { Ok(out) } else { Err(to_crypto_error()) }
    }

    fn xor(message: Vec<u8>, nonce: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if key.len() != crypto_stream_salsa20_KEYBYTES as usize { return Err(invalid_key()); }
        if nonce.len() != crypto_stream_salsa20_NONCEBYTES as usize { return Err(invalid_nonce()); }

        let mut out = vec![0u8; message.len()];
        let ret = unsafe { crypto_stream_salsa20_xor(out.as_mut_ptr(), message.as_ptr(), message.len() as u64, nonce.as_ptr(), key.as_ptr()) };
        if ret == 0 { Ok(out) } else { Err(to_crypto_error()) }
    }

    fn xor_ic(message: Vec<u8>, nonce: Vec<u8>, ic: u64, key: Vec<u8>) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if key.len() != crypto_stream_salsa20_KEYBYTES as usize { return Err(invalid_key()); }
        if nonce.len() != crypto_stream_salsa20_NONCEBYTES as usize { return Err(invalid_nonce()); }

        let mut out = vec![0u8; message.len()];
        let ret = unsafe { crypto_stream_salsa20_xor_ic(out.as_mut_ptr(), message.as_ptr(), message.len() as u64, nonce.as_ptr(), ic, key.as_ptr()) };
        if ret == 0 { Ok(out) } else { Err(to_crypto_error()) }
    }
}

// ============================================================================
// Cipher ChaCha20
// ============================================================================

impl exports::libsodium::crypto::cipher_chacha20::Guest for Component {
    fn key_bytes() -> u32 {
        crypto_stream_chacha20_KEYBYTES
    }

    fn nonce_bytes() -> u32 {
        crypto_stream_chacha20_NONCEBYTES
    }

    fn keygen() -> Vec<u8> {
        let mut key = vec![0u8; crypto_stream_chacha20_KEYBYTES as usize];
        unsafe { crypto_stream_chacha20_keygen(key.as_mut_ptr()) };
        key
    }

    fn keystream(len: u32, nonce: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if key.len() != crypto_stream_chacha20_KEYBYTES as usize { return Err(invalid_key()); }
        if nonce.len() != crypto_stream_chacha20_NONCEBYTES as usize { return Err(invalid_nonce()); }

        let mut out = vec![0u8; len as usize];
        let ret = unsafe { crypto_stream_chacha20(out.as_mut_ptr(), len as u64, nonce.as_ptr(), key.as_ptr()) };
        if ret == 0 { Ok(out) } else { Err(to_crypto_error()) }
    }

    fn xor(message: Vec<u8>, nonce: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if key.len() != crypto_stream_chacha20_KEYBYTES as usize { return Err(invalid_key()); }
        if nonce.len() != crypto_stream_chacha20_NONCEBYTES as usize { return Err(invalid_nonce()); }

        let mut out = vec![0u8; message.len()];
        let ret = unsafe { crypto_stream_chacha20_xor(out.as_mut_ptr(), message.as_ptr(), message.len() as u64, nonce.as_ptr(), key.as_ptr()) };
        if ret == 0 { Ok(out) } else { Err(to_crypto_error()) }
    }

    fn xor_ic(message: Vec<u8>, nonce: Vec<u8>, ic: u64, key: Vec<u8>) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if key.len() != crypto_stream_chacha20_KEYBYTES as usize { return Err(invalid_key()); }
        if nonce.len() != crypto_stream_chacha20_NONCEBYTES as usize { return Err(invalid_nonce()); }

        let mut out = vec![0u8; message.len()];
        let ret = unsafe { crypto_stream_chacha20_xor_ic(out.as_mut_ptr(), message.as_ptr(), message.len() as u64, nonce.as_ptr(), ic, key.as_ptr()) };
        if ret == 0 { Ok(out) } else { Err(to_crypto_error()) }
    }
}

// ============================================================================
// Cipher ChaCha20 IETF
// ============================================================================

impl exports::libsodium::crypto::cipher_chacha20_ietf::Guest for Component {
    fn key_bytes() -> u32 {
        crypto_stream_chacha20_ietf_KEYBYTES
    }

    fn nonce_bytes() -> u32 {
        crypto_stream_chacha20_ietf_NONCEBYTES
    }

    fn keygen() -> Vec<u8> {
        let mut key = vec![0u8; crypto_stream_chacha20_ietf_KEYBYTES as usize];
        unsafe { crypto_stream_chacha20_ietf_keygen(key.as_mut_ptr()) };
        key
    }

    fn keystream(len: u32, nonce: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if key.len() != crypto_stream_chacha20_ietf_KEYBYTES as usize { return Err(invalid_key()); }
        if nonce.len() != crypto_stream_chacha20_ietf_NONCEBYTES as usize { return Err(invalid_nonce()); }

        let mut out = vec![0u8; len as usize];
        let ret = unsafe { crypto_stream_chacha20_ietf(out.as_mut_ptr(), len as u64, nonce.as_ptr(), key.as_ptr()) };
        if ret == 0 { Ok(out) } else { Err(to_crypto_error()) }
    }

    fn xor(message: Vec<u8>, nonce: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if key.len() != crypto_stream_chacha20_ietf_KEYBYTES as usize { return Err(invalid_key()); }
        if nonce.len() != crypto_stream_chacha20_ietf_NONCEBYTES as usize { return Err(invalid_nonce()); }

        let mut out = vec![0u8; message.len()];
        let ret = unsafe { crypto_stream_chacha20_ietf_xor(out.as_mut_ptr(), message.as_ptr(), message.len() as u64, nonce.as_ptr(), key.as_ptr()) };
        if ret == 0 { Ok(out) } else { Err(to_crypto_error()) }
    }

    fn xor_ic(message: Vec<u8>, nonce: Vec<u8>, ic: u32, key: Vec<u8>) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if key.len() != crypto_stream_chacha20_ietf_KEYBYTES as usize { return Err(invalid_key()); }
        if nonce.len() != crypto_stream_chacha20_ietf_NONCEBYTES as usize { return Err(invalid_nonce()); }

        let mut out = vec![0u8; message.len()];
        let ret = unsafe { crypto_stream_chacha20_ietf_xor_ic(out.as_mut_ptr(), message.as_ptr(), message.len() as u64, nonce.as_ptr(), ic, key.as_ptr()) };
        if ret == 0 { Ok(out) } else { Err(to_crypto_error()) }
    }
}

// ============================================================================
// XOF SHAKE128
// ============================================================================

impl exports::libsodium::crypto::xof_shake128::Guest for Component {
    fn block_bytes() -> u32 {
        crypto_xof_shake128_BLOCKBYTES
    }

    fn state_bytes() -> u32 {
        crypto_xof_shake128_STATEBYTES
    }

    fn hash(out_len: u32, message: Vec<u8>) -> Vec<u8> {
        let mut out = vec![0u8; out_len as usize];
        unsafe { crypto_xof_shake128(out.as_mut_ptr(), out_len as usize, message.as_ptr(), message.len() as u64) };
        out
    }

    fn init() -> Result<u64, exports::libsodium::crypto::types::CryptoError> {
        let mut state: crypto_xof_shake128_state = unsafe { core::mem::zeroed() };
        let ret = unsafe { crypto_xof_shake128_init(&mut state) };
        if ret == 0 {
            let id = next_state_id();
            shake128_states().as_mut().unwrap().insert(id, state);
            Ok(id)
        } else {
            Err(to_crypto_error())
        }
    }

    fn update(state_id: u64, data: Vec<u8>) -> Result<(), exports::libsodium::crypto::types::CryptoError> {
        let mut states = shake128_states();
        let state = states.as_mut().unwrap().get_mut(&state_id).ok_or(to_crypto_error())?;
        let ret = unsafe { crypto_xof_shake128_update(state, data.as_ptr(), data.len() as u64) };
        if ret == 0 { Ok(()) } else { Err(to_crypto_error()) }
    }

    fn squeeze(state_id: u64, out_len: u32) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        let mut states = shake128_states();
        let state = states.as_mut().unwrap().get_mut(&state_id).ok_or(to_crypto_error())?;
        let mut out = vec![0u8; out_len as usize];
        let ret = unsafe { crypto_xof_shake128_squeeze(state, out.as_mut_ptr(), out_len as usize) };
        if ret == 0 { Ok(out) } else { Err(to_crypto_error()) }
    }

    fn destroy(state_id: u64) {
        shake128_states().as_mut().unwrap().remove(&state_id);
    }

    fn init_with_domain(domain_sep: u8) -> Result<u64, exports::libsodium::crypto::types::CryptoError> {
        let mut state: crypto_xof_shake128_state = unsafe { core::mem::zeroed() };
        let ret = unsafe { crypto_xof_shake128_init_with_domain(&mut state, domain_sep) };
        if ret == 0 {
            let id = next_state_id();
            shake128_states().as_mut().unwrap().insert(id, state);
            Ok(id)
        } else {
            Err(to_crypto_error())
        }
    }
}

// ============================================================================
// XOF SHAKE256
// ============================================================================

impl exports::libsodium::crypto::xof_shake256::Guest for Component {
    fn block_bytes() -> u32 {
        crypto_xof_shake256_BLOCKBYTES
    }

    fn state_bytes() -> u32 {
        crypto_xof_shake256_STATEBYTES
    }

    fn hash(out_len: u32, message: Vec<u8>) -> Vec<u8> {
        let mut out = vec![0u8; out_len as usize];
        unsafe { crypto_xof_shake256(out.as_mut_ptr(), out_len as usize, message.as_ptr(), message.len() as u64) };
        out
    }

    fn init() -> Result<u64, exports::libsodium::crypto::types::CryptoError> {
        let mut state: crypto_xof_shake256_state = unsafe { core::mem::zeroed() };
        let ret = unsafe { crypto_xof_shake256_init(&mut state) };
        if ret == 0 {
            let id = next_state_id();
            shake256_states().as_mut().unwrap().insert(id, state);
            Ok(id)
        } else {
            Err(to_crypto_error())
        }
    }

    fn update(state_id: u64, data: Vec<u8>) -> Result<(), exports::libsodium::crypto::types::CryptoError> {
        let mut states = shake256_states();
        let state = states.as_mut().unwrap().get_mut(&state_id).ok_or(to_crypto_error())?;
        let ret = unsafe { crypto_xof_shake256_update(state, data.as_ptr(), data.len() as u64) };
        if ret == 0 { Ok(()) } else { Err(to_crypto_error()) }
    }

    fn squeeze(state_id: u64, out_len: u32) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        let mut states = shake256_states();
        let state = states.as_mut().unwrap().get_mut(&state_id).ok_or(to_crypto_error())?;
        let mut out = vec![0u8; out_len as usize];
        let ret = unsafe { crypto_xof_shake256_squeeze(state, out.as_mut_ptr(), out_len as usize) };
        if ret == 0 { Ok(out) } else { Err(to_crypto_error()) }
    }

    fn destroy(state_id: u64) {
        shake256_states().as_mut().unwrap().remove(&state_id);
    }

    fn init_with_domain(domain_sep: u8) -> Result<u64, exports::libsodium::crypto::types::CryptoError> {
        let mut state: crypto_xof_shake256_state = unsafe { core::mem::zeroed() };
        let ret = unsafe { crypto_xof_shake256_init_with_domain(&mut state, domain_sep) };
        if ret == 0 {
            let id = next_state_id();
            shake256_states().as_mut().unwrap().insert(id, state);
            Ok(id)
        } else {
            Err(to_crypto_error())
        }
    }
}

// ============================================================================
// XOF TurboSHAKE128
// ============================================================================

impl exports::libsodium::crypto::xof_turboshake128::Guest for Component {
    fn block_bytes() -> u32 {
        crypto_xof_turboshake128_BLOCKBYTES
    }

    fn state_bytes() -> u32 {
        crypto_xof_turboshake128_STATEBYTES
    }

    fn hash(out_len: u32, message: Vec<u8>) -> Vec<u8> {
        let mut out = vec![0u8; out_len as usize];
        unsafe { crypto_xof_turboshake128(out.as_mut_ptr(), out_len as usize, message.as_ptr(), message.len() as u64) };
        out
    }

    fn init() -> Result<u64, exports::libsodium::crypto::types::CryptoError> {
        let mut state: crypto_xof_turboshake128_state = unsafe { core::mem::zeroed() };
        let ret = unsafe { crypto_xof_turboshake128_init(&mut state) };
        if ret == 0 {
            let id = next_state_id();
            turboshake128_states().as_mut().unwrap().insert(id, state);
            Ok(id)
        } else {
            Err(to_crypto_error())
        }
    }

    fn update(state_id: u64, data: Vec<u8>) -> Result<(), exports::libsodium::crypto::types::CryptoError> {
        let mut states = turboshake128_states();
        let state = states.as_mut().unwrap().get_mut(&state_id).ok_or(to_crypto_error())?;
        let ret = unsafe { crypto_xof_turboshake128_update(state, data.as_ptr(), data.len() as u64) };
        if ret == 0 { Ok(()) } else { Err(to_crypto_error()) }
    }

    fn squeeze(state_id: u64, out_len: u32) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        let mut states = turboshake128_states();
        let state = states.as_mut().unwrap().get_mut(&state_id).ok_or(to_crypto_error())?;
        let mut out = vec![0u8; out_len as usize];
        let ret = unsafe { crypto_xof_turboshake128_squeeze(state, out.as_mut_ptr(), out_len as usize) };
        if ret == 0 { Ok(out) } else { Err(to_crypto_error()) }
    }

    fn destroy(state_id: u64) {
        turboshake128_states().as_mut().unwrap().remove(&state_id);
    }

    fn init_with_domain(domain_sep: u8) -> Result<u64, exports::libsodium::crypto::types::CryptoError> {
        let mut state: crypto_xof_turboshake128_state = unsafe { core::mem::zeroed() };
        let ret = unsafe { crypto_xof_turboshake128_init_with_domain(&mut state, domain_sep) };
        if ret == 0 {
            let id = next_state_id();
            turboshake128_states().as_mut().unwrap().insert(id, state);
            Ok(id)
        } else {
            Err(to_crypto_error())
        }
    }
}

// ============================================================================
// XOF TurboSHAKE256
// ============================================================================

impl exports::libsodium::crypto::xof_turboshake256::Guest for Component {
    fn block_bytes() -> u32 {
        crypto_xof_turboshake256_BLOCKBYTES
    }

    fn state_bytes() -> u32 {
        crypto_xof_turboshake256_STATEBYTES
    }

    fn hash(out_len: u32, message: Vec<u8>) -> Vec<u8> {
        let mut out = vec![0u8; out_len as usize];
        unsafe { crypto_xof_turboshake256(out.as_mut_ptr(), out_len as usize, message.as_ptr(), message.len() as u64) };
        out
    }

    fn init() -> Result<u64, exports::libsodium::crypto::types::CryptoError> {
        let mut state: crypto_xof_turboshake256_state = unsafe { core::mem::zeroed() };
        let ret = unsafe { crypto_xof_turboshake256_init(&mut state) };
        if ret == 0 {
            let id = next_state_id();
            turboshake256_states().as_mut().unwrap().insert(id, state);
            Ok(id)
        } else {
            Err(to_crypto_error())
        }
    }

    fn update(state_id: u64, data: Vec<u8>) -> Result<(), exports::libsodium::crypto::types::CryptoError> {
        let mut states = turboshake256_states();
        let state = states.as_mut().unwrap().get_mut(&state_id).ok_or(to_crypto_error())?;
        let ret = unsafe { crypto_xof_turboshake256_update(state, data.as_ptr(), data.len() as u64) };
        if ret == 0 { Ok(()) } else { Err(to_crypto_error()) }
    }

    fn squeeze(state_id: u64, out_len: u32) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        let mut states = turboshake256_states();
        let state = states.as_mut().unwrap().get_mut(&state_id).ok_or(to_crypto_error())?;
        let mut out = vec![0u8; out_len as usize];
        let ret = unsafe { crypto_xof_turboshake256_squeeze(state, out.as_mut_ptr(), out_len as usize) };
        if ret == 0 { Ok(out) } else { Err(to_crypto_error()) }
    }

    fn init_with_domain(domain_sep: u8) -> Result<u64, exports::libsodium::crypto::types::CryptoError> {
        let mut state: crypto_xof_turboshake256_state = unsafe { core::mem::zeroed() };
        let ret = unsafe { crypto_xof_turboshake256_init_with_domain(&mut state, domain_sep) };
        if ret == 0 {
            let id = next_state_id();
            turboshake256_states().as_mut().unwrap().insert(id, state);
            Ok(id)
        } else {
            Err(to_crypto_error())
        }
    }

    fn destroy(state_id: u64) {
        turboshake256_states().as_mut().unwrap().remove(&state_id);
    }
}

// ============================================================================
// Secretbox XChaCha20-Poly1305
// ============================================================================

impl exports::libsodium::crypto::secretbox_xchacha20poly1305::Guest for Component {
    fn key_bytes() -> u32 {
        crypto_secretbox_xchacha20poly1305_KEYBYTES
    }

    fn nonce_bytes() -> u32 {
        crypto_secretbox_xchacha20poly1305_NONCEBYTES
    }

    fn mac_bytes() -> u32 {
        crypto_secretbox_xchacha20poly1305_MACBYTES
    }

    fn easy(message: Vec<u8>, nonce: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if key.len() != crypto_secretbox_xchacha20poly1305_KEYBYTES as usize { return Err(invalid_key()); }
        if nonce.len() != crypto_secretbox_xchacha20poly1305_NONCEBYTES as usize { return Err(invalid_nonce()); }

        let mut ciphertext = vec![0u8; message.len() + crypto_secretbox_xchacha20poly1305_MACBYTES as usize];
        let ret = unsafe {
            crypto_secretbox_xchacha20poly1305_easy(ciphertext.as_mut_ptr(), message.as_ptr(), message.len() as u64, nonce.as_ptr(), key.as_ptr())
        };
        if ret == 0 { Ok(ciphertext) } else { Err(to_crypto_error()) }
    }

    fn open_easy(ciphertext: Vec<u8>, nonce: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if key.len() != crypto_secretbox_xchacha20poly1305_KEYBYTES as usize { return Err(invalid_key()); }
        if nonce.len() != crypto_secretbox_xchacha20poly1305_NONCEBYTES as usize { return Err(invalid_nonce()); }
        if ciphertext.len() < crypto_secretbox_xchacha20poly1305_MACBYTES as usize { return Err(verification_failed()); }

        let mut message = vec![0u8; ciphertext.len() - crypto_secretbox_xchacha20poly1305_MACBYTES as usize];
        let ret = unsafe {
            crypto_secretbox_xchacha20poly1305_open_easy(message.as_mut_ptr(), ciphertext.as_ptr(), ciphertext.len() as u64, nonce.as_ptr(), key.as_ptr())
        };
        if ret == 0 { Ok(message) } else { Err(verification_failed()) }
    }

    fn detached(message: Vec<u8>, nonce: Vec<u8>, key: Vec<u8>) -> Result<(Vec<u8>, Vec<u8>), exports::libsodium::crypto::types::CryptoError> {
        if key.len() != crypto_secretbox_xchacha20poly1305_KEYBYTES as usize { return Err(invalid_key()); }
        if nonce.len() != crypto_secretbox_xchacha20poly1305_NONCEBYTES as usize { return Err(invalid_nonce()); }

        let mut ciphertext = vec![0u8; message.len()];
        let mut mac = vec![0u8; crypto_secretbox_xchacha20poly1305_MACBYTES as usize];
        let ret = unsafe {
            crypto_secretbox_xchacha20poly1305_detached(ciphertext.as_mut_ptr(), mac.as_mut_ptr(), message.as_ptr(), message.len() as u64, nonce.as_ptr(), key.as_ptr())
        };
        if ret == 0 { Ok((ciphertext, mac)) } else { Err(to_crypto_error()) }
    }

    fn open_detached(ciphertext: Vec<u8>, mac: Vec<u8>, nonce: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if key.len() != crypto_secretbox_xchacha20poly1305_KEYBYTES as usize { return Err(invalid_key()); }
        if nonce.len() != crypto_secretbox_xchacha20poly1305_NONCEBYTES as usize { return Err(invalid_nonce()); }
        if mac.len() != crypto_secretbox_xchacha20poly1305_MACBYTES as usize { return Err(verification_failed()); }

        let mut message = vec![0u8; ciphertext.len()];
        let ret = unsafe {
            crypto_secretbox_xchacha20poly1305_open_detached(message.as_mut_ptr(), ciphertext.as_ptr(), mac.as_ptr(), ciphertext.len() as u64, nonce.as_ptr(), key.as_ptr())
        };
        if ret == 0 { Ok(message) } else { Err(verification_failed()) }
    }

    fn keygen() -> Vec<u8> {
        let mut key = vec![0u8; crypto_secretbox_xchacha20poly1305_KEYBYTES as usize];
        unsafe { crypto_secretbox_keygen(key.as_mut_ptr()) };
        key
    }
}

// ============================================================================
// Crypto Box XChaCha20-Poly1305
// ============================================================================

impl exports::libsodium::crypto::crypto_box_xchacha20poly1305::Guest for Component {
    fn public_key_bytes() -> u32 {
        crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES
    }

    fn secret_key_bytes() -> u32 {
        crypto_box_curve25519xchacha20poly1305_SECRETKEYBYTES
    }

    fn nonce_bytes() -> u32 {
        crypto_box_curve25519xchacha20poly1305_NONCEBYTES
    }

    fn mac_bytes() -> u32 {
        crypto_box_curve25519xchacha20poly1305_MACBYTES
    }

    fn seed_bytes() -> u32 {
        crypto_box_curve25519xchacha20poly1305_SEEDBYTES
    }

    fn seal_bytes() -> u32 {
        crypto_box_curve25519xchacha20poly1305_SEALBYTES
    }

    fn keypair() -> exports::libsodium::crypto::types::KeyPair {
        let mut pk = vec![0u8; crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES as usize];
        let mut sk = vec![0u8; crypto_box_curve25519xchacha20poly1305_SECRETKEYBYTES as usize];
        unsafe { crypto_box_curve25519xchacha20poly1305_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()) };
        exports::libsodium::crypto::types::KeyPair { public_key: pk, secret_key: sk }
    }

    fn seed_keypair(seed: Vec<u8>) -> Result<exports::libsodium::crypto::types::KeyPair, exports::libsodium::crypto::types::CryptoError> {
        if seed.len() != crypto_box_curve25519xchacha20poly1305_SEEDBYTES as usize { return Err(invalid_key()); }
        let mut pk = vec![0u8; crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES as usize];
        let mut sk = vec![0u8; crypto_box_curve25519xchacha20poly1305_SECRETKEYBYTES as usize];
        let ret = unsafe { crypto_box_curve25519xchacha20poly1305_seed_keypair(pk.as_mut_ptr(), sk.as_mut_ptr(), seed.as_ptr()) };
        if ret == 0 { Ok(exports::libsodium::crypto::types::KeyPair { public_key: pk, secret_key: sk }) } else { Err(to_crypto_error()) }
    }

    fn easy(message: Vec<u8>, nonce: Vec<u8>, recipient_pk: Vec<u8>, sender_sk: Vec<u8>) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if recipient_pk.len() != crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES as usize { return Err(invalid_key()); }
        if sender_sk.len() != crypto_box_curve25519xchacha20poly1305_SECRETKEYBYTES as usize { return Err(invalid_key()); }
        if nonce.len() != crypto_box_curve25519xchacha20poly1305_NONCEBYTES as usize { return Err(invalid_nonce()); }

        let mut ciphertext = vec![0u8; message.len() + crypto_box_curve25519xchacha20poly1305_MACBYTES as usize];
        let ret = unsafe {
            crypto_box_curve25519xchacha20poly1305_easy(ciphertext.as_mut_ptr(), message.as_ptr(), message.len() as u64, nonce.as_ptr(), recipient_pk.as_ptr(), sender_sk.as_ptr())
        };
        if ret == 0 { Ok(ciphertext) } else { Err(to_crypto_error()) }
    }

    fn open_easy(ciphertext: Vec<u8>, nonce: Vec<u8>, sender_pk: Vec<u8>, recipient_sk: Vec<u8>) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if sender_pk.len() != crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES as usize { return Err(invalid_key()); }
        if recipient_sk.len() != crypto_box_curve25519xchacha20poly1305_SECRETKEYBYTES as usize { return Err(invalid_key()); }
        if nonce.len() != crypto_box_curve25519xchacha20poly1305_NONCEBYTES as usize { return Err(invalid_nonce()); }
        if ciphertext.len() < crypto_box_curve25519xchacha20poly1305_MACBYTES as usize { return Err(verification_failed()); }

        let mut message = vec![0u8; ciphertext.len() - crypto_box_curve25519xchacha20poly1305_MACBYTES as usize];
        let ret = unsafe {
            crypto_box_curve25519xchacha20poly1305_open_easy(message.as_mut_ptr(), ciphertext.as_ptr(), ciphertext.len() as u64, nonce.as_ptr(), sender_pk.as_ptr(), recipient_sk.as_ptr())
        };
        if ret == 0 { Ok(message) } else { Err(verification_failed()) }
    }

    fn detached(message: Vec<u8>, nonce: Vec<u8>, recipient_pk: Vec<u8>, sender_sk: Vec<u8>) -> Result<(Vec<u8>, Vec<u8>), exports::libsodium::crypto::types::CryptoError> {
        if recipient_pk.len() != crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES as usize { return Err(invalid_key()); }
        if sender_sk.len() != crypto_box_curve25519xchacha20poly1305_SECRETKEYBYTES as usize { return Err(invalid_key()); }
        if nonce.len() != crypto_box_curve25519xchacha20poly1305_NONCEBYTES as usize { return Err(invalid_nonce()); }

        let mut ciphertext = vec![0u8; message.len()];
        let mut mac = vec![0u8; crypto_box_curve25519xchacha20poly1305_MACBYTES as usize];
        let ret = unsafe {
            crypto_box_curve25519xchacha20poly1305_detached(ciphertext.as_mut_ptr(), mac.as_mut_ptr(), message.as_ptr(), message.len() as u64, nonce.as_ptr(), recipient_pk.as_ptr(), sender_sk.as_ptr())
        };
        if ret == 0 { Ok((ciphertext, mac)) } else { Err(to_crypto_error()) }
    }

    fn open_detached(ciphertext: Vec<u8>, mac: Vec<u8>, nonce: Vec<u8>, sender_pk: Vec<u8>, recipient_sk: Vec<u8>) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if sender_pk.len() != crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES as usize { return Err(invalid_key()); }
        if recipient_sk.len() != crypto_box_curve25519xchacha20poly1305_SECRETKEYBYTES as usize { return Err(invalid_key()); }
        if nonce.len() != crypto_box_curve25519xchacha20poly1305_NONCEBYTES as usize { return Err(invalid_nonce()); }
        if mac.len() != crypto_box_curve25519xchacha20poly1305_MACBYTES as usize { return Err(verification_failed()); }

        let mut message = vec![0u8; ciphertext.len()];
        let ret = unsafe {
            crypto_box_curve25519xchacha20poly1305_open_detached(message.as_mut_ptr(), ciphertext.as_ptr(), mac.as_ptr(), ciphertext.len() as u64, nonce.as_ptr(), sender_pk.as_ptr(), recipient_sk.as_ptr())
        };
        if ret == 0 { Ok(message) } else { Err(verification_failed()) }
    }

    fn beforenm(recipient_pk: Vec<u8>, sender_sk: Vec<u8>) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if recipient_pk.len() != crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES as usize { return Err(invalid_key()); }
        if sender_sk.len() != crypto_box_curve25519xchacha20poly1305_SECRETKEYBYTES as usize { return Err(invalid_key()); }

        let mut k = vec![0u8; crypto_box_curve25519xchacha20poly1305_BEFORENMBYTES as usize];
        let ret = unsafe { crypto_box_curve25519xchacha20poly1305_beforenm(k.as_mut_ptr(), recipient_pk.as_ptr(), sender_sk.as_ptr()) };
        if ret == 0 { Ok(k) } else { Err(to_crypto_error()) }
    }

    fn easy_afternm(message: Vec<u8>, nonce: Vec<u8>, shared_key: Vec<u8>) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if shared_key.len() != crypto_box_curve25519xchacha20poly1305_BEFORENMBYTES as usize { return Err(invalid_key()); }
        if nonce.len() != crypto_box_curve25519xchacha20poly1305_NONCEBYTES as usize { return Err(invalid_nonce()); }

        let mut ciphertext = vec![0u8; message.len() + crypto_box_curve25519xchacha20poly1305_MACBYTES as usize];
        let ret = unsafe {
            crypto_box_curve25519xchacha20poly1305_easy_afternm(ciphertext.as_mut_ptr(), message.as_ptr(), message.len() as u64, nonce.as_ptr(), shared_key.as_ptr())
        };
        if ret == 0 { Ok(ciphertext) } else { Err(to_crypto_error()) }
    }

    fn open_easy_afternm(ciphertext: Vec<u8>, nonce: Vec<u8>, shared_key: Vec<u8>) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if shared_key.len() != crypto_box_curve25519xchacha20poly1305_BEFORENMBYTES as usize { return Err(invalid_key()); }
        if nonce.len() != crypto_box_curve25519xchacha20poly1305_NONCEBYTES as usize { return Err(invalid_nonce()); }
        if ciphertext.len() < crypto_box_curve25519xchacha20poly1305_MACBYTES as usize { return Err(verification_failed()); }

        let mut message = vec![0u8; ciphertext.len() - crypto_box_curve25519xchacha20poly1305_MACBYTES as usize];
        let ret = unsafe {
            crypto_box_curve25519xchacha20poly1305_open_easy_afternm(message.as_mut_ptr(), ciphertext.as_ptr(), ciphertext.len() as u64, nonce.as_ptr(), shared_key.as_ptr())
        };
        if ret == 0 { Ok(message) } else { Err(verification_failed()) }
    }

    fn seal(message: Vec<u8>, recipient_pk: Vec<u8>) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if recipient_pk.len() != crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES as usize { return Err(invalid_key()); }

        let mut ciphertext = vec![0u8; message.len() + crypto_box_curve25519xchacha20poly1305_SEALBYTES as usize];
        let ret = unsafe {
            crypto_box_curve25519xchacha20poly1305_seal(ciphertext.as_mut_ptr(), message.as_ptr(), message.len() as u64, recipient_pk.as_ptr())
        };
        if ret == 0 { Ok(ciphertext) } else { Err(to_crypto_error()) }
    }

    fn seal_open(ciphertext: Vec<u8>, recipient_pk: Vec<u8>, recipient_sk: Vec<u8>) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if recipient_pk.len() != crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES as usize { return Err(invalid_key()); }
        if recipient_sk.len() != crypto_box_curve25519xchacha20poly1305_SECRETKEYBYTES as usize { return Err(invalid_key()); }
        if ciphertext.len() < crypto_box_curve25519xchacha20poly1305_SEALBYTES as usize { return Err(verification_failed()); }

        let mut message = vec![0u8; ciphertext.len() - crypto_box_curve25519xchacha20poly1305_SEALBYTES as usize];
        let ret = unsafe {
            crypto_box_curve25519xchacha20poly1305_seal_open(message.as_mut_ptr(), ciphertext.as_ptr(), ciphertext.len() as u64, recipient_pk.as_ptr(), recipient_sk.as_ptr())
        };
        if ret == 0 { Ok(message) } else { Err(verification_failed()) }
    }

    fn beforenm_bytes() -> u32 {
        crypto_box_curve25519xchacha20poly1305_BEFORENMBYTES
    }

    fn detached_afternm(message: Vec<u8>, nonce: Vec<u8>, shared_key: Vec<u8>) -> Result<(Vec<u8>, Vec<u8>), exports::libsodium::crypto::types::CryptoError> {
        if shared_key.len() != crypto_box_curve25519xchacha20poly1305_BEFORENMBYTES as usize { return Err(invalid_key()); }
        if nonce.len() != crypto_box_curve25519xchacha20poly1305_NONCEBYTES as usize { return Err(invalid_nonce()); }

        let mut ciphertext = vec![0u8; message.len()];
        let mut mac = vec![0u8; crypto_box_curve25519xchacha20poly1305_MACBYTES as usize];
        let ret = unsafe {
            crypto_box_curve25519xchacha20poly1305_detached_afternm(ciphertext.as_mut_ptr(), mac.as_mut_ptr(), message.as_ptr(), message.len() as u64, nonce.as_ptr(), shared_key.as_ptr())
        };
        if ret == 0 { Ok((ciphertext, mac)) } else { Err(to_crypto_error()) }
    }

    fn open_detached_afternm(ciphertext: Vec<u8>, mac: Vec<u8>, nonce: Vec<u8>, shared_key: Vec<u8>) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if shared_key.len() != crypto_box_curve25519xchacha20poly1305_BEFORENMBYTES as usize { return Err(invalid_key()); }
        if nonce.len() != crypto_box_curve25519xchacha20poly1305_NONCEBYTES as usize { return Err(invalid_nonce()); }
        if mac.len() != crypto_box_curve25519xchacha20poly1305_MACBYTES as usize { return Err(verification_failed()); }

        let mut message = vec![0u8; ciphertext.len()];
        let ret = unsafe {
            crypto_box_curve25519xchacha20poly1305_open_detached_afternm(message.as_mut_ptr(), ciphertext.as_ptr(), mac.as_ptr(), ciphertext.len() as u64, nonce.as_ptr(), shared_key.as_ptr())
        };
        if ret == 0 { Ok(message) } else { Err(verification_failed()) }
    }
}

// ============================================================================
// IPCrypt
// ============================================================================

impl exports::libsodium::crypto::ipcrypt::Guest for Component {
    fn bytes() -> u32 {
        crypto_ipcrypt_BYTES
    }

    fn key_bytes() -> u32 {
        crypto_ipcrypt_KEYBYTES
    }

    fn keygen() -> Vec<u8> {
        let mut key = vec![0u8; crypto_ipcrypt_KEYBYTES as usize];
        unsafe { crypto_ipcrypt_keygen(key.as_mut_ptr()) };
        key
    }

    fn encrypt(input: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if input.len() != crypto_ipcrypt_BYTES as usize { return Err(to_crypto_error()); }
        if key.len() != crypto_ipcrypt_KEYBYTES as usize { return Err(invalid_key()); }

        let mut out = vec![0u8; crypto_ipcrypt_BYTES as usize];
        unsafe { crypto_ipcrypt_encrypt(out.as_mut_ptr(), input.as_ptr(), key.as_ptr()) };
        Ok(out)
    }

    fn decrypt(input: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if input.len() != crypto_ipcrypt_BYTES as usize { return Err(to_crypto_error()); }
        if key.len() != crypto_ipcrypt_KEYBYTES as usize { return Err(invalid_key()); }

        let mut out = vec![0u8; crypto_ipcrypt_BYTES as usize];
        unsafe { crypto_ipcrypt_decrypt(out.as_mut_ptr(), input.as_ptr(), key.as_ptr()) };
        Ok(out)
    }

    fn ip2bin(ip: String) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        let mut bin = vec![0u8; 16];
        let ret = unsafe { sodium_ip2bin(bin.as_mut_ptr(), ip.as_ptr() as *const i8, ip.len()) };
        if ret == 0 { Ok(bin) } else { Err(to_crypto_error()) }
    }

    fn bin2ip(bin: Vec<u8>) -> Result<String, exports::libsodium::crypto::types::CryptoError> {
        if bin.len() != 16 { return Err(to_crypto_error()); }
        let mut ip = vec![0u8; 64]; // Max IP string length
        let ptr = unsafe { sodium_bin2ip(ip.as_mut_ptr() as *mut i8, ip.len(), bin.as_ptr()) };
        if ptr.is_null() {
            Err(to_crypto_error())
        } else {
            let len = unsafe { libc::strlen(ptr) };
            ip.truncate(len);
            String::from_utf8(ip).map_err(|_| to_crypto_error())
        }
    }

    fn nd_key_bytes() -> u32 {
        crypto_ipcrypt_ND_KEYBYTES
    }

    fn nd_tweak_bytes() -> u32 {
        crypto_ipcrypt_ND_TWEAKBYTES
    }

    fn nd_input_bytes() -> u32 {
        crypto_ipcrypt_ND_INPUTBYTES
    }

    fn nd_output_bytes() -> u32 {
        crypto_ipcrypt_ND_OUTPUTBYTES
    }

    fn nd_encrypt(input: Vec<u8>, tweak: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if input.len() != crypto_ipcrypt_ND_INPUTBYTES as usize { return Err(to_crypto_error()); }
        if tweak.len() != crypto_ipcrypt_ND_TWEAKBYTES as usize { return Err(to_crypto_error()); }
        if key.len() != crypto_ipcrypt_ND_KEYBYTES as usize { return Err(invalid_key()); }

        let mut out = vec![0u8; crypto_ipcrypt_ND_OUTPUTBYTES as usize];
        unsafe { crypto_ipcrypt_nd_encrypt(out.as_mut_ptr(), input.as_ptr(), tweak.as_ptr(), key.as_ptr()) };
        Ok(out)
    }

    fn nd_decrypt(ciphertext: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if ciphertext.len() != crypto_ipcrypt_ND_OUTPUTBYTES as usize { return Err(to_crypto_error()); }
        if key.len() != crypto_ipcrypt_ND_KEYBYTES as usize { return Err(invalid_key()); }

        let mut out = vec![0u8; crypto_ipcrypt_ND_INPUTBYTES as usize];
        unsafe { crypto_ipcrypt_nd_decrypt(out.as_mut_ptr(), ciphertext.as_ptr(), key.as_ptr()) };
        Ok(out)
    }

    fn ndx_key_bytes() -> u32 {
        crypto_ipcrypt_NDX_KEYBYTES
    }

    fn ndx_tweak_bytes() -> u32 {
        crypto_ipcrypt_NDX_TWEAKBYTES
    }

    fn ndx_input_bytes() -> u32 {
        crypto_ipcrypt_NDX_INPUTBYTES
    }

    fn ndx_output_bytes() -> u32 {
        crypto_ipcrypt_NDX_OUTPUTBYTES
    }

    fn ndx_keygen() -> Vec<u8> {
        let mut key = vec![0u8; crypto_ipcrypt_NDX_KEYBYTES as usize];
        unsafe { crypto_ipcrypt_ndx_keygen(key.as_mut_ptr()) };
        key
    }

    fn ndx_encrypt(input: Vec<u8>, tweak: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if input.len() != crypto_ipcrypt_NDX_INPUTBYTES as usize { return Err(to_crypto_error()); }
        if tweak.len() != crypto_ipcrypt_NDX_TWEAKBYTES as usize { return Err(to_crypto_error()); }
        if key.len() != crypto_ipcrypt_NDX_KEYBYTES as usize { return Err(invalid_key()); }

        let mut out = vec![0u8; crypto_ipcrypt_NDX_OUTPUTBYTES as usize];
        unsafe { crypto_ipcrypt_ndx_encrypt(out.as_mut_ptr(), input.as_ptr(), tweak.as_ptr(), key.as_ptr()) };
        Ok(out)
    }

    fn ndx_decrypt(ciphertext: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if ciphertext.len() != crypto_ipcrypt_NDX_OUTPUTBYTES as usize { return Err(to_crypto_error()); }
        if key.len() != crypto_ipcrypt_NDX_KEYBYTES as usize { return Err(invalid_key()); }

        let mut out = vec![0u8; crypto_ipcrypt_NDX_INPUTBYTES as usize];
        unsafe { crypto_ipcrypt_ndx_decrypt(out.as_mut_ptr(), ciphertext.as_ptr(), key.as_ptr()) };
        Ok(out)
    }

    fn pfx_key_bytes() -> u32 {
        crypto_ipcrypt_PFX_KEYBYTES
    }

    fn pfx_bytes() -> u32 {
        crypto_ipcrypt_PFX_BYTES
    }

    fn pfx_keygen() -> Vec<u8> {
        let mut key = vec![0u8; crypto_ipcrypt_PFX_KEYBYTES as usize];
        unsafe { crypto_ipcrypt_pfx_keygen(key.as_mut_ptr()) };
        key
    }

    fn pfx_encrypt(input: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if input.len() != crypto_ipcrypt_PFX_BYTES as usize { return Err(to_crypto_error()); }
        if key.len() != crypto_ipcrypt_PFX_KEYBYTES as usize { return Err(invalid_key()); }

        let mut out = vec![0u8; crypto_ipcrypt_PFX_BYTES as usize];
        unsafe { crypto_ipcrypt_pfx_encrypt(out.as_mut_ptr(), input.as_ptr(), key.as_ptr()) };
        Ok(out)
    }

    fn pfx_decrypt(input: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if input.len() != crypto_ipcrypt_PFX_BYTES as usize { return Err(to_crypto_error()); }
        if key.len() != crypto_ipcrypt_PFX_KEYBYTES as usize { return Err(invalid_key()); }

        let mut out = vec![0u8; crypto_ipcrypt_PFX_BYTES as usize];
        unsafe { crypto_ipcrypt_pfx_decrypt(out.as_mut_ptr(), input.as_ptr(), key.as_ptr()) };
        Ok(out)
    }
}

// ============================================================================
// Auth HMAC-SHA256
// ============================================================================

impl exports::libsodium::crypto::auth_hmacsha256::Guest for Component {
    fn bytes() -> u32 {
        crypto_auth_hmacsha256_BYTES
    }

    fn key_bytes() -> u32 {
        crypto_auth_hmacsha256_KEYBYTES
    }

    fn keygen() -> Vec<u8> {
        let mut key = vec![0u8; crypto_auth_hmacsha256_KEYBYTES as usize];
        unsafe { crypto_auth_hmacsha256_keygen(key.as_mut_ptr()) };
        key
    }

    fn auth(message: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if key.len() != crypto_auth_hmacsha256_KEYBYTES as usize { return Err(invalid_key()); }
        let mut tag = vec![0u8; crypto_auth_hmacsha256_BYTES as usize];
        let ret = unsafe { crypto_auth_hmacsha256(tag.as_mut_ptr(), message.as_ptr(), message.len() as u64, key.as_ptr()) };
        if ret == 0 { Ok(tag) } else { Err(to_crypto_error()) }
    }

    fn verify(tag: Vec<u8>, message: Vec<u8>, key: Vec<u8>) -> Result<(), exports::libsodium::crypto::types::CryptoError> {
        if key.len() != crypto_auth_hmacsha256_KEYBYTES as usize { return Err(invalid_key()); }
        if tag.len() != crypto_auth_hmacsha256_BYTES as usize { return Err(verification_failed()); }
        let ret = unsafe { crypto_auth_hmacsha256_verify(tag.as_ptr(), message.as_ptr(), message.len() as u64, key.as_ptr()) };
        if ret == 0 { Ok(()) } else { Err(verification_failed()) }
    }

    fn state_bytes() -> u32 {
        unsafe { crypto_auth_hmacsha256_statebytes() as u32 }
    }

    fn init(key: Vec<u8>) -> Result<u64, exports::libsodium::crypto::types::CryptoError> {
        if key.len() != crypto_auth_hmacsha256_KEYBYTES as usize { return Err(invalid_key()); }
        let mut state: crypto_auth_hmacsha256_state = unsafe { core::mem::zeroed() };
        let ret = unsafe { crypto_auth_hmacsha256_init(&mut state, key.as_ptr(), key.len()) };
        if ret == 0 {
            let id = next_state_id();
            hmacsha256_states().as_mut().unwrap().insert(id, state);
            Ok(id)
        } else { Err(to_crypto_error()) }
    }

    fn update(state_id: u64, data: Vec<u8>) -> Result<(), exports::libsodium::crypto::types::CryptoError> {
        let mut states = hmacsha256_states();
        let state = states.as_mut().unwrap().get_mut(&state_id).ok_or(to_crypto_error())?;
        let ret = unsafe { crypto_auth_hmacsha256_update(state, data.as_ptr(), data.len() as u64) };
        if ret == 0 { Ok(()) } else { Err(to_crypto_error()) }
    }

    fn final_(state_id: u64) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        let mut states = hmacsha256_states();
        let mut state = states.as_mut().unwrap().remove(&state_id).ok_or(to_crypto_error())?;
        let mut tag = vec![0u8; crypto_auth_hmacsha256_BYTES as usize];
        let ret = unsafe { crypto_auth_hmacsha256_final(&mut state, tag.as_mut_ptr()) };
        if ret == 0 { Ok(tag) } else { Err(to_crypto_error()) }
    }

    fn destroy(state_id: u64) {
        hmacsha256_states().as_mut().unwrap().remove(&state_id);
    }
}

// ============================================================================
// Auth HMAC-SHA512
// ============================================================================

impl exports::libsodium::crypto::auth_hmacsha512::Guest for Component {
    fn bytes() -> u32 {
        crypto_auth_hmacsha512_BYTES
    }

    fn key_bytes() -> u32 {
        crypto_auth_hmacsha512_KEYBYTES
    }

    fn keygen() -> Vec<u8> {
        let mut key = vec![0u8; crypto_auth_hmacsha512_KEYBYTES as usize];
        unsafe { crypto_auth_hmacsha512_keygen(key.as_mut_ptr()) };
        key
    }

    fn auth(message: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if key.len() != crypto_auth_hmacsha512_KEYBYTES as usize { return Err(invalid_key()); }
        let mut tag = vec![0u8; crypto_auth_hmacsha512_BYTES as usize];
        let ret = unsafe { crypto_auth_hmacsha512(tag.as_mut_ptr(), message.as_ptr(), message.len() as u64, key.as_ptr()) };
        if ret == 0 { Ok(tag) } else { Err(to_crypto_error()) }
    }

    fn verify(tag: Vec<u8>, message: Vec<u8>, key: Vec<u8>) -> Result<(), exports::libsodium::crypto::types::CryptoError> {
        if key.len() != crypto_auth_hmacsha512_KEYBYTES as usize { return Err(invalid_key()); }
        if tag.len() != crypto_auth_hmacsha512_BYTES as usize { return Err(verification_failed()); }
        let ret = unsafe { crypto_auth_hmacsha512_verify(tag.as_ptr(), message.as_ptr(), message.len() as u64, key.as_ptr()) };
        if ret == 0 { Ok(()) } else { Err(verification_failed()) }
    }

    fn state_bytes() -> u32 {
        unsafe { crypto_auth_hmacsha512_statebytes() as u32 }
    }

    fn init(key: Vec<u8>) -> Result<u64, exports::libsodium::crypto::types::CryptoError> {
        if key.len() != crypto_auth_hmacsha512_KEYBYTES as usize { return Err(invalid_key()); }
        let mut state: crypto_auth_hmacsha512_state = unsafe { core::mem::zeroed() };
        let ret = unsafe { crypto_auth_hmacsha512_init(&mut state, key.as_ptr(), key.len()) };
        if ret == 0 {
            let id = next_state_id();
            hmacsha512_states().as_mut().unwrap().insert(id, state);
            Ok(id)
        } else { Err(to_crypto_error()) }
    }

    fn update(state_id: u64, data: Vec<u8>) -> Result<(), exports::libsodium::crypto::types::CryptoError> {
        let mut states = hmacsha512_states();
        let state = states.as_mut().unwrap().get_mut(&state_id).ok_or(to_crypto_error())?;
        let ret = unsafe { crypto_auth_hmacsha512_update(state, data.as_ptr(), data.len() as u64) };
        if ret == 0 { Ok(()) } else { Err(to_crypto_error()) }
    }

    fn final_(state_id: u64) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        let mut states = hmacsha512_states();
        let mut state = states.as_mut().unwrap().remove(&state_id).ok_or(to_crypto_error())?;
        let mut tag = vec![0u8; crypto_auth_hmacsha512_BYTES as usize];
        let ret = unsafe { crypto_auth_hmacsha512_final(&mut state, tag.as_mut_ptr()) };
        if ret == 0 { Ok(tag) } else { Err(to_crypto_error()) }
    }

    fn destroy(state_id: u64) {
        hmacsha512_states().as_mut().unwrap().remove(&state_id);
    }
}

// ============================================================================
// HMAC-SHA512-256 Auth
// ============================================================================

impl exports::libsodium::crypto::auth_hmacsha512256::Guest for Component {
    fn bytes() -> u32 {
        crypto_auth_hmacsha512256_BYTES
    }

    fn key_bytes() -> u32 {
        crypto_auth_hmacsha512256_KEYBYTES
    }

    fn keygen() -> Vec<u8> {
        let mut key = vec![0u8; crypto_auth_hmacsha512256_KEYBYTES as usize];
        unsafe { crypto_auth_hmacsha512256_keygen(key.as_mut_ptr()) };
        key
    }

    fn auth(message: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if key.len() != crypto_auth_hmacsha512256_KEYBYTES as usize { return Err(invalid_key()); }
        let mut tag = vec![0u8; crypto_auth_hmacsha512256_BYTES as usize];
        let ret = unsafe { crypto_auth_hmacsha512256(tag.as_mut_ptr(), message.as_ptr(), message.len() as u64, key.as_ptr()) };
        if ret == 0 { Ok(tag) } else { Err(to_crypto_error()) }
    }

    fn verify(tag: Vec<u8>, message: Vec<u8>, key: Vec<u8>) -> Result<(), exports::libsodium::crypto::types::CryptoError> {
        if key.len() != crypto_auth_hmacsha512256_KEYBYTES as usize { return Err(invalid_key()); }
        if tag.len() != crypto_auth_hmacsha512256_BYTES as usize { return Err(verification_failed()); }
        let ret = unsafe { crypto_auth_hmacsha512256_verify(tag.as_ptr(), message.as_ptr(), message.len() as u64, key.as_ptr()) };
        if ret == 0 { Ok(()) } else { Err(verification_failed()) }
    }

    fn state_bytes() -> u32 {
        unsafe { crypto_auth_hmacsha512256_statebytes() as u32 }
    }

    fn init(key: Vec<u8>) -> Result<u64, exports::libsodium::crypto::types::CryptoError> {
        if key.len() != crypto_auth_hmacsha512256_KEYBYTES as usize { return Err(invalid_key()); }
        let mut state: crypto_auth_hmacsha512256_state = unsafe { core::mem::zeroed() };
        let ret = unsafe { crypto_auth_hmacsha512256_init(&mut state, key.as_ptr(), key.len()) };
        if ret == 0 {
            let id = next_state_id();
            hmacsha512256_states().as_mut().unwrap().insert(id, state);
            Ok(id)
        } else { Err(to_crypto_error()) }
    }

    fn update(state_id: u64, data: Vec<u8>) -> Result<(), exports::libsodium::crypto::types::CryptoError> {
        let mut states = hmacsha512256_states();
        let state = states.as_mut().unwrap().get_mut(&state_id).ok_or(to_crypto_error())?;
        let ret = unsafe { crypto_auth_hmacsha512256_update(state, data.as_ptr(), data.len() as u64) };
        if ret == 0 { Ok(()) } else { Err(to_crypto_error()) }
    }

    fn final_(state_id: u64) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        let mut states = hmacsha512256_states();
        let mut state = states.as_mut().unwrap().remove(&state_id).ok_or(to_crypto_error())?;
        let mut tag = vec![0u8; crypto_auth_hmacsha512256_BYTES as usize];
        let ret = unsafe { crypto_auth_hmacsha512256_final(&mut state, tag.as_mut_ptr()) };
        if ret == 0 { Ok(tag) } else { Err(to_crypto_error()) }
    }

    fn destroy(state_id: u64) {
        hmacsha512256_states().as_mut().unwrap().remove(&state_id);
    }
}

// ============================================================================
// Random Extended
// ============================================================================

impl exports::libsodium::crypto::random_extended::Guest for Component {
    fn seed_bytes() -> u32 {
        randombytes_SEEDBYTES
    }

    fn buf_deterministic(len: u32, seed: Vec<u8>) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        if seed.len() != randombytes_SEEDBYTES as usize { return Err(to_crypto_error()); }
        let mut buf = vec![0u8; len as usize];
        unsafe { randombytes_buf_deterministic(buf.as_mut_ptr() as *mut libc::c_void, len as usize, seed.as_ptr()) };
        Ok(buf)
    }
}

// ============================================================================
// Export all implementations
// ============================================================================

// The component struct that implements all interface Guest traits
struct Component;

// Export the component
export_libsodium!(Component);

