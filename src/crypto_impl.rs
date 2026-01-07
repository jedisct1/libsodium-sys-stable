//! Common cryptographic implementations shared between WIT and WAI components.
//!
//! This module contains the actual libsodium wrapper logic that can be used by
//! both the WIT (component.rs) and WAI (wai_component.rs) implementations.
//! Each component module handles type conversion to/from their specific bindgen types.

use crate::sodium_bindings::*;

/// Error type for cryptographic operations (internal representation)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    OperationFailed,
    InvalidKeySize,
    InvalidNonceSize,
    MessageTooLong,
    VerificationFailed,
    NotInitialized,
}

/// Result type alias for crypto operations
pub type CryptoResult<T> = Result<T, CryptoError>;

// ============================================================================
// Core
// ============================================================================

pub fn init() -> i32 {
    unsafe { sodium_init() }
}

pub fn version_string() -> String {
    unsafe {
        let ptr = sodium_version_string();
        let mut len = 0;
        while *ptr.add(len) != 0 {
            len += 1;
        }
        let slice = std::slice::from_raw_parts(ptr as *const u8, len);
        String::from_utf8_lossy(slice).into_owned()
    }
}

pub fn library_version_major() -> i32 {
    unsafe { sodium_library_version_major() }
}

pub fn library_version_minor() -> i32 {
    unsafe { sodium_library_version_minor() }
}

// ============================================================================
// Random
// ============================================================================

pub fn random_bytes(len: u32) -> Vec<u8> {
    let mut buf = vec![0u8; len as usize];
    unsafe {
        randombytes_buf(buf.as_mut_ptr() as *mut _, buf.len());
    }
    buf
}

pub fn random_u32() -> u32 {
    unsafe { randombytes_random() }
}

pub fn random_uniform(upper_bound: u32) -> u32 {
    unsafe { randombytes_uniform(upper_bound) }
}

// ============================================================================
// Secretbox
// ============================================================================

pub fn secretbox_key_bytes() -> u32 {
    crypto_secretbox_KEYBYTES
}

pub fn secretbox_nonce_bytes() -> u32 {
    crypto_secretbox_NONCEBYTES
}

pub fn secretbox_mac_bytes() -> u32 {
    crypto_secretbox_MACBYTES
}

pub fn secretbox_keygen() -> Vec<u8> {
    let mut key = vec![0u8; crypto_secretbox_KEYBYTES as usize];
    unsafe {
        crypto_secretbox_keygen(key.as_mut_ptr());
    }
    key
}

pub fn secretbox_easy(message: &[u8], nonce: &[u8], key: &[u8]) -> CryptoResult<Vec<u8>> {
    if key.len() != crypto_secretbox_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if nonce.len() != crypto_secretbox_NONCEBYTES as usize {
        return Err(CryptoError::InvalidNonceSize);
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
        Err(CryptoError::OperationFailed)
    }
}

pub fn secretbox_open_easy(ciphertext: &[u8], nonce: &[u8], key: &[u8]) -> CryptoResult<Vec<u8>> {
    if key.len() != crypto_secretbox_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if nonce.len() != crypto_secretbox_NONCEBYTES as usize {
        return Err(CryptoError::InvalidNonceSize);
    }
    if ciphertext.len() < crypto_secretbox_MACBYTES as usize {
        return Err(CryptoError::VerificationFailed);
    }

    let mut plaintext = vec![0u8; ciphertext.len() - crypto_secretbox_MACBYTES as usize];
    let ret = unsafe {
        crypto_secretbox_open_easy(
            plaintext.as_mut_ptr(),
            ciphertext.as_ptr(),
            ciphertext.len() as u64,
            nonce.as_ptr(),
            key.as_ptr(),
        )
    };

    if ret == 0 {
        Ok(plaintext)
    } else {
        Err(CryptoError::VerificationFailed)
    }
}

pub fn secretbox_detached(
    message: &[u8],
    nonce: &[u8],
    key: &[u8],
) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
    if key.len() != crypto_secretbox_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if nonce.len() != crypto_secretbox_NONCEBYTES as usize {
        return Err(CryptoError::InvalidNonceSize);
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
        Err(CryptoError::OperationFailed)
    }
}

pub fn secretbox_open_detached(
    ciphertext: &[u8],
    mac: &[u8],
    nonce: &[u8],
    key: &[u8],
) -> CryptoResult<Vec<u8>> {
    if key.len() != crypto_secretbox_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if nonce.len() != crypto_secretbox_NONCEBYTES as usize {
        return Err(CryptoError::InvalidNonceSize);
    }
    if mac.len() != crypto_secretbox_MACBYTES as usize {
        return Err(CryptoError::VerificationFailed);
    }

    let mut plaintext = vec![0u8; ciphertext.len()];
    let ret = unsafe {
        crypto_secretbox_open_detached(
            plaintext.as_mut_ptr(),
            ciphertext.as_ptr(),
            mac.as_ptr(),
            ciphertext.len() as u64,
            nonce.as_ptr(),
            key.as_ptr(),
        )
    };

    if ret == 0 {
        Ok(plaintext)
    } else {
        Err(CryptoError::VerificationFailed)
    }
}

// ============================================================================
// Box (Public-key encryption)
// ============================================================================

pub fn box_public_key_bytes() -> u32 {
    crypto_box_PUBLICKEYBYTES
}

pub fn box_secret_key_bytes() -> u32 {
    crypto_box_SECRETKEYBYTES
}

pub fn box_nonce_bytes() -> u32 {
    crypto_box_NONCEBYTES
}

pub fn box_mac_bytes() -> u32 {
    crypto_box_MACBYTES
}

pub fn box_seed_bytes() -> u32 {
    crypto_box_SEEDBYTES
}

pub fn box_beforenm_bytes() -> u32 {
    crypto_box_BEFORENMBYTES
}

pub fn box_keypair() -> (Vec<u8>, Vec<u8>) {
    let mut pk = vec![0u8; crypto_box_PUBLICKEYBYTES as usize];
    let mut sk = vec![0u8; crypto_box_SECRETKEYBYTES as usize];
    unsafe {
        crypto_box_keypair(pk.as_mut_ptr(), sk.as_mut_ptr());
    }
    (pk, sk)
}

pub fn box_seed_keypair(seed: &[u8]) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
    if seed.len() != crypto_box_SEEDBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    let mut pk = vec![0u8; crypto_box_PUBLICKEYBYTES as usize];
    let mut sk = vec![0u8; crypto_box_SECRETKEYBYTES as usize];
    let ret = unsafe { crypto_box_seed_keypair(pk.as_mut_ptr(), sk.as_mut_ptr(), seed.as_ptr()) };
    if ret == 0 {
        Ok((pk, sk))
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn box_easy(
    message: &[u8],
    nonce: &[u8],
    recipient_pk: &[u8],
    sender_sk: &[u8],
) -> CryptoResult<Vec<u8>> {
    if recipient_pk.len() != crypto_box_PUBLICKEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if sender_sk.len() != crypto_box_SECRETKEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if nonce.len() != crypto_box_NONCEBYTES as usize {
        return Err(CryptoError::InvalidNonceSize);
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
        Err(CryptoError::OperationFailed)
    }
}

pub fn box_open_easy(
    ciphertext: &[u8],
    nonce: &[u8],
    sender_pk: &[u8],
    recipient_sk: &[u8],
) -> CryptoResult<Vec<u8>> {
    if sender_pk.len() != crypto_box_PUBLICKEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if recipient_sk.len() != crypto_box_SECRETKEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if nonce.len() != crypto_box_NONCEBYTES as usize {
        return Err(CryptoError::InvalidNonceSize);
    }
    if ciphertext.len() < crypto_box_MACBYTES as usize {
        return Err(CryptoError::VerificationFailed);
    }

    let mut plaintext = vec![0u8; ciphertext.len() - crypto_box_MACBYTES as usize];
    let ret = unsafe {
        crypto_box_open_easy(
            plaintext.as_mut_ptr(),
            ciphertext.as_ptr(),
            ciphertext.len() as u64,
            nonce.as_ptr(),
            sender_pk.as_ptr(),
            recipient_sk.as_ptr(),
        )
    };

    if ret == 0 {
        Ok(plaintext)
    } else {
        Err(CryptoError::VerificationFailed)
    }
}

pub fn box_detached(
    message: &[u8],
    nonce: &[u8],
    recipient_pk: &[u8],
    sender_sk: &[u8],
) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
    if recipient_pk.len() != crypto_box_PUBLICKEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if sender_sk.len() != crypto_box_SECRETKEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if nonce.len() != crypto_box_NONCEBYTES as usize {
        return Err(CryptoError::InvalidNonceSize);
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
        Err(CryptoError::OperationFailed)
    }
}

pub fn box_open_detached(
    ciphertext: &[u8],
    mac: &[u8],
    nonce: &[u8],
    sender_pk: &[u8],
    recipient_sk: &[u8],
) -> CryptoResult<Vec<u8>> {
    if sender_pk.len() != crypto_box_PUBLICKEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if recipient_sk.len() != crypto_box_SECRETKEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if nonce.len() != crypto_box_NONCEBYTES as usize {
        return Err(CryptoError::InvalidNonceSize);
    }
    if mac.len() != crypto_box_MACBYTES as usize {
        return Err(CryptoError::VerificationFailed);
    }

    let mut plaintext = vec![0u8; ciphertext.len()];
    let ret = unsafe {
        crypto_box_open_detached(
            plaintext.as_mut_ptr(),
            ciphertext.as_ptr(),
            mac.as_ptr(),
            ciphertext.len() as u64,
            nonce.as_ptr(),
            sender_pk.as_ptr(),
            recipient_sk.as_ptr(),
        )
    };

    if ret == 0 {
        Ok(plaintext)
    } else {
        Err(CryptoError::VerificationFailed)
    }
}

pub fn box_beforenm(recipient_pk: &[u8], sender_sk: &[u8]) -> CryptoResult<Vec<u8>> {
    if recipient_pk.len() != crypto_box_PUBLICKEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if sender_sk.len() != crypto_box_SECRETKEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
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
        Err(CryptoError::OperationFailed)
    }
}

pub fn box_easy_afternm(message: &[u8], nonce: &[u8], shared_key: &[u8]) -> CryptoResult<Vec<u8>> {
    if shared_key.len() != crypto_box_BEFORENMBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if nonce.len() != crypto_box_NONCEBYTES as usize {
        return Err(CryptoError::InvalidNonceSize);
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
        Err(CryptoError::OperationFailed)
    }
}

pub fn box_open_easy_afternm(
    ciphertext: &[u8],
    nonce: &[u8],
    shared_key: &[u8],
) -> CryptoResult<Vec<u8>> {
    if shared_key.len() != crypto_box_BEFORENMBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if nonce.len() != crypto_box_NONCEBYTES as usize {
        return Err(CryptoError::InvalidNonceSize);
    }
    if ciphertext.len() < crypto_box_MACBYTES as usize {
        return Err(CryptoError::VerificationFailed);
    }

    let mut plaintext = vec![0u8; ciphertext.len() - crypto_box_MACBYTES as usize];
    let ret = unsafe {
        crypto_box_open_easy_afternm(
            plaintext.as_mut_ptr(),
            ciphertext.as_ptr(),
            ciphertext.len() as u64,
            nonce.as_ptr(),
            shared_key.as_ptr(),
        )
    };

    if ret == 0 {
        Ok(plaintext)
    } else {
        Err(CryptoError::VerificationFailed)
    }
}

// ============================================================================
// Seal (Anonymous encryption)
// ============================================================================

pub fn seal_bytes() -> u32 {
    crypto_box_SEALBYTES
}

pub fn seal(message: &[u8], recipient_pk: &[u8]) -> CryptoResult<Vec<u8>> {
    if recipient_pk.len() != crypto_box_PUBLICKEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
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
        Err(CryptoError::OperationFailed)
    }
}

pub fn seal_open(
    ciphertext: &[u8],
    recipient_pk: &[u8],
    recipient_sk: &[u8],
) -> CryptoResult<Vec<u8>> {
    if recipient_pk.len() != crypto_box_PUBLICKEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if recipient_sk.len() != crypto_box_SECRETKEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if ciphertext.len() < crypto_box_SEALBYTES as usize {
        return Err(CryptoError::VerificationFailed);
    }

    let mut plaintext = vec![0u8; ciphertext.len() - crypto_box_SEALBYTES as usize];
    let ret = unsafe {
        crypto_box_seal_open(
            plaintext.as_mut_ptr(),
            ciphertext.as_ptr(),
            ciphertext.len() as u64,
            recipient_pk.as_ptr(),
            recipient_sk.as_ptr(),
        )
    };

    if ret == 0 {
        Ok(plaintext)
    } else {
        Err(CryptoError::VerificationFailed)
    }
}

// ============================================================================
// Sign
// ============================================================================

pub fn sign_public_key_bytes() -> u32 {
    crypto_sign_PUBLICKEYBYTES
}

pub fn sign_secret_key_bytes() -> u32 {
    crypto_sign_SECRETKEYBYTES
}

pub fn sign_signature_bytes() -> u32 {
    crypto_sign_BYTES
}

pub fn sign_seed_bytes() -> u32 {
    crypto_sign_SEEDBYTES
}

pub fn sign_keypair() -> (Vec<u8>, Vec<u8>) {
    let mut pk = vec![0u8; crypto_sign_PUBLICKEYBYTES as usize];
    let mut sk = vec![0u8; crypto_sign_SECRETKEYBYTES as usize];
    unsafe {
        crypto_sign_keypair(pk.as_mut_ptr(), sk.as_mut_ptr());
    }
    (pk, sk)
}

pub fn sign_seed_keypair(seed: &[u8]) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
    if seed.len() != crypto_sign_SEEDBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    let mut pk = vec![0u8; crypto_sign_PUBLICKEYBYTES as usize];
    let mut sk = vec![0u8; crypto_sign_SECRETKEYBYTES as usize];
    let ret = unsafe { crypto_sign_seed_keypair(pk.as_mut_ptr(), sk.as_mut_ptr(), seed.as_ptr()) };
    if ret == 0 {
        Ok((pk, sk))
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn sign(message: &[u8], secret_key: &[u8]) -> CryptoResult<Vec<u8>> {
    if secret_key.len() != crypto_sign_SECRETKEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
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
        Err(CryptoError::OperationFailed)
    }
}

pub fn sign_open(signed_message: &[u8], public_key: &[u8]) -> CryptoResult<Vec<u8>> {
    if public_key.len() != crypto_sign_PUBLICKEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if signed_message.len() < crypto_sign_BYTES as usize {
        return Err(CryptoError::VerificationFailed);
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
        Err(CryptoError::VerificationFailed)
    }
}

pub fn sign_detached(message: &[u8], secret_key: &[u8]) -> CryptoResult<Vec<u8>> {
    if secret_key.len() != crypto_sign_SECRETKEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
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
        signature.truncate(sig_len as usize);
        Ok(signature)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn sign_verify_detached(
    signature: &[u8],
    message: &[u8],
    public_key: &[u8],
) -> CryptoResult<()> {
    if public_key.len() != crypto_sign_PUBLICKEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if signature.len() != crypto_sign_BYTES as usize {
        return Err(CryptoError::VerificationFailed);
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
        Err(CryptoError::VerificationFailed)
    }
}

// ============================================================================
// Generichash (BLAKE2b)
// ============================================================================

pub fn generichash_bytes() -> u32 {
    crypto_generichash_BYTES as u32
}

pub fn generichash_bytes_min() -> u32 {
    crypto_generichash_BYTES_MIN as u32
}

pub fn generichash_bytes_max() -> u32 {
    crypto_generichash_BYTES_MAX as u32
}

pub fn generichash_key_bytes() -> u32 {
    crypto_generichash_KEYBYTES as u32
}

pub fn generichash_key_bytes_min() -> u32 {
    crypto_generichash_KEYBYTES_MIN as u32
}

pub fn generichash_key_bytes_max() -> u32 {
    crypto_generichash_KEYBYTES_MAX as u32
}

pub fn generichash_keygen() -> Vec<u8> {
    let mut key = vec![0u8; crypto_generichash_KEYBYTES as usize];
    unsafe {
        crypto_generichash_keygen(key.as_mut_ptr());
    }
    key
}

pub fn generichash(message: &[u8], out_len: u32) -> CryptoResult<Vec<u8>> {
    if out_len < crypto_generichash_BYTES_MIN as u32
        || out_len > crypto_generichash_BYTES_MAX as u32
    {
        return Err(CryptoError::OperationFailed);
    }

    let mut hash = vec![0u8; out_len as usize];
    let ret = unsafe {
        crypto_generichash(
            hash.as_mut_ptr(),
            out_len as usize,
            message.as_ptr(),
            message.len() as u64,
            std::ptr::null(),
            0,
        )
    };

    if ret == 0 {
        Ok(hash)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn generichash_keyed(message: &[u8], out_len: u32, key: &[u8]) -> CryptoResult<Vec<u8>> {
    if out_len < crypto_generichash_BYTES_MIN as u32
        || out_len > crypto_generichash_BYTES_MAX as u32
    {
        return Err(CryptoError::OperationFailed);
    }
    if !key.is_empty()
        && (key.len() < crypto_generichash_KEYBYTES_MIN as usize
            || key.len() > crypto_generichash_KEYBYTES_MAX as usize)
    {
        return Err(CryptoError::InvalidKeySize);
    }

    let mut hash = vec![0u8; out_len as usize];
    let ret = unsafe {
        crypto_generichash(
            hash.as_mut_ptr(),
            out_len as usize,
            message.as_ptr(),
            message.len() as u64,
            if key.is_empty() {
                std::ptr::null()
            } else {
                key.as_ptr()
            },
            key.len(),
        )
    };

    if ret == 0 {
        Ok(hash)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

// ============================================================================
// SHA-256
// ============================================================================

pub fn sha256_bytes() -> u32 {
    crypto_hash_sha256_BYTES
}

pub fn sha256(message: &[u8]) -> Vec<u8> {
    let mut hash = vec![0u8; crypto_hash_sha256_BYTES as usize];
    unsafe {
        crypto_hash_sha256(hash.as_mut_ptr(), message.as_ptr(), message.len() as u64);
    }
    hash
}

// ============================================================================
// SHA-512
// ============================================================================

pub fn sha512_bytes() -> u32 {
    crypto_hash_sha512_BYTES
}

pub fn sha512(message: &[u8]) -> Vec<u8> {
    let mut hash = vec![0u8; crypto_hash_sha512_BYTES as usize];
    unsafe {
        crypto_hash_sha512(hash.as_mut_ptr(), message.as_ptr(), message.len() as u64);
    }
    hash
}

// ============================================================================
// Auth (HMAC-SHA512-256)
// ============================================================================

pub fn auth_bytes() -> u32 {
    crypto_auth_BYTES
}

pub fn auth_key_bytes() -> u32 {
    crypto_auth_KEYBYTES
}

pub fn auth_keygen() -> Vec<u8> {
    let mut key = vec![0u8; crypto_auth_KEYBYTES as usize];
    unsafe {
        crypto_auth_keygen(key.as_mut_ptr());
    }
    key
}

pub fn auth(message: &[u8], key: &[u8]) -> CryptoResult<Vec<u8>> {
    if key.len() != crypto_auth_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
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
        Err(CryptoError::OperationFailed)
    }
}

pub fn auth_verify(tag: &[u8], message: &[u8], key: &[u8]) -> CryptoResult<()> {
    if key.len() != crypto_auth_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if tag.len() != crypto_auth_BYTES as usize {
        return Err(CryptoError::VerificationFailed);
    }

    let ret = unsafe {
        crypto_auth_verify(
            tag.as_ptr(),
            message.as_ptr(),
            message.len() as u64,
            key.as_ptr(),
        )
    };

    if ret == 0 {
        Ok(())
    } else {
        Err(CryptoError::VerificationFailed)
    }
}

// ============================================================================
// KDF (Key Derivation)
// ============================================================================

pub fn kdf_key_bytes() -> u32 {
    crypto_kdf_KEYBYTES
}

pub fn kdf_context_bytes() -> u32 {
    crypto_kdf_CONTEXTBYTES
}

pub fn kdf_bytes_min() -> u32 {
    crypto_kdf_BYTES_MIN
}

pub fn kdf_bytes_max() -> u32 {
    crypto_kdf_BYTES_MAX
}

pub fn kdf_keygen() -> Vec<u8> {
    let mut key = vec![0u8; crypto_kdf_KEYBYTES as usize];
    unsafe {
        crypto_kdf_keygen(key.as_mut_ptr());
    }
    key
}

pub fn kdf_derive_from_key(
    subkey_len: u32,
    subkey_id: u64,
    context: &[u8],
    key: &[u8],
) -> CryptoResult<Vec<u8>> {
    if key.len() != crypto_kdf_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if context.len() != crypto_kdf_CONTEXTBYTES as usize {
        return Err(CryptoError::OperationFailed);
    }
    if subkey_len < crypto_kdf_BYTES_MIN || subkey_len > crypto_kdf_BYTES_MAX {
        return Err(CryptoError::OperationFailed);
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
        Err(CryptoError::OperationFailed)
    }
}

// ============================================================================
// Password Hashing (Argon2)
// ============================================================================

pub fn pwhash_salt_bytes() -> u32 {
    crypto_pwhash_SALTBYTES
}

pub fn pwhash_str_bytes() -> u32 {
    crypto_pwhash_STRBYTES
}

pub fn pwhash_opslimit_interactive() -> u64 {
    crypto_pwhash_OPSLIMIT_INTERACTIVE as u64
}

pub fn pwhash_opslimit_moderate() -> u64 {
    crypto_pwhash_OPSLIMIT_MODERATE as u64
}

pub fn pwhash_opslimit_sensitive() -> u64 {
    crypto_pwhash_OPSLIMIT_SENSITIVE as u64
}

pub fn pwhash_memlimit_interactive() -> u64 {
    crypto_pwhash_MEMLIMIT_INTERACTIVE as u64
}

pub fn pwhash_memlimit_moderate() -> u64 {
    crypto_pwhash_MEMLIMIT_MODERATE as u64
}

pub fn pwhash_memlimit_sensitive() -> u64 {
    crypto_pwhash_MEMLIMIT_SENSITIVE as u64
}

pub fn pwhash(
    out_len: u32,
    password: &[u8],
    salt: &[u8],
    opslimit: u64,
    memlimit: u64,
) -> CryptoResult<Vec<u8>> {
    if salt.len() != crypto_pwhash_SALTBYTES as usize {
        return Err(CryptoError::OperationFailed);
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
            crypto_pwhash_ALG_DEFAULT as i32,
        )
    };

    if ret == 0 {
        Ok(out)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn pwhash_str(password: &[u8], opslimit: u64, memlimit: u64) -> CryptoResult<String> {
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
        let len = out.iter().position(|&b| b == 0).unwrap_or(out.len());
        Ok(String::from_utf8_lossy(&out[..len]).into_owned())
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn pwhash_str_verify(hash: &str, password: &[u8]) -> CryptoResult<()> {
    let hash_bytes = hash.as_bytes();
    if hash_bytes.len() >= crypto_pwhash_STRBYTES as usize {
        return Err(CryptoError::VerificationFailed);
    }

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
        Err(CryptoError::VerificationFailed)
    }
}

// ============================================================================
// Utils
// ============================================================================

pub fn bin2hex(data: &[u8]) -> String {
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
    let len = hex.iter().position(|&b| b == 0).unwrap_or(hex.len());
    String::from_utf8_lossy(&hex[..len]).into_owned()
}

pub fn hex2bin(hex: &str) -> CryptoResult<Vec<u8>> {
    let hex_bytes = hex.as_bytes();
    let mut bin = vec![0u8; hex_bytes.len() / 2 + 1];
    let mut bin_len: usize = 0;
    let ret = unsafe {
        sodium_hex2bin(
            bin.as_mut_ptr(),
            bin.len(),
            hex_bytes.as_ptr() as *const i8,
            hex_bytes.len(),
            std::ptr::null(),
            &mut bin_len,
            std::ptr::null_mut(),
        )
    };

    if ret == 0 {
        bin.truncate(bin_len);
        Ok(bin)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn bin2base64(data: &[u8]) -> String {
    let b64_len =
        unsafe { sodium_base64_encoded_len(data.len(), sodium_base64_VARIANT_ORIGINAL as i32) };
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
    let len = b64.iter().position(|&b| b == 0).unwrap_or(b64.len());
    String::from_utf8_lossy(&b64[..len]).into_owned()
}

pub fn base642bin(base64: &str) -> CryptoResult<Vec<u8>> {
    let b64_bytes = base64.as_bytes();
    let mut bin = vec![0u8; b64_bytes.len()];
    let mut bin_len: usize = 0;
    let ret = unsafe {
        sodium_base642bin(
            bin.as_mut_ptr(),
            bin.len(),
            b64_bytes.as_ptr() as *const i8,
            b64_bytes.len(),
            std::ptr::null(),
            &mut bin_len,
            std::ptr::null_mut(),
            sodium_base64_VARIANT_ORIGINAL as i32,
        )
    };

    if ret == 0 {
        bin.truncate(bin_len);
        Ok(bin)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn verify16(x: &[u8], y: &[u8]) -> bool {
    if x.len() != 16 || y.len() != 16 {
        return false;
    }
    unsafe { crypto_verify_16(x.as_ptr(), y.as_ptr()) == 0 }
}

pub fn verify32(x: &[u8], y: &[u8]) -> bool {
    if x.len() != 32 || y.len() != 32 {
        return false;
    }
    unsafe { crypto_verify_32(x.as_ptr(), y.as_ptr()) == 0 }
}

pub fn verify64(x: &[u8], y: &[u8]) -> bool {
    if x.len() != 64 || y.len() != 64 {
        return false;
    }
    unsafe { crypto_verify_64(x.as_ptr(), y.as_ptr()) == 0 }
}

// ============================================================================
// AEAD XChaCha20-Poly1305
// ============================================================================

pub fn aead_xchacha20poly1305_key_bytes() -> u32 {
    crypto_aead_xchacha20poly1305_ietf_KEYBYTES
}

pub fn aead_xchacha20poly1305_nonce_bytes() -> u32 {
    crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
}

pub fn aead_xchacha20poly1305_a_bytes() -> u32 {
    crypto_aead_xchacha20poly1305_ietf_ABYTES
}

pub fn aead_xchacha20poly1305_keygen() -> Vec<u8> {
    let mut key = vec![0u8; crypto_aead_xchacha20poly1305_ietf_KEYBYTES as usize];
    unsafe {
        crypto_aead_xchacha20poly1305_ietf_keygen(key.as_mut_ptr());
    }
    key
}

pub fn aead_xchacha20poly1305_encrypt(
    message: &[u8],
    ad: &[u8],
    nonce: &[u8],
    key: &[u8],
) -> CryptoResult<Vec<u8>> {
    if key.len() != crypto_aead_xchacha20poly1305_ietf_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if nonce.len() != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES as usize {
        return Err(CryptoError::InvalidNonceSize);
    }

    let mut ciphertext =
        vec![0u8; message.len() + crypto_aead_xchacha20poly1305_ietf_ABYTES as usize];
    let mut ciphertext_len: u64 = 0;
    let ret = unsafe {
        crypto_aead_xchacha20poly1305_ietf_encrypt(
            ciphertext.as_mut_ptr(),
            &mut ciphertext_len,
            message.as_ptr(),
            message.len() as u64,
            ad.as_ptr(),
            ad.len() as u64,
            std::ptr::null(),
            nonce.as_ptr(),
            key.as_ptr(),
        )
    };

    if ret == 0 {
        ciphertext.truncate(ciphertext_len as usize);
        Ok(ciphertext)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn aead_xchacha20poly1305_decrypt(
    ciphertext: &[u8],
    ad: &[u8],
    nonce: &[u8],
    key: &[u8],
) -> CryptoResult<Vec<u8>> {
    if key.len() != crypto_aead_xchacha20poly1305_ietf_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if nonce.len() != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES as usize {
        return Err(CryptoError::InvalidNonceSize);
    }
    if ciphertext.len() < crypto_aead_xchacha20poly1305_ietf_ABYTES as usize {
        return Err(CryptoError::VerificationFailed);
    }

    let mut plaintext =
        vec![0u8; ciphertext.len() - crypto_aead_xchacha20poly1305_ietf_ABYTES as usize];
    let mut plaintext_len: u64 = 0;
    let ret = unsafe {
        crypto_aead_xchacha20poly1305_ietf_decrypt(
            plaintext.as_mut_ptr(),
            &mut plaintext_len,
            std::ptr::null_mut(),
            ciphertext.as_ptr(),
            ciphertext.len() as u64,
            ad.as_ptr(),
            ad.len() as u64,
            nonce.as_ptr(),
            key.as_ptr(),
        )
    };

    if ret == 0 {
        plaintext.truncate(plaintext_len as usize);
        Ok(plaintext)
    } else {
        Err(CryptoError::VerificationFailed)
    }
}

pub fn aead_xchacha20poly1305_encrypt_detached(
    message: &[u8],
    ad: &[u8],
    nonce: &[u8],
    key: &[u8],
) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
    if key.len() != crypto_aead_xchacha20poly1305_ietf_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if nonce.len() != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES as usize {
        return Err(CryptoError::InvalidNonceSize);
    }

    let mut ciphertext = vec![0u8; message.len()];
    let mut mac = vec![0u8; crypto_aead_xchacha20poly1305_ietf_ABYTES as usize];
    let mut mac_len: u64 = 0;
    let ret = unsafe {
        crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
            ciphertext.as_mut_ptr(),
            mac.as_mut_ptr(),
            &mut mac_len,
            message.as_ptr(),
            message.len() as u64,
            ad.as_ptr(),
            ad.len() as u64,
            std::ptr::null(),
            nonce.as_ptr(),
            key.as_ptr(),
        )
    };

    if ret == 0 {
        mac.truncate(mac_len as usize);
        Ok((ciphertext, mac))
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn aead_xchacha20poly1305_decrypt_detached(
    ciphertext: &[u8],
    mac: &[u8],
    ad: &[u8],
    nonce: &[u8],
    key: &[u8],
) -> CryptoResult<Vec<u8>> {
    if key.len() != crypto_aead_xchacha20poly1305_ietf_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if nonce.len() != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES as usize {
        return Err(CryptoError::InvalidNonceSize);
    }
    if mac.len() != crypto_aead_xchacha20poly1305_ietf_ABYTES as usize {
        return Err(CryptoError::VerificationFailed);
    }

    let mut plaintext = vec![0u8; ciphertext.len()];
    let ret = unsafe {
        crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
            plaintext.as_mut_ptr(),
            std::ptr::null_mut(),
            ciphertext.as_ptr(),
            ciphertext.len() as u64,
            mac.as_ptr(),
            ad.as_ptr(),
            ad.len() as u64,
            nonce.as_ptr(),
            key.as_ptr(),
        )
    };

    if ret == 0 {
        Ok(plaintext)
    } else {
        Err(CryptoError::VerificationFailed)
    }
}

// ============================================================================
// AEAD ChaCha20-Poly1305-IETF
// ============================================================================

pub fn aead_chacha20poly1305_ietf_key_bytes() -> u32 {
    crypto_aead_chacha20poly1305_ietf_KEYBYTES
}

pub fn aead_chacha20poly1305_ietf_nonce_bytes() -> u32 {
    crypto_aead_chacha20poly1305_ietf_NPUBBYTES
}

pub fn aead_chacha20poly1305_ietf_a_bytes() -> u32 {
    crypto_aead_chacha20poly1305_ietf_ABYTES
}

pub fn aead_chacha20poly1305_ietf_keygen() -> Vec<u8> {
    let mut key = vec![0u8; crypto_aead_chacha20poly1305_ietf_KEYBYTES as usize];
    unsafe {
        crypto_aead_chacha20poly1305_ietf_keygen(key.as_mut_ptr());
    }
    key
}

pub fn aead_chacha20poly1305_ietf_encrypt(
    message: &[u8],
    ad: &[u8],
    nonce: &[u8],
    key: &[u8],
) -> CryptoResult<Vec<u8>> {
    if key.len() != crypto_aead_chacha20poly1305_ietf_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if nonce.len() != crypto_aead_chacha20poly1305_ietf_NPUBBYTES as usize {
        return Err(CryptoError::InvalidNonceSize);
    }

    let mut ciphertext =
        vec![0u8; message.len() + crypto_aead_chacha20poly1305_ietf_ABYTES as usize];
    let mut ciphertext_len: u64 = 0;
    let ret = unsafe {
        crypto_aead_chacha20poly1305_ietf_encrypt(
            ciphertext.as_mut_ptr(),
            &mut ciphertext_len,
            message.as_ptr(),
            message.len() as u64,
            ad.as_ptr(),
            ad.len() as u64,
            std::ptr::null(),
            nonce.as_ptr(),
            key.as_ptr(),
        )
    };

    if ret == 0 {
        ciphertext.truncate(ciphertext_len as usize);
        Ok(ciphertext)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn aead_chacha20poly1305_ietf_decrypt(
    ciphertext: &[u8],
    ad: &[u8],
    nonce: &[u8],
    key: &[u8],
) -> CryptoResult<Vec<u8>> {
    if key.len() != crypto_aead_chacha20poly1305_ietf_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if nonce.len() != crypto_aead_chacha20poly1305_ietf_NPUBBYTES as usize {
        return Err(CryptoError::InvalidNonceSize);
    }
    if ciphertext.len() < crypto_aead_chacha20poly1305_ietf_ABYTES as usize {
        return Err(CryptoError::VerificationFailed);
    }

    let mut plaintext =
        vec![0u8; ciphertext.len() - crypto_aead_chacha20poly1305_ietf_ABYTES as usize];
    let mut plaintext_len: u64 = 0;
    let ret = unsafe {
        crypto_aead_chacha20poly1305_ietf_decrypt(
            plaintext.as_mut_ptr(),
            &mut plaintext_len,
            std::ptr::null_mut(),
            ciphertext.as_ptr(),
            ciphertext.len() as u64,
            ad.as_ptr(),
            ad.len() as u64,
            nonce.as_ptr(),
            key.as_ptr(),
        )
    };

    if ret == 0 {
        plaintext.truncate(plaintext_len as usize);
        Ok(plaintext)
    } else {
        Err(CryptoError::VerificationFailed)
    }
}

pub fn aead_chacha20poly1305_ietf_encrypt_detached(
    message: &[u8],
    ad: &[u8],
    nonce: &[u8],
    key: &[u8],
) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
    if key.len() != crypto_aead_chacha20poly1305_ietf_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if nonce.len() != crypto_aead_chacha20poly1305_ietf_NPUBBYTES as usize {
        return Err(CryptoError::InvalidNonceSize);
    }

    let mut ciphertext = vec![0u8; message.len()];
    let mut mac = vec![0u8; crypto_aead_chacha20poly1305_ietf_ABYTES as usize];
    let mut mac_len: u64 = 0;
    let ret = unsafe {
        crypto_aead_chacha20poly1305_ietf_encrypt_detached(
            ciphertext.as_mut_ptr(),
            mac.as_mut_ptr(),
            &mut mac_len,
            message.as_ptr(),
            message.len() as u64,
            ad.as_ptr(),
            ad.len() as u64,
            std::ptr::null(),
            nonce.as_ptr(),
            key.as_ptr(),
        )
    };

    if ret == 0 {
        mac.truncate(mac_len as usize);
        Ok((ciphertext, mac))
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn aead_chacha20poly1305_ietf_decrypt_detached(
    ciphertext: &[u8],
    mac: &[u8],
    ad: &[u8],
    nonce: &[u8],
    key: &[u8],
) -> CryptoResult<Vec<u8>> {
    if key.len() != crypto_aead_chacha20poly1305_ietf_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if nonce.len() != crypto_aead_chacha20poly1305_ietf_NPUBBYTES as usize {
        return Err(CryptoError::InvalidNonceSize);
    }
    if mac.len() != crypto_aead_chacha20poly1305_ietf_ABYTES as usize {
        return Err(CryptoError::VerificationFailed);
    }

    let mut plaintext = vec![0u8; ciphertext.len()];
    let ret = unsafe {
        crypto_aead_chacha20poly1305_ietf_decrypt_detached(
            plaintext.as_mut_ptr(),
            std::ptr::null_mut(),
            ciphertext.as_ptr(),
            ciphertext.len() as u64,
            mac.as_ptr(),
            ad.as_ptr(),
            ad.len() as u64,
            nonce.as_ptr(),
            key.as_ptr(),
        )
    };

    if ret == 0 {
        Ok(plaintext)
    } else {
        Err(CryptoError::VerificationFailed)
    }
}

// ============================================================================
// AEAD ChaCha20-Poly1305 (original)
// ============================================================================

pub fn aead_chacha20poly1305_key_bytes() -> u32 {
    crypto_aead_chacha20poly1305_KEYBYTES
}

pub fn aead_chacha20poly1305_nonce_bytes() -> u32 {
    crypto_aead_chacha20poly1305_NPUBBYTES
}

pub fn aead_chacha20poly1305_a_bytes() -> u32 {
    crypto_aead_chacha20poly1305_ABYTES
}

pub fn aead_chacha20poly1305_keygen() -> Vec<u8> {
    let mut key = vec![0u8; crypto_aead_chacha20poly1305_KEYBYTES as usize];
    unsafe {
        crypto_aead_chacha20poly1305_keygen(key.as_mut_ptr());
    }
    key
}

pub fn aead_chacha20poly1305_encrypt(
    message: &[u8],
    ad: &[u8],
    nonce: &[u8],
    key: &[u8],
) -> CryptoResult<Vec<u8>> {
    if key.len() != crypto_aead_chacha20poly1305_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if nonce.len() != crypto_aead_chacha20poly1305_NPUBBYTES as usize {
        return Err(CryptoError::InvalidNonceSize);
    }

    let mut ciphertext = vec![0u8; message.len() + crypto_aead_chacha20poly1305_ABYTES as usize];
    let mut ciphertext_len: u64 = 0;
    let ret = unsafe {
        crypto_aead_chacha20poly1305_encrypt(
            ciphertext.as_mut_ptr(),
            &mut ciphertext_len,
            message.as_ptr(),
            message.len() as u64,
            ad.as_ptr(),
            ad.len() as u64,
            std::ptr::null(),
            nonce.as_ptr(),
            key.as_ptr(),
        )
    };

    if ret == 0 {
        ciphertext.truncate(ciphertext_len as usize);
        Ok(ciphertext)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn aead_chacha20poly1305_decrypt(
    ciphertext: &[u8],
    ad: &[u8],
    nonce: &[u8],
    key: &[u8],
) -> CryptoResult<Vec<u8>> {
    if key.len() != crypto_aead_chacha20poly1305_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if nonce.len() != crypto_aead_chacha20poly1305_NPUBBYTES as usize {
        return Err(CryptoError::InvalidNonceSize);
    }
    if ciphertext.len() < crypto_aead_chacha20poly1305_ABYTES as usize {
        return Err(CryptoError::VerificationFailed);
    }

    let mut plaintext = vec![0u8; ciphertext.len() - crypto_aead_chacha20poly1305_ABYTES as usize];
    let mut plaintext_len: u64 = 0;
    let ret = unsafe {
        crypto_aead_chacha20poly1305_decrypt(
            plaintext.as_mut_ptr(),
            &mut plaintext_len,
            std::ptr::null_mut(),
            ciphertext.as_ptr(),
            ciphertext.len() as u64,
            ad.as_ptr(),
            ad.len() as u64,
            nonce.as_ptr(),
            key.as_ptr(),
        )
    };

    if ret == 0 {
        plaintext.truncate(plaintext_len as usize);
        Ok(plaintext)
    } else {
        Err(CryptoError::VerificationFailed)
    }
}

pub fn aead_chacha20poly1305_encrypt_detached(
    message: &[u8],
    ad: &[u8],
    nonce: &[u8],
    key: &[u8],
) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
    if key.len() != crypto_aead_chacha20poly1305_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if nonce.len() != crypto_aead_chacha20poly1305_NPUBBYTES as usize {
        return Err(CryptoError::InvalidNonceSize);
    }

    let mut ciphertext = vec![0u8; message.len()];
    let mut mac = vec![0u8; crypto_aead_chacha20poly1305_ABYTES as usize];
    let mut mac_len: u64 = 0;
    let ret = unsafe {
        crypto_aead_chacha20poly1305_encrypt_detached(
            ciphertext.as_mut_ptr(),
            mac.as_mut_ptr(),
            &mut mac_len,
            message.as_ptr(),
            message.len() as u64,
            ad.as_ptr(),
            ad.len() as u64,
            std::ptr::null(),
            nonce.as_ptr(),
            key.as_ptr(),
        )
    };

    if ret == 0 {
        mac.truncate(mac_len as usize);
        Ok((ciphertext, mac))
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn aead_chacha20poly1305_decrypt_detached(
    ciphertext: &[u8],
    mac: &[u8],
    ad: &[u8],
    nonce: &[u8],
    key: &[u8],
) -> CryptoResult<Vec<u8>> {
    if key.len() != crypto_aead_chacha20poly1305_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if nonce.len() != crypto_aead_chacha20poly1305_NPUBBYTES as usize {
        return Err(CryptoError::InvalidNonceSize);
    }
    if mac.len() != crypto_aead_chacha20poly1305_ABYTES as usize {
        return Err(CryptoError::VerificationFailed);
    }

    let mut plaintext = vec![0u8; ciphertext.len()];
    let ret = unsafe {
        crypto_aead_chacha20poly1305_decrypt_detached(
            plaintext.as_mut_ptr(),
            std::ptr::null_mut(),
            ciphertext.as_ptr(),
            ciphertext.len() as u64,
            mac.as_ptr(),
            ad.as_ptr(),
            ad.len() as u64,
            nonce.as_ptr(),
            key.as_ptr(),
        )
    };

    if ret == 0 {
        Ok(plaintext)
    } else {
        Err(CryptoError::VerificationFailed)
    }
}

// ============================================================================
// AEAD AEGIS-128L
// ============================================================================

pub fn aead_aegis128l_key_bytes() -> u32 {
    crypto_aead_aegis128l_KEYBYTES
}

pub fn aead_aegis128l_nonce_bytes() -> u32 {
    crypto_aead_aegis128l_NPUBBYTES
}

pub fn aead_aegis128l_a_bytes() -> u32 {
    crypto_aead_aegis128l_ABYTES
}

pub fn aead_aegis128l_keygen() -> Vec<u8> {
    let mut key = vec![0u8; crypto_aead_aegis128l_KEYBYTES as usize];
    unsafe {
        crypto_aead_aegis128l_keygen(key.as_mut_ptr());
    }
    key
}

pub fn aead_aegis128l_encrypt(
    message: &[u8],
    ad: &[u8],
    nonce: &[u8],
    key: &[u8],
) -> CryptoResult<Vec<u8>> {
    if key.len() != crypto_aead_aegis128l_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if nonce.len() != crypto_aead_aegis128l_NPUBBYTES as usize {
        return Err(CryptoError::InvalidNonceSize);
    }

    let mut ciphertext = vec![0u8; message.len() + crypto_aead_aegis128l_ABYTES as usize];
    let mut ciphertext_len: u64 = 0;
    let ret = unsafe {
        crypto_aead_aegis128l_encrypt(
            ciphertext.as_mut_ptr(),
            &mut ciphertext_len,
            message.as_ptr(),
            message.len() as u64,
            ad.as_ptr(),
            ad.len() as u64,
            std::ptr::null(),
            nonce.as_ptr(),
            key.as_ptr(),
        )
    };

    if ret == 0 {
        ciphertext.truncate(ciphertext_len as usize);
        Ok(ciphertext)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn aead_aegis128l_decrypt(
    ciphertext: &[u8],
    ad: &[u8],
    nonce: &[u8],
    key: &[u8],
) -> CryptoResult<Vec<u8>> {
    if key.len() != crypto_aead_aegis128l_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if nonce.len() != crypto_aead_aegis128l_NPUBBYTES as usize {
        return Err(CryptoError::InvalidNonceSize);
    }
    if ciphertext.len() < crypto_aead_aegis128l_ABYTES as usize {
        return Err(CryptoError::VerificationFailed);
    }

    let mut plaintext = vec![0u8; ciphertext.len() - crypto_aead_aegis128l_ABYTES as usize];
    let mut plaintext_len: u64 = 0;
    let ret = unsafe {
        crypto_aead_aegis128l_decrypt(
            plaintext.as_mut_ptr(),
            &mut plaintext_len,
            std::ptr::null_mut(),
            ciphertext.as_ptr(),
            ciphertext.len() as u64,
            ad.as_ptr(),
            ad.len() as u64,
            nonce.as_ptr(),
            key.as_ptr(),
        )
    };

    if ret == 0 {
        plaintext.truncate(plaintext_len as usize);
        Ok(plaintext)
    } else {
        Err(CryptoError::VerificationFailed)
    }
}

pub fn aead_aegis128l_encrypt_detached(
    message: &[u8],
    ad: &[u8],
    nonce: &[u8],
    key: &[u8],
) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
    if key.len() != crypto_aead_aegis128l_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if nonce.len() != crypto_aead_aegis128l_NPUBBYTES as usize {
        return Err(CryptoError::InvalidNonceSize);
    }

    let mut ciphertext = vec![0u8; message.len()];
    let mut mac = vec![0u8; crypto_aead_aegis128l_ABYTES as usize];
    let mut mac_len: u64 = 0;
    let ret = unsafe {
        crypto_aead_aegis128l_encrypt_detached(
            ciphertext.as_mut_ptr(),
            mac.as_mut_ptr(),
            &mut mac_len,
            message.as_ptr(),
            message.len() as u64,
            ad.as_ptr(),
            ad.len() as u64,
            std::ptr::null(),
            nonce.as_ptr(),
            key.as_ptr(),
        )
    };

    if ret == 0 {
        mac.truncate(mac_len as usize);
        Ok((ciphertext, mac))
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn aead_aegis128l_decrypt_detached(
    ciphertext: &[u8],
    mac: &[u8],
    ad: &[u8],
    nonce: &[u8],
    key: &[u8],
) -> CryptoResult<Vec<u8>> {
    if key.len() != crypto_aead_aegis128l_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if nonce.len() != crypto_aead_aegis128l_NPUBBYTES as usize {
        return Err(CryptoError::InvalidNonceSize);
    }
    if mac.len() != crypto_aead_aegis128l_ABYTES as usize {
        return Err(CryptoError::VerificationFailed);
    }

    let mut plaintext = vec![0u8; ciphertext.len()];
    let ret = unsafe {
        crypto_aead_aegis128l_decrypt_detached(
            plaintext.as_mut_ptr(),
            std::ptr::null_mut(),
            ciphertext.as_ptr(),
            ciphertext.len() as u64,
            mac.as_ptr(),
            ad.as_ptr(),
            ad.len() as u64,
            nonce.as_ptr(),
            key.as_ptr(),
        )
    };

    if ret == 0 {
        Ok(plaintext)
    } else {
        Err(CryptoError::VerificationFailed)
    }
}

// ============================================================================
// AEAD AEGIS-256
// ============================================================================

pub fn aead_aegis256_key_bytes() -> u32 {
    crypto_aead_aegis256_KEYBYTES
}

pub fn aead_aegis256_nonce_bytes() -> u32 {
    crypto_aead_aegis256_NPUBBYTES
}

pub fn aead_aegis256_a_bytes() -> u32 {
    crypto_aead_aegis256_ABYTES
}

pub fn aead_aegis256_keygen() -> Vec<u8> {
    let mut key = vec![0u8; crypto_aead_aegis256_KEYBYTES as usize];
    unsafe {
        crypto_aead_aegis256_keygen(key.as_mut_ptr());
    }
    key
}

pub fn aead_aegis256_encrypt(
    message: &[u8],
    ad: &[u8],
    nonce: &[u8],
    key: &[u8],
) -> CryptoResult<Vec<u8>> {
    if key.len() != crypto_aead_aegis256_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if nonce.len() != crypto_aead_aegis256_NPUBBYTES as usize {
        return Err(CryptoError::InvalidNonceSize);
    }

    let mut ciphertext = vec![0u8; message.len() + crypto_aead_aegis256_ABYTES as usize];
    let mut ciphertext_len: u64 = 0;
    let ret = unsafe {
        crypto_aead_aegis256_encrypt(
            ciphertext.as_mut_ptr(),
            &mut ciphertext_len,
            message.as_ptr(),
            message.len() as u64,
            ad.as_ptr(),
            ad.len() as u64,
            std::ptr::null(),
            nonce.as_ptr(),
            key.as_ptr(),
        )
    };

    if ret == 0 {
        ciphertext.truncate(ciphertext_len as usize);
        Ok(ciphertext)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn aead_aegis256_decrypt(
    ciphertext: &[u8],
    ad: &[u8],
    nonce: &[u8],
    key: &[u8],
) -> CryptoResult<Vec<u8>> {
    if key.len() != crypto_aead_aegis256_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if nonce.len() != crypto_aead_aegis256_NPUBBYTES as usize {
        return Err(CryptoError::InvalidNonceSize);
    }
    if ciphertext.len() < crypto_aead_aegis256_ABYTES as usize {
        return Err(CryptoError::VerificationFailed);
    }

    let mut plaintext = vec![0u8; ciphertext.len() - crypto_aead_aegis256_ABYTES as usize];
    let mut plaintext_len: u64 = 0;
    let ret = unsafe {
        crypto_aead_aegis256_decrypt(
            plaintext.as_mut_ptr(),
            &mut plaintext_len,
            std::ptr::null_mut(),
            ciphertext.as_ptr(),
            ciphertext.len() as u64,
            ad.as_ptr(),
            ad.len() as u64,
            nonce.as_ptr(),
            key.as_ptr(),
        )
    };

    if ret == 0 {
        plaintext.truncate(plaintext_len as usize);
        Ok(plaintext)
    } else {
        Err(CryptoError::VerificationFailed)
    }
}

pub fn aead_aegis256_encrypt_detached(
    message: &[u8],
    ad: &[u8],
    nonce: &[u8],
    key: &[u8],
) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
    if key.len() != crypto_aead_aegis256_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if nonce.len() != crypto_aead_aegis256_NPUBBYTES as usize {
        return Err(CryptoError::InvalidNonceSize);
    }

    let mut ciphertext = vec![0u8; message.len()];
    let mut mac = vec![0u8; crypto_aead_aegis256_ABYTES as usize];
    let mut mac_len: u64 = 0;
    let ret = unsafe {
        crypto_aead_aegis256_encrypt_detached(
            ciphertext.as_mut_ptr(),
            mac.as_mut_ptr(),
            &mut mac_len,
            message.as_ptr(),
            message.len() as u64,
            ad.as_ptr(),
            ad.len() as u64,
            std::ptr::null(),
            nonce.as_ptr(),
            key.as_ptr(),
        )
    };

    if ret == 0 {
        mac.truncate(mac_len as usize);
        Ok((ciphertext, mac))
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn aead_aegis256_decrypt_detached(
    ciphertext: &[u8],
    mac: &[u8],
    ad: &[u8],
    nonce: &[u8],
    key: &[u8],
) -> CryptoResult<Vec<u8>> {
    if key.len() != crypto_aead_aegis256_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if nonce.len() != crypto_aead_aegis256_NPUBBYTES as usize {
        return Err(CryptoError::InvalidNonceSize);
    }
    if mac.len() != crypto_aead_aegis256_ABYTES as usize {
        return Err(CryptoError::VerificationFailed);
    }

    let mut plaintext = vec![0u8; ciphertext.len()];
    let ret = unsafe {
        crypto_aead_aegis256_decrypt_detached(
            plaintext.as_mut_ptr(),
            std::ptr::null_mut(),
            ciphertext.as_ptr(),
            ciphertext.len() as u64,
            mac.as_ptr(),
            ad.as_ptr(),
            ad.len() as u64,
            nonce.as_ptr(),
            key.as_ptr(),
        )
    };

    if ret == 0 {
        Ok(plaintext)
    } else {
        Err(CryptoError::VerificationFailed)
    }
}

// ============================================================================
// Key Exchange
// ============================================================================

pub fn kx_public_key_bytes() -> u32 {
    crypto_kx_PUBLICKEYBYTES
}

pub fn kx_secret_key_bytes() -> u32 {
    crypto_kx_SECRETKEYBYTES
}

pub fn kx_seed_bytes() -> u32 {
    crypto_kx_SEEDBYTES
}

pub fn kx_session_key_bytes() -> u32 {
    crypto_kx_SESSIONKEYBYTES
}

pub fn kx_keypair() -> (Vec<u8>, Vec<u8>) {
    let mut pk = vec![0u8; crypto_kx_PUBLICKEYBYTES as usize];
    let mut sk = vec![0u8; crypto_kx_SECRETKEYBYTES as usize];
    unsafe {
        crypto_kx_keypair(pk.as_mut_ptr(), sk.as_mut_ptr());
    }
    (pk, sk)
}

pub fn kx_seed_keypair(seed: &[u8]) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
    if seed.len() != crypto_kx_SEEDBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    let mut pk = vec![0u8; crypto_kx_PUBLICKEYBYTES as usize];
    let mut sk = vec![0u8; crypto_kx_SECRETKEYBYTES as usize];
    let ret = unsafe { crypto_kx_seed_keypair(pk.as_mut_ptr(), sk.as_mut_ptr(), seed.as_ptr()) };
    if ret == 0 {
        Ok((pk, sk))
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn kx_client_session_keys(
    client_pk: &[u8],
    client_sk: &[u8],
    server_pk: &[u8],
) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
    if client_pk.len() != crypto_kx_PUBLICKEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if client_sk.len() != crypto_kx_SECRETKEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if server_pk.len() != crypto_kx_PUBLICKEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
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
        Ok((rx, tx))
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn kx_server_session_keys(
    server_pk: &[u8],
    server_sk: &[u8],
    client_pk: &[u8],
) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
    if server_pk.len() != crypto_kx_PUBLICKEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if server_sk.len() != crypto_kx_SECRETKEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if client_pk.len() != crypto_kx_PUBLICKEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
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
        Ok((rx, tx))
    } else {
        Err(CryptoError::OperationFailed)
    }
}

// ============================================================================
// Scalarmult (Curve25519)
// ============================================================================

pub fn scalarmult_bytes() -> u32 {
    crypto_scalarmult_BYTES
}

pub fn scalarmult_scalar_bytes() -> u32 {
    crypto_scalarmult_SCALARBYTES
}

pub fn scalarmult(n: &[u8], p: &[u8]) -> CryptoResult<Vec<u8>> {
    if n.len() != crypto_scalarmult_SCALARBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if p.len() != crypto_scalarmult_BYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }

    let mut q = vec![0u8; crypto_scalarmult_BYTES as usize];
    let ret = unsafe { crypto_scalarmult(q.as_mut_ptr(), n.as_ptr(), p.as_ptr()) };

    if ret == 0 {
        Ok(q)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn scalarmult_base(n: &[u8]) -> CryptoResult<Vec<u8>> {
    if n.len() != crypto_scalarmult_SCALARBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }

    let mut q = vec![0u8; crypto_scalarmult_BYTES as usize];
    let ret = unsafe { crypto_scalarmult_base(q.as_mut_ptr(), n.as_ptr()) };

    if ret == 0 {
        Ok(q)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

// ============================================================================
// Shorthash (SipHash)
// ============================================================================

pub fn shorthash_bytes() -> u32 {
    crypto_shorthash_BYTES as u32
}

pub fn shorthash_key_bytes() -> u32 {
    crypto_shorthash_KEYBYTES as u32
}

pub fn shorthash_keygen() -> Vec<u8> {
    let mut key = vec![0u8; crypto_shorthash_KEYBYTES as usize];
    unsafe {
        crypto_shorthash_keygen(key.as_mut_ptr());
    }
    key
}

pub fn shorthash(message: &[u8], key: &[u8]) -> CryptoResult<Vec<u8>> {
    if key.len() != crypto_shorthash_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }

    let mut hash = vec![0u8; crypto_shorthash_BYTES as usize];
    let ret = unsafe {
        crypto_shorthash(
            hash.as_mut_ptr(),
            message.as_ptr(),
            message.len() as u64,
            key.as_ptr(),
        )
    };

    if ret == 0 {
        Ok(hash)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

// ============================================================================
// Onetimeauth (Poly1305)
// ============================================================================

pub fn onetimeauth_bytes() -> u32 {
    crypto_onetimeauth_BYTES as u32
}

pub fn onetimeauth_key_bytes() -> u32 {
    crypto_onetimeauth_KEYBYTES as u32
}

pub fn onetimeauth_keygen() -> Vec<u8> {
    let mut key = vec![0u8; crypto_onetimeauth_KEYBYTES as usize];
    unsafe {
        crypto_onetimeauth_keygen(key.as_mut_ptr());
    }
    key
}

pub fn onetimeauth(message: &[u8], key: &[u8]) -> CryptoResult<Vec<u8>> {
    if key.len() != crypto_onetimeauth_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
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
        Err(CryptoError::OperationFailed)
    }
}

pub fn onetimeauth_verify(tag: &[u8], message: &[u8], key: &[u8]) -> CryptoResult<()> {
    if key.len() != crypto_onetimeauth_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if tag.len() != crypto_onetimeauth_BYTES as usize {
        return Err(CryptoError::VerificationFailed);
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
        Err(CryptoError::VerificationFailed)
    }
}

// ============================================================================
// Stream ciphers - XSalsa20
// ============================================================================

pub fn stream_xsalsa20_key_bytes() -> u32 {
    crypto_stream_xsalsa20_KEYBYTES
}

pub fn stream_xsalsa20_nonce_bytes() -> u32 {
    crypto_stream_xsalsa20_NONCEBYTES
}

pub fn stream_xsalsa20_keygen() -> Vec<u8> {
    let mut key = vec![0u8; crypto_stream_xsalsa20_KEYBYTES as usize];
    unsafe {
        crypto_stream_xsalsa20_keygen(key.as_mut_ptr());
    }
    key
}

pub fn stream_xsalsa20(len: u32, nonce: &[u8], key: &[u8]) -> CryptoResult<Vec<u8>> {
    if key.len() != crypto_stream_xsalsa20_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if nonce.len() != crypto_stream_xsalsa20_NONCEBYTES as usize {
        return Err(CryptoError::InvalidNonceSize);
    }

    let mut stream = vec![0u8; len as usize];
    let ret = unsafe {
        crypto_stream_xsalsa20(
            stream.as_mut_ptr(),
            len as u64,
            nonce.as_ptr(),
            key.as_ptr(),
        )
    };

    if ret == 0 {
        Ok(stream)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn stream_xsalsa20_xor(message: &[u8], nonce: &[u8], key: &[u8]) -> CryptoResult<Vec<u8>> {
    if key.len() != crypto_stream_xsalsa20_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if nonce.len() != crypto_stream_xsalsa20_NONCEBYTES as usize {
        return Err(CryptoError::InvalidNonceSize);
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
        Err(CryptoError::OperationFailed)
    }
}

// ============================================================================
// Stream ciphers - XChaCha20
// ============================================================================

pub fn stream_xchacha20_key_bytes() -> u32 {
    crypto_stream_xchacha20_KEYBYTES
}

pub fn stream_xchacha20_nonce_bytes() -> u32 {
    crypto_stream_xchacha20_NONCEBYTES
}

pub fn stream_xchacha20_keygen() -> Vec<u8> {
    let mut key = vec![0u8; crypto_stream_xchacha20_KEYBYTES as usize];
    unsafe {
        crypto_stream_xchacha20_keygen(key.as_mut_ptr());
    }
    key
}

pub fn stream_xchacha20(len: u32, nonce: &[u8], key: &[u8]) -> CryptoResult<Vec<u8>> {
    if key.len() != crypto_stream_xchacha20_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if nonce.len() != crypto_stream_xchacha20_NONCEBYTES as usize {
        return Err(CryptoError::InvalidNonceSize);
    }

    let mut stream = vec![0u8; len as usize];
    let ret = unsafe {
        crypto_stream_xchacha20(
            stream.as_mut_ptr(),
            len as u64,
            nonce.as_ptr(),
            key.as_ptr(),
        )
    };

    if ret == 0 {
        Ok(stream)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn stream_xchacha20_xor(message: &[u8], nonce: &[u8], key: &[u8]) -> CryptoResult<Vec<u8>> {
    if key.len() != crypto_stream_xchacha20_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if nonce.len() != crypto_stream_xchacha20_NONCEBYTES as usize {
        return Err(CryptoError::InvalidNonceSize);
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
        Err(CryptoError::OperationFailed)
    }
}

pub fn stream_xchacha20_xor_ic(
    message: &[u8],
    nonce: &[u8],
    ic: u64,
    key: &[u8],
) -> CryptoResult<Vec<u8>> {
    if key.len() != crypto_stream_xchacha20_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if nonce.len() != crypto_stream_xchacha20_NONCEBYTES as usize {
        return Err(CryptoError::InvalidNonceSize);
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
        Err(CryptoError::OperationFailed)
    }
}

// ============================================================================
// Additional utils
// ============================================================================

pub fn memzero(data: &mut [u8]) {
    unsafe {
        sodium_memzero(data.as_mut_ptr() as *mut _, data.len());
    }
}

pub fn memcmp(a: &[u8], b: &[u8]) -> CryptoResult<bool> {
    if a.len() != b.len() {
        return Err(CryptoError::OperationFailed);
    }
    let ret = unsafe { sodium_memcmp(a.as_ptr() as *const _, b.as_ptr() as *const _, a.len()) };
    Ok(ret == 0)
}

pub fn increment(data: &mut [u8]) {
    unsafe {
        sodium_increment(data.as_mut_ptr(), data.len());
    }
}

pub fn add(a: &mut [u8], b: &[u8]) -> CryptoResult<()> {
    if a.len() != b.len() {
        return Err(CryptoError::OperationFailed);
    }
    unsafe {
        sodium_add(a.as_mut_ptr(), b.as_ptr(), a.len());
    }
    Ok(())
}

pub fn compare(a: &[u8], b: &[u8]) -> i32 {
    if a.len() != b.len() {
        return if a.len() < b.len() { -1 } else { 1 };
    }
    unsafe { sodium_compare(a.as_ptr(), b.as_ptr(), a.len()) }
}

pub fn is_zero(data: &[u8]) -> bool {
    unsafe { sodium_is_zero(data.as_ptr(), data.len()) == 1 }
}

pub fn hex2bin_ignore(hex: &str, ignore: &str) -> CryptoResult<Vec<u8>> {
    let hex_bytes = hex.as_bytes();
    let ignore_bytes = ignore.as_bytes();
    let mut bin = vec![0u8; hex_bytes.len() / 2 + 1];
    let mut bin_len: usize = 0;

    // Create null-terminated ignore string
    let mut ignore_cstr = ignore_bytes.to_vec();
    ignore_cstr.push(0);

    let ret = unsafe {
        sodium_hex2bin(
            bin.as_mut_ptr(),
            bin.len(),
            hex_bytes.as_ptr() as *const i8,
            hex_bytes.len(),
            ignore_cstr.as_ptr() as *const i8,
            &mut bin_len,
            std::ptr::null_mut(),
        )
    };

    if ret == 0 {
        bin.truncate(bin_len);
        Ok(bin)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn bin2base64_variant(data: &[u8], variant: u32) -> String {
    let b64_len = unsafe { sodium_base64_encoded_len(data.len(), variant as i32) };
    let mut b64 = vec![0u8; b64_len];
    unsafe {
        sodium_bin2base64(
            b64.as_mut_ptr() as *mut i8,
            b64_len,
            data.as_ptr(),
            data.len(),
            variant as i32,
        );
    }
    let len = b64.iter().position(|&b| b == 0).unwrap_or(b64.len());
    String::from_utf8_lossy(&b64[..len]).into_owned()
}

pub fn base642bin_variant(base64: &str, variant: u32) -> CryptoResult<Vec<u8>> {
    let b64_bytes = base64.as_bytes();
    let mut bin = vec![0u8; b64_bytes.len()];
    let mut bin_len: usize = 0;
    let ret = unsafe {
        sodium_base642bin(
            bin.as_mut_ptr(),
            bin.len(),
            b64_bytes.as_ptr() as *const i8,
            b64_bytes.len(),
            std::ptr::null(),
            &mut bin_len,
            std::ptr::null_mut(),
            variant as i32,
        )
    };

    if ret == 0 {
        bin.truncate(bin_len);
        Ok(bin)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn pad(data: &[u8], block_size: u32) -> CryptoResult<Vec<u8>> {
    let padded_len = ((data.len() / block_size as usize) + 1) * block_size as usize;
    let mut padded = vec![0u8; padded_len];
    padded[..data.len()].copy_from_slice(data);
    let mut padded_buflen: usize = 0;
    let ret = unsafe {
        sodium_pad(
            &mut padded_buflen,
            padded.as_mut_ptr(),
            data.len(),
            block_size as usize,
            padded.len(),
        )
    };
    if ret == 0 {
        padded.truncate(padded_buflen);
        Ok(padded)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn unpad(data: &[u8], block_size: u32) -> CryptoResult<Vec<u8>> {
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
        Ok(data[..unpadded_len].to_vec())
    } else {
        Err(CryptoError::OperationFailed)
    }
}

// ============================================================================
// Sign Ed25519 helpers
// ============================================================================

pub fn sign_ed25519_sk_to_pk(sk: &[u8]) -> CryptoResult<Vec<u8>> {
    if sk.len() != crypto_sign_SECRETKEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    let mut pk = vec![0u8; crypto_sign_PUBLICKEYBYTES as usize];
    let ret = unsafe { crypto_sign_ed25519_sk_to_pk(pk.as_mut_ptr(), sk.as_ptr()) };
    if ret == 0 {
        Ok(pk)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn sign_ed25519_sk_to_seed(sk: &[u8]) -> CryptoResult<Vec<u8>> {
    if sk.len() != crypto_sign_SECRETKEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    let mut seed = vec![0u8; crypto_sign_SEEDBYTES as usize];
    let ret = unsafe { crypto_sign_ed25519_sk_to_seed(seed.as_mut_ptr(), sk.as_ptr()) };
    if ret == 0 {
        Ok(seed)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn sign_ed25519_pk_to_curve25519(ed25519_pk: &[u8]) -> CryptoResult<Vec<u8>> {
    if ed25519_pk.len() != crypto_sign_PUBLICKEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    let mut curve25519_pk = vec![0u8; crypto_scalarmult_curve25519_BYTES as usize];
    let ret = unsafe {
        crypto_sign_ed25519_pk_to_curve25519(curve25519_pk.as_mut_ptr(), ed25519_pk.as_ptr())
    };
    if ret == 0 {
        Ok(curve25519_pk)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn sign_ed25519_sk_to_curve25519(ed25519_sk: &[u8]) -> CryptoResult<Vec<u8>> {
    if ed25519_sk.len() != crypto_sign_SECRETKEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    let mut curve25519_sk = vec![0u8; crypto_scalarmult_curve25519_BYTES as usize];
    let ret = unsafe {
        crypto_sign_ed25519_sk_to_curve25519(curve25519_sk.as_mut_ptr(), ed25519_sk.as_ptr())
    };
    if ret == 0 {
        Ok(curve25519_sk)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

// ============================================================================
// State Management Infrastructure
// ============================================================================

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

static STATE_ID_COUNTER: AtomicU64 = AtomicU64::new(1);

fn next_state_id() -> u64 {
    STATE_ID_COUNTER.fetch_add(1, Ordering::SeqCst)
}

// State storage for each cryptographic operation type
static GENERICHASH_STATES: Mutex<Option<HashMap<u64, (crypto_generichash_state, usize)>>> =
    Mutex::new(None);
static SHA256_STATES: Mutex<Option<HashMap<u64, crypto_hash_sha256_state>>> = Mutex::new(None);
static SHA512_STATES: Mutex<Option<HashMap<u64, crypto_hash_sha512_state>>> = Mutex::new(None);
static AUTH_STATES: Mutex<Option<HashMap<u64, crypto_auth_hmacsha512256_state>>> = Mutex::new(None);
static ONETIMEAUTH_STATES: Mutex<Option<HashMap<u64, crypto_onetimeauth_state>>> = Mutex::new(None);
static SECRETSTREAM_STATES: Mutex<
    Option<HashMap<u64, crypto_secretstream_xchacha20poly1305_state>>,
> = Mutex::new(None);
static SIGN_STATES: Mutex<Option<HashMap<u64, crypto_sign_ed25519ph_state>>> = Mutex::new(None);
static HMACSHA256_STATES: Mutex<Option<HashMap<u64, crypto_auth_hmacsha256_state>>> =
    Mutex::new(None);
static HMACSHA512_STATES: Mutex<Option<HashMap<u64, crypto_auth_hmacsha512_state>>> =
    Mutex::new(None);
static HMACSHA512256_STATES: Mutex<Option<HashMap<u64, crypto_auth_hmacsha512256_state>>> =
    Mutex::new(None);
static HKDF_SHA256_STATES: Mutex<Option<HashMap<u64, crypto_kdf_hkdf_sha256_state>>> =
    Mutex::new(None);
static HKDF_SHA512_STATES: Mutex<Option<HashMap<u64, crypto_kdf_hkdf_sha512_state>>> =
    Mutex::new(None);
static SHAKE128_STATES: Mutex<Option<HashMap<u64, crypto_xof_shake128_state>>> = Mutex::new(None);
static SHAKE256_STATES: Mutex<Option<HashMap<u64, crypto_xof_shake256_state>>> = Mutex::new(None);
static TURBOSHAKE128_STATES: Mutex<Option<HashMap<u64, crypto_xof_turboshake128_state>>> =
    Mutex::new(None);
static TURBOSHAKE256_STATES: Mutex<Option<HashMap<u64, crypto_xof_turboshake256_state>>> =
    Mutex::new(None);

// Helper functions to get state storage
fn generichash_states(
) -> std::sync::MutexGuard<'static, Option<HashMap<u64, (crypto_generichash_state, usize)>>> {
    let mut guard = GENERICHASH_STATES.lock().unwrap();
    if guard.is_none() {
        *guard = Some(HashMap::new());
    }
    guard
}

fn sha256_states() -> std::sync::MutexGuard<'static, Option<HashMap<u64, crypto_hash_sha256_state>>>
{
    let mut guard = SHA256_STATES.lock().unwrap();
    if guard.is_none() {
        *guard = Some(HashMap::new());
    }
    guard
}

fn sha512_states() -> std::sync::MutexGuard<'static, Option<HashMap<u64, crypto_hash_sha512_state>>>
{
    let mut guard = SHA512_STATES.lock().unwrap();
    if guard.is_none() {
        *guard = Some(HashMap::new());
    }
    guard
}

fn auth_states(
) -> std::sync::MutexGuard<'static, Option<HashMap<u64, crypto_auth_hmacsha512256_state>>> {
    let mut guard = AUTH_STATES.lock().unwrap();
    if guard.is_none() {
        *guard = Some(HashMap::new());
    }
    guard
}

fn onetimeauth_states(
) -> std::sync::MutexGuard<'static, Option<HashMap<u64, crypto_onetimeauth_state>>> {
    let mut guard = ONETIMEAUTH_STATES.lock().unwrap();
    if guard.is_none() {
        *guard = Some(HashMap::new());
    }
    guard
}

fn secretstream_states(
) -> std::sync::MutexGuard<'static, Option<HashMap<u64, crypto_secretstream_xchacha20poly1305_state>>>
{
    let mut guard = SECRETSTREAM_STATES.lock().unwrap();
    if guard.is_none() {
        *guard = Some(HashMap::new());
    }
    guard
}

fn sign_states() -> std::sync::MutexGuard<'static, Option<HashMap<u64, crypto_sign_ed25519ph_state>>>
{
    let mut guard = SIGN_STATES.lock().unwrap();
    if guard.is_none() {
        *guard = Some(HashMap::new());
    }
    guard
}

fn hmacsha256_states(
) -> std::sync::MutexGuard<'static, Option<HashMap<u64, crypto_auth_hmacsha256_state>>> {
    let mut guard = HMACSHA256_STATES.lock().unwrap();
    if guard.is_none() {
        *guard = Some(HashMap::new());
    }
    guard
}

fn hmacsha512_states(
) -> std::sync::MutexGuard<'static, Option<HashMap<u64, crypto_auth_hmacsha512_state>>> {
    let mut guard = HMACSHA512_STATES.lock().unwrap();
    if guard.is_none() {
        *guard = Some(HashMap::new());
    }
    guard
}

fn hmacsha512256_states(
) -> std::sync::MutexGuard<'static, Option<HashMap<u64, crypto_auth_hmacsha512256_state>>> {
    let mut guard = HMACSHA512256_STATES.lock().unwrap();
    if guard.is_none() {
        *guard = Some(HashMap::new());
    }
    guard
}

fn hkdf_sha256_states(
) -> std::sync::MutexGuard<'static, Option<HashMap<u64, crypto_kdf_hkdf_sha256_state>>> {
    let mut guard = HKDF_SHA256_STATES.lock().unwrap();
    if guard.is_none() {
        *guard = Some(HashMap::new());
    }
    guard
}

fn hkdf_sha512_states(
) -> std::sync::MutexGuard<'static, Option<HashMap<u64, crypto_kdf_hkdf_sha512_state>>> {
    let mut guard = HKDF_SHA512_STATES.lock().unwrap();
    if guard.is_none() {
        *guard = Some(HashMap::new());
    }
    guard
}

fn shake128_states(
) -> std::sync::MutexGuard<'static, Option<HashMap<u64, crypto_xof_shake128_state>>> {
    let mut guard = SHAKE128_STATES.lock().unwrap();
    if guard.is_none() {
        *guard = Some(HashMap::new());
    }
    guard
}

fn shake256_states(
) -> std::sync::MutexGuard<'static, Option<HashMap<u64, crypto_xof_shake256_state>>> {
    let mut guard = SHAKE256_STATES.lock().unwrap();
    if guard.is_none() {
        *guard = Some(HashMap::new());
    }
    guard
}

fn turboshake128_states(
) -> std::sync::MutexGuard<'static, Option<HashMap<u64, crypto_xof_turboshake128_state>>> {
    let mut guard = TURBOSHAKE128_STATES.lock().unwrap();
    if guard.is_none() {
        *guard = Some(HashMap::new());
    }
    guard
}

fn turboshake256_states(
) -> std::sync::MutexGuard<'static, Option<HashMap<u64, crypto_xof_turboshake256_state>>> {
    let mut guard = TURBOSHAKE256_STATES.lock().unwrap();
    if guard.is_none() {
        *guard = Some(HashMap::new());
    }
    guard
}

// ============================================================================
// Generichash State (BLAKE2b streaming)
// ============================================================================

pub fn generichash_state_bytes() -> u32 {
    std::mem::size_of::<crypto_generichash_state>() as u32
}

pub fn generichash_state_init(out_len: u32, key: &[u8]) -> CryptoResult<u64> {
    let out_len_usize = out_len as usize;
    if out_len_usize < crypto_generichash_BYTES_MIN as usize
        || out_len_usize > crypto_generichash_BYTES_MAX as usize
    {
        return Err(CryptoError::OperationFailed);
    }
    if !key.is_empty()
        && (key.len() < crypto_generichash_KEYBYTES_MIN as usize
            || key.len() > crypto_generichash_KEYBYTES_MAX as usize)
    {
        return Err(CryptoError::InvalidKeySize);
    }

    let mut state = unsafe { std::mem::zeroed::<crypto_generichash_state>() };
    let key_ptr = if key.is_empty() {
        std::ptr::null()
    } else {
        key.as_ptr()
    };
    let key_len = key.len();

    let ret = unsafe { crypto_generichash_init(&mut state, key_ptr, key_len, out_len_usize) };

    if ret != 0 {
        return Err(CryptoError::OperationFailed);
    }

    let id = next_state_id();
    let mut states = generichash_states();
    states.as_mut().unwrap().insert(id, (state, out_len_usize));
    Ok(id)
}

pub fn generichash_state_update(state_id: u64, data: &[u8]) -> CryptoResult<()> {
    let mut states = generichash_states();
    let (state, _) = states
        .as_mut()
        .unwrap()
        .get_mut(&state_id)
        .ok_or(CryptoError::OperationFailed)?;

    let ret = unsafe { crypto_generichash_update(state, data.as_ptr(), data.len() as u64) };

    if ret == 0 {
        Ok(())
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn generichash_state_final(state_id: u64) -> CryptoResult<Vec<u8>> {
    let mut states = generichash_states();
    let (state, out_len) = states
        .as_mut()
        .unwrap()
        .remove(&state_id)
        .ok_or(CryptoError::OperationFailed)?;

    let mut out = vec![0u8; out_len];
    let mut state = state;
    let ret = unsafe { crypto_generichash_final(&mut state, out.as_mut_ptr(), out_len) };

    if ret == 0 {
        Ok(out)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn generichash_state_destroy(state_id: u64) {
    let mut states = generichash_states();
    states.as_mut().unwrap().remove(&state_id);
}

// ============================================================================
// SHA-256 State
// ============================================================================

pub fn sha256_state_bytes() -> u32 {
    std::mem::size_of::<crypto_hash_sha256_state>() as u32
}

pub fn sha256_state_init() -> CryptoResult<u64> {
    let mut state = unsafe { std::mem::zeroed::<crypto_hash_sha256_state>() };
    let ret = unsafe { crypto_hash_sha256_init(&mut state) };

    if ret != 0 {
        return Err(CryptoError::OperationFailed);
    }

    let id = next_state_id();
    let mut states = sha256_states();
    states.as_mut().unwrap().insert(id, state);
    Ok(id)
}

pub fn sha256_state_update(state_id: u64, data: &[u8]) -> CryptoResult<()> {
    let mut states = sha256_states();
    let state = states
        .as_mut()
        .unwrap()
        .get_mut(&state_id)
        .ok_or(CryptoError::OperationFailed)?;

    let ret = unsafe { crypto_hash_sha256_update(state, data.as_ptr(), data.len() as u64) };

    if ret == 0 {
        Ok(())
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn sha256_state_final(state_id: u64) -> CryptoResult<Vec<u8>> {
    let mut states = sha256_states();
    let mut state = states
        .as_mut()
        .unwrap()
        .remove(&state_id)
        .ok_or(CryptoError::OperationFailed)?;

    let mut out = vec![0u8; crypto_hash_sha256_BYTES as usize];
    let ret = unsafe { crypto_hash_sha256_final(&mut state, out.as_mut_ptr()) };

    if ret == 0 {
        Ok(out)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn sha256_state_destroy(state_id: u64) {
    let mut states = sha256_states();
    states.as_mut().unwrap().remove(&state_id);
}

// ============================================================================
// SHA-512 State
// ============================================================================

pub fn sha512_state_bytes() -> u32 {
    std::mem::size_of::<crypto_hash_sha512_state>() as u32
}

pub fn sha512_state_init() -> CryptoResult<u64> {
    let mut state = unsafe { std::mem::zeroed::<crypto_hash_sha512_state>() };
    let ret = unsafe { crypto_hash_sha512_init(&mut state) };

    if ret != 0 {
        return Err(CryptoError::OperationFailed);
    }

    let id = next_state_id();
    let mut states = sha512_states();
    states.as_mut().unwrap().insert(id, state);
    Ok(id)
}

pub fn sha512_state_update(state_id: u64, data: &[u8]) -> CryptoResult<()> {
    let mut states = sha512_states();
    let state = states
        .as_mut()
        .unwrap()
        .get_mut(&state_id)
        .ok_or(CryptoError::OperationFailed)?;

    let ret = unsafe { crypto_hash_sha512_update(state, data.as_ptr(), data.len() as u64) };

    if ret == 0 {
        Ok(())
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn sha512_state_final(state_id: u64) -> CryptoResult<Vec<u8>> {
    let mut states = sha512_states();
    let mut state = states
        .as_mut()
        .unwrap()
        .remove(&state_id)
        .ok_or(CryptoError::OperationFailed)?;

    let mut out = vec![0u8; crypto_hash_sha512_BYTES as usize];
    let ret = unsafe { crypto_hash_sha512_final(&mut state, out.as_mut_ptr()) };

    if ret == 0 {
        Ok(out)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn sha512_state_destroy(state_id: u64) {
    let mut states = sha512_states();
    states.as_mut().unwrap().remove(&state_id);
}

// ============================================================================
// Auth State (HMAC-SHA512-256 streaming)
// ============================================================================

pub fn auth_state_bytes() -> u32 {
    std::mem::size_of::<crypto_auth_hmacsha512256_state>() as u32
}

pub fn auth_state_init(key: &[u8]) -> CryptoResult<u64> {
    if key.len() != crypto_auth_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }

    let mut state = unsafe { std::mem::zeroed::<crypto_auth_hmacsha512256_state>() };
    let ret = unsafe { crypto_auth_hmacsha512256_init(&mut state, key.as_ptr(), key.len()) };

    if ret != 0 {
        return Err(CryptoError::OperationFailed);
    }

    let id = next_state_id();
    let mut states = auth_states();
    states.as_mut().unwrap().insert(id, state);
    Ok(id)
}

pub fn auth_state_update(state_id: u64, data: &[u8]) -> CryptoResult<()> {
    let mut states = auth_states();
    let state = states
        .as_mut()
        .unwrap()
        .get_mut(&state_id)
        .ok_or(CryptoError::OperationFailed)?;

    let ret = unsafe { crypto_auth_hmacsha512256_update(state, data.as_ptr(), data.len() as u64) };

    if ret == 0 {
        Ok(())
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn auth_state_final(state_id: u64) -> CryptoResult<Vec<u8>> {
    let mut states = auth_states();
    let mut state = states
        .as_mut()
        .unwrap()
        .remove(&state_id)
        .ok_or(CryptoError::OperationFailed)?;

    let mut out = vec![0u8; crypto_auth_BYTES as usize];
    let ret = unsafe { crypto_auth_hmacsha512256_final(&mut state, out.as_mut_ptr()) };

    if ret == 0 {
        Ok(out)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn auth_state_destroy(state_id: u64) {
    let mut states = auth_states();
    states.as_mut().unwrap().remove(&state_id);
}

// ============================================================================
// Onetimeauth State (Poly1305 streaming)
// ============================================================================

pub fn onetimeauth_state_bytes() -> u32 {
    std::mem::size_of::<crypto_onetimeauth_state>() as u32
}

pub fn onetimeauth_state_init(key: &[u8]) -> CryptoResult<u64> {
    if key.len() != crypto_onetimeauth_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }

    let mut state = unsafe { std::mem::zeroed::<crypto_onetimeauth_state>() };
    let ret = unsafe { crypto_onetimeauth_init(&mut state, key.as_ptr()) };

    if ret != 0 {
        return Err(CryptoError::OperationFailed);
    }

    let id = next_state_id();
    let mut states = onetimeauth_states();
    states.as_mut().unwrap().insert(id, state);
    Ok(id)
}

pub fn onetimeauth_state_update(state_id: u64, data: &[u8]) -> CryptoResult<()> {
    let mut states = onetimeauth_states();
    let state = states
        .as_mut()
        .unwrap()
        .get_mut(&state_id)
        .ok_or(CryptoError::OperationFailed)?;

    let ret = unsafe { crypto_onetimeauth_update(state, data.as_ptr(), data.len() as u64) };

    if ret == 0 {
        Ok(())
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn onetimeauth_state_final(state_id: u64) -> CryptoResult<Vec<u8>> {
    let mut states = onetimeauth_states();
    let mut state = states
        .as_mut()
        .unwrap()
        .remove(&state_id)
        .ok_or(CryptoError::OperationFailed)?;

    let mut out = vec![0u8; crypto_onetimeauth_BYTES as usize];
    let ret = unsafe { crypto_onetimeauth_final(&mut state, out.as_mut_ptr()) };

    if ret == 0 {
        Ok(out)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn onetimeauth_state_destroy(state_id: u64) {
    let mut states = onetimeauth_states();
    states.as_mut().unwrap().remove(&state_id);
}

// ============================================================================
// Secret Stream (XChaCha20-Poly1305)
// ============================================================================

pub fn secretstream_key_bytes() -> u32 {
    crypto_secretstream_xchacha20poly1305_KEYBYTES
}

pub fn secretstream_header_bytes() -> u32 {
    crypto_secretstream_xchacha20poly1305_HEADERBYTES
}

pub fn secretstream_a_bytes() -> u32 {
    crypto_secretstream_xchacha20poly1305_ABYTES
}

pub fn secretstream_messagebytes_max() -> u64 {
    unsafe { crypto_secretstream_xchacha20poly1305_messagebytes_max() as u64 }
}

pub fn secretstream_keygen() -> Vec<u8> {
    let mut key = vec![0u8; crypto_secretstream_xchacha20poly1305_KEYBYTES as usize];
    unsafe {
        crypto_secretstream_xchacha20poly1305_keygen(key.as_mut_ptr());
    }
    key
}

pub fn secretstream_tag_message() -> u8 {
    crypto_secretstream_xchacha20poly1305_TAG_MESSAGE as u8
}

pub fn secretstream_tag_push() -> u8 {
    crypto_secretstream_xchacha20poly1305_TAG_PUSH as u8
}

pub fn secretstream_tag_rekey() -> u8 {
    crypto_secretstream_xchacha20poly1305_TAG_REKEY as u8
}

pub fn secretstream_tag_final() -> u8 {
    crypto_secretstream_xchacha20poly1305_TAG_FINAL as u8
}

pub fn secretstream_init_push(key: &[u8]) -> CryptoResult<(u64, Vec<u8>)> {
    if key.len() != crypto_secretstream_xchacha20poly1305_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }

    let mut state = unsafe { std::mem::zeroed::<crypto_secretstream_xchacha20poly1305_state>() };
    let mut header = vec![0u8; crypto_secretstream_xchacha20poly1305_HEADERBYTES as usize];

    let ret = unsafe {
        crypto_secretstream_xchacha20poly1305_init_push(
            &mut state,
            header.as_mut_ptr(),
            key.as_ptr(),
        )
    };

    if ret != 0 {
        return Err(CryptoError::OperationFailed);
    }

    let id = next_state_id();
    let mut states = secretstream_states();
    states.as_mut().unwrap().insert(id, state);
    Ok((id, header))
}

pub fn secretstream_push(
    state_id: u64,
    message: &[u8],
    ad: &[u8],
    tag: u8,
) -> CryptoResult<Vec<u8>> {
    let mut states = secretstream_states();
    let state = states
        .as_mut()
        .unwrap()
        .get_mut(&state_id)
        .ok_or(CryptoError::OperationFailed)?;

    let mut ciphertext =
        vec![0u8; message.len() + crypto_secretstream_xchacha20poly1305_ABYTES as usize];
    let ad_ptr = if ad.is_empty() {
        std::ptr::null()
    } else {
        ad.as_ptr()
    };
    let ad_len = ad.len() as u64;

    let ret = unsafe {
        crypto_secretstream_xchacha20poly1305_push(
            state,
            ciphertext.as_mut_ptr(),
            std::ptr::null_mut(),
            message.as_ptr(),
            message.len() as u64,
            ad_ptr,
            ad_len,
            tag,
        )
    };

    if ret == 0 {
        Ok(ciphertext)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn secretstream_init_pull(header: &[u8], key: &[u8]) -> CryptoResult<u64> {
    if key.len() != crypto_secretstream_xchacha20poly1305_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if header.len() != crypto_secretstream_xchacha20poly1305_HEADERBYTES as usize {
        return Err(CryptoError::OperationFailed);
    }

    let mut state = unsafe { std::mem::zeroed::<crypto_secretstream_xchacha20poly1305_state>() };

    let ret = unsafe {
        crypto_secretstream_xchacha20poly1305_init_pull(&mut state, header.as_ptr(), key.as_ptr())
    };

    if ret != 0 {
        return Err(CryptoError::OperationFailed);
    }

    let id = next_state_id();
    let mut states = secretstream_states();
    states.as_mut().unwrap().insert(id, state);
    Ok(id)
}

pub fn secretstream_pull(
    state_id: u64,
    ciphertext: &[u8],
    ad: &[u8],
) -> CryptoResult<(Vec<u8>, u8)> {
    let mut states = secretstream_states();
    let state = states
        .as_mut()
        .unwrap()
        .get_mut(&state_id)
        .ok_or(CryptoError::OperationFailed)?;

    if ciphertext.len() < crypto_secretstream_xchacha20poly1305_ABYTES as usize {
        return Err(CryptoError::OperationFailed);
    }

    let mut message =
        vec![0u8; ciphertext.len() - crypto_secretstream_xchacha20poly1305_ABYTES as usize];
    let mut tag: u8 = 0;
    let ad_ptr = if ad.is_empty() {
        std::ptr::null()
    } else {
        ad.as_ptr()
    };
    let ad_len = ad.len() as u64;

    let ret = unsafe {
        crypto_secretstream_xchacha20poly1305_pull(
            state,
            message.as_mut_ptr(),
            std::ptr::null_mut(),
            &mut tag,
            ciphertext.as_ptr(),
            ciphertext.len() as u64,
            ad_ptr,
            ad_len,
        )
    };

    if ret == 0 {
        Ok((message, tag))
    } else {
        Err(CryptoError::VerificationFailed)
    }
}

pub fn secretstream_rekey(state_id: u64) -> CryptoResult<()> {
    let mut states = secretstream_states();
    let state = states
        .as_mut()
        .unwrap()
        .get_mut(&state_id)
        .ok_or(CryptoError::OperationFailed)?;

    unsafe {
        crypto_secretstream_xchacha20poly1305_rekey(state);
    }
    Ok(())
}

pub fn secretstream_destroy(state_id: u64) {
    let mut states = secretstream_states();
    states.as_mut().unwrap().remove(&state_id);
}

// ============================================================================
// Sign Multi-part API (Ed25519ph)
// ============================================================================

pub fn sign_state_bytes() -> u32 {
    std::mem::size_of::<crypto_sign_ed25519ph_state>() as u32
}

pub fn sign_state_init() -> CryptoResult<u64> {
    let mut state = unsafe { std::mem::zeroed::<crypto_sign_ed25519ph_state>() };
    let ret = unsafe { crypto_sign_ed25519ph_init(&mut state) };

    if ret != 0 {
        return Err(CryptoError::OperationFailed);
    }

    let id = next_state_id();
    let mut states = sign_states();
    states.as_mut().unwrap().insert(id, state);
    Ok(id)
}

pub fn sign_state_update(state_id: u64, message: &[u8]) -> CryptoResult<()> {
    let mut states = sign_states();
    let state = states
        .as_mut()
        .unwrap()
        .get_mut(&state_id)
        .ok_or(CryptoError::OperationFailed)?;

    let ret =
        unsafe { crypto_sign_ed25519ph_update(state, message.as_ptr(), message.len() as u64) };

    if ret == 0 {
        Ok(())
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn sign_state_final_create(state_id: u64, secret_key: &[u8]) -> CryptoResult<Vec<u8>> {
    if secret_key.len() != crypto_sign_SECRETKEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }

    let mut states = sign_states();
    let mut state = states
        .as_mut()
        .unwrap()
        .remove(&state_id)
        .ok_or(CryptoError::OperationFailed)?;

    let mut signature = vec![0u8; crypto_sign_BYTES as usize];
    let ret = unsafe {
        crypto_sign_ed25519ph_final_create(
            &mut state,
            signature.as_mut_ptr(),
            std::ptr::null_mut(),
            secret_key.as_ptr(),
        )
    };

    if ret == 0 {
        Ok(signature)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn sign_state_final_verify(
    state_id: u64,
    signature: &[u8],
    public_key: &[u8],
) -> CryptoResult<()> {
    if signature.len() != crypto_sign_BYTES as usize {
        return Err(CryptoError::OperationFailed);
    }
    if public_key.len() != crypto_sign_PUBLICKEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }

    let mut states = sign_states();
    let mut state = states
        .as_mut()
        .unwrap()
        .remove(&state_id)
        .ok_or(CryptoError::OperationFailed)?;

    let ret = unsafe {
        crypto_sign_ed25519ph_final_verify(&mut state, signature.as_ptr(), public_key.as_ptr())
    };

    if ret == 0 {
        Ok(())
    } else {
        Err(CryptoError::VerificationFailed)
    }
}

pub fn sign_state_destroy(state_id: u64) {
    let mut states = sign_states();
    states.as_mut().unwrap().remove(&state_id);
}

// ============================================================================
// HMAC-SHA256 Streaming
// ============================================================================

pub fn auth_hmacsha256_bytes() -> u32 {
    crypto_auth_hmacsha256_BYTES
}

pub fn auth_hmacsha256_key_bytes() -> u32 {
    crypto_auth_hmacsha256_KEYBYTES
}

pub fn auth_hmacsha256_keygen() -> Vec<u8> {
    let mut key = vec![0u8; crypto_auth_hmacsha256_KEYBYTES as usize];
    unsafe {
        crypto_auth_hmacsha256_keygen(key.as_mut_ptr());
    }
    key
}

pub fn auth_hmacsha256(message: &[u8], key: &[u8]) -> CryptoResult<Vec<u8>> {
    if key.len() != crypto_auth_hmacsha256_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }

    let mut out = vec![0u8; crypto_auth_hmacsha256_BYTES as usize];
    let ret = unsafe {
        crypto_auth_hmacsha256(
            out.as_mut_ptr(),
            message.as_ptr(),
            message.len() as u64,
            key.as_ptr(),
        )
    };

    if ret == 0 {
        Ok(out)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn auth_hmacsha256_verify(tag: &[u8], message: &[u8], key: &[u8]) -> CryptoResult<()> {
    if tag.len() != crypto_auth_hmacsha256_BYTES as usize {
        return Err(CryptoError::VerificationFailed);
    }
    if key.len() != crypto_auth_hmacsha256_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }

    let ret = unsafe {
        crypto_auth_hmacsha256_verify(
            tag.as_ptr(),
            message.as_ptr(),
            message.len() as u64,
            key.as_ptr(),
        )
    };

    if ret == 0 {
        Ok(())
    } else {
        Err(CryptoError::VerificationFailed)
    }
}

pub fn auth_hmacsha256_state_bytes() -> u32 {
    std::mem::size_of::<crypto_auth_hmacsha256_state>() as u32
}

pub fn auth_hmacsha256_state_init(key: &[u8]) -> CryptoResult<u64> {
    if key.len() != crypto_auth_hmacsha256_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }

    let mut state = unsafe { std::mem::zeroed::<crypto_auth_hmacsha256_state>() };
    let ret = unsafe { crypto_auth_hmacsha256_init(&mut state, key.as_ptr(), key.len()) };

    if ret != 0 {
        return Err(CryptoError::OperationFailed);
    }

    let id = next_state_id();
    let mut states = hmacsha256_states();
    states.as_mut().unwrap().insert(id, state);
    Ok(id)
}

pub fn auth_hmacsha256_state_update(state_id: u64, data: &[u8]) -> CryptoResult<()> {
    let mut states = hmacsha256_states();
    let state = states
        .as_mut()
        .unwrap()
        .get_mut(&state_id)
        .ok_or(CryptoError::OperationFailed)?;

    let ret = unsafe { crypto_auth_hmacsha256_update(state, data.as_ptr(), data.len() as u64) };

    if ret == 0 {
        Ok(())
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn auth_hmacsha256_state_final(state_id: u64) -> CryptoResult<Vec<u8>> {
    let mut states = hmacsha256_states();
    let mut state = states
        .as_mut()
        .unwrap()
        .remove(&state_id)
        .ok_or(CryptoError::OperationFailed)?;

    let mut out = vec![0u8; crypto_auth_hmacsha256_BYTES as usize];
    let ret = unsafe { crypto_auth_hmacsha256_final(&mut state, out.as_mut_ptr()) };

    if ret == 0 {
        Ok(out)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn auth_hmacsha256_state_destroy(state_id: u64) {
    let mut states = hmacsha256_states();
    states.as_mut().unwrap().remove(&state_id);
}

// ============================================================================
// HMAC-SHA512 Streaming
// ============================================================================

pub fn auth_hmacsha512_bytes() -> u32 {
    crypto_auth_hmacsha512_BYTES
}

pub fn auth_hmacsha512_key_bytes() -> u32 {
    crypto_auth_hmacsha512_KEYBYTES
}

pub fn auth_hmacsha512_keygen() -> Vec<u8> {
    let mut key = vec![0u8; crypto_auth_hmacsha512_KEYBYTES as usize];
    unsafe {
        crypto_auth_hmacsha512_keygen(key.as_mut_ptr());
    }
    key
}

pub fn auth_hmacsha512(message: &[u8], key: &[u8]) -> CryptoResult<Vec<u8>> {
    if key.len() != crypto_auth_hmacsha512_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }

    let mut out = vec![0u8; crypto_auth_hmacsha512_BYTES as usize];
    let ret = unsafe {
        crypto_auth_hmacsha512(
            out.as_mut_ptr(),
            message.as_ptr(),
            message.len() as u64,
            key.as_ptr(),
        )
    };

    if ret == 0 {
        Ok(out)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn auth_hmacsha512_verify(tag: &[u8], message: &[u8], key: &[u8]) -> CryptoResult<()> {
    if tag.len() != crypto_auth_hmacsha512_BYTES as usize {
        return Err(CryptoError::VerificationFailed);
    }
    if key.len() != crypto_auth_hmacsha512_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }

    let ret = unsafe {
        crypto_auth_hmacsha512_verify(
            tag.as_ptr(),
            message.as_ptr(),
            message.len() as u64,
            key.as_ptr(),
        )
    };

    if ret == 0 {
        Ok(())
    } else {
        Err(CryptoError::VerificationFailed)
    }
}

pub fn auth_hmacsha512_state_bytes() -> u32 {
    std::mem::size_of::<crypto_auth_hmacsha512_state>() as u32
}

pub fn auth_hmacsha512_state_init(key: &[u8]) -> CryptoResult<u64> {
    if key.len() != crypto_auth_hmacsha512_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }

    let mut state = unsafe { std::mem::zeroed::<crypto_auth_hmacsha512_state>() };
    let ret = unsafe { crypto_auth_hmacsha512_init(&mut state, key.as_ptr(), key.len()) };

    if ret != 0 {
        return Err(CryptoError::OperationFailed);
    }

    let id = next_state_id();
    let mut states = hmacsha512_states();
    states.as_mut().unwrap().insert(id, state);
    Ok(id)
}

pub fn auth_hmacsha512_state_update(state_id: u64, data: &[u8]) -> CryptoResult<()> {
    let mut states = hmacsha512_states();
    let state = states
        .as_mut()
        .unwrap()
        .get_mut(&state_id)
        .ok_or(CryptoError::OperationFailed)?;

    let ret = unsafe { crypto_auth_hmacsha512_update(state, data.as_ptr(), data.len() as u64) };

    if ret == 0 {
        Ok(())
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn auth_hmacsha512_state_final(state_id: u64) -> CryptoResult<Vec<u8>> {
    let mut states = hmacsha512_states();
    let mut state = states
        .as_mut()
        .unwrap()
        .remove(&state_id)
        .ok_or(CryptoError::OperationFailed)?;

    let mut out = vec![0u8; crypto_auth_hmacsha512_BYTES as usize];
    let ret = unsafe { crypto_auth_hmacsha512_final(&mut state, out.as_mut_ptr()) };

    if ret == 0 {
        Ok(out)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn auth_hmacsha512_state_destroy(state_id: u64) {
    let mut states = hmacsha512_states();
    states.as_mut().unwrap().remove(&state_id);
}

// ============================================================================
// HMAC-SHA512-256 Streaming
// ============================================================================

pub fn auth_hmacsha512256_bytes() -> u32 {
    crypto_auth_hmacsha512256_BYTES
}

pub fn auth_hmacsha512256_key_bytes() -> u32 {
    crypto_auth_hmacsha512256_KEYBYTES
}

pub fn auth_hmacsha512256_keygen() -> Vec<u8> {
    let mut key = vec![0u8; crypto_auth_hmacsha512256_KEYBYTES as usize];
    unsafe {
        crypto_auth_hmacsha512256_keygen(key.as_mut_ptr());
    }
    key
}

pub fn auth_hmacsha512256(message: &[u8], key: &[u8]) -> CryptoResult<Vec<u8>> {
    if key.len() != crypto_auth_hmacsha512256_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }

    let mut out = vec![0u8; crypto_auth_hmacsha512256_BYTES as usize];
    let ret = unsafe {
        crypto_auth_hmacsha512256(
            out.as_mut_ptr(),
            message.as_ptr(),
            message.len() as u64,
            key.as_ptr(),
        )
    };

    if ret == 0 {
        Ok(out)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn auth_hmacsha512256_verify(tag: &[u8], message: &[u8], key: &[u8]) -> CryptoResult<()> {
    if tag.len() != crypto_auth_hmacsha512256_BYTES as usize {
        return Err(CryptoError::VerificationFailed);
    }
    if key.len() != crypto_auth_hmacsha512256_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }

    let ret = unsafe {
        crypto_auth_hmacsha512256_verify(
            tag.as_ptr(),
            message.as_ptr(),
            message.len() as u64,
            key.as_ptr(),
        )
    };

    if ret == 0 {
        Ok(())
    } else {
        Err(CryptoError::VerificationFailed)
    }
}

pub fn auth_hmacsha512256_state_bytes() -> u32 {
    std::mem::size_of::<crypto_auth_hmacsha512256_state>() as u32
}

pub fn auth_hmacsha512256_state_init(key: &[u8]) -> CryptoResult<u64> {
    if key.len() != crypto_auth_hmacsha512256_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }

    let mut state = unsafe { std::mem::zeroed::<crypto_auth_hmacsha512256_state>() };
    let ret = unsafe { crypto_auth_hmacsha512256_init(&mut state, key.as_ptr(), key.len()) };

    if ret != 0 {
        return Err(CryptoError::OperationFailed);
    }

    let id = next_state_id();
    let mut states = hmacsha512256_states();
    states.as_mut().unwrap().insert(id, state);
    Ok(id)
}

pub fn auth_hmacsha512256_state_update(state_id: u64, data: &[u8]) -> CryptoResult<()> {
    let mut states = hmacsha512256_states();
    let state = states
        .as_mut()
        .unwrap()
        .get_mut(&state_id)
        .ok_or(CryptoError::OperationFailed)?;

    let ret = unsafe { crypto_auth_hmacsha512256_update(state, data.as_ptr(), data.len() as u64) };

    if ret == 0 {
        Ok(())
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn auth_hmacsha512256_state_final(state_id: u64) -> CryptoResult<Vec<u8>> {
    let mut states = hmacsha512256_states();
    let mut state = states
        .as_mut()
        .unwrap()
        .remove(&state_id)
        .ok_or(CryptoError::OperationFailed)?;

    let mut out = vec![0u8; crypto_auth_hmacsha512256_BYTES as usize];
    let ret = unsafe { crypto_auth_hmacsha512256_final(&mut state, out.as_mut_ptr()) };

    if ret == 0 {
        Ok(out)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn auth_hmacsha512256_state_destroy(state_id: u64) {
    let mut states = hmacsha512256_states();
    states.as_mut().unwrap().remove(&state_id);
}

// ============================================================================
// HKDF-SHA256
// ============================================================================

pub fn kdf_hkdf_sha256_key_bytes() -> u32 {
    crypto_kdf_hkdf_sha256_KEYBYTES
}

pub fn kdf_hkdf_sha256_bytes_min() -> u32 {
    crypto_kdf_hkdf_sha256_BYTES_MIN
}

pub fn kdf_hkdf_sha256_bytes_max() -> u32 {
    crypto_kdf_hkdf_sha256_BYTES_MAX
}

pub fn kdf_hkdf_sha256_keygen() -> Vec<u8> {
    let mut key = vec![0u8; crypto_kdf_hkdf_sha256_KEYBYTES as usize];
    unsafe {
        crypto_kdf_hkdf_sha256_keygen(key.as_mut_ptr());
    }
    key
}

pub fn kdf_hkdf_sha256_extract(salt: &[u8], ikm: &[u8]) -> CryptoResult<Vec<u8>> {
    let mut prk = vec![0u8; crypto_kdf_hkdf_sha256_KEYBYTES as usize];
    let salt_ptr = if salt.is_empty() {
        std::ptr::null()
    } else {
        salt.as_ptr()
    };
    let salt_len = salt.len();

    let ret = unsafe {
        crypto_kdf_hkdf_sha256_extract(
            prk.as_mut_ptr(),
            salt_ptr,
            salt_len,
            ikm.as_ptr(),
            ikm.len(),
        )
    };

    if ret == 0 {
        Ok(prk)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn kdf_hkdf_sha256_expand(prk: &[u8], info: &[u8], out_len: u32) -> CryptoResult<Vec<u8>> {
    if prk.len() != crypto_kdf_hkdf_sha256_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if out_len < crypto_kdf_hkdf_sha256_BYTES_MIN || out_len > crypto_kdf_hkdf_sha256_BYTES_MAX {
        return Err(CryptoError::OperationFailed);
    }

    let mut out = vec![0u8; out_len as usize];
    let info_ptr = if info.is_empty() {
        std::ptr::null()
    } else {
        info.as_ptr() as *const i8
    };
    let info_len = info.len();

    let ret = unsafe {
        crypto_kdf_hkdf_sha256_expand(
            out.as_mut_ptr(),
            out_len as usize,
            info_ptr,
            info_len,
            prk.as_ptr(),
        )
    };

    if ret == 0 {
        Ok(out)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn kdf_hkdf_sha256_extract_init(salt: &[u8]) -> CryptoResult<u64> {
    let mut state = unsafe { std::mem::zeroed::<crypto_kdf_hkdf_sha256_state>() };
    let salt_ptr = if salt.is_empty() {
        std::ptr::null()
    } else {
        salt.as_ptr()
    };
    let salt_len = salt.len();

    let ret = unsafe { crypto_kdf_hkdf_sha256_extract_init(&mut state, salt_ptr, salt_len) };

    if ret != 0 {
        return Err(CryptoError::OperationFailed);
    }

    let id = next_state_id();
    let mut states = hkdf_sha256_states();
    states.as_mut().unwrap().insert(id, state);
    Ok(id)
}

pub fn kdf_hkdf_sha256_extract_update(state_id: u64, ikm: &[u8]) -> CryptoResult<()> {
    let mut states = hkdf_sha256_states();
    let state = states
        .as_mut()
        .unwrap()
        .get_mut(&state_id)
        .ok_or(CryptoError::OperationFailed)?;

    let ret = unsafe { crypto_kdf_hkdf_sha256_extract_update(state, ikm.as_ptr(), ikm.len()) };

    if ret == 0 {
        Ok(())
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn kdf_hkdf_sha256_extract_final(state_id: u64) -> CryptoResult<Vec<u8>> {
    let mut states = hkdf_sha256_states();
    let mut state = states
        .as_mut()
        .unwrap()
        .remove(&state_id)
        .ok_or(CryptoError::OperationFailed)?;

    let mut prk = vec![0u8; crypto_kdf_hkdf_sha256_KEYBYTES as usize];
    let ret = unsafe { crypto_kdf_hkdf_sha256_extract_final(&mut state, prk.as_mut_ptr()) };

    if ret == 0 {
        Ok(prk)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

// ============================================================================
// HKDF-SHA512
// ============================================================================

pub fn kdf_hkdf_sha512_key_bytes() -> u32 {
    crypto_kdf_hkdf_sha512_KEYBYTES
}

pub fn kdf_hkdf_sha512_bytes_min() -> u32 {
    crypto_kdf_hkdf_sha512_BYTES_MIN
}

pub fn kdf_hkdf_sha512_bytes_max() -> u32 {
    crypto_kdf_hkdf_sha512_BYTES_MAX
}

pub fn kdf_hkdf_sha512_keygen() -> Vec<u8> {
    let mut key = vec![0u8; crypto_kdf_hkdf_sha512_KEYBYTES as usize];
    unsafe {
        crypto_kdf_hkdf_sha512_keygen(key.as_mut_ptr());
    }
    key
}

pub fn kdf_hkdf_sha512_extract(salt: &[u8], ikm: &[u8]) -> CryptoResult<Vec<u8>> {
    let mut prk = vec![0u8; crypto_kdf_hkdf_sha512_KEYBYTES as usize];
    let salt_ptr = if salt.is_empty() {
        std::ptr::null()
    } else {
        salt.as_ptr()
    };
    let salt_len = salt.len();

    let ret = unsafe {
        crypto_kdf_hkdf_sha512_extract(
            prk.as_mut_ptr(),
            salt_ptr,
            salt_len,
            ikm.as_ptr(),
            ikm.len(),
        )
    };

    if ret == 0 {
        Ok(prk)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn kdf_hkdf_sha512_expand(prk: &[u8], info: &[u8], out_len: u32) -> CryptoResult<Vec<u8>> {
    if prk.len() != crypto_kdf_hkdf_sha512_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if out_len < crypto_kdf_hkdf_sha512_BYTES_MIN || out_len > crypto_kdf_hkdf_sha512_BYTES_MAX {
        return Err(CryptoError::OperationFailed);
    }

    let mut out = vec![0u8; out_len as usize];
    let info_ptr = if info.is_empty() {
        std::ptr::null()
    } else {
        info.as_ptr() as *const i8
    };
    let info_len = info.len();

    let ret = unsafe {
        crypto_kdf_hkdf_sha512_expand(
            out.as_mut_ptr(),
            out_len as usize,
            info_ptr,
            info_len,
            prk.as_ptr(),
        )
    };

    if ret == 0 {
        Ok(out)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn kdf_hkdf_sha512_extract_init(salt: &[u8]) -> CryptoResult<u64> {
    let mut state = unsafe { std::mem::zeroed::<crypto_kdf_hkdf_sha512_state>() };
    let salt_ptr = if salt.is_empty() {
        std::ptr::null()
    } else {
        salt.as_ptr()
    };
    let salt_len = salt.len();

    let ret = unsafe { crypto_kdf_hkdf_sha512_extract_init(&mut state, salt_ptr, salt_len) };

    if ret != 0 {
        return Err(CryptoError::OperationFailed);
    }

    let id = next_state_id();
    let mut states = hkdf_sha512_states();
    states.as_mut().unwrap().insert(id, state);
    Ok(id)
}

pub fn kdf_hkdf_sha512_extract_update(state_id: u64, ikm: &[u8]) -> CryptoResult<()> {
    let mut states = hkdf_sha512_states();
    let state = states
        .as_mut()
        .unwrap()
        .get_mut(&state_id)
        .ok_or(CryptoError::OperationFailed)?;

    let ret = unsafe { crypto_kdf_hkdf_sha512_extract_update(state, ikm.as_ptr(), ikm.len()) };

    if ret == 0 {
        Ok(())
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn kdf_hkdf_sha512_extract_final(state_id: u64) -> CryptoResult<Vec<u8>> {
    let mut states = hkdf_sha512_states();
    let mut state = states
        .as_mut()
        .unwrap()
        .remove(&state_id)
        .ok_or(CryptoError::OperationFailed)?;

    let mut prk = vec![0u8; crypto_kdf_hkdf_sha512_KEYBYTES as usize];
    let ret = unsafe { crypto_kdf_hkdf_sha512_extract_final(&mut state, prk.as_mut_ptr()) };

    if ret == 0 {
        Ok(prk)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

// ============================================================================
// XOF SHAKE128
// ============================================================================

pub fn xof_shake128_state_bytes() -> u32 {
    std::mem::size_of::<crypto_xof_shake128_state>() as u32
}

pub fn xof_shake128(message: &[u8], out_len: u32) -> Vec<u8> {
    let mut out = vec![0u8; out_len as usize];
    unsafe {
        crypto_xof_shake128(
            out.as_mut_ptr(),
            out_len as usize,
            message.as_ptr(),
            message.len() as u64,
        );
    }
    out
}

pub fn xof_shake128_init() -> CryptoResult<u64> {
    let mut state = unsafe { std::mem::zeroed::<crypto_xof_shake128_state>() };
    let ret = unsafe { crypto_xof_shake128_init(&mut state) };

    if ret != 0 {
        return Err(CryptoError::OperationFailed);
    }

    let id = next_state_id();
    let mut states = shake128_states();
    states.as_mut().unwrap().insert(id, state);
    Ok(id)
}

pub fn xof_shake128_init_with_domain(domain: u8) -> CryptoResult<u64> {
    let mut state = unsafe { std::mem::zeroed::<crypto_xof_shake128_state>() };
    let ret = unsafe { crypto_xof_shake128_init_with_domain(&mut state, domain) };

    if ret != 0 {
        return Err(CryptoError::OperationFailed);
    }

    let id = next_state_id();
    let mut states = shake128_states();
    states.as_mut().unwrap().insert(id, state);
    Ok(id)
}

pub fn xof_shake128_update(state_id: u64, data: &[u8]) -> CryptoResult<()> {
    let mut states = shake128_states();
    let state = states
        .as_mut()
        .unwrap()
        .get_mut(&state_id)
        .ok_or(CryptoError::OperationFailed)?;

    let ret = unsafe { crypto_xof_shake128_update(state, data.as_ptr(), data.len() as u64) };

    if ret == 0 {
        Ok(())
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn xof_shake128_squeeze(state_id: u64, out_len: u32) -> CryptoResult<Vec<u8>> {
    let mut states = shake128_states();
    let state = states
        .as_mut()
        .unwrap()
        .get_mut(&state_id)
        .ok_or(CryptoError::OperationFailed)?;

    let mut out = vec![0u8; out_len as usize];
    let ret = unsafe { crypto_xof_shake128_squeeze(state, out.as_mut_ptr(), out_len as usize) };

    if ret == 0 {
        Ok(out)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn xof_shake128_destroy(state_id: u64) {
    let mut states = shake128_states();
    states.as_mut().unwrap().remove(&state_id);
}

// ============================================================================
// XOF SHAKE256
// ============================================================================

pub fn xof_shake256_state_bytes() -> u32 {
    std::mem::size_of::<crypto_xof_shake256_state>() as u32
}

pub fn xof_shake256(message: &[u8], out_len: u32) -> Vec<u8> {
    let mut out = vec![0u8; out_len as usize];
    unsafe {
        crypto_xof_shake256(
            out.as_mut_ptr(),
            out_len as usize,
            message.as_ptr(),
            message.len() as u64,
        );
    }
    out
}

pub fn xof_shake256_init() -> CryptoResult<u64> {
    let mut state = unsafe { std::mem::zeroed::<crypto_xof_shake256_state>() };
    let ret = unsafe { crypto_xof_shake256_init(&mut state) };

    if ret != 0 {
        return Err(CryptoError::OperationFailed);
    }

    let id = next_state_id();
    let mut states = shake256_states();
    states.as_mut().unwrap().insert(id, state);
    Ok(id)
}

pub fn xof_shake256_init_with_domain(domain: u8) -> CryptoResult<u64> {
    let mut state = unsafe { std::mem::zeroed::<crypto_xof_shake256_state>() };
    let ret = unsafe { crypto_xof_shake256_init_with_domain(&mut state, domain) };

    if ret != 0 {
        return Err(CryptoError::OperationFailed);
    }

    let id = next_state_id();
    let mut states = shake256_states();
    states.as_mut().unwrap().insert(id, state);
    Ok(id)
}

pub fn xof_shake256_update(state_id: u64, data: &[u8]) -> CryptoResult<()> {
    let mut states = shake256_states();
    let state = states
        .as_mut()
        .unwrap()
        .get_mut(&state_id)
        .ok_or(CryptoError::OperationFailed)?;

    let ret = unsafe { crypto_xof_shake256_update(state, data.as_ptr(), data.len() as u64) };

    if ret == 0 {
        Ok(())
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn xof_shake256_squeeze(state_id: u64, out_len: u32) -> CryptoResult<Vec<u8>> {
    let mut states = shake256_states();
    let state = states
        .as_mut()
        .unwrap()
        .get_mut(&state_id)
        .ok_or(CryptoError::OperationFailed)?;

    let mut out = vec![0u8; out_len as usize];
    let ret = unsafe { crypto_xof_shake256_squeeze(state, out.as_mut_ptr(), out_len as usize) };

    if ret == 0 {
        Ok(out)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn xof_shake256_destroy(state_id: u64) {
    let mut states = shake256_states();
    states.as_mut().unwrap().remove(&state_id);
}

// ============================================================================
// XOF TurboSHAKE128
// ============================================================================

pub fn xof_turboshake128_state_bytes() -> u32 {
    std::mem::size_of::<crypto_xof_turboshake128_state>() as u32
}

pub fn xof_turboshake128(message: &[u8], out_len: u32) -> Vec<u8> {
    let mut out = vec![0u8; out_len as usize];
    unsafe {
        crypto_xof_turboshake128(
            out.as_mut_ptr(),
            out_len as usize,
            message.as_ptr(),
            message.len() as u64,
        );
    }
    out
}

pub fn xof_turboshake128_init() -> CryptoResult<u64> {
    let mut state = unsafe { std::mem::zeroed::<crypto_xof_turboshake128_state>() };
    let ret = unsafe { crypto_xof_turboshake128_init(&mut state) };

    if ret != 0 {
        return Err(CryptoError::OperationFailed);
    }

    let id = next_state_id();
    let mut states = turboshake128_states();
    states.as_mut().unwrap().insert(id, state);
    Ok(id)
}

pub fn xof_turboshake128_init_with_domain(domain: u8) -> CryptoResult<u64> {
    let mut state = unsafe { std::mem::zeroed::<crypto_xof_turboshake128_state>() };
    let ret = unsafe { crypto_xof_turboshake128_init_with_domain(&mut state, domain) };

    if ret != 0 {
        return Err(CryptoError::OperationFailed);
    }

    let id = next_state_id();
    let mut states = turboshake128_states();
    states.as_mut().unwrap().insert(id, state);
    Ok(id)
}

pub fn xof_turboshake128_update(state_id: u64, data: &[u8]) -> CryptoResult<()> {
    let mut states = turboshake128_states();
    let state = states
        .as_mut()
        .unwrap()
        .get_mut(&state_id)
        .ok_or(CryptoError::OperationFailed)?;

    let ret = unsafe { crypto_xof_turboshake128_update(state, data.as_ptr(), data.len() as u64) };

    if ret == 0 {
        Ok(())
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn xof_turboshake128_squeeze(state_id: u64, out_len: u32) -> CryptoResult<Vec<u8>> {
    let mut states = turboshake128_states();
    let state = states
        .as_mut()
        .unwrap()
        .get_mut(&state_id)
        .ok_or(CryptoError::OperationFailed)?;

    let mut out = vec![0u8; out_len as usize];
    let ret =
        unsafe { crypto_xof_turboshake128_squeeze(state, out.as_mut_ptr(), out_len as usize) };

    if ret == 0 {
        Ok(out)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn xof_turboshake128_destroy(state_id: u64) {
    let mut states = turboshake128_states();
    states.as_mut().unwrap().remove(&state_id);
}

// ============================================================================
// XOF TurboSHAKE256
// ============================================================================

pub fn xof_turboshake256_state_bytes() -> u32 {
    std::mem::size_of::<crypto_xof_turboshake256_state>() as u32
}

pub fn xof_turboshake256(message: &[u8], out_len: u32) -> Vec<u8> {
    let mut out = vec![0u8; out_len as usize];
    unsafe {
        crypto_xof_turboshake256(
            out.as_mut_ptr(),
            out_len as usize,
            message.as_ptr(),
            message.len() as u64,
        );
    }
    out
}

pub fn xof_turboshake256_init() -> CryptoResult<u64> {
    let mut state = unsafe { std::mem::zeroed::<crypto_xof_turboshake256_state>() };
    let ret = unsafe { crypto_xof_turboshake256_init(&mut state) };

    if ret != 0 {
        return Err(CryptoError::OperationFailed);
    }

    let id = next_state_id();
    let mut states = turboshake256_states();
    states.as_mut().unwrap().insert(id, state);
    Ok(id)
}

pub fn xof_turboshake256_init_with_domain(domain: u8) -> CryptoResult<u64> {
    let mut state = unsafe { std::mem::zeroed::<crypto_xof_turboshake256_state>() };
    let ret = unsafe { crypto_xof_turboshake256_init_with_domain(&mut state, domain) };

    if ret != 0 {
        return Err(CryptoError::OperationFailed);
    }

    let id = next_state_id();
    let mut states = turboshake256_states();
    states.as_mut().unwrap().insert(id, state);
    Ok(id)
}

pub fn xof_turboshake256_update(state_id: u64, data: &[u8]) -> CryptoResult<()> {
    let mut states = turboshake256_states();
    let state = states
        .as_mut()
        .unwrap()
        .get_mut(&state_id)
        .ok_or(CryptoError::OperationFailed)?;

    let ret = unsafe { crypto_xof_turboshake256_update(state, data.as_ptr(), data.len() as u64) };

    if ret == 0 {
        Ok(())
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn xof_turboshake256_squeeze(state_id: u64, out_len: u32) -> CryptoResult<Vec<u8>> {
    let mut states = turboshake256_states();
    let state = states
        .as_mut()
        .unwrap()
        .get_mut(&state_id)
        .ok_or(CryptoError::OperationFailed)?;

    let mut out = vec![0u8; out_len as usize];
    let ret =
        unsafe { crypto_xof_turboshake256_squeeze(state, out.as_mut_ptr(), out_len as usize) };

    if ret == 0 {
        Ok(out)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn xof_turboshake256_destroy(state_id: u64) {
    let mut states = turboshake256_states();
    states.as_mut().unwrap().remove(&state_id);
}

// ============================================================================
// AEAD AES256-GCM
// ============================================================================

pub fn aead_aes256gcm_is_available() -> bool {
    unsafe { crypto_aead_aes256gcm_is_available() == 1 }
}

pub fn aead_aes256gcm_key_bytes() -> u32 {
    crypto_aead_aes256gcm_KEYBYTES
}

pub fn aead_aes256gcm_nonce_bytes() -> u32 {
    crypto_aead_aes256gcm_NPUBBYTES
}

pub fn aead_aes256gcm_a_bytes() -> u32 {
    crypto_aead_aes256gcm_ABYTES
}

pub fn aead_aes256gcm_keygen() -> Vec<u8> {
    let mut key = vec![0u8; crypto_aead_aes256gcm_KEYBYTES as usize];
    unsafe {
        crypto_aead_aes256gcm_keygen(key.as_mut_ptr());
    }
    key
}

pub fn aead_aes256gcm_encrypt(
    message: &[u8],
    ad: &[u8],
    nonce: &[u8],
    key: &[u8],
) -> CryptoResult<Vec<u8>> {
    if key.len() != crypto_aead_aes256gcm_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if nonce.len() != crypto_aead_aes256gcm_NPUBBYTES as usize {
        return Err(CryptoError::InvalidNonceSize);
    }

    let mut ciphertext = vec![0u8; message.len() + crypto_aead_aes256gcm_ABYTES as usize];
    let mut clen: u64 = 0;

    let ad_ptr = if ad.is_empty() {
        std::ptr::null()
    } else {
        ad.as_ptr()
    };

    let ret = unsafe {
        crypto_aead_aes256gcm_encrypt(
            ciphertext.as_mut_ptr(),
            &mut clen,
            message.as_ptr(),
            message.len() as u64,
            ad_ptr,
            ad.len() as u64,
            std::ptr::null(),
            nonce.as_ptr(),
            key.as_ptr(),
        )
    };

    if ret == 0 {
        ciphertext.truncate(clen as usize);
        Ok(ciphertext)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn aead_aes256gcm_decrypt(
    ciphertext: &[u8],
    ad: &[u8],
    nonce: &[u8],
    key: &[u8],
) -> CryptoResult<Vec<u8>> {
    if key.len() != crypto_aead_aes256gcm_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if nonce.len() != crypto_aead_aes256gcm_NPUBBYTES as usize {
        return Err(CryptoError::InvalidNonceSize);
    }
    if ciphertext.len() < crypto_aead_aes256gcm_ABYTES as usize {
        return Err(CryptoError::VerificationFailed);
    }

    let mut message = vec![0u8; ciphertext.len() - crypto_aead_aes256gcm_ABYTES as usize];
    let mut mlen: u64 = 0;

    let ad_ptr = if ad.is_empty() {
        std::ptr::null()
    } else {
        ad.as_ptr()
    };

    let ret = unsafe {
        crypto_aead_aes256gcm_decrypt(
            message.as_mut_ptr(),
            &mut mlen,
            std::ptr::null_mut(),
            ciphertext.as_ptr(),
            ciphertext.len() as u64,
            ad_ptr,
            ad.len() as u64,
            nonce.as_ptr(),
            key.as_ptr(),
        )
    };

    if ret == 0 {
        message.truncate(mlen as usize);
        Ok(message)
    } else {
        Err(CryptoError::VerificationFailed)
    }
}

pub fn aead_aes256gcm_encrypt_detached(
    message: &[u8],
    ad: &[u8],
    nonce: &[u8],
    key: &[u8],
) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
    if key.len() != crypto_aead_aes256gcm_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if nonce.len() != crypto_aead_aes256gcm_NPUBBYTES as usize {
        return Err(CryptoError::InvalidNonceSize);
    }

    let mut ciphertext = vec![0u8; message.len()];
    let mut mac = vec![0u8; crypto_aead_aes256gcm_ABYTES as usize];
    let mut maclen: u64 = 0;

    let ad_ptr = if ad.is_empty() {
        std::ptr::null()
    } else {
        ad.as_ptr()
    };

    let ret = unsafe {
        crypto_aead_aes256gcm_encrypt_detached(
            ciphertext.as_mut_ptr(),
            mac.as_mut_ptr(),
            &mut maclen,
            message.as_ptr(),
            message.len() as u64,
            ad_ptr,
            ad.len() as u64,
            std::ptr::null(),
            nonce.as_ptr(),
            key.as_ptr(),
        )
    };

    if ret == 0 {
        Ok((ciphertext, mac))
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn aead_aes256gcm_decrypt_detached(
    ciphertext: &[u8],
    mac: &[u8],
    ad: &[u8],
    nonce: &[u8],
    key: &[u8],
) -> CryptoResult<Vec<u8>> {
    if key.len() != crypto_aead_aes256gcm_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if nonce.len() != crypto_aead_aes256gcm_NPUBBYTES as usize {
        return Err(CryptoError::InvalidNonceSize);
    }
    if mac.len() != crypto_aead_aes256gcm_ABYTES as usize {
        return Err(CryptoError::VerificationFailed);
    }

    let mut message = vec![0u8; ciphertext.len()];

    let ad_ptr = if ad.is_empty() {
        std::ptr::null()
    } else {
        ad.as_ptr()
    };

    let ret = unsafe {
        crypto_aead_aes256gcm_decrypt_detached(
            message.as_mut_ptr(),
            std::ptr::null_mut(),
            ciphertext.as_ptr(),
            ciphertext.len() as u64,
            mac.as_ptr(),
            ad_ptr,
            ad.len() as u64,
            nonce.as_ptr(),
            key.as_ptr(),
        )
    };

    if ret == 0 {
        Ok(message)
    } else {
        Err(CryptoError::VerificationFailed)
    }
}

// ============================================================================
// Ristretto255 group operations
// ============================================================================

pub fn ristretto255_bytes() -> u32 {
    crypto_core_ristretto255_BYTES
}

pub fn ristretto255_hash_bytes() -> u32 {
    crypto_core_ristretto255_HASHBYTES
}

pub fn ristretto255_scalar_bytes() -> u32 {
    crypto_core_ristretto255_SCALARBYTES
}

pub fn ristretto255_non_reduced_scalar_bytes() -> u32 {
    crypto_core_ristretto255_NONREDUCEDSCALARBYTES
}

pub fn ristretto255_is_valid_point(p: &[u8]) -> bool {
    if p.len() != crypto_core_ristretto255_BYTES as usize {
        return false;
    }
    unsafe { crypto_core_ristretto255_is_valid_point(p.as_ptr()) == 1 }
}

pub fn ristretto255_add(p: &[u8], q: &[u8]) -> CryptoResult<Vec<u8>> {
    if p.len() != crypto_core_ristretto255_BYTES as usize
        || q.len() != crypto_core_ristretto255_BYTES as usize
    {
        return Err(CryptoError::OperationFailed);
    }
    let mut r = vec![0u8; crypto_core_ristretto255_BYTES as usize];
    let ret = unsafe { crypto_core_ristretto255_add(r.as_mut_ptr(), p.as_ptr(), q.as_ptr()) };
    if ret == 0 {
        Ok(r)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn ristretto255_sub(p: &[u8], q: &[u8]) -> CryptoResult<Vec<u8>> {
    if p.len() != crypto_core_ristretto255_BYTES as usize
        || q.len() != crypto_core_ristretto255_BYTES as usize
    {
        return Err(CryptoError::OperationFailed);
    }
    let mut r = vec![0u8; crypto_core_ristretto255_BYTES as usize];
    let ret = unsafe { crypto_core_ristretto255_sub(r.as_mut_ptr(), p.as_ptr(), q.as_ptr()) };
    if ret == 0 {
        Ok(r)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn ristretto255_from_hash(h: &[u8]) -> CryptoResult<Vec<u8>> {
    if h.len() != crypto_core_ristretto255_HASHBYTES as usize {
        return Err(CryptoError::OperationFailed);
    }
    let mut p = vec![0u8; crypto_core_ristretto255_BYTES as usize];
    let ret = unsafe { crypto_core_ristretto255_from_hash(p.as_mut_ptr(), h.as_ptr()) };
    if ret == 0 {
        Ok(p)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn ristretto255_random() -> Vec<u8> {
    let mut p = vec![0u8; crypto_core_ristretto255_BYTES as usize];
    unsafe { crypto_core_ristretto255_random(p.as_mut_ptr()) };
    p
}

pub fn ristretto255_scalar_random() -> Vec<u8> {
    let mut s = vec![0u8; crypto_core_ristretto255_SCALARBYTES as usize];
    unsafe { crypto_core_ristretto255_scalar_random(s.as_mut_ptr()) };
    s
}

pub fn ristretto255_scalar_invert(s: &[u8]) -> CryptoResult<Vec<u8>> {
    if s.len() != crypto_core_ristretto255_SCALARBYTES as usize {
        return Err(CryptoError::OperationFailed);
    }
    let mut r = vec![0u8; crypto_core_ristretto255_SCALARBYTES as usize];
    let ret = unsafe { crypto_core_ristretto255_scalar_invert(r.as_mut_ptr(), s.as_ptr()) };
    if ret == 0 {
        Ok(r)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn ristretto255_scalar_negate(s: &[u8]) -> Vec<u8> {
    let mut r = vec![0u8; crypto_core_ristretto255_SCALARBYTES as usize];
    if s.len() == crypto_core_ristretto255_SCALARBYTES as usize {
        unsafe { crypto_core_ristretto255_scalar_negate(r.as_mut_ptr(), s.as_ptr()) };
    }
    r
}

pub fn ristretto255_scalar_complement(s: &[u8]) -> Vec<u8> {
    let mut r = vec![0u8; crypto_core_ristretto255_SCALARBYTES as usize];
    if s.len() == crypto_core_ristretto255_SCALARBYTES as usize {
        unsafe { crypto_core_ristretto255_scalar_complement(r.as_mut_ptr(), s.as_ptr()) };
    }
    r
}

pub fn ristretto255_scalar_add(x: &[u8], y: &[u8]) -> Vec<u8> {
    let mut r = vec![0u8; crypto_core_ristretto255_SCALARBYTES as usize];
    if x.len() == crypto_core_ristretto255_SCALARBYTES as usize
        && y.len() == crypto_core_ristretto255_SCALARBYTES as usize
    {
        unsafe { crypto_core_ristretto255_scalar_add(r.as_mut_ptr(), x.as_ptr(), y.as_ptr()) };
    }
    r
}

pub fn ristretto255_scalar_sub(x: &[u8], y: &[u8]) -> Vec<u8> {
    let mut r = vec![0u8; crypto_core_ristretto255_SCALARBYTES as usize];
    if x.len() == crypto_core_ristretto255_SCALARBYTES as usize
        && y.len() == crypto_core_ristretto255_SCALARBYTES as usize
    {
        unsafe { crypto_core_ristretto255_scalar_sub(r.as_mut_ptr(), x.as_ptr(), y.as_ptr()) };
    }
    r
}

pub fn ristretto255_scalar_mul(x: &[u8], y: &[u8]) -> Vec<u8> {
    let mut r = vec![0u8; crypto_core_ristretto255_SCALARBYTES as usize];
    if x.len() == crypto_core_ristretto255_SCALARBYTES as usize
        && y.len() == crypto_core_ristretto255_SCALARBYTES as usize
    {
        unsafe { crypto_core_ristretto255_scalar_mul(r.as_mut_ptr(), x.as_ptr(), y.as_ptr()) };
    }
    r
}

pub fn ristretto255_scalar_reduce(s: &[u8]) -> Vec<u8> {
    let mut r = vec![0u8; crypto_core_ristretto255_SCALARBYTES as usize];
    if s.len() == crypto_core_ristretto255_NONREDUCEDSCALARBYTES as usize {
        unsafe { crypto_core_ristretto255_scalar_reduce(r.as_mut_ptr(), s.as_ptr()) };
    }
    r
}

// ============================================================================
// Ed25519 group operations
// ============================================================================

pub fn ed25519_bytes() -> u32 {
    crypto_core_ed25519_BYTES
}

pub fn ed25519_uniform_bytes() -> u32 {
    crypto_core_ed25519_UNIFORMBYTES
}

pub fn ed25519_hash_bytes() -> u32 {
    crypto_core_ed25519_HASHBYTES
}

pub fn ed25519_scalar_bytes() -> u32 {
    crypto_core_ed25519_SCALARBYTES
}

pub fn ed25519_non_reduced_scalar_bytes() -> u32 {
    crypto_core_ed25519_NONREDUCEDSCALARBYTES
}

pub fn ed25519_is_valid_point(p: &[u8]) -> bool {
    if p.len() != crypto_core_ed25519_BYTES as usize {
        return false;
    }
    unsafe { crypto_core_ed25519_is_valid_point(p.as_ptr()) == 1 }
}

pub fn ed25519_add(p: &[u8], q: &[u8]) -> CryptoResult<Vec<u8>> {
    if p.len() != crypto_core_ed25519_BYTES as usize
        || q.len() != crypto_core_ed25519_BYTES as usize
    {
        return Err(CryptoError::OperationFailed);
    }
    let mut r = vec![0u8; crypto_core_ed25519_BYTES as usize];
    let ret = unsafe { crypto_core_ed25519_add(r.as_mut_ptr(), p.as_ptr(), q.as_ptr()) };
    if ret == 0 {
        Ok(r)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn ed25519_sub(p: &[u8], q: &[u8]) -> CryptoResult<Vec<u8>> {
    if p.len() != crypto_core_ed25519_BYTES as usize
        || q.len() != crypto_core_ed25519_BYTES as usize
    {
        return Err(CryptoError::OperationFailed);
    }
    let mut r = vec![0u8; crypto_core_ed25519_BYTES as usize];
    let ret = unsafe { crypto_core_ed25519_sub(r.as_mut_ptr(), p.as_ptr(), q.as_ptr()) };
    if ret == 0 {
        Ok(r)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn ed25519_from_uniform(u: &[u8]) -> CryptoResult<Vec<u8>> {
    if u.len() != crypto_core_ed25519_UNIFORMBYTES as usize {
        return Err(CryptoError::OperationFailed);
    }
    let mut p = vec![0u8; crypto_core_ed25519_BYTES as usize];
    let ret = unsafe { crypto_core_ed25519_from_uniform(p.as_mut_ptr(), u.as_ptr()) };
    if ret == 0 {
        Ok(p)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn ed25519_from_hash(h: &[u8]) -> CryptoResult<Vec<u8>> {
    if h.len() != crypto_core_ed25519_HASHBYTES as usize {
        return Err(CryptoError::OperationFailed);
    }
    let mut p = vec![0u8; crypto_core_ed25519_BYTES as usize];
    let ret = unsafe { crypto_core_ed25519_from_hash(p.as_mut_ptr(), h.as_ptr()) };
    if ret == 0 {
        Ok(p)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn ed25519_random() -> Vec<u8> {
    let mut p = vec![0u8; crypto_core_ed25519_BYTES as usize];
    unsafe { crypto_core_ed25519_random(p.as_mut_ptr()) };
    p
}

pub fn ed25519_scalar_random() -> Vec<u8> {
    let mut s = vec![0u8; crypto_core_ed25519_SCALARBYTES as usize];
    unsafe { crypto_core_ed25519_scalar_random(s.as_mut_ptr()) };
    s
}

pub fn ed25519_scalar_invert(s: &[u8]) -> CryptoResult<Vec<u8>> {
    if s.len() != crypto_core_ed25519_SCALARBYTES as usize {
        return Err(CryptoError::OperationFailed);
    }
    let mut r = vec![0u8; crypto_core_ed25519_SCALARBYTES as usize];
    let ret = unsafe { crypto_core_ed25519_scalar_invert(r.as_mut_ptr(), s.as_ptr()) };
    if ret == 0 {
        Ok(r)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn ed25519_scalar_negate(s: &[u8]) -> Vec<u8> {
    let mut r = vec![0u8; crypto_core_ed25519_SCALARBYTES as usize];
    if s.len() == crypto_core_ed25519_SCALARBYTES as usize {
        unsafe { crypto_core_ed25519_scalar_negate(r.as_mut_ptr(), s.as_ptr()) };
    }
    r
}

pub fn ed25519_scalar_complement(s: &[u8]) -> Vec<u8> {
    let mut r = vec![0u8; crypto_core_ed25519_SCALARBYTES as usize];
    if s.len() == crypto_core_ed25519_SCALARBYTES as usize {
        unsafe { crypto_core_ed25519_scalar_complement(r.as_mut_ptr(), s.as_ptr()) };
    }
    r
}

pub fn ed25519_scalar_add(x: &[u8], y: &[u8]) -> Vec<u8> {
    let mut r = vec![0u8; crypto_core_ed25519_SCALARBYTES as usize];
    if x.len() == crypto_core_ed25519_SCALARBYTES as usize
        && y.len() == crypto_core_ed25519_SCALARBYTES as usize
    {
        unsafe { crypto_core_ed25519_scalar_add(r.as_mut_ptr(), x.as_ptr(), y.as_ptr()) };
    }
    r
}

pub fn ed25519_scalar_sub(x: &[u8], y: &[u8]) -> Vec<u8> {
    let mut r = vec![0u8; crypto_core_ed25519_SCALARBYTES as usize];
    if x.len() == crypto_core_ed25519_SCALARBYTES as usize
        && y.len() == crypto_core_ed25519_SCALARBYTES as usize
    {
        unsafe { crypto_core_ed25519_scalar_sub(r.as_mut_ptr(), x.as_ptr(), y.as_ptr()) };
    }
    r
}

pub fn ed25519_scalar_mul(x: &[u8], y: &[u8]) -> Vec<u8> {
    let mut r = vec![0u8; crypto_core_ed25519_SCALARBYTES as usize];
    if x.len() == crypto_core_ed25519_SCALARBYTES as usize
        && y.len() == crypto_core_ed25519_SCALARBYTES as usize
    {
        unsafe { crypto_core_ed25519_scalar_mul(r.as_mut_ptr(), x.as_ptr(), y.as_ptr()) };
    }
    r
}

pub fn ed25519_scalar_reduce(s: &[u8]) -> Vec<u8> {
    let mut r = vec![0u8; crypto_core_ed25519_SCALARBYTES as usize];
    if s.len() == crypto_core_ed25519_NONREDUCEDSCALARBYTES as usize {
        unsafe { crypto_core_ed25519_scalar_reduce(r.as_mut_ptr(), s.as_ptr()) };
    }
    r
}

// ============================================================================
// Scalarmult Ed25519
// ============================================================================

pub fn scalarmult_ed25519_bytes() -> u32 {
    crypto_scalarmult_ed25519_BYTES
}

pub fn scalarmult_ed25519_scalar_bytes() -> u32 {
    crypto_scalarmult_ed25519_SCALARBYTES
}

pub fn scalarmult_ed25519(n: &[u8], p: &[u8]) -> CryptoResult<Vec<u8>> {
    if n.len() != crypto_scalarmult_ed25519_SCALARBYTES as usize {
        return Err(CryptoError::OperationFailed);
    }
    if p.len() != crypto_scalarmult_ed25519_BYTES as usize {
        return Err(CryptoError::OperationFailed);
    }
    let mut q = vec![0u8; crypto_scalarmult_ed25519_BYTES as usize];
    let ret = unsafe { crypto_scalarmult_ed25519(q.as_mut_ptr(), n.as_ptr(), p.as_ptr()) };
    if ret == 0 {
        Ok(q)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn scalarmult_ed25519_noclamp(n: &[u8], p: &[u8]) -> CryptoResult<Vec<u8>> {
    if n.len() != crypto_scalarmult_ed25519_SCALARBYTES as usize {
        return Err(CryptoError::OperationFailed);
    }
    if p.len() != crypto_scalarmult_ed25519_BYTES as usize {
        return Err(CryptoError::OperationFailed);
    }
    let mut q = vec![0u8; crypto_scalarmult_ed25519_BYTES as usize];
    let ret = unsafe { crypto_scalarmult_ed25519_noclamp(q.as_mut_ptr(), n.as_ptr(), p.as_ptr()) };
    if ret == 0 {
        Ok(q)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn scalarmult_ed25519_base(n: &[u8]) -> CryptoResult<Vec<u8>> {
    if n.len() != crypto_scalarmult_ed25519_SCALARBYTES as usize {
        return Err(CryptoError::OperationFailed);
    }
    let mut q = vec![0u8; crypto_scalarmult_ed25519_BYTES as usize];
    let ret = unsafe { crypto_scalarmult_ed25519_base(q.as_mut_ptr(), n.as_ptr()) };
    if ret == 0 {
        Ok(q)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn scalarmult_ed25519_base_noclamp(n: &[u8]) -> CryptoResult<Vec<u8>> {
    if n.len() != crypto_scalarmult_ed25519_SCALARBYTES as usize {
        return Err(CryptoError::OperationFailed);
    }
    let mut q = vec![0u8; crypto_scalarmult_ed25519_BYTES as usize];
    let ret = unsafe { crypto_scalarmult_ed25519_base_noclamp(q.as_mut_ptr(), n.as_ptr()) };
    if ret == 0 {
        Ok(q)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

// ============================================================================
// Scalarmult Ristretto255
// ============================================================================

pub fn scalarmult_ristretto255_bytes() -> u32 {
    crypto_scalarmult_ristretto255_BYTES
}

pub fn scalarmult_ristretto255_scalar_bytes() -> u32 {
    crypto_scalarmult_ristretto255_SCALARBYTES
}

pub fn scalarmult_ristretto255(n: &[u8], p: &[u8]) -> CryptoResult<Vec<u8>> {
    if n.len() != crypto_scalarmult_ristretto255_SCALARBYTES as usize {
        return Err(CryptoError::OperationFailed);
    }
    if p.len() != crypto_scalarmult_ristretto255_BYTES as usize {
        return Err(CryptoError::OperationFailed);
    }
    let mut q = vec![0u8; crypto_scalarmult_ristretto255_BYTES as usize];
    let ret = unsafe { crypto_scalarmult_ristretto255(q.as_mut_ptr(), n.as_ptr(), p.as_ptr()) };
    if ret == 0 {
        Ok(q)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn scalarmult_ristretto255_base(n: &[u8]) -> CryptoResult<Vec<u8>> {
    if n.len() != crypto_scalarmult_ristretto255_SCALARBYTES as usize {
        return Err(CryptoError::OperationFailed);
    }
    let mut q = vec![0u8; crypto_scalarmult_ristretto255_BYTES as usize];
    let ret = unsafe { crypto_scalarmult_ristretto255_base(q.as_mut_ptr(), n.as_ptr()) };
    if ret == 0 {
        Ok(q)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

// ============================================================================
// Password Hashing Scrypt
// ============================================================================

pub fn pwhash_scrypt_salt_bytes() -> u32 {
    crypto_pwhash_scryptsalsa208sha256_SALTBYTES
}

pub fn pwhash_scrypt_str_bytes() -> u32 {
    crypto_pwhash_scryptsalsa208sha256_STRBYTES
}

pub fn pwhash_scrypt_str_prefix() -> &'static str {
    "$7$"
}

pub fn pwhash_scrypt_opslimit_min() -> u64 {
    crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MIN as u64
}

pub fn pwhash_scrypt_opslimit_max() -> u64 {
    crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MAX as u64
}

pub fn pwhash_scrypt_memlimit_min() -> u64 {
    crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MIN as u64
}

pub fn pwhash_scrypt_memlimit_max() -> u64 {
    unsafe { crypto_pwhash_scryptsalsa208sha256_memlimit_max() as u64 }
}

pub fn pwhash_scrypt_opslimit_interactive() -> u64 {
    crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE as u64
}

pub fn pwhash_scrypt_opslimit_sensitive() -> u64 {
    crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE as u64
}

pub fn pwhash_scrypt_memlimit_interactive() -> u64 {
    crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE as u64
}

pub fn pwhash_scrypt_memlimit_sensitive() -> u64 {
    crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE as u64
}

pub fn pwhash_scrypt(
    out_len: u32,
    password: &[u8],
    salt: &[u8],
    opslimit: u64,
    memlimit: u64,
) -> CryptoResult<Vec<u8>> {
    if salt.len() != crypto_pwhash_scryptsalsa208sha256_SALTBYTES as usize {
        return Err(CryptoError::OperationFailed);
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

    if ret == 0 {
        Ok(out)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn pwhash_scrypt_str(password: &[u8], opslimit: u64, memlimit: u64) -> CryptoResult<String> {
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
        let nul_pos = out.iter().position(|&b| b == 0).unwrap_or(out.len());
        Ok(String::from_utf8_lossy(&out[..nul_pos]).into_owned())
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn pwhash_scrypt_str_verify(hash: &str, password: &[u8]) -> CryptoResult<()> {
    let hash_bytes = hash.as_bytes();
    if hash_bytes.len() >= crypto_pwhash_scryptsalsa208sha256_STRBYTES as usize {
        return Err(CryptoError::VerificationFailed);
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

    if ret == 0 {
        Ok(())
    } else {
        Err(CryptoError::VerificationFailed)
    }
}

pub fn pwhash_scrypt_str_needs_rehash(
    hash: &str,
    opslimit: u64,
    memlimit: u64,
) -> CryptoResult<bool> {
    let hash_bytes = hash.as_bytes();
    if hash_bytes.len() >= crypto_pwhash_scryptsalsa208sha256_STRBYTES as usize {
        return Err(CryptoError::OperationFailed);
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
        _ => Err(CryptoError::OperationFailed),
    }
}

pub fn pwhash_scrypt_bytes_min() -> u32 {
    crypto_pwhash_scryptsalsa208sha256_BYTES_MIN
}

pub fn pwhash_scrypt_bytes_max() -> u32 {
    unsafe { crypto_pwhash_scryptsalsa208sha256_bytes_max() as u32 }
}

pub fn pwhash_scrypt_passwd_min() -> u32 {
    crypto_pwhash_scryptsalsa208sha256_PASSWD_MIN
}

pub fn pwhash_scrypt_passwd_max() -> u32 {
    unsafe { crypto_pwhash_scryptsalsa208sha256_passwd_max() as u32 }
}

pub fn pwhash_scrypt_derive_ll(
    out_len: u32,
    password: &[u8],
    salt: &[u8],
    n: u64,
    r: u32,
    p: u32,
) -> CryptoResult<Vec<u8>> {
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

    if ret == 0 {
        Ok(out)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

// ============================================================================
// Cipher Salsa20
// ============================================================================

pub fn stream_salsa20_key_bytes() -> u32 {
    crypto_stream_salsa20_KEYBYTES
}

pub fn stream_salsa20_nonce_bytes() -> u32 {
    crypto_stream_salsa20_NONCEBYTES
}

pub fn stream_salsa20_keygen() -> Vec<u8> {
    let mut key = vec![0u8; crypto_stream_salsa20_KEYBYTES as usize];
    unsafe {
        crypto_stream_salsa20_keygen(key.as_mut_ptr());
    }
    key
}

pub fn stream_salsa20(len: u32, nonce: &[u8], key: &[u8]) -> CryptoResult<Vec<u8>> {
    if key.len() != crypto_stream_salsa20_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if nonce.len() != crypto_stream_salsa20_NONCEBYTES as usize {
        return Err(CryptoError::InvalidNonceSize);
    }

    let mut out = vec![0u8; len as usize];
    let ret = unsafe {
        crypto_stream_salsa20(out.as_mut_ptr(), len as u64, nonce.as_ptr(), key.as_ptr())
    };

    if ret == 0 {
        Ok(out)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn stream_salsa20_xor(message: &[u8], nonce: &[u8], key: &[u8]) -> CryptoResult<Vec<u8>> {
    if key.len() != crypto_stream_salsa20_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if nonce.len() != crypto_stream_salsa20_NONCEBYTES as usize {
        return Err(CryptoError::InvalidNonceSize);
    }

    let mut out = vec![0u8; message.len()];
    let ret = unsafe {
        crypto_stream_salsa20_xor(
            out.as_mut_ptr(),
            message.as_ptr(),
            message.len() as u64,
            nonce.as_ptr(),
            key.as_ptr(),
        )
    };

    if ret == 0 {
        Ok(out)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn stream_salsa20_xor_ic(
    message: &[u8],
    nonce: &[u8],
    ic: u64,
    key: &[u8],
) -> CryptoResult<Vec<u8>> {
    if key.len() != crypto_stream_salsa20_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if nonce.len() != crypto_stream_salsa20_NONCEBYTES as usize {
        return Err(CryptoError::InvalidNonceSize);
    }

    let mut out = vec![0u8; message.len()];
    let ret = unsafe {
        crypto_stream_salsa20_xor_ic(
            out.as_mut_ptr(),
            message.as_ptr(),
            message.len() as u64,
            nonce.as_ptr(),
            ic,
            key.as_ptr(),
        )
    };

    if ret == 0 {
        Ok(out)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

// ============================================================================
// Cipher ChaCha20
// ============================================================================

pub fn stream_chacha20_key_bytes() -> u32 {
    crypto_stream_chacha20_KEYBYTES
}

pub fn stream_chacha20_nonce_bytes() -> u32 {
    crypto_stream_chacha20_NONCEBYTES
}

pub fn stream_chacha20_keygen() -> Vec<u8> {
    let mut key = vec![0u8; crypto_stream_chacha20_KEYBYTES as usize];
    unsafe {
        crypto_stream_chacha20_keygen(key.as_mut_ptr());
    }
    key
}

pub fn stream_chacha20(len: u32, nonce: &[u8], key: &[u8]) -> CryptoResult<Vec<u8>> {
    if key.len() != crypto_stream_chacha20_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if nonce.len() != crypto_stream_chacha20_NONCEBYTES as usize {
        return Err(CryptoError::InvalidNonceSize);
    }

    let mut out = vec![0u8; len as usize];
    let ret = unsafe {
        crypto_stream_chacha20(out.as_mut_ptr(), len as u64, nonce.as_ptr(), key.as_ptr())
    };

    if ret == 0 {
        Ok(out)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn stream_chacha20_xor(message: &[u8], nonce: &[u8], key: &[u8]) -> CryptoResult<Vec<u8>> {
    if key.len() != crypto_stream_chacha20_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if nonce.len() != crypto_stream_chacha20_NONCEBYTES as usize {
        return Err(CryptoError::InvalidNonceSize);
    }

    let mut out = vec![0u8; message.len()];
    let ret = unsafe {
        crypto_stream_chacha20_xor(
            out.as_mut_ptr(),
            message.as_ptr(),
            message.len() as u64,
            nonce.as_ptr(),
            key.as_ptr(),
        )
    };

    if ret == 0 {
        Ok(out)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn stream_chacha20_xor_ic(
    message: &[u8],
    nonce: &[u8],
    ic: u64,
    key: &[u8],
) -> CryptoResult<Vec<u8>> {
    if key.len() != crypto_stream_chacha20_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if nonce.len() != crypto_stream_chacha20_NONCEBYTES as usize {
        return Err(CryptoError::InvalidNonceSize);
    }

    let mut out = vec![0u8; message.len()];
    let ret = unsafe {
        crypto_stream_chacha20_xor_ic(
            out.as_mut_ptr(),
            message.as_ptr(),
            message.len() as u64,
            nonce.as_ptr(),
            ic,
            key.as_ptr(),
        )
    };

    if ret == 0 {
        Ok(out)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

// ============================================================================
// Cipher ChaCha20 IETF
// ============================================================================

pub fn stream_chacha20_ietf_key_bytes() -> u32 {
    crypto_stream_chacha20_ietf_KEYBYTES
}

pub fn stream_chacha20_ietf_nonce_bytes() -> u32 {
    crypto_stream_chacha20_ietf_NONCEBYTES
}

pub fn stream_chacha20_ietf_keygen() -> Vec<u8> {
    let mut key = vec![0u8; crypto_stream_chacha20_ietf_KEYBYTES as usize];
    unsafe {
        crypto_stream_chacha20_ietf_keygen(key.as_mut_ptr());
    }
    key
}

pub fn stream_chacha20_ietf(len: u32, nonce: &[u8], key: &[u8]) -> CryptoResult<Vec<u8>> {
    if key.len() != crypto_stream_chacha20_ietf_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if nonce.len() != crypto_stream_chacha20_ietf_NONCEBYTES as usize {
        return Err(CryptoError::InvalidNonceSize);
    }

    let mut out = vec![0u8; len as usize];
    let ret = unsafe {
        crypto_stream_chacha20_ietf(out.as_mut_ptr(), len as u64, nonce.as_ptr(), key.as_ptr())
    };

    if ret == 0 {
        Ok(out)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn stream_chacha20_ietf_xor(message: &[u8], nonce: &[u8], key: &[u8]) -> CryptoResult<Vec<u8>> {
    if key.len() != crypto_stream_chacha20_ietf_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if nonce.len() != crypto_stream_chacha20_ietf_NONCEBYTES as usize {
        return Err(CryptoError::InvalidNonceSize);
    }

    let mut out = vec![0u8; message.len()];
    let ret = unsafe {
        crypto_stream_chacha20_ietf_xor(
            out.as_mut_ptr(),
            message.as_ptr(),
            message.len() as u64,
            nonce.as_ptr(),
            key.as_ptr(),
        )
    };

    if ret == 0 {
        Ok(out)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn stream_chacha20_ietf_xor_ic(
    message: &[u8],
    nonce: &[u8],
    ic: u32,
    key: &[u8],
) -> CryptoResult<Vec<u8>> {
    if key.len() != crypto_stream_chacha20_ietf_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if nonce.len() != crypto_stream_chacha20_ietf_NONCEBYTES as usize {
        return Err(CryptoError::InvalidNonceSize);
    }

    let mut out = vec![0u8; message.len()];
    let ret = unsafe {
        crypto_stream_chacha20_ietf_xor_ic(
            out.as_mut_ptr(),
            message.as_ptr(),
            message.len() as u64,
            nonce.as_ptr(),
            ic,
            key.as_ptr(),
        )
    };

    if ret == 0 {
        Ok(out)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

// ============================================================================
// Secretbox XChaCha20-Poly1305
// ============================================================================

pub fn secretbox_xchacha20poly1305_key_bytes() -> u32 {
    crypto_secretbox_xchacha20poly1305_KEYBYTES
}

pub fn secretbox_xchacha20poly1305_nonce_bytes() -> u32 {
    crypto_secretbox_xchacha20poly1305_NONCEBYTES
}

pub fn secretbox_xchacha20poly1305_mac_bytes() -> u32 {
    crypto_secretbox_xchacha20poly1305_MACBYTES
}

pub fn secretbox_xchacha20poly1305_keygen() -> Vec<u8> {
    let mut key = vec![0u8; crypto_secretbox_xchacha20poly1305_KEYBYTES as usize];
    unsafe {
        randombytes_buf(key.as_mut_ptr() as *mut _, key.len());
    }
    key
}

pub fn secretbox_xchacha20poly1305_easy(
    message: &[u8],
    nonce: &[u8],
    key: &[u8],
) -> CryptoResult<Vec<u8>> {
    if key.len() != crypto_secretbox_xchacha20poly1305_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if nonce.len() != crypto_secretbox_xchacha20poly1305_NONCEBYTES as usize {
        return Err(CryptoError::InvalidNonceSize);
    }

    let mut ciphertext =
        vec![0u8; message.len() + crypto_secretbox_xchacha20poly1305_MACBYTES as usize];
    let ret = unsafe {
        crypto_secretbox_xchacha20poly1305_easy(
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
        Err(CryptoError::OperationFailed)
    }
}

pub fn secretbox_xchacha20poly1305_open_easy(
    ciphertext: &[u8],
    nonce: &[u8],
    key: &[u8],
) -> CryptoResult<Vec<u8>> {
    if key.len() != crypto_secretbox_xchacha20poly1305_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if nonce.len() != crypto_secretbox_xchacha20poly1305_NONCEBYTES as usize {
        return Err(CryptoError::InvalidNonceSize);
    }
    if ciphertext.len() < crypto_secretbox_xchacha20poly1305_MACBYTES as usize {
        return Err(CryptoError::VerificationFailed);
    }

    let mut plaintext =
        vec![0u8; ciphertext.len() - crypto_secretbox_xchacha20poly1305_MACBYTES as usize];
    let ret = unsafe {
        crypto_secretbox_xchacha20poly1305_open_easy(
            plaintext.as_mut_ptr(),
            ciphertext.as_ptr(),
            ciphertext.len() as u64,
            nonce.as_ptr(),
            key.as_ptr(),
        )
    };

    if ret == 0 {
        Ok(plaintext)
    } else {
        Err(CryptoError::VerificationFailed)
    }
}

pub fn secretbox_xchacha20poly1305_detached(
    message: &[u8],
    nonce: &[u8],
    key: &[u8],
) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
    if key.len() != crypto_secretbox_xchacha20poly1305_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if nonce.len() != crypto_secretbox_xchacha20poly1305_NONCEBYTES as usize {
        return Err(CryptoError::InvalidNonceSize);
    }

    let mut ciphertext = vec![0u8; message.len()];
    let mut mac = vec![0u8; crypto_secretbox_xchacha20poly1305_MACBYTES as usize];
    let ret = unsafe {
        crypto_secretbox_xchacha20poly1305_detached(
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
        Err(CryptoError::OperationFailed)
    }
}

pub fn secretbox_xchacha20poly1305_open_detached(
    ciphertext: &[u8],
    mac: &[u8],
    nonce: &[u8],
    key: &[u8],
) -> CryptoResult<Vec<u8>> {
    if key.len() != crypto_secretbox_xchacha20poly1305_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if nonce.len() != crypto_secretbox_xchacha20poly1305_NONCEBYTES as usize {
        return Err(CryptoError::InvalidNonceSize);
    }
    if mac.len() != crypto_secretbox_xchacha20poly1305_MACBYTES as usize {
        return Err(CryptoError::VerificationFailed);
    }

    let mut plaintext = vec![0u8; ciphertext.len()];
    let ret = unsafe {
        crypto_secretbox_xchacha20poly1305_open_detached(
            plaintext.as_mut_ptr(),
            ciphertext.as_ptr(),
            mac.as_ptr(),
            ciphertext.len() as u64,
            nonce.as_ptr(),
            key.as_ptr(),
        )
    };

    if ret == 0 {
        Ok(plaintext)
    } else {
        Err(CryptoError::VerificationFailed)
    }
}

// ============================================================================
// Box XChaCha20-Poly1305
// ============================================================================

pub fn box_xchacha20poly1305_public_key_bytes() -> u32 {
    crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES
}

pub fn box_xchacha20poly1305_secret_key_bytes() -> u32 {
    crypto_box_curve25519xchacha20poly1305_SECRETKEYBYTES
}

pub fn box_xchacha20poly1305_nonce_bytes() -> u32 {
    crypto_box_curve25519xchacha20poly1305_NONCEBYTES
}

pub fn box_xchacha20poly1305_mac_bytes() -> u32 {
    crypto_box_curve25519xchacha20poly1305_MACBYTES
}

pub fn box_xchacha20poly1305_seed_bytes() -> u32 {
    crypto_box_curve25519xchacha20poly1305_SEEDBYTES
}

pub fn box_xchacha20poly1305_beforenm_bytes() -> u32 {
    crypto_box_curve25519xchacha20poly1305_BEFORENMBYTES
}

pub fn box_xchacha20poly1305_seal_bytes() -> u32 {
    crypto_box_curve25519xchacha20poly1305_SEALBYTES
}

pub fn box_xchacha20poly1305_keypair() -> (Vec<u8>, Vec<u8>) {
    let mut pk = vec![0u8; crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES as usize];
    let mut sk = vec![0u8; crypto_box_curve25519xchacha20poly1305_SECRETKEYBYTES as usize];
    unsafe {
        crypto_box_curve25519xchacha20poly1305_keypair(pk.as_mut_ptr(), sk.as_mut_ptr());
    }
    (pk, sk)
}

pub fn box_xchacha20poly1305_seed_keypair(seed: &[u8]) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
    if seed.len() != crypto_box_curve25519xchacha20poly1305_SEEDBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    let mut pk = vec![0u8; crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES as usize];
    let mut sk = vec![0u8; crypto_box_curve25519xchacha20poly1305_SECRETKEYBYTES as usize];
    let ret = unsafe {
        crypto_box_curve25519xchacha20poly1305_seed_keypair(
            pk.as_mut_ptr(),
            sk.as_mut_ptr(),
            seed.as_ptr(),
        )
    };
    if ret == 0 {
        Ok((pk, sk))
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn box_xchacha20poly1305_easy(
    message: &[u8],
    nonce: &[u8],
    recipient_pk: &[u8],
    sender_sk: &[u8],
) -> CryptoResult<Vec<u8>> {
    if recipient_pk.len() != crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if sender_sk.len() != crypto_box_curve25519xchacha20poly1305_SECRETKEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if nonce.len() != crypto_box_curve25519xchacha20poly1305_NONCEBYTES as usize {
        return Err(CryptoError::InvalidNonceSize);
    }

    let mut ciphertext =
        vec![0u8; message.len() + crypto_box_curve25519xchacha20poly1305_MACBYTES as usize];
    let ret = unsafe {
        crypto_box_curve25519xchacha20poly1305_easy(
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
        Err(CryptoError::OperationFailed)
    }
}

pub fn box_xchacha20poly1305_open_easy(
    ciphertext: &[u8],
    nonce: &[u8],
    sender_pk: &[u8],
    recipient_sk: &[u8],
) -> CryptoResult<Vec<u8>> {
    if sender_pk.len() != crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if recipient_sk.len() != crypto_box_curve25519xchacha20poly1305_SECRETKEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if nonce.len() != crypto_box_curve25519xchacha20poly1305_NONCEBYTES as usize {
        return Err(CryptoError::InvalidNonceSize);
    }
    if ciphertext.len() < crypto_box_curve25519xchacha20poly1305_MACBYTES as usize {
        return Err(CryptoError::VerificationFailed);
    }

    let mut plaintext =
        vec![0u8; ciphertext.len() - crypto_box_curve25519xchacha20poly1305_MACBYTES as usize];
    let ret = unsafe {
        crypto_box_curve25519xchacha20poly1305_open_easy(
            plaintext.as_mut_ptr(),
            ciphertext.as_ptr(),
            ciphertext.len() as u64,
            nonce.as_ptr(),
            sender_pk.as_ptr(),
            recipient_sk.as_ptr(),
        )
    };

    if ret == 0 {
        Ok(plaintext)
    } else {
        Err(CryptoError::VerificationFailed)
    }
}

pub fn box_xchacha20poly1305_detached(
    message: &[u8],
    nonce: &[u8],
    recipient_pk: &[u8],
    sender_sk: &[u8],
) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
    if recipient_pk.len() != crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if sender_sk.len() != crypto_box_curve25519xchacha20poly1305_SECRETKEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if nonce.len() != crypto_box_curve25519xchacha20poly1305_NONCEBYTES as usize {
        return Err(CryptoError::InvalidNonceSize);
    }

    let mut ciphertext = vec![0u8; message.len()];
    let mut mac = vec![0u8; crypto_box_curve25519xchacha20poly1305_MACBYTES as usize];
    let ret = unsafe {
        crypto_box_curve25519xchacha20poly1305_detached(
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
        Err(CryptoError::OperationFailed)
    }
}

pub fn box_xchacha20poly1305_open_detached(
    ciphertext: &[u8],
    mac: &[u8],
    nonce: &[u8],
    sender_pk: &[u8],
    recipient_sk: &[u8],
) -> CryptoResult<Vec<u8>> {
    if sender_pk.len() != crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if recipient_sk.len() != crypto_box_curve25519xchacha20poly1305_SECRETKEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if nonce.len() != crypto_box_curve25519xchacha20poly1305_NONCEBYTES as usize {
        return Err(CryptoError::InvalidNonceSize);
    }
    if mac.len() != crypto_box_curve25519xchacha20poly1305_MACBYTES as usize {
        return Err(CryptoError::VerificationFailed);
    }

    let mut plaintext = vec![0u8; ciphertext.len()];
    let ret = unsafe {
        crypto_box_curve25519xchacha20poly1305_open_detached(
            plaintext.as_mut_ptr(),
            ciphertext.as_ptr(),
            mac.as_ptr(),
            ciphertext.len() as u64,
            nonce.as_ptr(),
            sender_pk.as_ptr(),
            recipient_sk.as_ptr(),
        )
    };

    if ret == 0 {
        Ok(plaintext)
    } else {
        Err(CryptoError::VerificationFailed)
    }
}

pub fn box_xchacha20poly1305_beforenm(
    recipient_pk: &[u8],
    sender_sk: &[u8],
) -> CryptoResult<Vec<u8>> {
    if recipient_pk.len() != crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if sender_sk.len() != crypto_box_curve25519xchacha20poly1305_SECRETKEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }

    let mut shared_key = vec![0u8; crypto_box_curve25519xchacha20poly1305_BEFORENMBYTES as usize];
    let ret = unsafe {
        crypto_box_curve25519xchacha20poly1305_beforenm(
            shared_key.as_mut_ptr(),
            recipient_pk.as_ptr(),
            sender_sk.as_ptr(),
        )
    };

    if ret == 0 {
        Ok(shared_key)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn box_xchacha20poly1305_easy_afternm(
    message: &[u8],
    nonce: &[u8],
    shared_key: &[u8],
) -> CryptoResult<Vec<u8>> {
    if shared_key.len() != crypto_box_curve25519xchacha20poly1305_BEFORENMBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if nonce.len() != crypto_box_curve25519xchacha20poly1305_NONCEBYTES as usize {
        return Err(CryptoError::InvalidNonceSize);
    }

    let mut ciphertext =
        vec![0u8; message.len() + crypto_box_curve25519xchacha20poly1305_MACBYTES as usize];
    let ret = unsafe {
        crypto_box_curve25519xchacha20poly1305_easy_afternm(
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
        Err(CryptoError::OperationFailed)
    }
}

pub fn box_xchacha20poly1305_open_easy_afternm(
    ciphertext: &[u8],
    nonce: &[u8],
    shared_key: &[u8],
) -> CryptoResult<Vec<u8>> {
    if shared_key.len() != crypto_box_curve25519xchacha20poly1305_BEFORENMBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if nonce.len() != crypto_box_curve25519xchacha20poly1305_NONCEBYTES as usize {
        return Err(CryptoError::InvalidNonceSize);
    }
    if ciphertext.len() < crypto_box_curve25519xchacha20poly1305_MACBYTES as usize {
        return Err(CryptoError::VerificationFailed);
    }

    let mut plaintext =
        vec![0u8; ciphertext.len() - crypto_box_curve25519xchacha20poly1305_MACBYTES as usize];
    let ret = unsafe {
        crypto_box_curve25519xchacha20poly1305_open_easy_afternm(
            plaintext.as_mut_ptr(),
            ciphertext.as_ptr(),
            ciphertext.len() as u64,
            nonce.as_ptr(),
            shared_key.as_ptr(),
        )
    };

    if ret == 0 {
        Ok(plaintext)
    } else {
        Err(CryptoError::VerificationFailed)
    }
}

pub fn box_xchacha20poly1305_seal(message: &[u8], recipient_pk: &[u8]) -> CryptoResult<Vec<u8>> {
    if recipient_pk.len() != crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }

    let mut ciphertext =
        vec![0u8; message.len() + crypto_box_curve25519xchacha20poly1305_SEALBYTES as usize];
    let ret = unsafe {
        crypto_box_curve25519xchacha20poly1305_seal(
            ciphertext.as_mut_ptr(),
            message.as_ptr(),
            message.len() as u64,
            recipient_pk.as_ptr(),
        )
    };

    if ret == 0 {
        Ok(ciphertext)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn box_xchacha20poly1305_seal_open(
    ciphertext: &[u8],
    recipient_pk: &[u8],
    recipient_sk: &[u8],
) -> CryptoResult<Vec<u8>> {
    if recipient_pk.len() != crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if recipient_sk.len() != crypto_box_curve25519xchacha20poly1305_SECRETKEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if ciphertext.len() < crypto_box_curve25519xchacha20poly1305_SEALBYTES as usize {
        return Err(CryptoError::VerificationFailed);
    }

    let mut plaintext =
        vec![0u8; ciphertext.len() - crypto_box_curve25519xchacha20poly1305_SEALBYTES as usize];
    let ret = unsafe {
        crypto_box_curve25519xchacha20poly1305_seal_open(
            plaintext.as_mut_ptr(),
            ciphertext.as_ptr(),
            ciphertext.len() as u64,
            recipient_pk.as_ptr(),
            recipient_sk.as_ptr(),
        )
    };

    if ret == 0 {
        Ok(plaintext)
    } else {
        Err(CryptoError::VerificationFailed)
    }
}

pub fn box_xchacha20poly1305_detached_afternm(
    message: &[u8],
    nonce: &[u8],
    shared_key: &[u8],
) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
    if shared_key.len() != crypto_box_curve25519xchacha20poly1305_BEFORENMBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if nonce.len() != crypto_box_curve25519xchacha20poly1305_NONCEBYTES as usize {
        return Err(CryptoError::InvalidNonceSize);
    }

    let mut ciphertext = vec![0u8; message.len()];
    let mut mac = vec![0u8; crypto_box_curve25519xchacha20poly1305_MACBYTES as usize];
    let ret = unsafe {
        crypto_box_curve25519xchacha20poly1305_detached_afternm(
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
        Err(CryptoError::OperationFailed)
    }
}

pub fn box_xchacha20poly1305_open_detached_afternm(
    ciphertext: &[u8],
    mac: &[u8],
    nonce: &[u8],
    shared_key: &[u8],
) -> CryptoResult<Vec<u8>> {
    if shared_key.len() != crypto_box_curve25519xchacha20poly1305_BEFORENMBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if nonce.len() != crypto_box_curve25519xchacha20poly1305_NONCEBYTES as usize {
        return Err(CryptoError::InvalidNonceSize);
    }
    if mac.len() != crypto_box_curve25519xchacha20poly1305_MACBYTES as usize {
        return Err(CryptoError::VerificationFailed);
    }

    let mut message = vec![0u8; ciphertext.len()];
    let ret = unsafe {
        crypto_box_curve25519xchacha20poly1305_open_detached_afternm(
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
        Err(CryptoError::VerificationFailed)
    }
}

// ============================================================================
// IPCrypt
// ============================================================================

pub fn ipcrypt_bytes() -> u32 {
    crypto_ipcrypt_BYTES
}

pub fn ipcrypt_key_bytes() -> u32 {
    crypto_ipcrypt_KEYBYTES
}

pub fn ipcrypt_input_bytes() -> u32 {
    crypto_ipcrypt_BYTES
}

pub fn ipcrypt_output_bytes() -> u32 {
    crypto_ipcrypt_BYTES
}

pub fn ipcrypt_keygen() -> Vec<u8> {
    let mut key = vec![0u8; crypto_ipcrypt_KEYBYTES as usize];
    unsafe {
        crypto_ipcrypt_keygen(key.as_mut_ptr());
    }
    key
}

pub fn ipcrypt_encrypt(input: &[u8], key: &[u8]) -> CryptoResult<Vec<u8>> {
    if key.len() != crypto_ipcrypt_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if input.len() != crypto_ipcrypt_BYTES as usize {
        return Err(CryptoError::OperationFailed);
    }

    let mut output = vec![0u8; crypto_ipcrypt_BYTES as usize];
    unsafe {
        crypto_ipcrypt_encrypt(output.as_mut_ptr(), input.as_ptr(), key.as_ptr());
    }
    Ok(output)
}

pub fn ipcrypt_decrypt(ciphertext: &[u8], key: &[u8]) -> CryptoResult<Vec<u8>> {
    if key.len() != crypto_ipcrypt_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if ciphertext.len() != crypto_ipcrypt_BYTES as usize {
        return Err(CryptoError::OperationFailed);
    }

    let mut output = vec![0u8; crypto_ipcrypt_BYTES as usize];
    unsafe {
        crypto_ipcrypt_decrypt(output.as_mut_ptr(), ciphertext.as_ptr(), key.as_ptr());
    }
    Ok(output)
}

pub fn ipcrypt_nd_encrypt(input: &[u8], tweak: &[u8], key: &[u8]) -> CryptoResult<Vec<u8>> {
    if key.len() != crypto_ipcrypt_ND_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if input.len() != crypto_ipcrypt_ND_INPUTBYTES as usize {
        return Err(CryptoError::OperationFailed);
    }
    if tweak.len() != crypto_ipcrypt_ND_TWEAKBYTES as usize {
        return Err(CryptoError::OperationFailed);
    }

    let mut output = vec![0u8; crypto_ipcrypt_ND_OUTPUTBYTES as usize];
    unsafe {
        crypto_ipcrypt_nd_encrypt(
            output.as_mut_ptr(),
            input.as_ptr(),
            tweak.as_ptr(),
            key.as_ptr(),
        );
    }
    Ok(output)
}

pub fn ipcrypt_nd_decrypt(ciphertext: &[u8], key: &[u8]) -> CryptoResult<Vec<u8>> {
    if key.len() != crypto_ipcrypt_ND_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if ciphertext.len() != crypto_ipcrypt_ND_OUTPUTBYTES as usize {
        return Err(CryptoError::OperationFailed);
    }

    let mut output = vec![0u8; crypto_ipcrypt_ND_INPUTBYTES as usize];
    unsafe {
        crypto_ipcrypt_nd_decrypt(output.as_mut_ptr(), ciphertext.as_ptr(), key.as_ptr());
    }
    Ok(output)
}

// ============================================================================
// Random Extended
// ============================================================================

pub fn random_seedbytes() -> u32 {
    randombytes_SEEDBYTES
}

pub fn random_buf_deterministic(len: u32, seed: &[u8]) -> CryptoResult<Vec<u8>> {
    if seed.len() != randombytes_SEEDBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    let mut buf = vec![0u8; len as usize];
    unsafe {
        randombytes_buf_deterministic(buf.as_mut_ptr() as *mut _, len as usize, seed.as_ptr());
    }
    Ok(buf)
}

// ============================================================================
// Additional utility functions
// ============================================================================

pub fn pwhash_str_needs_rehash(hash: &str, opslimit: u64, memlimit: u64) -> CryptoResult<bool> {
    let hash_bytes = hash.as_bytes();
    if hash_bytes.len() >= crypto_pwhash_STRBYTES as usize {
        return Err(CryptoError::OperationFailed);
    }

    // Create null-terminated string
    let mut hash_buf = vec![0u8; crypto_pwhash_STRBYTES as usize];
    hash_buf[..hash_bytes.len()].copy_from_slice(hash_bytes);

    let ret = unsafe {
        crypto_pwhash_str_needs_rehash(hash_buf.as_ptr() as *const i8, opslimit, memlimit as usize)
    };

    match ret {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(CryptoError::OperationFailed),
    }
}

pub fn sub(a: &mut [u8], b: &[u8]) -> CryptoResult<()> {
    if a.len() != b.len() {
        return Err(CryptoError::OperationFailed);
    }
    unsafe {
        sodium_sub(a.as_mut_ptr(), b.as_ptr(), a.len());
    }
    Ok(())
}

pub fn base642bin_variant_ignore(
    base64: &str,
    encoding: u32,
    ignore: &str,
) -> CryptoResult<Vec<u8>> {
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
        Err(CryptoError::OperationFailed)
    }
}

pub fn shorthash_siphashx24(message: &[u8], key: &[u8]) -> CryptoResult<Vec<u8>> {
    if key.len() != crypto_shorthash_siphashx24_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }

    let mut hash = vec![0u8; crypto_shorthash_siphashx24_BYTES as usize];
    let ret = unsafe {
        crypto_shorthash_siphashx24(
            hash.as_mut_ptr(),
            message.as_ptr(),
            message.len() as u64,
            key.as_ptr(),
        )
    };

    if ret == 0 {
        Ok(hash)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn box_detached_afternm(
    message: &[u8],
    nonce: &[u8],
    shared_key: &[u8],
) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
    if shared_key.len() != crypto_box_BEFORENMBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if nonce.len() != crypto_box_NONCEBYTES as usize {
        return Err(CryptoError::InvalidNonceSize);
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
        Err(CryptoError::OperationFailed)
    }
}

pub fn box_open_detached_afternm(
    ciphertext: &[u8],
    mac: &[u8],
    nonce: &[u8],
    shared_key: &[u8],
) -> CryptoResult<Vec<u8>> {
    if shared_key.len() != crypto_box_BEFORENMBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }
    if nonce.len() != crypto_box_NONCEBYTES as usize {
        return Err(CryptoError::InvalidNonceSize);
    }
    if mac.len() != crypto_box_MACBYTES as usize {
        return Err(CryptoError::VerificationFailed);
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
        Err(CryptoError::VerificationFailed)
    }
}

// ============================================================================
// IPcrypt extended functions
// ============================================================================

pub fn ip2bin(ip: &str) -> CryptoResult<Vec<u8>> {
    let mut bin = vec![0u8; 16];
    let ret = unsafe { sodium_ip2bin(bin.as_mut_ptr(), ip.as_ptr() as *const i8, ip.len()) };
    if ret == 0 {
        Ok(bin)
    } else {
        Err(CryptoError::OperationFailed)
    }
}

pub fn bin2ip(bin: &[u8]) -> CryptoResult<String> {
    if bin.len() != 16 {
        return Err(CryptoError::OperationFailed);
    }
    let mut ip = vec![0u8; 64]; // Max IP string length
    let ptr = unsafe { sodium_bin2ip(ip.as_mut_ptr() as *mut i8, ip.len(), bin.as_ptr()) };
    if ptr.is_null() {
        Err(CryptoError::OperationFailed)
    } else {
        let len = unsafe { libc::strlen(ptr) };
        ip.truncate(len);
        String::from_utf8(ip).map_err(|_| CryptoError::OperationFailed)
    }
}

pub fn ipcrypt_ndx_key_bytes() -> u32 {
    crypto_ipcrypt_NDX_KEYBYTES
}

pub fn ipcrypt_ndx_tweak_bytes() -> u32 {
    crypto_ipcrypt_NDX_TWEAKBYTES
}

pub fn ipcrypt_ndx_input_bytes() -> u32 {
    crypto_ipcrypt_NDX_INPUTBYTES
}

pub fn ipcrypt_ndx_output_bytes() -> u32 {
    crypto_ipcrypt_NDX_OUTPUTBYTES
}

pub fn ipcrypt_ndx_keygen() -> Vec<u8> {
    let mut key = vec![0u8; crypto_ipcrypt_NDX_KEYBYTES as usize];
    unsafe { crypto_ipcrypt_ndx_keygen(key.as_mut_ptr()) };
    key
}

pub fn ipcrypt_ndx_encrypt(input: &[u8], tweak: &[u8], key: &[u8]) -> CryptoResult<Vec<u8>> {
    if input.len() != crypto_ipcrypt_NDX_INPUTBYTES as usize {
        return Err(CryptoError::OperationFailed);
    }
    if tweak.len() != crypto_ipcrypt_NDX_TWEAKBYTES as usize {
        return Err(CryptoError::OperationFailed);
    }
    if key.len() != crypto_ipcrypt_NDX_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }

    let mut out = vec![0u8; crypto_ipcrypt_NDX_OUTPUTBYTES as usize];
    unsafe {
        crypto_ipcrypt_ndx_encrypt(
            out.as_mut_ptr(),
            input.as_ptr(),
            tweak.as_ptr(),
            key.as_ptr(),
        )
    };
    Ok(out)
}

pub fn ipcrypt_ndx_decrypt(ciphertext: &[u8], key: &[u8]) -> CryptoResult<Vec<u8>> {
    if ciphertext.len() != crypto_ipcrypt_NDX_OUTPUTBYTES as usize {
        return Err(CryptoError::OperationFailed);
    }
    if key.len() != crypto_ipcrypt_NDX_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }

    let mut out = vec![0u8; crypto_ipcrypt_NDX_INPUTBYTES as usize];
    unsafe { crypto_ipcrypt_ndx_decrypt(out.as_mut_ptr(), ciphertext.as_ptr(), key.as_ptr()) };
    Ok(out)
}

pub fn ipcrypt_pfx_key_bytes() -> u32 {
    crypto_ipcrypt_PFX_KEYBYTES
}

pub fn ipcrypt_pfx_bytes() -> u32 {
    crypto_ipcrypt_PFX_BYTES
}

pub fn ipcrypt_pfx_keygen() -> Vec<u8> {
    let mut key = vec![0u8; crypto_ipcrypt_PFX_KEYBYTES as usize];
    unsafe { crypto_ipcrypt_pfx_keygen(key.as_mut_ptr()) };
    key
}

pub fn ipcrypt_pfx_encrypt(input: &[u8], key: &[u8]) -> CryptoResult<Vec<u8>> {
    if input.len() != crypto_ipcrypt_PFX_BYTES as usize {
        return Err(CryptoError::OperationFailed);
    }
    if key.len() != crypto_ipcrypt_PFX_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }

    let mut out = vec![0u8; crypto_ipcrypt_PFX_BYTES as usize];
    unsafe { crypto_ipcrypt_pfx_encrypt(out.as_mut_ptr(), input.as_ptr(), key.as_ptr()) };
    Ok(out)
}

pub fn ipcrypt_pfx_decrypt(input: &[u8], key: &[u8]) -> CryptoResult<Vec<u8>> {
    if input.len() != crypto_ipcrypt_PFX_BYTES as usize {
        return Err(CryptoError::OperationFailed);
    }
    if key.len() != crypto_ipcrypt_PFX_KEYBYTES as usize {
        return Err(CryptoError::InvalidKeySize);
    }

    let mut out = vec![0u8; crypto_ipcrypt_PFX_BYTES as usize];
    unsafe { crypto_ipcrypt_pfx_decrypt(out.as_mut_ptr(), input.as_ptr(), key.as_ptr()) };
    Ok(out)
}
