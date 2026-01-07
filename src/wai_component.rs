//! Wasmer WAI implementation for libsodium
//!
//! This module provides WAI bindings that mirror the WIT component implementation.
//! All functions delegate to the shared crypto_impl module.

#![allow(unused_unsafe)]

use crate::crypto_impl;
use crate::sodium_bindings::*;

// Export the WAI interface - this generates the Libsodium trait
wai_bindgen_rust::export!("wai/libsodium.wai");

pub struct Libsodium;

// Helper to convert our internal error to WAI error type
fn to_wai_error(e: crypto_impl::CryptoError) -> libsodium::CryptoError {
    match e {
        crypto_impl::CryptoError::OperationFailed => libsodium::CryptoError::OperationFailed,
        crypto_impl::CryptoError::InvalidKeySize => libsodium::CryptoError::InvalidKeySize,
        crypto_impl::CryptoError::InvalidNonceSize => libsodium::CryptoError::InvalidNonceSize,
        crypto_impl::CryptoError::MessageTooLong => libsodium::CryptoError::MessageTooLong,
        crypto_impl::CryptoError::VerificationFailed => libsodium::CryptoError::VerificationFailed,
        crypto_impl::CryptoError::NotInitialized => libsodium::CryptoError::NotInitialized,
    }
}

impl libsodium::Libsodium for Libsodium {
    // ========================================================================
    // Core
    // ========================================================================

    fn init() -> i32 {
        crypto_impl::init()
    }

    fn version_string() -> String {
        crypto_impl::version_string()
    }

    fn library_version_major() -> i32 {
        crypto_impl::library_version_major()
    }

    fn library_version_minor() -> i32 {
        crypto_impl::library_version_minor()
    }

    // ========================================================================
    // Random
    // ========================================================================

    fn random_bytes(len: u32) -> Vec<u8> {
        crypto_impl::random_bytes(len)
    }

    fn random_u32() -> u32 {
        crypto_impl::random_u32()
    }

    fn random_uniform(upper_bound: u32) -> u32 {
        crypto_impl::random_uniform(upper_bound)
    }

    // ========================================================================
    // Secretbox
    // ========================================================================

    fn secretbox_key_bytes() -> u32 {
        crypto_impl::secretbox_key_bytes()
    }

    fn secretbox_nonce_bytes() -> u32 {
        crypto_impl::secretbox_nonce_bytes()
    }

    fn secretbox_mac_bytes() -> u32 {
        crypto_impl::secretbox_mac_bytes()
    }

    fn secretbox_keygen() -> Vec<u8> {
        crypto_impl::secretbox_keygen()
    }

    fn secretbox_easy(
        message: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::secretbox_easy(&message, &nonce, &key).map_err(to_wai_error)
    }

    fn secretbox_open_easy(
        ciphertext: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::secretbox_open_easy(&ciphertext, &nonce, &key).map_err(to_wai_error)
    }

    fn secretbox_detached(
        message: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<(Vec<u8>, Vec<u8>), libsodium::CryptoError> {
        crypto_impl::secretbox_detached(&message, &nonce, &key).map_err(to_wai_error)
    }

    fn secretbox_open_detached(
        ciphertext: Vec<u8>,
        mac: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::secretbox_open_detached(&ciphertext, &mac, &nonce, &key).map_err(to_wai_error)
    }

    // ========================================================================
    // Crypto Box
    // ========================================================================

    fn crypto_box_public_key_bytes() -> u32 {
        crypto_impl::box_public_key_bytes()
    }

    fn crypto_box_secret_key_bytes() -> u32 {
        crypto_impl::box_secret_key_bytes()
    }

    fn crypto_box_nonce_bytes() -> u32 {
        crypto_impl::box_nonce_bytes()
    }

    fn crypto_box_mac_bytes() -> u32 {
        crypto_impl::box_mac_bytes()
    }

    fn crypto_box_seed_bytes() -> u32 {
        crypto_impl::box_seed_bytes()
    }

    fn crypto_box_keypair() -> libsodium::KeyPair {
        let (public_key, secret_key) = crypto_impl::box_keypair();
        libsodium::KeyPair {
            public_key,
            secret_key,
        }
    }

    fn crypto_box_seed_keypair(seed: Vec<u8>) -> Result<libsodium::KeyPair, libsodium::CryptoError> {
        crypto_impl::box_seed_keypair(&seed)
            .map(|(public_key, secret_key)| libsodium::KeyPair {
                public_key,
                secret_key,
            })
            .map_err(to_wai_error)
    }

    fn crypto_box_easy(
        message: Vec<u8>,
        nonce: Vec<u8>,
        recipient_pk: Vec<u8>,
        sender_sk: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::box_easy(&message, &nonce, &recipient_pk, &sender_sk).map_err(to_wai_error)
    }

    fn crypto_box_open_easy(
        ciphertext: Vec<u8>,
        nonce: Vec<u8>,
        sender_pk: Vec<u8>,
        recipient_sk: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::box_open_easy(&ciphertext, &nonce, &sender_pk, &recipient_sk)
            .map_err(to_wai_error)
    }

    fn crypto_box_detached(
        message: Vec<u8>,
        nonce: Vec<u8>,
        recipient_pk: Vec<u8>,
        sender_sk: Vec<u8>,
    ) -> Result<(Vec<u8>, Vec<u8>), libsodium::CryptoError> {
        crypto_impl::box_detached(&message, &nonce, &recipient_pk, &sender_sk).map_err(to_wai_error)
    }

    fn crypto_box_open_detached(
        ciphertext: Vec<u8>,
        mac: Vec<u8>,
        nonce: Vec<u8>,
        sender_pk: Vec<u8>,
        recipient_sk: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::box_open_detached(&ciphertext, &mac, &nonce, &sender_pk, &recipient_sk)
            .map_err(to_wai_error)
    }

    fn crypto_box_beforenm_bytes() -> u32 {
        crypto_impl::box_beforenm_bytes()
    }

    fn crypto_box_beforenm(
        pk: Vec<u8>,
        sk: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::box_beforenm(&pk, &sk).map_err(to_wai_error)
    }

    fn crypto_box_easy_afternm(
        message: Vec<u8>,
        nonce: Vec<u8>,
        shared_key: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::box_easy_afternm(&message, &nonce, &shared_key).map_err(to_wai_error)
    }

    fn crypto_box_open_easy_afternm(
        ciphertext: Vec<u8>,
        nonce: Vec<u8>,
        shared_key: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::box_open_easy_afternm(&ciphertext, &nonce, &shared_key).map_err(to_wai_error)
    }

    fn crypto_box_detached_afternm(
        message: Vec<u8>,
        nonce: Vec<u8>,
        shared_key: Vec<u8>,
    ) -> Result<(Vec<u8>, Vec<u8>), libsodium::CryptoError> {
        crypto_impl::box_detached_afternm(&message, &nonce, &shared_key).map_err(to_wai_error)
    }

    fn crypto_box_open_detached_afternm(
        ciphertext: Vec<u8>,
        mac: Vec<u8>,
        nonce: Vec<u8>,
        shared_key: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::box_open_detached_afternm(&ciphertext, &mac, &nonce, &shared_key)
            .map_err(to_wai_error)
    }

    // ========================================================================
    // Seal
    // ========================================================================

    fn seal_bytes() -> u32 {
        crypto_impl::seal_bytes()
    }

    fn seal_seal(
        message: Vec<u8>,
        recipient_pk: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::seal(&message, &recipient_pk).map_err(to_wai_error)
    }

    fn seal_open(
        ciphertext: Vec<u8>,
        recipient_pk: Vec<u8>,
        recipient_sk: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::seal_open(&ciphertext, &recipient_pk, &recipient_sk).map_err(to_wai_error)
    }

    // ========================================================================
    // Sign
    // ========================================================================

    fn sign_public_key_bytes() -> u32 {
        crypto_impl::sign_public_key_bytes()
    }

    fn sign_secret_key_bytes() -> u32 {
        crypto_impl::sign_secret_key_bytes()
    }

    fn sign_signature_bytes() -> u32 {
        crypto_impl::sign_signature_bytes()
    }

    fn sign_seed_bytes() -> u32 {
        crypto_impl::sign_seed_bytes()
    }

    fn sign_state_bytes() -> u32 {
        crypto_impl::sign_state_bytes()
    }

    fn sign_keypair() -> libsodium::SignKeyPair {
        let (public_key, secret_key) = crypto_impl::sign_keypair();
        libsodium::SignKeyPair {
            public_key,
            secret_key,
        }
    }

    fn sign_seed_keypair(seed: Vec<u8>) -> Result<libsodium::SignKeyPair, libsodium::CryptoError> {
        crypto_impl::sign_seed_keypair(&seed)
            .map(|(public_key, secret_key)| libsodium::SignKeyPair {
                public_key,
                secret_key,
            })
            .map_err(to_wai_error)
    }

    fn sign_sign(
        message: Vec<u8>,
        secret_key: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::sign(&message, &secret_key).map_err(to_wai_error)
    }

    fn sign_open(
        signed_message: Vec<u8>,
        public_key: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::sign_open(&signed_message, &public_key).map_err(to_wai_error)
    }

    fn sign_detached(
        message: Vec<u8>,
        secret_key: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::sign_detached(&message, &secret_key).map_err(to_wai_error)
    }

    fn sign_verify_detached(
        signature: Vec<u8>,
        message: Vec<u8>,
        public_key: Vec<u8>,
    ) -> Result<(), libsodium::CryptoError> {
        crypto_impl::sign_verify_detached(&signature, &message, &public_key).map_err(to_wai_error)
    }

    fn sign_init() -> Result<u64, libsodium::CryptoError> {
        crypto_impl::sign_state_init().map_err(to_wai_error)
    }

    fn sign_update(state_id: u64, message: Vec<u8>) -> Result<(), libsodium::CryptoError> {
        crypto_impl::sign_state_update(state_id, &message).map_err(to_wai_error)
    }

    fn sign_final_create(
        state_id: u64,
        secret_key: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::sign_state_final_create(state_id, &secret_key).map_err(to_wai_error)
    }

    fn sign_final_verify(
        state_id: u64,
        signature: Vec<u8>,
        public_key: Vec<u8>,
    ) -> Result<(), libsodium::CryptoError> {
        crypto_impl::sign_state_final_verify(state_id, &signature, &public_key).map_err(to_wai_error)
    }

    fn sign_destroy(state_id: u64) {
        crypto_impl::sign_state_destroy(state_id);
    }

    fn sign_ed25519_sk_to_pk(secret_key: Vec<u8>) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::sign_ed25519_sk_to_pk(&secret_key).map_err(to_wai_error)
    }

    fn sign_ed25519_sk_to_seed(secret_key: Vec<u8>) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::sign_ed25519_sk_to_seed(&secret_key).map_err(to_wai_error)
    }

    fn sign_ed25519_pk_to_curve25519(
        ed25519_pk: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::sign_ed25519_pk_to_curve25519(&ed25519_pk).map_err(to_wai_error)
    }

    fn sign_ed25519_sk_to_curve25519(
        ed25519_sk: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::sign_ed25519_sk_to_curve25519(&ed25519_sk).map_err(to_wai_error)
    }

    // ========================================================================
    // Generic Hash
    // ========================================================================

    fn generichash_bytes() -> u32 {
        crypto_impl::generichash_bytes()
    }

    fn generichash_bytes_min() -> u32 {
        crypto_impl::generichash_bytes_min()
    }

    fn generichash_bytes_max() -> u32 {
        crypto_impl::generichash_bytes_max()
    }

    fn generichash_key_bytes() -> u32 {
        crypto_impl::generichash_key_bytes()
    }

    fn generichash_key_bytes_min() -> u32 {
        crypto_impl::generichash_key_bytes_min()
    }

    fn generichash_key_bytes_max() -> u32 {
        crypto_impl::generichash_key_bytes_max()
    }

    fn generichash_keygen() -> Vec<u8> {
        crypto_impl::generichash_keygen()
    }

    fn generichash_hash(
        message: Vec<u8>,
        out_len: u32,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::generichash(&message, out_len).map_err(to_wai_error)
    }

    fn generichash_hash_keyed(
        message: Vec<u8>,
        out_len: u32,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::generichash_keyed(&message, out_len, &key).map_err(to_wai_error)
    }

    // ========================================================================
    // SHA256
    // ========================================================================

    fn sha256_bytes() -> u32 {
        crypto_impl::sha256_bytes()
    }

    fn sha256_hash(message: Vec<u8>) -> Vec<u8> {
        crypto_impl::sha256(&message)
    }

    // ========================================================================
    // SHA512
    // ========================================================================

    fn sha512_bytes() -> u32 {
        crypto_impl::sha512_bytes()
    }

    fn sha512_hash(message: Vec<u8>) -> Vec<u8> {
        crypto_impl::sha512(&message)
    }

    // ========================================================================
    // Auth
    // ========================================================================

    fn auth_bytes() -> u32 {
        crypto_impl::auth_bytes()
    }

    fn auth_key_bytes() -> u32 {
        crypto_impl::auth_key_bytes()
    }

    fn auth_keygen() -> Vec<u8> {
        crypto_impl::auth_keygen()
    }

    fn auth_auth(message: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::auth(&message, &key).map_err(to_wai_error)
    }

    fn auth_verify(
        tag: Vec<u8>,
        message: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<(), libsodium::CryptoError> {
        crypto_impl::auth_verify(&tag, &message, &key).map_err(to_wai_error)
    }

    // ========================================================================
    // AEAD XChaCha20-Poly1305
    // ========================================================================

    fn aead_xchacha20poly1305_key_bytes() -> u32 {
        crypto_impl::aead_xchacha20poly1305_key_bytes()
    }

    fn aead_xchacha20poly1305_nonce_bytes() -> u32 {
        crypto_impl::aead_xchacha20poly1305_nonce_bytes()
    }

    fn aead_xchacha20poly1305_a_bytes() -> u32 {
        crypto_impl::aead_xchacha20poly1305_a_bytes()
    }

    fn aead_xchacha20poly1305_keygen() -> Vec<u8> {
        crypto_impl::aead_xchacha20poly1305_keygen()
    }

    fn aead_xchacha20poly1305_encrypt(
        message: Vec<u8>,
        additional_data: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::aead_xchacha20poly1305_encrypt(&message, &additional_data, &nonce, &key)
            .map_err(to_wai_error)
    }

    fn aead_xchacha20poly1305_decrypt(
        ciphertext: Vec<u8>,
        additional_data: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::aead_xchacha20poly1305_decrypt(&ciphertext, &additional_data, &nonce, &key)
            .map_err(to_wai_error)
    }

    fn aead_xchacha20poly1305_encrypt_detached(
        message: Vec<u8>,
        additional_data: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<(Vec<u8>, Vec<u8>), libsodium::CryptoError> {
        crypto_impl::aead_xchacha20poly1305_encrypt_detached(
            &message,
            &additional_data,
            &nonce,
            &key,
        )
        .map_err(to_wai_error)
    }

    fn aead_xchacha20poly1305_decrypt_detached(
        ciphertext: Vec<u8>,
        mac: Vec<u8>,
        additional_data: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::aead_xchacha20poly1305_decrypt_detached(
            &ciphertext,
            &mac,
            &additional_data,
            &nonce,
            &key,
        )
        .map_err(to_wai_error)
    }

    // ========================================================================
    // AEAD ChaCha20-Poly1305 IETF
    // ========================================================================

    fn aead_chacha20poly1305_ietf_key_bytes() -> u32 {
        crypto_impl::aead_chacha20poly1305_ietf_key_bytes()
    }

    fn aead_chacha20poly1305_ietf_nonce_bytes() -> u32 {
        crypto_impl::aead_chacha20poly1305_ietf_nonce_bytes()
    }

    fn aead_chacha20poly1305_ietf_a_bytes() -> u32 {
        crypto_impl::aead_chacha20poly1305_ietf_a_bytes()
    }

    fn aead_chacha20poly1305_ietf_keygen() -> Vec<u8> {
        crypto_impl::aead_chacha20poly1305_ietf_keygen()
    }

    fn aead_chacha20poly1305_ietf_encrypt(
        message: Vec<u8>,
        additional_data: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::aead_chacha20poly1305_ietf_encrypt(&message, &additional_data, &nonce, &key)
            .map_err(to_wai_error)
    }

    fn aead_chacha20poly1305_ietf_decrypt(
        ciphertext: Vec<u8>,
        additional_data: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::aead_chacha20poly1305_ietf_decrypt(&ciphertext, &additional_data, &nonce, &key)
            .map_err(to_wai_error)
    }

    fn aead_chacha20poly1305_ietf_encrypt_detached(
        message: Vec<u8>,
        additional_data: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<(Vec<u8>, Vec<u8>), libsodium::CryptoError> {
        crypto_impl::aead_chacha20poly1305_ietf_encrypt_detached(
            &message,
            &additional_data,
            &nonce,
            &key,
        )
        .map_err(to_wai_error)
    }

    fn aead_chacha20poly1305_ietf_decrypt_detached(
        ciphertext: Vec<u8>,
        mac: Vec<u8>,
        additional_data: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::aead_chacha20poly1305_ietf_decrypt_detached(
            &ciphertext,
            &mac,
            &additional_data,
            &nonce,
            &key,
        )
        .map_err(to_wai_error)
    }

    // ========================================================================
    // AEAD ChaCha20-Poly1305 (original)
    // ========================================================================

    fn aead_chacha20poly1305_key_bytes() -> u32 {
        crypto_impl::aead_chacha20poly1305_key_bytes()
    }

    fn aead_chacha20poly1305_nonce_bytes() -> u32 {
        crypto_impl::aead_chacha20poly1305_nonce_bytes()
    }

    fn aead_chacha20poly1305_a_bytes() -> u32 {
        crypto_impl::aead_chacha20poly1305_a_bytes()
    }

    fn aead_chacha20poly1305_keygen() -> Vec<u8> {
        crypto_impl::aead_chacha20poly1305_keygen()
    }

    fn aead_chacha20poly1305_encrypt(
        message: Vec<u8>,
        additional_data: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::aead_chacha20poly1305_encrypt(&message, &additional_data, &nonce, &key)
            .map_err(to_wai_error)
    }

    fn aead_chacha20poly1305_decrypt(
        ciphertext: Vec<u8>,
        additional_data: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::aead_chacha20poly1305_decrypt(&ciphertext, &additional_data, &nonce, &key)
            .map_err(to_wai_error)
    }

    fn aead_chacha20poly1305_encrypt_detached(
        message: Vec<u8>,
        additional_data: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<(Vec<u8>, Vec<u8>), libsodium::CryptoError> {
        crypto_impl::aead_chacha20poly1305_encrypt_detached(
            &message,
            &additional_data,
            &nonce,
            &key,
        )
        .map_err(to_wai_error)
    }

    fn aead_chacha20poly1305_decrypt_detached(
        ciphertext: Vec<u8>,
        mac: Vec<u8>,
        additional_data: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::aead_chacha20poly1305_decrypt_detached(
            &ciphertext,
            &mac,
            &additional_data,
            &nonce,
            &key,
        )
        .map_err(to_wai_error)
    }

    // ========================================================================
    // AEAD AEGIS-128L
    // ========================================================================

    fn aead_aegis128l_key_bytes() -> u32 {
        crypto_impl::aead_aegis128l_key_bytes()
    }

    fn aead_aegis128l_nonce_bytes() -> u32 {
        crypto_impl::aead_aegis128l_nonce_bytes()
    }

    fn aead_aegis128l_a_bytes() -> u32 {
        crypto_impl::aead_aegis128l_a_bytes()
    }

    fn aead_aegis128l_keygen() -> Vec<u8> {
        crypto_impl::aead_aegis128l_keygen()
    }

    fn aead_aegis128l_encrypt(
        message: Vec<u8>,
        additional_data: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::aead_aegis128l_encrypt(&message, &additional_data, &nonce, &key)
            .map_err(to_wai_error)
    }

    fn aead_aegis128l_decrypt(
        ciphertext: Vec<u8>,
        additional_data: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::aead_aegis128l_decrypt(&ciphertext, &additional_data, &nonce, &key)
            .map_err(to_wai_error)
    }

    fn aead_aegis128l_encrypt_detached(
        message: Vec<u8>,
        additional_data: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<(Vec<u8>, Vec<u8>), libsodium::CryptoError> {
        crypto_impl::aead_aegis128l_encrypt_detached(&message, &additional_data, &nonce, &key)
            .map_err(to_wai_error)
    }

    fn aead_aegis128l_decrypt_detached(
        ciphertext: Vec<u8>,
        mac: Vec<u8>,
        additional_data: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::aead_aegis128l_decrypt_detached(
            &ciphertext,
            &mac,
            &additional_data,
            &nonce,
            &key,
        )
        .map_err(to_wai_error)
    }

    // ========================================================================
    // AEAD AEGIS-256
    // ========================================================================

    fn aead_aegis256_key_bytes() -> u32 {
        crypto_impl::aead_aegis256_key_bytes()
    }

    fn aead_aegis256_nonce_bytes() -> u32 {
        crypto_impl::aead_aegis256_nonce_bytes()
    }

    fn aead_aegis256_a_bytes() -> u32 {
        crypto_impl::aead_aegis256_a_bytes()
    }

    fn aead_aegis256_keygen() -> Vec<u8> {
        crypto_impl::aead_aegis256_keygen()
    }

    fn aead_aegis256_encrypt(
        message: Vec<u8>,
        additional_data: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::aead_aegis256_encrypt(&message, &additional_data, &nonce, &key)
            .map_err(to_wai_error)
    }

    fn aead_aegis256_decrypt(
        ciphertext: Vec<u8>,
        additional_data: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::aead_aegis256_decrypt(&ciphertext, &additional_data, &nonce, &key)
            .map_err(to_wai_error)
    }

    fn aead_aegis256_encrypt_detached(
        message: Vec<u8>,
        additional_data: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<(Vec<u8>, Vec<u8>), libsodium::CryptoError> {
        crypto_impl::aead_aegis256_encrypt_detached(&message, &additional_data, &nonce, &key)
            .map_err(to_wai_error)
    }

    fn aead_aegis256_decrypt_detached(
        ciphertext: Vec<u8>,
        mac: Vec<u8>,
        additional_data: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::aead_aegis256_decrypt_detached(
            &ciphertext,
            &mac,
            &additional_data,
            &nonce,
            &key,
        )
        .map_err(to_wai_error)
    }

    // ========================================================================
    // Password Hashing (Argon2)
    // ========================================================================

    fn pwhash_salt_bytes() -> u32 {
        crypto_impl::pwhash_salt_bytes()
    }

    fn pwhash_str_bytes() -> u32 {
        crypto_impl::pwhash_str_bytes()
    }

    fn pwhash_bytes_min() -> u32 {
        crypto_pwhash_BYTES_MIN
    }

    fn pwhash_bytes_max() -> u32 {
        unsafe { crypto_pwhash_bytes_max() as u32 }
    }

    fn pwhash_passwd_min() -> u32 {
        crypto_pwhash_PASSWD_MIN
    }

    fn pwhash_passwd_max() -> u32 {
        crypto_pwhash_PASSWD_MAX
    }

    fn pwhash_opslimit_min() -> u64 {
        crypto_pwhash_OPSLIMIT_MIN as u64
    }

    fn pwhash_opslimit_max() -> u64 {
        crypto_pwhash_OPSLIMIT_MAX as u64
    }

    fn pwhash_opslimit_interactive() -> u64 {
        crypto_impl::pwhash_opslimit_interactive()
    }

    fn pwhash_opslimit_moderate() -> u64 {
        crypto_impl::pwhash_opslimit_moderate()
    }

    fn pwhash_opslimit_sensitive() -> u64 {
        crypto_impl::pwhash_opslimit_sensitive()
    }

    fn pwhash_memlimit_min() -> u64 {
        crypto_pwhash_MEMLIMIT_MIN as u64
    }

    fn pwhash_memlimit_interactive() -> u64 {
        crypto_impl::pwhash_memlimit_interactive()
    }

    fn pwhash_memlimit_moderate() -> u64 {
        crypto_impl::pwhash_memlimit_moderate()
    }

    fn pwhash_memlimit_sensitive() -> u64 {
        crypto_impl::pwhash_memlimit_sensitive()
    }

    fn pwhash_memlimit_max() -> u64 {
        unsafe { crypto_pwhash_memlimit_max() as u64 }
    }

    fn pwhash_alg_argon2i13() -> i32 {
        crypto_pwhash_ALG_ARGON2I13 as i32
    }

    fn pwhash_alg_argon2id13() -> i32 {
        crypto_pwhash_ALG_ARGON2ID13 as i32
    }

    fn pwhash_alg_default() -> i32 {
        crypto_pwhash_ALG_DEFAULT as i32
    }

    fn pwhash_strprefix() -> String {
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

    fn pwhash_derive(
        out_len: u32,
        password: Vec<u8>,
        salt: Vec<u8>,
        opslimit: u64,
        memlimit: u64,
        _alg: i32,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::pwhash(out_len, &password, &salt, opslimit, memlimit).map_err(to_wai_error)
    }

    fn pwhash_str(
        password: Vec<u8>,
        opslimit: u64,
        memlimit: u64,
    ) -> Result<String, libsodium::CryptoError> {
        crypto_impl::pwhash_str(&password, opslimit, memlimit).map_err(to_wai_error)
    }

    fn pwhash_str_verify(
        hash: String,
        password: Vec<u8>,
    ) -> Result<(), libsodium::CryptoError> {
        crypto_impl::pwhash_str_verify(&hash, &password).map_err(to_wai_error)
    }

    fn pwhash_str_needs_rehash(
        hash: String,
        opslimit: u64,
        memlimit: u64,
    ) -> Result<bool, libsodium::CryptoError> {
        crypto_impl::pwhash_str_needs_rehash(&hash, opslimit, memlimit).map_err(to_wai_error)
    }

    // ========================================================================
    // KDF
    // ========================================================================

    fn kdf_key_bytes() -> u32 {
        crypto_impl::kdf_key_bytes()
    }

    fn kdf_context_bytes() -> u32 {
        crypto_impl::kdf_context_bytes()
    }

    fn kdf_bytes_min() -> u32 {
        crypto_impl::kdf_bytes_min()
    }

    fn kdf_bytes_max() -> u32 {
        crypto_impl::kdf_bytes_max()
    }

    fn kdf_keygen() -> Vec<u8> {
        crypto_impl::kdf_keygen()
    }

    fn kdf_derive_from_key(
        subkey_len: u32,
        subkey_id: u64,
        context: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::kdf_derive_from_key(subkey_len, subkey_id, &context, &key)
            .map_err(to_wai_error)
    }

    fn kdf_primitive() -> String {
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

    // ========================================================================
    // KDF HKDF-SHA256
    // ========================================================================

    fn kdf_hkdf_sha256_key_bytes() -> u32 {
        crypto_impl::kdf_hkdf_sha256_key_bytes()
    }

    fn kdf_hkdf_sha256_extract(salt: Vec<u8>, ikm: Vec<u8>) -> Vec<u8> {
        crypto_impl::kdf_hkdf_sha256_extract(&salt, &ikm).unwrap()
    }

    fn kdf_hkdf_sha256_expand(
        out_len: u32,
        prk: Vec<u8>,
        info: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::kdf_hkdf_sha256_expand(&prk, &info, out_len).map_err(to_wai_error)
    }

    fn kdf_hkdf_sha256_bytes_min() -> u32 {
        crypto_impl::kdf_hkdf_sha256_bytes_min()
    }

    fn kdf_hkdf_sha256_bytes_max() -> u32 {
        crypto_impl::kdf_hkdf_sha256_bytes_max()
    }

    fn kdf_hkdf_sha256_keygen() -> Vec<u8> {
        crypto_impl::kdf_hkdf_sha256_keygen()
    }

    fn kdf_hkdf_sha256_extract_init(salt: Vec<u8>) -> Result<u64, libsodium::CryptoError> {
        crypto_impl::kdf_hkdf_sha256_extract_init(&salt).map_err(to_wai_error)
    }

    fn kdf_hkdf_sha256_extract_update(
        state_id: u64,
        ikm: Vec<u8>,
    ) -> Result<(), libsodium::CryptoError> {
        crypto_impl::kdf_hkdf_sha256_extract_update(state_id, &ikm).map_err(to_wai_error)
    }

    fn kdf_hkdf_sha256_extract_final(
        state_id: u64,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::kdf_hkdf_sha256_extract_final(state_id).map_err(to_wai_error)
    }

    // ========================================================================
    // Key Exchange
    // ========================================================================

    fn kx_public_key_bytes() -> u32 {
        crypto_impl::kx_public_key_bytes()
    }

    fn kx_secret_key_bytes() -> u32 {
        crypto_impl::kx_secret_key_bytes()
    }

    fn kx_seed_bytes() -> u32 {
        crypto_impl::kx_seed_bytes()
    }

    fn kx_session_key_bytes() -> u32 {
        crypto_impl::kx_session_key_bytes()
    }

    fn kx_keypair() -> libsodium::KxKeyPair {
        let (public_key, secret_key) = crypto_impl::kx_keypair();
        libsodium::KxKeyPair {
            public_key,
            secret_key,
        }
    }

    fn kx_seed_keypair(seed: Vec<u8>) -> Result<libsodium::KxKeyPair, libsodium::CryptoError> {
        crypto_impl::kx_seed_keypair(&seed)
            .map(|(public_key, secret_key)| libsodium::KxKeyPair {
                public_key,
                secret_key,
            })
            .map_err(to_wai_error)
    }

    fn kx_client_session_keys(
        client_pk: Vec<u8>,
        client_sk: Vec<u8>,
        server_pk: Vec<u8>,
    ) -> Result<libsodium::SessionKeys, libsodium::CryptoError> {
        crypto_impl::kx_client_session_keys(&client_pk, &client_sk, &server_pk)
            .map(|(rx, tx)| libsodium::SessionKeys { rx, tx })
            .map_err(to_wai_error)
    }

    fn kx_server_session_keys(
        server_pk: Vec<u8>,
        server_sk: Vec<u8>,
        client_pk: Vec<u8>,
    ) -> Result<libsodium::SessionKeys, libsodium::CryptoError> {
        crypto_impl::kx_server_session_keys(&server_pk, &server_sk, &client_pk)
            .map(|(rx, tx)| libsodium::SessionKeys { rx, tx })
            .map_err(to_wai_error)
    }

    fn kx_primitive() -> String {
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

    // ========================================================================
    // Scalar Multiplication
    // ========================================================================

    fn scalarmult_scalar_bytes() -> u32 {
        crypto_impl::scalarmult_scalar_bytes()
    }

    fn scalarmult_bytes() -> u32 {
        crypto_impl::scalarmult_bytes()
    }

    fn scalarmult_scalarmult(
        n: Vec<u8>,
        p: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::scalarmult(&n, &p).map_err(to_wai_error)
    }

    fn scalarmult_base(n: Vec<u8>) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::scalarmult_base(&n).map_err(to_wai_error)
    }

    // ========================================================================
    // Utils
    // ========================================================================

    fn utils_memzero(mut data: Vec<u8>) -> Vec<u8> {
        crypto_impl::memzero(&mut data);
        data
    }

    fn utils_memcmp(
        a: Vec<u8>,
        b: Vec<u8>,
    ) -> Result<bool, libsodium::CryptoError> {
        crypto_impl::memcmp(&a, &b).map_err(to_wai_error)
    }

    fn utils_increment(mut data: Vec<u8>) -> Vec<u8> {
        crypto_impl::increment(&mut data);
        data
    }

    fn utils_add(
        mut a: Vec<u8>,
        b: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::add(&mut a, &b).map_err(to_wai_error)?;
        Ok(a)
    }

    fn utils_sub(
        mut a: Vec<u8>,
        b: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::sub(&mut a, &b).map_err(to_wai_error)?;
        Ok(a)
    }

    fn utils_compare(a: Vec<u8>, b: Vec<u8>) -> i32 {
        crypto_impl::compare(&a, &b)
    }

    fn utils_is_zero(data: Vec<u8>) -> bool {
        crypto_impl::is_zero(&data)
    }

    fn utils_bin2hex(data: Vec<u8>) -> String {
        crypto_impl::bin2hex(&data)
    }

    fn utils_hex2bin(hex: String) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::hex2bin(&hex).map_err(to_wai_error)
    }

    fn utils_bin2base64(data: Vec<u8>) -> String {
        crypto_impl::bin2base64(&data)
    }

    fn utils_base642bin(base64: String) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::base642bin(&base64).map_err(to_wai_error)
    }

    fn utils_hex2bin_ignore(
        hex: String,
        ignore: String,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::hex2bin_ignore(&hex, &ignore).map_err(to_wai_error)
    }

    fn utils_base64_variant_original() -> u32 {
        sodium_base64_VARIANT_ORIGINAL
    }

    fn utils_base64_variant_original_no_padding() -> u32 {
        sodium_base64_VARIANT_ORIGINAL_NO_PADDING
    }

    fn utils_base64_variant_urlsafe() -> u32 {
        sodium_base64_VARIANT_URLSAFE
    }

    fn utils_base64_variant_urlsafe_no_padding() -> u32 {
        sodium_base64_VARIANT_URLSAFE_NO_PADDING
    }

    fn utils_bin2base64_variant(data: Vec<u8>, encoding: u32) -> String {
        crypto_impl::bin2base64_variant(&data, encoding)
    }

    fn utils_base642bin_variant(
        base64: String,
        encoding: u32,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::base642bin_variant(&base64, encoding).map_err(to_wai_error)
    }

    fn utils_base642bin_variant_ignore(
        base64: String,
        encoding: u32,
        ignore: String,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::base642bin_variant_ignore(&base64, encoding, &ignore).map_err(to_wai_error)
    }

    fn utils_pad(
        data: Vec<u8>,
        block_size: u32,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::pad(&data, block_size).map_err(to_wai_error)
    }

    fn utils_unpad(
        data: Vec<u8>,
        block_size: u32,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::unpad(&data, block_size).map_err(to_wai_error)
    }

    // ========================================================================
    // Short Hash
    // ========================================================================

    fn shorthash_bytes() -> u32 {
        crypto_impl::shorthash_bytes()
    }

    fn shorthash_key_bytes() -> u32 {
        crypto_impl::shorthash_key_bytes()
    }

    fn shorthash_keygen() -> Vec<u8> {
        crypto_impl::shorthash_keygen()
    }

    fn shorthash_hash(
        message: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::shorthash(&message, &key).map_err(to_wai_error)
    }

    fn shorthash_siphashx24_bytes() -> u32 {
        crypto_shorthash_siphashx24_BYTES
    }

    fn shorthash_siphashx24_key_bytes() -> u32 {
        crypto_shorthash_siphashx24_KEYBYTES
    }

    fn shorthash_hashx24(
        message: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::shorthash_siphashx24(&message, &key).map_err(to_wai_error)
    }

    // ========================================================================
    // One-Time Auth
    // ========================================================================

    fn onetimeauth_bytes() -> u32 {
        crypto_impl::onetimeauth_bytes()
    }

    fn onetimeauth_key_bytes() -> u32 {
        crypto_impl::onetimeauth_key_bytes()
    }

    fn onetimeauth_keygen() -> Vec<u8> {
        crypto_impl::onetimeauth_keygen()
    }

    fn onetimeauth_auth(
        message: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::onetimeauth(&message, &key).map_err(to_wai_error)
    }

    fn onetimeauth_verify(
        tag: Vec<u8>,
        message: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<(), libsodium::CryptoError> {
        crypto_impl::onetimeauth_verify(&tag, &message, &key).map_err(to_wai_error)
    }

    // ========================================================================
    // Cipher XSalsa20
    // ========================================================================

    fn cipher_xsalsa20_key_bytes() -> u32 {
        crypto_impl::stream_xsalsa20_key_bytes()
    }

    fn cipher_xsalsa20_nonce_bytes() -> u32 {
        crypto_impl::stream_xsalsa20_nonce_bytes()
    }

    fn cipher_xsalsa20_keygen() -> Vec<u8> {
        crypto_impl::stream_xsalsa20_keygen()
    }

    fn cipher_xsalsa20_keystream(
        len: u32,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::stream_xsalsa20(len, &nonce, &key).map_err(to_wai_error)
    }

    fn cipher_xsalsa20_xor(
        message: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::stream_xsalsa20_xor(&message, &nonce, &key).map_err(to_wai_error)
    }

    // ========================================================================
    // Cipher XChaCha20
    // ========================================================================

    fn cipher_xchacha20_key_bytes() -> u32 {
        crypto_impl::stream_xchacha20_key_bytes()
    }

    fn cipher_xchacha20_nonce_bytes() -> u32 {
        crypto_impl::stream_xchacha20_nonce_bytes()
    }

    fn cipher_xchacha20_keygen() -> Vec<u8> {
        crypto_impl::stream_xchacha20_keygen()
    }

    fn cipher_xchacha20_keystream(
        len: u32,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::stream_xchacha20(len, &nonce, &key).map_err(to_wai_error)
    }

    fn cipher_xchacha20_xor(
        message: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::stream_xchacha20_xor(&message, &nonce, &key).map_err(to_wai_error)
    }

    fn cipher_xchacha20_xor_ic(
        message: Vec<u8>,
        nonce: Vec<u8>,
        ic: u64,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::stream_xchacha20_xor_ic(&message, &nonce, ic, &key).map_err(to_wai_error)
    }

    // ========================================================================
    // Secret Stream (XChaCha20-Poly1305 streaming)
    // ========================================================================

    fn secret_stream_key_bytes() -> u32 {
        crypto_impl::secretstream_key_bytes()
    }

    fn secret_stream_header_bytes() -> u32 {
        crypto_impl::secretstream_header_bytes()
    }

    fn secret_stream_a_bytes() -> u32 {
        crypto_impl::secretstream_a_bytes()
    }

    fn secret_stream_tag_message() -> u8 {
        crypto_impl::secretstream_tag_message()
    }

    fn secret_stream_tag_push() -> u8 {
        crypto_impl::secretstream_tag_push()
    }

    fn secret_stream_tag_rekey() -> u8 {
        crypto_impl::secretstream_tag_rekey()
    }

    fn secret_stream_tag_final() -> u8 {
        crypto_impl::secretstream_tag_final()
    }

    fn secret_stream_messagebytes_max() -> u64 {
        crypto_impl::secretstream_messagebytes_max()
    }

    fn secret_stream_keygen() -> Vec<u8> {
        crypto_impl::secretstream_keygen()
    }

    fn secret_stream_init_push(
        key: Vec<u8>,
    ) -> Result<(u64, Vec<u8>), libsodium::CryptoError> {
        crypto_impl::secretstream_init_push(&key).map_err(to_wai_error)
    }

    fn secret_stream_push(
        state_id: u64,
        message: Vec<u8>,
        additional_data: Vec<u8>,
        tag: u8,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::secretstream_push(state_id, &message, &additional_data, tag)
            .map_err(to_wai_error)
    }

    fn secret_stream_init_pull(
        header: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<u64, libsodium::CryptoError> {
        crypto_impl::secretstream_init_pull(&header, &key).map_err(to_wai_error)
    }

    fn secret_stream_pull(
        state_id: u64,
        ciphertext: Vec<u8>,
        additional_data: Vec<u8>,
    ) -> Result<(Vec<u8>, u8), libsodium::CryptoError> {
        crypto_impl::secretstream_pull(state_id, &ciphertext, &additional_data)
            .map_err(to_wai_error)
    }

    fn secret_stream_rekey(state_id: u64) -> Result<(), libsodium::CryptoError> {
        crypto_impl::secretstream_rekey(state_id).map_err(to_wai_error)
    }

    fn secret_stream_destroy(state_id: u64) {
        crypto_impl::secretstream_destroy(state_id);
    }

    // ========================================================================
    // Generichash State (streaming BLAKE2b)
    // ========================================================================

    fn generichash_state_state_bytes() -> u32 {
        crypto_impl::generichash_state_bytes()
    }

    fn generichash_state_init(
        out_len: u32,
        key: Vec<u8>,
    ) -> Result<u64, libsodium::CryptoError> {
        crypto_impl::generichash_state_init(out_len, &key).map_err(to_wai_error)
    }

    fn generichash_state_update(
        state_id: u64,
        data: Vec<u8>,
    ) -> Result<(), libsodium::CryptoError> {
        crypto_impl::generichash_state_update(state_id, &data).map_err(to_wai_error)
    }

    fn generichash_state_final(state_id: u64) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::generichash_state_final(state_id).map_err(to_wai_error)
    }

    fn generichash_state_destroy(state_id: u64) {
        crypto_impl::generichash_state_destroy(state_id)
    }

    // ========================================================================
    // SHA-256 State (streaming)
    // ========================================================================

    fn sha256_state_state_bytes() -> u32 {
        crypto_impl::sha256_state_bytes()
    }

    fn sha256_state_init() -> Result<u64, libsodium::CryptoError> {
        crypto_impl::sha256_state_init().map_err(to_wai_error)
    }

    fn sha256_state_update(
        state_id: u64,
        data: Vec<u8>,
    ) -> Result<(), libsodium::CryptoError> {
        crypto_impl::sha256_state_update(state_id, &data).map_err(to_wai_error)
    }

    fn sha256_state_final(state_id: u64) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::sha256_state_final(state_id).map_err(to_wai_error)
    }

    fn sha256_state_destroy(state_id: u64) {
        crypto_impl::sha256_state_destroy(state_id)
    }

    // ========================================================================
    // SHA-512 State (streaming)
    // ========================================================================

    fn sha512_state_state_bytes() -> u32 {
        crypto_impl::sha512_state_bytes()
    }

    fn sha512_state_init() -> Result<u64, libsodium::CryptoError> {
        crypto_impl::sha512_state_init().map_err(to_wai_error)
    }

    fn sha512_state_update(
        state_id: u64,
        data: Vec<u8>,
    ) -> Result<(), libsodium::CryptoError> {
        crypto_impl::sha512_state_update(state_id, &data).map_err(to_wai_error)
    }

    fn sha512_state_final(state_id: u64) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::sha512_state_final(state_id).map_err(to_wai_error)
    }

    fn sha512_state_destroy(state_id: u64) {
        crypto_impl::sha512_state_destroy(state_id)
    }

    // ========================================================================
    // Auth State (streaming HMAC-SHA512-256)
    // ========================================================================

    fn auth_state_state_bytes() -> u32 {
        crypto_impl::auth_state_bytes()
    }

    fn auth_state_init(key: Vec<u8>) -> Result<u64, libsodium::CryptoError> {
        crypto_impl::auth_state_init(&key).map_err(to_wai_error)
    }

    fn auth_state_update(
        state_id: u64,
        data: Vec<u8>,
    ) -> Result<(), libsodium::CryptoError> {
        crypto_impl::auth_state_update(state_id, &data).map_err(to_wai_error)
    }

    fn auth_state_final(state_id: u64) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::auth_state_final(state_id).map_err(to_wai_error)
    }

    fn auth_state_destroy(state_id: u64) {
        crypto_impl::auth_state_destroy(state_id)
    }

    // ========================================================================
    // Onetimeauth State (streaming Poly1305)
    // ========================================================================

    fn onetimeauth_state_state_bytes() -> u32 {
        crypto_impl::onetimeauth_state_bytes()
    }

    fn onetimeauth_state_init(key: Vec<u8>) -> Result<u64, libsodium::CryptoError> {
        crypto_impl::onetimeauth_state_init(&key).map_err(to_wai_error)
    }

    fn onetimeauth_state_update(
        state_id: u64,
        data: Vec<u8>,
    ) -> Result<(), libsodium::CryptoError> {
        crypto_impl::onetimeauth_state_update(state_id, &data).map_err(to_wai_error)
    }

    fn onetimeauth_state_final(state_id: u64) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::onetimeauth_state_final(state_id).map_err(to_wai_error)
    }

    fn onetimeauth_state_destroy(state_id: u64) {
        crypto_impl::onetimeauth_state_destroy(state_id)
    }

    // ========================================================================
    // AEAD AES-256-GCM
    // ========================================================================

    fn aead_aes256gcm_is_available() -> bool {
        crypto_impl::aead_aes256gcm_is_available()
    }

    fn aead_aes256gcm_key_bytes() -> u32 {
        crypto_impl::aead_aes256gcm_key_bytes()
    }

    fn aead_aes256gcm_nonce_bytes() -> u32 {
        crypto_impl::aead_aes256gcm_nonce_bytes()
    }

    fn aead_aes256gcm_a_bytes() -> u32 {
        crypto_impl::aead_aes256gcm_a_bytes()
    }

    fn aead_aes256gcm_keygen() -> Vec<u8> {
        crypto_impl::aead_aes256gcm_keygen()
    }

    fn aead_aes256gcm_encrypt(
        message: Vec<u8>,
        additional_data: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::aead_aes256gcm_encrypt(&message, &additional_data, &nonce, &key)
            .map_err(to_wai_error)
    }

    fn aead_aes256gcm_decrypt(
        ciphertext: Vec<u8>,
        additional_data: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::aead_aes256gcm_decrypt(&ciphertext, &additional_data, &nonce, &key)
            .map_err(to_wai_error)
    }

    fn aead_aes256gcm_encrypt_detached(
        message: Vec<u8>,
        additional_data: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<(Vec<u8>, Vec<u8>), libsodium::CryptoError> {
        crypto_impl::aead_aes256gcm_encrypt_detached(&message, &additional_data, &nonce, &key)
            .map_err(to_wai_error)
    }

    fn aead_aes256gcm_decrypt_detached(
        ciphertext: Vec<u8>,
        mac: Vec<u8>,
        additional_data: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::aead_aes256gcm_decrypt_detached(
            &ciphertext,
            &mac,
            &additional_data,
            &nonce,
            &key,
        )
        .map_err(to_wai_error)
    }

    // ========================================================================
    // Verify (constant-time comparison)
    // ========================================================================

    fn verify_verify16(x: Vec<u8>, y: Vec<u8>) -> bool {
        crypto_impl::verify16(&x, &y)
    }

    fn verify_verify32(x: Vec<u8>, y: Vec<u8>) -> bool {
        crypto_impl::verify32(&x, &y)
    }

    fn verify_verify64(x: Vec<u8>, y: Vec<u8>) -> bool {
        crypto_impl::verify64(&x, &y)
    }

    // ========================================================================
    // Ristretto255 group operations
    // ========================================================================

    fn ristretto255_bytes() -> u32 {
        crypto_impl::ristretto255_bytes()
    }

    fn ristretto255_hash_bytes() -> u32 {
        crypto_impl::ristretto255_hash_bytes()
    }

    fn ristretto255_scalar_bytes() -> u32 {
        crypto_impl::ristretto255_scalar_bytes()
    }

    fn ristretto255_non_reduced_scalar_bytes() -> u32 {
        crypto_impl::ristretto255_non_reduced_scalar_bytes()
    }

    fn ristretto255_is_valid_point(p: Vec<u8>) -> bool {
        crypto_impl::ristretto255_is_valid_point(&p)
    }

    fn ristretto255_add(
        p: Vec<u8>,
        q: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::ristretto255_add(&p, &q).map_err(to_wai_error)
    }

    fn ristretto255_sub(
        p: Vec<u8>,
        q: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::ristretto255_sub(&p, &q).map_err(to_wai_error)
    }

    fn ristretto255_from_hash(h: Vec<u8>) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::ristretto255_from_hash(&h).map_err(to_wai_error)
    }

    fn ristretto255_random() -> Vec<u8> {
        crypto_impl::ristretto255_random()
    }

    fn ristretto255_scalar_random() -> Vec<u8> {
        crypto_impl::ristretto255_scalar_random()
    }

    fn ristretto255_scalar_invert(s: Vec<u8>) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::ristretto255_scalar_invert(&s).map_err(to_wai_error)
    }

    fn ristretto255_scalar_negate(s: Vec<u8>) -> Vec<u8> {
        crypto_impl::ristretto255_scalar_negate(&s)
    }

    fn ristretto255_scalar_complement(s: Vec<u8>) -> Vec<u8> {
        crypto_impl::ristretto255_scalar_complement(&s)
    }

    fn ristretto255_scalar_add(x: Vec<u8>, y: Vec<u8>) -> Vec<u8> {
        crypto_impl::ristretto255_scalar_add(&x, &y)
    }

    fn ristretto255_scalar_sub(x: Vec<u8>, y: Vec<u8>) -> Vec<u8> {
        crypto_impl::ristretto255_scalar_sub(&x, &y)
    }

    fn ristretto255_scalar_mul(x: Vec<u8>, y: Vec<u8>) -> Vec<u8> {
        crypto_impl::ristretto255_scalar_mul(&x, &y)
    }

    fn ristretto255_scalar_reduce(s: Vec<u8>) -> Vec<u8> {
        crypto_impl::ristretto255_scalar_reduce(&s)
    }

    // ========================================================================
    // Ed25519 group operations
    // ========================================================================

    fn ed25519_bytes() -> u32 {
        crypto_impl::ed25519_bytes()
    }

    fn ed25519_uniform_bytes() -> u32 {
        crypto_impl::ed25519_uniform_bytes()
    }

    fn ed25519_hash_bytes() -> u32 {
        crypto_impl::ed25519_hash_bytes()
    }

    fn ed25519_scalar_bytes() -> u32 {
        crypto_impl::ed25519_scalar_bytes()
    }

    fn ed25519_non_reduced_scalar_bytes() -> u32 {
        crypto_impl::ed25519_non_reduced_scalar_bytes()
    }

    fn ed25519_is_valid_point(p: Vec<u8>) -> bool {
        crypto_impl::ed25519_is_valid_point(&p)
    }

    fn ed25519_add(
        p: Vec<u8>,
        q: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::ed25519_add(&p, &q).map_err(to_wai_error)
    }

    fn ed25519_sub(
        p: Vec<u8>,
        q: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::ed25519_sub(&p, &q).map_err(to_wai_error)
    }

    fn ed25519_from_uniform(u: Vec<u8>) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::ed25519_from_uniform(&u).map_err(to_wai_error)
    }

    fn ed25519_from_hash(h: Vec<u8>) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::ed25519_from_hash(&h).map_err(to_wai_error)
    }

    fn ed25519_random() -> Vec<u8> {
        crypto_impl::ed25519_random()
    }

    fn ed25519_scalar_random() -> Vec<u8> {
        crypto_impl::ed25519_scalar_random()
    }

    fn ed25519_scalar_invert(s: Vec<u8>) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::ed25519_scalar_invert(&s).map_err(to_wai_error)
    }

    fn ed25519_scalar_negate(s: Vec<u8>) -> Vec<u8> {
        crypto_impl::ed25519_scalar_negate(&s)
    }

    fn ed25519_scalar_complement(s: Vec<u8>) -> Vec<u8> {
        crypto_impl::ed25519_scalar_complement(&s)
    }

    fn ed25519_scalar_add(x: Vec<u8>, y: Vec<u8>) -> Vec<u8> {
        crypto_impl::ed25519_scalar_add(&x, &y)
    }

    fn ed25519_scalar_sub(x: Vec<u8>, y: Vec<u8>) -> Vec<u8> {
        crypto_impl::ed25519_scalar_sub(&x, &y)
    }

    fn ed25519_scalar_mul(x: Vec<u8>, y: Vec<u8>) -> Vec<u8> {
        crypto_impl::ed25519_scalar_mul(&x, &y)
    }

    fn ed25519_scalar_reduce(s: Vec<u8>) -> Vec<u8> {
        crypto_impl::ed25519_scalar_reduce(&s)
    }

    // ========================================================================
    // Scalarmult Ed25519
    // ========================================================================

    fn scalarmult_ed25519_bytes() -> u32 {
        crypto_impl::scalarmult_ed25519_bytes()
    }

    fn scalarmult_ed25519_scalar_bytes() -> u32 {
        crypto_impl::scalarmult_ed25519_scalar_bytes()
    }

    fn scalarmult_ed25519_scalarmult(
        n: Vec<u8>,
        p: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::scalarmult_ed25519(&n, &p).map_err(to_wai_error)
    }

    fn scalarmult_ed25519_scalarmult_noclamp(
        n: Vec<u8>,
        p: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::scalarmult_ed25519_noclamp(&n, &p).map_err(to_wai_error)
    }

    fn scalarmult_ed25519_base(n: Vec<u8>) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::scalarmult_ed25519_base(&n).map_err(to_wai_error)
    }

    fn scalarmult_ed25519_base_noclamp(n: Vec<u8>) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::scalarmult_ed25519_base_noclamp(&n).map_err(to_wai_error)
    }

    // ========================================================================
    // Scalarmult Ristretto255
    // ========================================================================

    fn scalarmult_ristretto255_bytes() -> u32 {
        crypto_impl::scalarmult_ristretto255_bytes()
    }

    fn scalarmult_ristretto255_scalar_bytes() -> u32 {
        crypto_impl::scalarmult_ristretto255_scalar_bytes()
    }

    fn scalarmult_ristretto255_scalarmult(
        n: Vec<u8>,
        p: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::scalarmult_ristretto255(&n, &p).map_err(to_wai_error)
    }

    fn scalarmult_ristretto255_base(n: Vec<u8>) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::scalarmult_ristretto255_base(&n).map_err(to_wai_error)
    }

    // ========================================================================
    // KDF HKDF-SHA512
    // ========================================================================

    fn kdf_hkdf_sha512_key_bytes() -> u32 {
        crypto_impl::kdf_hkdf_sha512_key_bytes()
    }

    fn kdf_hkdf_sha512_extract(salt: Vec<u8>, ikm: Vec<u8>) -> Vec<u8> {
        crypto_impl::kdf_hkdf_sha512_extract(&salt, &ikm).unwrap()
    }

    fn kdf_hkdf_sha512_expand(
        out_len: u32,
        prk: Vec<u8>,
        info: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::kdf_hkdf_sha512_expand(&prk, &info, out_len).map_err(to_wai_error)
    }

    fn kdf_hkdf_sha512_bytes_min() -> u32 {
        crypto_impl::kdf_hkdf_sha512_bytes_min()
    }

    fn kdf_hkdf_sha512_bytes_max() -> u32 {
        crypto_impl::kdf_hkdf_sha512_bytes_max()
    }

    fn kdf_hkdf_sha512_keygen() -> Vec<u8> {
        crypto_impl::kdf_hkdf_sha512_keygen()
    }

    fn kdf_hkdf_sha512_extract_init(salt: Vec<u8>) -> Result<u64, libsodium::CryptoError> {
        crypto_impl::kdf_hkdf_sha512_extract_init(&salt).map_err(to_wai_error)
    }

    fn kdf_hkdf_sha512_extract_update(
        state_id: u64,
        ikm: Vec<u8>,
    ) -> Result<(), libsodium::CryptoError> {
        crypto_impl::kdf_hkdf_sha512_extract_update(state_id, &ikm).map_err(to_wai_error)
    }

    fn kdf_hkdf_sha512_extract_final(
        state_id: u64,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::kdf_hkdf_sha512_extract_final(state_id).map_err(to_wai_error)
    }

    // ========================================================================
    // Password Hashing (scrypt)
    // ========================================================================

    fn pwhash_scrypt_salt_bytes() -> u32 {
        crypto_impl::pwhash_scrypt_salt_bytes()
    }

    fn pwhash_scrypt_str_bytes() -> u32 {
        crypto_impl::pwhash_scrypt_str_bytes()
    }

    fn pwhash_scrypt_opslimit_min() -> u64 {
        crypto_impl::pwhash_scrypt_opslimit_min()
    }

    fn pwhash_scrypt_opslimit_max() -> u64 {
        crypto_impl::pwhash_scrypt_opslimit_max()
    }

    fn pwhash_scrypt_opslimit_interactive() -> u64 {
        crypto_impl::pwhash_scrypt_opslimit_interactive()
    }

    fn pwhash_scrypt_opslimit_sensitive() -> u64 {
        crypto_impl::pwhash_scrypt_opslimit_sensitive()
    }

    fn pwhash_scrypt_memlimit_min() -> u64 {
        crypto_impl::pwhash_scrypt_memlimit_min()
    }

    fn pwhash_scrypt_memlimit_interactive() -> u64 {
        crypto_impl::pwhash_scrypt_memlimit_interactive()
    }

    fn pwhash_scrypt_memlimit_sensitive() -> u64 {
        crypto_impl::pwhash_scrypt_memlimit_sensitive()
    }

    fn pwhash_scrypt_derive(
        out_len: u32,
        password: Vec<u8>,
        salt: Vec<u8>,
        opslimit: u64,
        memlimit: u64,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::pwhash_scrypt(out_len, &password, &salt, opslimit, memlimit)
            .map_err(to_wai_error)
    }

    fn pwhash_scrypt_str(
        password: Vec<u8>,
        opslimit: u64,
        memlimit: u64,
    ) -> Result<String, libsodium::CryptoError> {
        crypto_impl::pwhash_scrypt_str(&password, opslimit, memlimit).map_err(to_wai_error)
    }

    fn pwhash_scrypt_str_verify(
        hash: String,
        password: Vec<u8>,
    ) -> Result<(), libsodium::CryptoError> {
        crypto_impl::pwhash_scrypt_str_verify(&hash, &password).map_err(to_wai_error)
    }

    fn pwhash_scrypt_str_needs_rehash(
        hash: String,
        opslimit: u64,
        memlimit: u64,
    ) -> Result<bool, libsodium::CryptoError> {
        crypto_impl::pwhash_scrypt_str_needs_rehash(&hash, opslimit, memlimit).map_err(to_wai_error)
    }

    fn pwhash_scrypt_bytes_min() -> u32 {
        crypto_impl::pwhash_scrypt_bytes_min()
    }

    fn pwhash_scrypt_bytes_max() -> u32 {
        crypto_impl::pwhash_scrypt_bytes_max()
    }

    fn pwhash_scrypt_passwd_min() -> u32 {
        crypto_impl::pwhash_scrypt_passwd_min()
    }

    fn pwhash_scrypt_passwd_max() -> u32 {
        crypto_impl::pwhash_scrypt_passwd_max()
    }

    fn pwhash_scrypt_memlimit_max() -> u64 {
        crypto_impl::pwhash_scrypt_memlimit_max()
    }

    fn pwhash_scrypt_strprefix() -> String {
        crypto_impl::pwhash_scrypt_str_prefix().to_string()
    }

    fn pwhash_scrypt_derive_ll(
        out_len: u32,
        password: Vec<u8>,
        salt: Vec<u8>,
        n: u64,
        r: u32,
        p: u32,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::pwhash_scrypt_derive_ll(out_len, &password, &salt, n, r, p)
            .map_err(to_wai_error)
    }

    // ========================================================================
    // Cipher Salsa20
    // ========================================================================

    fn cipher_salsa20_key_bytes() -> u32 {
        crypto_impl::stream_salsa20_key_bytes()
    }

    fn cipher_salsa20_nonce_bytes() -> u32 {
        crypto_impl::stream_salsa20_nonce_bytes()
    }

    fn cipher_salsa20_keygen() -> Vec<u8> {
        crypto_impl::stream_salsa20_keygen()
    }

    fn cipher_salsa20_keystream(
        len: u32,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::stream_salsa20(len, &nonce, &key).map_err(to_wai_error)
    }

    fn cipher_salsa20_xor(
        message: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::stream_salsa20_xor(&message, &nonce, &key).map_err(to_wai_error)
    }

    fn cipher_salsa20_xor_ic(
        message: Vec<u8>,
        nonce: Vec<u8>,
        ic: u64,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::stream_salsa20_xor_ic(&message, &nonce, ic, &key).map_err(to_wai_error)
    }

    // ========================================================================
    // Cipher ChaCha20
    // ========================================================================

    fn cipher_chacha20_key_bytes() -> u32 {
        crypto_impl::stream_chacha20_key_bytes()
    }

    fn cipher_chacha20_nonce_bytes() -> u32 {
        crypto_impl::stream_chacha20_nonce_bytes()
    }

    fn cipher_chacha20_keygen() -> Vec<u8> {
        crypto_impl::stream_chacha20_keygen()
    }

    fn cipher_chacha20_keystream(
        len: u32,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::stream_chacha20(len, &nonce, &key).map_err(to_wai_error)
    }

    fn cipher_chacha20_xor(
        message: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::stream_chacha20_xor(&message, &nonce, &key).map_err(to_wai_error)
    }

    fn cipher_chacha20_xor_ic(
        message: Vec<u8>,
        nonce: Vec<u8>,
        ic: u64,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::stream_chacha20_xor_ic(&message, &nonce, ic, &key).map_err(to_wai_error)
    }

    // ========================================================================
    // Cipher ChaCha20 IETF
    // ========================================================================

    fn cipher_chacha20_ietf_key_bytes() -> u32 {
        crypto_impl::stream_chacha20_ietf_key_bytes()
    }

    fn cipher_chacha20_ietf_nonce_bytes() -> u32 {
        crypto_impl::stream_chacha20_ietf_nonce_bytes()
    }

    fn cipher_chacha20_ietf_keygen() -> Vec<u8> {
        crypto_impl::stream_chacha20_ietf_keygen()
    }

    fn cipher_chacha20_ietf_keystream(
        len: u32,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::stream_chacha20_ietf(len, &nonce, &key).map_err(to_wai_error)
    }

    fn cipher_chacha20_ietf_xor(
        message: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::stream_chacha20_ietf_xor(&message, &nonce, &key).map_err(to_wai_error)
    }

    fn cipher_chacha20_ietf_xor_ic(
        message: Vec<u8>,
        nonce: Vec<u8>,
        ic: u32,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::stream_chacha20_ietf_xor_ic(&message, &nonce, ic, &key).map_err(to_wai_error)
    }

    // ========================================================================
    // XOF SHAKE128
    // ========================================================================

    fn xof_shake128_block_bytes() -> u32 {
        crypto_xof_shake128_BLOCKBYTES
    }

    fn xof_shake128_state_bytes() -> u32 {
        crypto_impl::xof_shake128_state_bytes()
    }

    fn xof_shake128_hash(out_len: u32, message: Vec<u8>) -> Vec<u8> {
        crypto_impl::xof_shake128(&message, out_len)
    }

    fn xof_shake128_init() -> Result<u64, libsodium::CryptoError> {
        crypto_impl::xof_shake128_init().map_err(to_wai_error)
    }

    fn xof_shake128_update(
        state_id: u64,
        data: Vec<u8>,
    ) -> Result<(), libsodium::CryptoError> {
        crypto_impl::xof_shake128_update(state_id, &data).map_err(to_wai_error)
    }

    fn xof_shake128_squeeze(
        state_id: u64,
        out_len: u32,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::xof_shake128_squeeze(state_id, out_len).map_err(to_wai_error)
    }

    fn xof_shake128_destroy(state_id: u64) {
        crypto_impl::xof_shake128_destroy(state_id)
    }

    fn xof_shake128_init_with_domain(
        domain_sep: u8,
    ) -> Result<u64, libsodium::CryptoError> {
        crypto_impl::xof_shake128_init_with_domain(domain_sep).map_err(to_wai_error)
    }

    // ========================================================================
    // XOF SHAKE256
    // ========================================================================

    fn xof_shake256_block_bytes() -> u32 {
        crypto_xof_shake256_BLOCKBYTES
    }

    fn xof_shake256_state_bytes() -> u32 {
        crypto_impl::xof_shake256_state_bytes()
    }

    fn xof_shake256_hash(out_len: u32, message: Vec<u8>) -> Vec<u8> {
        crypto_impl::xof_shake256(&message, out_len)
    }

    fn xof_shake256_init() -> Result<u64, libsodium::CryptoError> {
        crypto_impl::xof_shake256_init().map_err(to_wai_error)
    }

    fn xof_shake256_update(
        state_id: u64,
        data: Vec<u8>,
    ) -> Result<(), libsodium::CryptoError> {
        crypto_impl::xof_shake256_update(state_id, &data).map_err(to_wai_error)
    }

    fn xof_shake256_squeeze(
        state_id: u64,
        out_len: u32,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::xof_shake256_squeeze(state_id, out_len).map_err(to_wai_error)
    }

    fn xof_shake256_destroy(state_id: u64) {
        crypto_impl::xof_shake256_destroy(state_id)
    }

    fn xof_shake256_init_with_domain(
        domain_sep: u8,
    ) -> Result<u64, libsodium::CryptoError> {
        crypto_impl::xof_shake256_init_with_domain(domain_sep).map_err(to_wai_error)
    }

    // ========================================================================
    // XOF TurboSHAKE128
    // ========================================================================

    fn xof_turboshake128_block_bytes() -> u32 {
        crypto_xof_turboshake128_BLOCKBYTES
    }

    fn xof_turboshake128_state_bytes() -> u32 {
        crypto_impl::xof_turboshake128_state_bytes()
    }

    fn xof_turboshake128_hash(out_len: u32, message: Vec<u8>) -> Vec<u8> {
        crypto_impl::xof_turboshake128(&message, out_len)
    }

    fn xof_turboshake128_init() -> Result<u64, libsodium::CryptoError> {
        crypto_impl::xof_turboshake128_init().map_err(to_wai_error)
    }

    fn xof_turboshake128_update(
        state_id: u64,
        data: Vec<u8>,
    ) -> Result<(), libsodium::CryptoError> {
        crypto_impl::xof_turboshake128_update(state_id, &data).map_err(to_wai_error)
    }

    fn xof_turboshake128_squeeze(
        state_id: u64,
        out_len: u32,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::xof_turboshake128_squeeze(state_id, out_len).map_err(to_wai_error)
    }

    fn xof_turboshake128_destroy(state_id: u64) {
        crypto_impl::xof_turboshake128_destroy(state_id)
    }

    fn xof_turboshake128_init_with_domain(
        domain_sep: u8,
    ) -> Result<u64, libsodium::CryptoError> {
        crypto_impl::xof_turboshake128_init_with_domain(domain_sep).map_err(to_wai_error)
    }

    // ========================================================================
    // XOF TurboSHAKE256
    // ========================================================================

    fn xof_turboshake256_block_bytes() -> u32 {
        crypto_xof_turboshake256_BLOCKBYTES
    }

    fn xof_turboshake256_state_bytes() -> u32 {
        crypto_impl::xof_turboshake256_state_bytes()
    }

    fn xof_turboshake256_hash(out_len: u32, message: Vec<u8>) -> Vec<u8> {
        crypto_impl::xof_turboshake256(&message, out_len)
    }

    fn xof_turboshake256_init() -> Result<u64, libsodium::CryptoError> {
        crypto_impl::xof_turboshake256_init().map_err(to_wai_error)
    }

    fn xof_turboshake256_update(
        state_id: u64,
        data: Vec<u8>,
    ) -> Result<(), libsodium::CryptoError> {
        crypto_impl::xof_turboshake256_update(state_id, &data).map_err(to_wai_error)
    }

    fn xof_turboshake256_squeeze(
        state_id: u64,
        out_len: u32,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::xof_turboshake256_squeeze(state_id, out_len).map_err(to_wai_error)
    }

    fn xof_turboshake256_init_with_domain(
        domain_sep: u8,
    ) -> Result<u64, libsodium::CryptoError> {
        crypto_impl::xof_turboshake256_init_with_domain(domain_sep).map_err(to_wai_error)
    }

    fn xof_turboshake256_destroy(state_id: u64) {
        crypto_impl::xof_turboshake256_destroy(state_id)
    }

    // ========================================================================
    // Secretbox XChaCha20-Poly1305
    // ========================================================================

    fn secretbox_xchacha20poly1305_key_bytes() -> u32 {
        crypto_impl::secretbox_xchacha20poly1305_key_bytes()
    }

    fn secretbox_xchacha20poly1305_nonce_bytes() -> u32 {
        crypto_impl::secretbox_xchacha20poly1305_nonce_bytes()
    }

    fn secretbox_xchacha20poly1305_mac_bytes() -> u32 {
        crypto_impl::secretbox_xchacha20poly1305_mac_bytes()
    }

    fn secretbox_xchacha20poly1305_easy(
        message: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::secretbox_xchacha20poly1305_easy(&message, &nonce, &key).map_err(to_wai_error)
    }

    fn secretbox_xchacha20poly1305_open_easy(
        ciphertext: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::secretbox_xchacha20poly1305_open_easy(&ciphertext, &nonce, &key)
            .map_err(to_wai_error)
    }

    fn secretbox_xchacha20poly1305_detached(
        message: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<(Vec<u8>, Vec<u8>), libsodium::CryptoError> {
        crypto_impl::secretbox_xchacha20poly1305_detached(&message, &nonce, &key)
            .map_err(to_wai_error)
    }

    fn secretbox_xchacha20poly1305_open_detached(
        ciphertext: Vec<u8>,
        mac: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::secretbox_xchacha20poly1305_open_detached(&ciphertext, &mac, &nonce, &key)
            .map_err(to_wai_error)
    }

    fn secretbox_xchacha20poly1305_keygen() -> Vec<u8> {
        crypto_impl::secretbox_xchacha20poly1305_keygen()
    }

    // ========================================================================
    // Crypto Box XChaCha20-Poly1305
    // ========================================================================

    fn crypto_box_xchacha20poly1305_public_key_bytes() -> u32 {
        crypto_impl::box_xchacha20poly1305_public_key_bytes()
    }

    fn crypto_box_xchacha20poly1305_secret_key_bytes() -> u32 {
        crypto_impl::box_xchacha20poly1305_secret_key_bytes()
    }

    fn crypto_box_xchacha20poly1305_nonce_bytes() -> u32 {
        crypto_impl::box_xchacha20poly1305_nonce_bytes()
    }

    fn crypto_box_xchacha20poly1305_mac_bytes() -> u32 {
        crypto_impl::box_xchacha20poly1305_mac_bytes()
    }

    fn crypto_box_xchacha20poly1305_seed_bytes() -> u32 {
        crypto_impl::box_xchacha20poly1305_seed_bytes()
    }

    fn crypto_box_xchacha20poly1305_seal_bytes() -> u32 {
        crypto_impl::box_xchacha20poly1305_seal_bytes()
    }

    fn crypto_box_xchacha20poly1305_keypair() -> libsodium::KeyPair {
        let (pk, sk) = crypto_impl::box_xchacha20poly1305_keypair();
        libsodium::KeyPair {
            public_key: pk,
            secret_key: sk,
        }
    }

    fn crypto_box_xchacha20poly1305_seed_keypair(
        seed: Vec<u8>,
    ) -> Result<libsodium::KeyPair, libsodium::CryptoError> {
        let (pk, sk) =
            crypto_impl::box_xchacha20poly1305_seed_keypair(&seed).map_err(to_wai_error)?;
        Ok(libsodium::KeyPair {
            public_key: pk,
            secret_key: sk,
        })
    }

    fn crypto_box_xchacha20poly1305_easy(
        message: Vec<u8>,
        nonce: Vec<u8>,
        recipient_pk: Vec<u8>,
        sender_sk: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::box_xchacha20poly1305_easy(&message, &nonce, &recipient_pk, &sender_sk)
            .map_err(to_wai_error)
    }

    fn crypto_box_xchacha20poly1305_open_easy(
        ciphertext: Vec<u8>,
        nonce: Vec<u8>,
        sender_pk: Vec<u8>,
        recipient_sk: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::box_xchacha20poly1305_open_easy(&ciphertext, &nonce, &sender_pk, &recipient_sk)
            .map_err(to_wai_error)
    }

    fn crypto_box_xchacha20poly1305_detached(
        message: Vec<u8>,
        nonce: Vec<u8>,
        recipient_pk: Vec<u8>,
        sender_sk: Vec<u8>,
    ) -> Result<(Vec<u8>, Vec<u8>), libsodium::CryptoError> {
        crypto_impl::box_xchacha20poly1305_detached(&message, &nonce, &recipient_pk, &sender_sk)
            .map_err(to_wai_error)
    }

    fn crypto_box_xchacha20poly1305_open_detached(
        ciphertext: Vec<u8>,
        mac: Vec<u8>,
        nonce: Vec<u8>,
        sender_pk: Vec<u8>,
        recipient_sk: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::box_xchacha20poly1305_open_detached(
            &ciphertext,
            &mac,
            &nonce,
            &sender_pk,
            &recipient_sk,
        )
        .map_err(to_wai_error)
    }

    fn crypto_box_xchacha20poly1305_beforenm(
        recipient_pk: Vec<u8>,
        sender_sk: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::box_xchacha20poly1305_beforenm(&recipient_pk, &sender_sk).map_err(to_wai_error)
    }

    fn crypto_box_xchacha20poly1305_easy_afternm(
        message: Vec<u8>,
        nonce: Vec<u8>,
        shared_key: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::box_xchacha20poly1305_easy_afternm(&message, &nonce, &shared_key)
            .map_err(to_wai_error)
    }

    fn crypto_box_xchacha20poly1305_open_easy_afternm(
        ciphertext: Vec<u8>,
        nonce: Vec<u8>,
        shared_key: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::box_xchacha20poly1305_open_easy_afternm(&ciphertext, &nonce, &shared_key)
            .map_err(to_wai_error)
    }

    fn crypto_box_xchacha20poly1305_seal(
        message: Vec<u8>,
        recipient_pk: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::box_xchacha20poly1305_seal(&message, &recipient_pk).map_err(to_wai_error)
    }

    fn crypto_box_xchacha20poly1305_seal_open(
        ciphertext: Vec<u8>,
        recipient_pk: Vec<u8>,
        recipient_sk: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::box_xchacha20poly1305_seal_open(&ciphertext, &recipient_pk, &recipient_sk)
            .map_err(to_wai_error)
    }

    fn crypto_box_xchacha20poly1305_beforenm_bytes() -> u32 {
        crypto_impl::box_xchacha20poly1305_beforenm_bytes()
    }

    fn crypto_box_xchacha20poly1305_detached_afternm(
        message: Vec<u8>,
        nonce: Vec<u8>,
        shared_key: Vec<u8>,
    ) -> Result<(Vec<u8>, Vec<u8>), libsodium::CryptoError> {
        crypto_impl::box_xchacha20poly1305_detached_afternm(&message, &nonce, &shared_key)
            .map_err(to_wai_error)
    }

    fn crypto_box_xchacha20poly1305_open_detached_afternm(
        ciphertext: Vec<u8>,
        mac: Vec<u8>,
        nonce: Vec<u8>,
        shared_key: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::box_xchacha20poly1305_open_detached_afternm(
            &ciphertext,
            &mac,
            &nonce,
            &shared_key,
        )
        .map_err(to_wai_error)
    }

    // ========================================================================
    // IPCrypt
    // ========================================================================

    fn ipcrypt_bytes() -> u32 {
        crypto_impl::ipcrypt_bytes()
    }

    fn ipcrypt_key_bytes() -> u32 {
        crypto_impl::ipcrypt_key_bytes()
    }

    fn ipcrypt_keygen() -> Vec<u8> {
        crypto_impl::ipcrypt_keygen()
    }

    fn ipcrypt_encrypt(
        input: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::ipcrypt_encrypt(&input, &key).map_err(to_wai_error)
    }

    fn ipcrypt_decrypt(
        input: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::ipcrypt_decrypt(&input, &key).map_err(to_wai_error)
    }

    fn ipcrypt_ip2bin(ip: String) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::ip2bin(&ip).map_err(to_wai_error)
    }

    fn ipcrypt_bin2ip(bin: Vec<u8>) -> Result<String, libsodium::CryptoError> {
        crypto_impl::bin2ip(&bin).map_err(to_wai_error)
    }

    fn ipcrypt_nd_key_bytes() -> u32 {
        crypto_ipcrypt_ND_KEYBYTES
    }

    fn ipcrypt_nd_tweak_bytes() -> u32 {
        crypto_ipcrypt_ND_TWEAKBYTES
    }

    fn ipcrypt_nd_input_bytes() -> u32 {
        crypto_ipcrypt_ND_INPUTBYTES
    }

    fn ipcrypt_nd_output_bytes() -> u32 {
        crypto_ipcrypt_ND_OUTPUTBYTES
    }

    fn ipcrypt_nd_encrypt(
        input: Vec<u8>,
        tweak: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::ipcrypt_nd_encrypt(&input, &tweak, &key).map_err(to_wai_error)
    }

    fn ipcrypt_nd_decrypt(
        ciphertext: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::ipcrypt_nd_decrypt(&ciphertext, &key).map_err(to_wai_error)
    }

    fn ipcrypt_ndx_key_bytes() -> u32 {
        crypto_impl::ipcrypt_ndx_key_bytes()
    }

    fn ipcrypt_ndx_tweak_bytes() -> u32 {
        crypto_impl::ipcrypt_ndx_tweak_bytes()
    }

    fn ipcrypt_ndx_input_bytes() -> u32 {
        crypto_impl::ipcrypt_ndx_input_bytes()
    }

    fn ipcrypt_ndx_output_bytes() -> u32 {
        crypto_impl::ipcrypt_ndx_output_bytes()
    }

    fn ipcrypt_ndx_keygen() -> Vec<u8> {
        crypto_impl::ipcrypt_ndx_keygen()
    }

    fn ipcrypt_ndx_encrypt(
        input: Vec<u8>,
        tweak: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::ipcrypt_ndx_encrypt(&input, &tweak, &key).map_err(to_wai_error)
    }

    fn ipcrypt_ndx_decrypt(
        ciphertext: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::ipcrypt_ndx_decrypt(&ciphertext, &key).map_err(to_wai_error)
    }

    fn ipcrypt_pfx_key_bytes() -> u32 {
        crypto_impl::ipcrypt_pfx_key_bytes()
    }

    fn ipcrypt_pfx_bytes() -> u32 {
        crypto_impl::ipcrypt_pfx_bytes()
    }

    fn ipcrypt_pfx_keygen() -> Vec<u8> {
        crypto_impl::ipcrypt_pfx_keygen()
    }

    fn ipcrypt_pfx_encrypt(
        input: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::ipcrypt_pfx_encrypt(&input, &key).map_err(to_wai_error)
    }

    fn ipcrypt_pfx_decrypt(
        input: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::ipcrypt_pfx_decrypt(&input, &key).map_err(to_wai_error)
    }

    // ========================================================================
    // Auth HMAC-SHA256
    // ========================================================================

    fn auth_hmacsha256_bytes() -> u32 {
        crypto_impl::auth_hmacsha256_bytes()
    }

    fn auth_hmacsha256_key_bytes() -> u32 {
        crypto_impl::auth_hmacsha256_key_bytes()
    }

    fn auth_hmacsha256_keygen() -> Vec<u8> {
        crypto_impl::auth_hmacsha256_keygen()
    }

    fn auth_hmacsha256_auth(
        message: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::auth_hmacsha256(&message, &key).map_err(to_wai_error)
    }

    fn auth_hmacsha256_verify(
        tag: Vec<u8>,
        message: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<(), libsodium::CryptoError> {
        crypto_impl::auth_hmacsha256_verify(&tag, &message, &key).map_err(to_wai_error)
    }

    fn auth_hmacsha256_state_bytes() -> u32 {
        crypto_impl::auth_hmacsha256_state_bytes()
    }

    fn auth_hmacsha256_init(key: Vec<u8>) -> Result<u64, libsodium::CryptoError> {
        crypto_impl::auth_hmacsha256_state_init(&key).map_err(to_wai_error)
    }

    fn auth_hmacsha256_update(
        state_id: u64,
        data: Vec<u8>,
    ) -> Result<(), libsodium::CryptoError> {
        crypto_impl::auth_hmacsha256_state_update(state_id, &data).map_err(to_wai_error)
    }

    fn auth_hmacsha256_final(state_id: u64) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::auth_hmacsha256_state_final(state_id).map_err(to_wai_error)
    }

    fn auth_hmacsha256_destroy(state_id: u64) {
        crypto_impl::auth_hmacsha256_state_destroy(state_id);
    }

    // ========================================================================
    // Auth HMAC-SHA512
    // ========================================================================

    fn auth_hmacsha512_bytes() -> u32 {
        crypto_impl::auth_hmacsha512_bytes()
    }

    fn auth_hmacsha512_key_bytes() -> u32 {
        crypto_impl::auth_hmacsha512_key_bytes()
    }

    fn auth_hmacsha512_keygen() -> Vec<u8> {
        crypto_impl::auth_hmacsha512_keygen()
    }

    fn auth_hmacsha512_auth(
        message: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::auth_hmacsha512(&message, &key).map_err(to_wai_error)
    }

    fn auth_hmacsha512_verify(
        tag: Vec<u8>,
        message: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<(), libsodium::CryptoError> {
        crypto_impl::auth_hmacsha512_verify(&tag, &message, &key).map_err(to_wai_error)
    }

    fn auth_hmacsha512_state_bytes() -> u32 {
        crypto_impl::auth_hmacsha512_state_bytes()
    }

    fn auth_hmacsha512_init(key: Vec<u8>) -> Result<u64, libsodium::CryptoError> {
        crypto_impl::auth_hmacsha512_state_init(&key).map_err(to_wai_error)
    }

    fn auth_hmacsha512_update(
        state_id: u64,
        data: Vec<u8>,
    ) -> Result<(), libsodium::CryptoError> {
        crypto_impl::auth_hmacsha512_state_update(state_id, &data).map_err(to_wai_error)
    }

    fn auth_hmacsha512_final(state_id: u64) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::auth_hmacsha512_state_final(state_id).map_err(to_wai_error)
    }

    fn auth_hmacsha512_destroy(state_id: u64) {
        crypto_impl::auth_hmacsha512_state_destroy(state_id);
    }

    // ========================================================================
    // HMAC-SHA512-256 Auth
    // ========================================================================

    fn auth_hmacsha512256_bytes() -> u32 {
        crypto_impl::auth_hmacsha512256_bytes()
    }

    fn auth_hmacsha512256_key_bytes() -> u32 {
        crypto_impl::auth_hmacsha512256_key_bytes()
    }

    fn auth_hmacsha512256_keygen() -> Vec<u8> {
        crypto_impl::auth_hmacsha512256_keygen()
    }

    fn auth_hmacsha512256_auth(
        message: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::auth_hmacsha512256(&message, &key).map_err(to_wai_error)
    }

    fn auth_hmacsha512256_verify(
        tag: Vec<u8>,
        message: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<(), libsodium::CryptoError> {
        crypto_impl::auth_hmacsha512256_verify(&tag, &message, &key).map_err(to_wai_error)
    }

    fn auth_hmacsha512256_state_bytes() -> u32 {
        crypto_impl::auth_hmacsha512256_state_bytes()
    }

    fn auth_hmacsha512256_init(key: Vec<u8>) -> Result<u64, libsodium::CryptoError> {
        crypto_impl::auth_hmacsha512256_state_init(&key).map_err(to_wai_error)
    }

    fn auth_hmacsha512256_update(
        state_id: u64,
        data: Vec<u8>,
    ) -> Result<(), libsodium::CryptoError> {
        crypto_impl::auth_hmacsha512256_state_update(state_id, &data).map_err(to_wai_error)
    }

    fn auth_hmacsha512256_final(state_id: u64) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::auth_hmacsha512256_state_final(state_id).map_err(to_wai_error)
    }

    fn auth_hmacsha512256_destroy(state_id: u64) {
        crypto_impl::auth_hmacsha512256_state_destroy(state_id);
    }

    // ========================================================================
    // Random Extended
    // ========================================================================

    fn random_extended_seed_bytes() -> u32 {
        crypto_impl::random_seedbytes()
    }

    fn random_extended_buf_deterministic(
        len: u32,
        seed: Vec<u8>,
    ) -> Result<Vec<u8>, libsodium::CryptoError> {
        crypto_impl::random_buf_deterministic(len, &seed).map_err(to_wai_error)
    }
}