//! WASI Component Model implementation for libsodium
//!
//! This module provides safe wrappers around libsodium's FFI that are exported
//! as a WASI component using the Component Model.

#![allow(unused_unsafe)]

use crate::crypto_impl;
use crate::sodium_bindings::*;

wit_bindgen::generate!({
    world: "libsodium",
    path: "wit",
    pub_export_macro: true,
    export_macro_name: "export_libsodium",
});

// Error conversion helper
fn to_wit_error(e: crypto_impl::CryptoError) -> exports::libsodium::crypto::types::CryptoError {
    match e {
        crypto_impl::CryptoError::OperationFailed => {
            exports::libsodium::crypto::types::CryptoError::OperationFailed
        }
        crypto_impl::CryptoError::InvalidKeySize => {
            exports::libsodium::crypto::types::CryptoError::InvalidKeySize
        }
        crypto_impl::CryptoError::InvalidNonceSize => {
            exports::libsodium::crypto::types::CryptoError::InvalidNonceSize
        }
        crypto_impl::CryptoError::MessageTooLong => {
            exports::libsodium::crypto::types::CryptoError::MessageTooLong
        }
        crypto_impl::CryptoError::VerificationFailed => {
            exports::libsodium::crypto::types::CryptoError::VerificationFailed
        }
        crypto_impl::CryptoError::NotInitialized => {
            exports::libsodium::crypto::types::CryptoError::NotInitialized
        }
    }
}

// ============================================================================
// Core
// ============================================================================

impl exports::libsodium::crypto::core::Guest for Component {
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
}

// ============================================================================
// Random
// ============================================================================

impl exports::libsodium::crypto::random::Guest for Component {
    fn random_bytes(len: u32) -> Vec<u8> {
        crypto_impl::random_bytes(len)
    }

    fn random_u32() -> u32 {
        crypto_impl::random_u32()
    }

    fn random_uniform(upper_bound: u32) -> u32 {
        crypto_impl::random_uniform(upper_bound)
    }
}

// ============================================================================
// Secretbox
// ============================================================================

impl exports::libsodium::crypto::secretbox::Guest for Component {
    fn key_bytes() -> u32 {
        crypto_impl::secretbox_key_bytes()
    }

    fn nonce_bytes() -> u32 {
        crypto_impl::secretbox_nonce_bytes()
    }

    fn mac_bytes() -> u32 {
        crypto_impl::secretbox_mac_bytes()
    }

    fn keygen() -> Vec<u8> {
        crypto_impl::secretbox_keygen()
    }

    fn easy(
        message: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::secretbox_easy(&message, &nonce, &key).map_err(to_wit_error)
    }

    fn open_easy(
        ciphertext: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::secretbox_open_easy(&ciphertext, &nonce, &key).map_err(to_wit_error)
    }

    fn detached(
        message: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<(Vec<u8>, Vec<u8>), exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::secretbox_detached(&message, &nonce, &key).map_err(to_wit_error)
    }

    fn open_detached(
        ciphertext: Vec<u8>,
        mac: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::secretbox_open_detached(&ciphertext, &mac, &nonce, &key).map_err(to_wit_error)
    }
}

// ============================================================================
// Crypto Box
// ============================================================================

impl exports::libsodium::crypto::crypto_box::Guest for Component {
    fn public_key_bytes() -> u32 {
        crypto_impl::box_public_key_bytes()
    }

    fn secret_key_bytes() -> u32 {
        crypto_impl::box_secret_key_bytes()
    }

    fn nonce_bytes() -> u32 {
        crypto_impl::box_nonce_bytes()
    }

    fn mac_bytes() -> u32 {
        crypto_impl::box_mac_bytes()
    }

    fn seed_bytes() -> u32 {
        crypto_impl::box_seed_bytes()
    }

    fn keypair() -> exports::libsodium::crypto::types::KeyPair {
        let (public_key, secret_key) = crypto_impl::box_keypair();
        exports::libsodium::crypto::types::KeyPair {
            public_key,
            secret_key,
        }
    }

    fn seed_keypair(
        seed: Vec<u8>,
    ) -> Result<
        exports::libsodium::crypto::types::KeyPair,
        exports::libsodium::crypto::types::CryptoError,
    > {
        crypto_impl::box_seed_keypair(&seed)
            .map(
                |(public_key, secret_key)| exports::libsodium::crypto::types::KeyPair {
                    public_key,
                    secret_key,
                },
            )
            .map_err(to_wit_error)
    }

    fn easy(
        message: Vec<u8>,
        nonce: Vec<u8>,
        recipient_pk: Vec<u8>,
        sender_sk: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::box_easy(&message, &nonce, &recipient_pk, &sender_sk).map_err(to_wit_error)
    }

    fn open_easy(
        ciphertext: Vec<u8>,
        nonce: Vec<u8>,
        sender_pk: Vec<u8>,
        recipient_sk: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::box_open_easy(&ciphertext, &nonce, &sender_pk, &recipient_sk)
            .map_err(to_wit_error)
    }

    fn detached(
        message: Vec<u8>,
        nonce: Vec<u8>,
        recipient_pk: Vec<u8>,
        sender_sk: Vec<u8>,
    ) -> Result<(Vec<u8>, Vec<u8>), exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::box_detached(&message, &nonce, &recipient_pk, &sender_sk).map_err(to_wit_error)
    }

    fn open_detached(
        ciphertext: Vec<u8>,
        mac: Vec<u8>,
        nonce: Vec<u8>,
        sender_pk: Vec<u8>,
        recipient_sk: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::box_open_detached(&ciphertext, &mac, &nonce, &sender_pk, &recipient_sk)
            .map_err(to_wit_error)
    }

    fn beforenm(
        recipient_pk: Vec<u8>,
        sender_sk: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::box_beforenm(&recipient_pk, &sender_sk).map_err(to_wit_error)
    }

    fn easy_afternm(
        message: Vec<u8>,
        nonce: Vec<u8>,
        shared_key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::box_easy_afternm(&message, &nonce, &shared_key).map_err(to_wit_error)
    }

    fn open_easy_afternm(
        ciphertext: Vec<u8>,
        nonce: Vec<u8>,
        shared_key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::box_open_easy_afternm(&ciphertext, &nonce, &shared_key).map_err(to_wit_error)
    }

    fn beforenm_bytes() -> u32 {
        crypto_impl::box_beforenm_bytes()
    }

    fn detached_afternm(
        message: Vec<u8>,
        nonce: Vec<u8>,
        shared_key: Vec<u8>,
    ) -> Result<(Vec<u8>, Vec<u8>), exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::box_detached_afternm(&message, &nonce, &shared_key).map_err(to_wit_error)
    }

    fn open_detached_afternm(
        ciphertext: Vec<u8>,
        mac: Vec<u8>,
        nonce: Vec<u8>,
        shared_key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::box_open_detached_afternm(&ciphertext, &mac, &nonce, &shared_key)
            .map_err(to_wit_error)
    }
}

// ============================================================================
// Seal
// ============================================================================

impl exports::libsodium::crypto::seal::Guest for Component {
    fn seal_bytes() -> u32 {
        crypto_impl::seal_bytes()
    }

    fn seal(
        message: Vec<u8>,
        recipient_pk: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::seal(&message, &recipient_pk).map_err(to_wit_error)
    }

    fn seal_open(
        ciphertext: Vec<u8>,
        recipient_pk: Vec<u8>,
        recipient_sk: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::seal_open(&ciphertext, &recipient_pk, &recipient_sk).map_err(to_wit_error)
    }
}

// ============================================================================
// Sign
// ============================================================================

impl exports::libsodium::crypto::sign::Guest for Component {
    fn public_key_bytes() -> u32 {
        crypto_impl::sign_public_key_bytes()
    }

    fn secret_key_bytes() -> u32 {
        crypto_impl::sign_secret_key_bytes()
    }

    fn signature_bytes() -> u32 {
        crypto_impl::sign_signature_bytes()
    }

    fn seed_bytes() -> u32 {
        crypto_impl::sign_seed_bytes()
    }

    fn keypair() -> exports::libsodium::crypto::types::SignKeyPair {
        let (public_key, secret_key) = crypto_impl::sign_keypair();
        exports::libsodium::crypto::types::SignKeyPair {
            public_key,
            secret_key,
        }
    }

    fn seed_keypair(
        seed: Vec<u8>,
    ) -> Result<
        exports::libsodium::crypto::types::SignKeyPair,
        exports::libsodium::crypto::types::CryptoError,
    > {
        crypto_impl::sign_seed_keypair(&seed)
            .map(
                |(public_key, secret_key)| exports::libsodium::crypto::types::SignKeyPair {
                    public_key,
                    secret_key,
                },
            )
            .map_err(to_wit_error)
    }

    fn sign(
        message: Vec<u8>,
        secret_key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::sign(&message, &secret_key).map_err(to_wit_error)
    }

    fn open(
        signed_message: Vec<u8>,
        public_key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::sign_open(&signed_message, &public_key).map_err(to_wit_error)
    }

    fn detached(
        message: Vec<u8>,
        secret_key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::sign_detached(&message, &secret_key).map_err(to_wit_error)
    }

    fn verify_detached(
        signature: Vec<u8>,
        message: Vec<u8>,
        public_key: Vec<u8>,
    ) -> Result<(), exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::sign_verify_detached(&signature, &message, &public_key).map_err(to_wit_error)
    }

    fn ed25519_sk_to_pk(
        secret_key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::sign_ed25519_sk_to_pk(&secret_key).map_err(to_wit_error)
    }

    fn ed25519_sk_to_seed(
        secret_key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::sign_ed25519_sk_to_seed(&secret_key).map_err(to_wit_error)
    }

    fn ed25519_pk_to_curve25519(
        ed25519_pk: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::sign_ed25519_pk_to_curve25519(&ed25519_pk).map_err(to_wit_error)
    }

    fn ed25519_sk_to_curve25519(
        ed25519_sk: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::sign_ed25519_sk_to_curve25519(&ed25519_sk).map_err(to_wit_error)
    }

    fn state_bytes() -> u32 {
        crypto_impl::sign_state_bytes()
    }

    fn init() -> Result<u64, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::sign_state_init().map_err(to_wit_error)
    }

    fn update(
        state_id: u64,
        message: Vec<u8>,
    ) -> Result<(), exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::sign_state_update(state_id, &message).map_err(to_wit_error)
    }

    fn final_create(
        state_id: u64,
        secret_key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::sign_state_final_create(state_id, &secret_key).map_err(to_wit_error)
    }

    fn final_verify(
        state_id: u64,
        signature: Vec<u8>,
        public_key: Vec<u8>,
    ) -> Result<(), exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::sign_state_final_verify(state_id, &signature, &public_key)
            .map_err(to_wit_error)
    }

    fn destroy(state_id: u64) {
        crypto_impl::sign_state_destroy(state_id);
    }
}

// ============================================================================
// Generic Hash
// ============================================================================

impl exports::libsodium::crypto::generichash::Guest for Component {
    fn bytes() -> u32 {
        crypto_impl::generichash_bytes()
    }

    fn bytes_min() -> u32 {
        crypto_impl::generichash_bytes_min()
    }

    fn bytes_max() -> u32 {
        crypto_impl::generichash_bytes_max()
    }

    fn key_bytes() -> u32 {
        crypto_impl::generichash_key_bytes()
    }

    fn key_bytes_min() -> u32 {
        crypto_impl::generichash_key_bytes_min()
    }

    fn key_bytes_max() -> u32 {
        crypto_impl::generichash_key_bytes_max()
    }

    fn keygen() -> Vec<u8> {
        crypto_impl::generichash_keygen()
    }

    fn hash(
        message: Vec<u8>,
        out_len: u32,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::generichash(&message, out_len).map_err(to_wit_error)
    }

    fn hash_keyed(
        message: Vec<u8>,
        out_len: u32,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::generichash_keyed(&message, out_len, &key).map_err(to_wit_error)
    }
}

// ============================================================================
// SHA-256
// ============================================================================

impl exports::libsodium::crypto::sha256::Guest for Component {
    fn bytes() -> u32 {
        crypto_impl::sha256_bytes()
    }

    fn hash(message: Vec<u8>) -> Vec<u8> {
        crypto_impl::sha256(&message)
    }
}

// ============================================================================
// SHA-512
// ============================================================================

impl exports::libsodium::crypto::sha512::Guest for Component {
    fn bytes() -> u32 {
        crypto_impl::sha512_bytes()
    }

    fn hash(message: Vec<u8>) -> Vec<u8> {
        crypto_impl::sha512(&message)
    }
}

// ============================================================================
// Auth
// ============================================================================

impl exports::libsodium::crypto::auth::Guest for Component {
    fn bytes() -> u32 {
        crypto_impl::auth_bytes()
    }

    fn key_bytes() -> u32 {
        crypto_impl::auth_key_bytes()
    }

    fn keygen() -> Vec<u8> {
        crypto_impl::auth_keygen()
    }

    fn auth(
        message: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::auth(&message, &key).map_err(to_wit_error)
    }

    fn verify(
        tag: Vec<u8>,
        message: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<(), exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::auth_verify(&tag, &message, &key).map_err(to_wit_error)
    }
}

// ============================================================================
// AEAD XChaCha20-Poly1305
// ============================================================================

impl exports::libsodium::crypto::aead_xchacha20poly1305::Guest for Component {
    fn key_bytes() -> u32 {
        crypto_impl::aead_xchacha20poly1305_key_bytes()
    }

    fn nonce_bytes() -> u32 {
        crypto_impl::aead_xchacha20poly1305_nonce_bytes()
    }

    fn a_bytes() -> u32 {
        crypto_impl::aead_xchacha20poly1305_a_bytes()
    }

    fn keygen() -> Vec<u8> {
        crypto_impl::aead_xchacha20poly1305_keygen()
    }

    fn encrypt(
        message: Vec<u8>,
        additional_data: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::aead_xchacha20poly1305_encrypt(&message, &additional_data, &nonce, &key)
            .map_err(to_wit_error)
    }

    fn decrypt(
        ciphertext: Vec<u8>,
        additional_data: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::aead_xchacha20poly1305_decrypt(&ciphertext, &additional_data, &nonce, &key)
            .map_err(to_wit_error)
    }

    fn encrypt_detached(
        message: Vec<u8>,
        additional_data: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<(Vec<u8>, Vec<u8>), exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::aead_xchacha20poly1305_encrypt_detached(
            &message,
            &additional_data,
            &nonce,
            &key,
        )
        .map_err(to_wit_error)
    }

    fn decrypt_detached(
        ciphertext: Vec<u8>,
        mac: Vec<u8>,
        additional_data: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::aead_xchacha20poly1305_decrypt_detached(
            &ciphertext,
            &mac,
            &additional_data,
            &nonce,
            &key,
        )
        .map_err(to_wit_error)
    }
}

// ============================================================================
// AEAD ChaCha20-Poly1305-IETF
// ============================================================================

impl exports::libsodium::crypto::aead_chacha20poly1305_ietf::Guest for Component {
    fn key_bytes() -> u32 {
        crypto_impl::aead_chacha20poly1305_ietf_key_bytes()
    }

    fn nonce_bytes() -> u32 {
        crypto_impl::aead_chacha20poly1305_ietf_nonce_bytes()
    }

    fn a_bytes() -> u32 {
        crypto_impl::aead_chacha20poly1305_ietf_a_bytes()
    }

    fn keygen() -> Vec<u8> {
        crypto_impl::aead_chacha20poly1305_ietf_keygen()
    }

    fn encrypt(
        message: Vec<u8>,
        additional_data: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::aead_chacha20poly1305_ietf_encrypt(&message, &additional_data, &nonce, &key)
            .map_err(to_wit_error)
    }

    fn decrypt(
        ciphertext: Vec<u8>,
        additional_data: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::aead_chacha20poly1305_ietf_decrypt(&ciphertext, &additional_data, &nonce, &key)
            .map_err(to_wit_error)
    }

    fn encrypt_detached(
        message: Vec<u8>,
        additional_data: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<(Vec<u8>, Vec<u8>), exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::aead_chacha20poly1305_ietf_encrypt_detached(
            &message,
            &additional_data,
            &nonce,
            &key,
        )
        .map_err(to_wit_error)
    }

    fn decrypt_detached(
        ciphertext: Vec<u8>,
        mac: Vec<u8>,
        additional_data: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::aead_chacha20poly1305_ietf_decrypt_detached(
            &ciphertext,
            &mac,
            &additional_data,
            &nonce,
            &key,
        )
        .map_err(to_wit_error)
    }
}

// ============================================================================
// AEAD ChaCha20-Poly1305 (original, 8-byte nonce)
// ============================================================================

impl exports::libsodium::crypto::aead_chacha20poly1305::Guest for Component {
    fn key_bytes() -> u32 {
        crypto_impl::aead_chacha20poly1305_key_bytes()
    }

    fn nonce_bytes() -> u32 {
        crypto_impl::aead_chacha20poly1305_nonce_bytes()
    }

    fn a_bytes() -> u32 {
        crypto_impl::aead_chacha20poly1305_a_bytes()
    }

    fn keygen() -> Vec<u8> {
        crypto_impl::aead_chacha20poly1305_keygen()
    }

    fn encrypt(
        message: Vec<u8>,
        additional_data: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::aead_chacha20poly1305_encrypt(&message, &additional_data, &nonce, &key)
            .map_err(to_wit_error)
    }

    fn decrypt(
        ciphertext: Vec<u8>,
        additional_data: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::aead_chacha20poly1305_decrypt(&ciphertext, &additional_data, &nonce, &key)
            .map_err(to_wit_error)
    }

    fn encrypt_detached(
        message: Vec<u8>,
        additional_data: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<(Vec<u8>, Vec<u8>), exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::aead_chacha20poly1305_encrypt_detached(
            &message,
            &additional_data,
            &nonce,
            &key,
        )
        .map_err(to_wit_error)
    }

    fn decrypt_detached(
        ciphertext: Vec<u8>,
        mac: Vec<u8>,
        additional_data: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::aead_chacha20poly1305_decrypt_detached(
            &ciphertext,
            &mac,
            &additional_data,
            &nonce,
            &key,
        )
        .map_err(to_wit_error)
    }
}

// ============================================================================
// AEAD AEGIS-128L
// ============================================================================

impl exports::libsodium::crypto::aead_aegis128l::Guest for Component {
    fn key_bytes() -> u32 {
        crypto_impl::aead_aegis128l_key_bytes()
    }

    fn nonce_bytes() -> u32 {
        crypto_impl::aead_aegis128l_nonce_bytes()
    }

    fn a_bytes() -> u32 {
        crypto_impl::aead_aegis128l_a_bytes()
    }

    fn keygen() -> Vec<u8> {
        crypto_impl::aead_aegis128l_keygen()
    }

    fn encrypt(
        message: Vec<u8>,
        additional_data: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::aead_aegis128l_encrypt(&message, &additional_data, &nonce, &key)
            .map_err(to_wit_error)
    }

    fn decrypt(
        ciphertext: Vec<u8>,
        additional_data: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::aead_aegis128l_decrypt(&ciphertext, &additional_data, &nonce, &key)
            .map_err(to_wit_error)
    }

    fn encrypt_detached(
        message: Vec<u8>,
        additional_data: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<(Vec<u8>, Vec<u8>), exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::aead_aegis128l_encrypt_detached(&message, &additional_data, &nonce, &key)
            .map_err(to_wit_error)
    }

    fn decrypt_detached(
        ciphertext: Vec<u8>,
        mac: Vec<u8>,
        additional_data: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::aead_aegis128l_decrypt_detached(
            &ciphertext,
            &mac,
            &additional_data,
            &nonce,
            &key,
        )
        .map_err(to_wit_error)
    }
}

// ============================================================================
// AEAD AEGIS-256
// ============================================================================

impl exports::libsodium::crypto::aead_aegis256::Guest for Component {
    fn key_bytes() -> u32 {
        crypto_impl::aead_aegis256_key_bytes()
    }

    fn nonce_bytes() -> u32 {
        crypto_impl::aead_aegis256_nonce_bytes()
    }

    fn a_bytes() -> u32 {
        crypto_impl::aead_aegis256_a_bytes()
    }

    fn keygen() -> Vec<u8> {
        crypto_impl::aead_aegis256_keygen()
    }

    fn encrypt(
        message: Vec<u8>,
        additional_data: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::aead_aegis256_encrypt(&message, &additional_data, &nonce, &key)
            .map_err(to_wit_error)
    }

    fn decrypt(
        ciphertext: Vec<u8>,
        additional_data: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::aead_aegis256_decrypt(&ciphertext, &additional_data, &nonce, &key)
            .map_err(to_wit_error)
    }

    fn encrypt_detached(
        message: Vec<u8>,
        additional_data: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<(Vec<u8>, Vec<u8>), exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::aead_aegis256_encrypt_detached(&message, &additional_data, &nonce, &key)
            .map_err(to_wit_error)
    }

    fn decrypt_detached(
        ciphertext: Vec<u8>,
        mac: Vec<u8>,
        additional_data: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::aead_aegis256_decrypt_detached(
            &ciphertext,
            &mac,
            &additional_data,
            &nonce,
            &key,
        )
        .map_err(to_wit_error)
    }
}

// ============================================================================
// Password Hashing
// ============================================================================

impl exports::libsodium::crypto::pwhash::Guest for Component {
    fn salt_bytes() -> u32 {
        crypto_impl::pwhash_salt_bytes()
    }

    fn str_bytes() -> u32 {
        crypto_impl::pwhash_str_bytes()
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
        crypto_impl::pwhash_opslimit_interactive()
    }

    fn opslimit_moderate() -> u64 {
        crypto_impl::pwhash_opslimit_moderate()
    }

    fn opslimit_sensitive() -> u64 {
        crypto_impl::pwhash_opslimit_sensitive()
    }

    fn memlimit_min() -> u64 {
        crypto_pwhash_MEMLIMIT_MIN as u64
    }

    fn memlimit_interactive() -> u64 {
        crypto_impl::pwhash_memlimit_interactive()
    }

    fn memlimit_moderate() -> u64 {
        crypto_impl::pwhash_memlimit_moderate()
    }

    fn memlimit_sensitive() -> u64 {
        crypto_impl::pwhash_memlimit_sensitive()
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
        _alg: i32,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::pwhash(out_len, &password, &salt, opslimit, memlimit).map_err(to_wit_error)
    }

    fn str(
        password: Vec<u8>,
        opslimit: u64,
        memlimit: u64,
    ) -> Result<String, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::pwhash_str(&password, opslimit, memlimit).map_err(to_wit_error)
    }

    fn str_verify(
        hash: String,
        password: Vec<u8>,
    ) -> Result<(), exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::pwhash_str_verify(&hash, &password).map_err(to_wit_error)
    }

    fn str_needs_rehash(
        hash: String,
        opslimit: u64,
        memlimit: u64,
    ) -> Result<bool, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::pwhash_str_needs_rehash(&hash, opslimit, memlimit).map_err(to_wit_error)
    }
}

// ============================================================================
// KDF
// ============================================================================

impl exports::libsodium::crypto::kdf::Guest for Component {
    fn key_bytes() -> u32 {
        crypto_impl::kdf_key_bytes()
    }

    fn context_bytes() -> u32 {
        crypto_impl::kdf_context_bytes()
    }

    fn bytes_min() -> u32 {
        crypto_impl::kdf_bytes_min()
    }

    fn bytes_max() -> u32 {
        crypto_impl::kdf_bytes_max()
    }

    fn keygen() -> Vec<u8> {
        crypto_impl::kdf_keygen()
    }

    fn derive_from_key(
        subkey_len: u32,
        subkey_id: u64,
        context: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::kdf_derive_from_key(subkey_len, subkey_id, &context, &key)
            .map_err(to_wit_error)
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
        crypto_impl::kdf_hkdf_sha256_key_bytes()
    }

    fn extract(salt: Vec<u8>, ikm: Vec<u8>) -> Vec<u8> {
        // extract cannot fail, so unwrap is safe here
        crypto_impl::kdf_hkdf_sha256_extract(&salt, &ikm).unwrap()
    }

    fn expand(
        out_len: u32,
        prk: Vec<u8>,
        info: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::kdf_hkdf_sha256_expand(&prk, &info, out_len).map_err(to_wit_error)
    }

    fn bytes_min() -> u32 {
        crypto_impl::kdf_hkdf_sha256_bytes_min()
    }

    fn bytes_max() -> u32 {
        crypto_impl::kdf_hkdf_sha256_bytes_max()
    }

    fn keygen() -> Vec<u8> {
        crypto_impl::kdf_hkdf_sha256_keygen()
    }

    fn extract_init(salt: Vec<u8>) -> Result<u64, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::kdf_hkdf_sha256_extract_init(&salt).map_err(to_wit_error)
    }

    fn extract_update(
        state_id: u64,
        ikm: Vec<u8>,
    ) -> Result<(), exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::kdf_hkdf_sha256_extract_update(state_id, &ikm).map_err(to_wit_error)
    }

    fn extract_final(
        state_id: u64,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::kdf_hkdf_sha256_extract_final(state_id).map_err(to_wit_error)
    }
}

// ============================================================================
// Key Exchange
// ============================================================================

impl exports::libsodium::crypto::kx::Guest for Component {
    fn public_key_bytes() -> u32 {
        crypto_impl::kx_public_key_bytes()
    }

    fn secret_key_bytes() -> u32 {
        crypto_impl::kx_secret_key_bytes()
    }

    fn seed_bytes() -> u32 {
        crypto_impl::kx_seed_bytes()
    }

    fn session_key_bytes() -> u32 {
        crypto_impl::kx_session_key_bytes()
    }

    fn keypair() -> exports::libsodium::crypto::types::KxKeyPair {
        let (public_key, secret_key) = crypto_impl::kx_keypair();
        exports::libsodium::crypto::types::KxKeyPair {
            public_key,
            secret_key,
        }
    }

    fn seed_keypair(
        seed: Vec<u8>,
    ) -> Result<
        exports::libsodium::crypto::types::KxKeyPair,
        exports::libsodium::crypto::types::CryptoError,
    > {
        crypto_impl::kx_seed_keypair(&seed)
            .map(
                |(public_key, secret_key)| exports::libsodium::crypto::types::KxKeyPair {
                    public_key,
                    secret_key,
                },
            )
            .map_err(to_wit_error)
    }

    fn client_session_keys(
        client_pk: Vec<u8>,
        client_sk: Vec<u8>,
        server_pk: Vec<u8>,
    ) -> Result<
        exports::libsodium::crypto::types::SessionKeys,
        exports::libsodium::crypto::types::CryptoError,
    > {
        crypto_impl::kx_client_session_keys(&client_pk, &client_sk, &server_pk)
            .map(|(rx, tx)| exports::libsodium::crypto::types::SessionKeys { rx, tx })
            .map_err(to_wit_error)
    }

    fn server_session_keys(
        server_pk: Vec<u8>,
        server_sk: Vec<u8>,
        client_pk: Vec<u8>,
    ) -> Result<
        exports::libsodium::crypto::types::SessionKeys,
        exports::libsodium::crypto::types::CryptoError,
    > {
        crypto_impl::kx_server_session_keys(&server_pk, &server_sk, &client_pk)
            .map(|(rx, tx)| exports::libsodium::crypto::types::SessionKeys { rx, tx })
            .map_err(to_wit_error)
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
        crypto_impl::scalarmult_scalar_bytes()
    }

    fn bytes() -> u32 {
        crypto_impl::scalarmult_bytes()
    }

    fn scalarmult(
        n: Vec<u8>,
        p: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::scalarmult(&n, &p).map_err(to_wit_error)
    }

    fn base(n: Vec<u8>) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::scalarmult_base(&n).map_err(to_wit_error)
    }
}

// ============================================================================
// Utils
// ============================================================================

impl exports::libsodium::crypto::utils::Guest for Component {
    fn memzero(mut data: Vec<u8>) -> Vec<u8> {
        crypto_impl::memzero(&mut data);
        data
    }

    fn memcmp(
        a: Vec<u8>,
        b: Vec<u8>,
    ) -> Result<bool, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::memcmp(&a, &b).map_err(to_wit_error)
    }

    fn increment(mut data: Vec<u8>) -> Vec<u8> {
        crypto_impl::increment(&mut data);
        data
    }

    fn add(
        mut a: Vec<u8>,
        b: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::add(&mut a, &b).map_err(to_wit_error)?;
        Ok(a)
    }

    fn sub(
        mut a: Vec<u8>,
        b: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::sub(&mut a, &b).map_err(to_wit_error)?;
        Ok(a)
    }

    fn compare(a: Vec<u8>, b: Vec<u8>) -> i32 {
        crypto_impl::compare(&a, &b)
    }

    fn is_zero(data: Vec<u8>) -> bool {
        crypto_impl::is_zero(&data)
    }

    fn bin2hex(data: Vec<u8>) -> String {
        crypto_impl::bin2hex(&data)
    }

    fn hex2bin(hex: String) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::hex2bin(&hex).map_err(to_wit_error)
    }

    fn bin2base64(data: Vec<u8>) -> String {
        crypto_impl::bin2base64(&data)
    }

    fn base642bin(
        base64: String,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::base642bin(&base64).map_err(to_wit_error)
    }

    fn hex2bin_ignore(
        hex: String,
        ignore: String,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::hex2bin_ignore(&hex, &ignore).map_err(to_wit_error)
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
        crypto_impl::bin2base64_variant(&data, encoding)
    }

    fn base642bin_variant(
        base64: String,
        encoding: u32,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::base642bin_variant(&base64, encoding).map_err(to_wit_error)
    }

    fn base642bin_variant_ignore(
        base64: String,
        encoding: u32,
        ignore: String,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::base642bin_variant_ignore(&base64, encoding, &ignore).map_err(to_wit_error)
    }

    fn pad(
        data: Vec<u8>,
        block_size: u32,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::pad(&data, block_size).map_err(to_wit_error)
    }

    fn unpad(
        data: Vec<u8>,
        block_size: u32,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::unpad(&data, block_size).map_err(to_wit_error)
    }
}

// ============================================================================
// Short Hash
// ============================================================================

impl exports::libsodium::crypto::shorthash::Guest for Component {
    fn bytes() -> u32 {
        crypto_impl::shorthash_bytes()
    }

    fn key_bytes() -> u32 {
        crypto_impl::shorthash_key_bytes()
    }

    fn keygen() -> Vec<u8> {
        crypto_impl::shorthash_keygen()
    }

    fn hash(
        message: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::shorthash(&message, &key).map_err(to_wit_error)
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
        crypto_impl::shorthash_siphashx24(&message, &key).map_err(to_wit_error)
    }
}

// ============================================================================
// One-Time Auth
// ============================================================================

impl exports::libsodium::crypto::onetimeauth::Guest for Component {
    fn bytes() -> u32 {
        crypto_impl::onetimeauth_bytes()
    }

    fn key_bytes() -> u32 {
        crypto_impl::onetimeauth_key_bytes()
    }

    fn keygen() -> Vec<u8> {
        crypto_impl::onetimeauth_keygen()
    }

    fn auth(
        message: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::onetimeauth(&message, &key).map_err(to_wit_error)
    }

    fn verify(
        tag: Vec<u8>,
        message: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<(), exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::onetimeauth_verify(&tag, &message, &key).map_err(to_wit_error)
    }
}

// ============================================================================
// Cipher XSalsa20
// ============================================================================

impl exports::libsodium::crypto::cipher_xsalsa20::Guest for Component {
    fn key_bytes() -> u32 {
        crypto_impl::stream_xsalsa20_key_bytes()
    }

    fn nonce_bytes() -> u32 {
        crypto_impl::stream_xsalsa20_nonce_bytes()
    }

    fn keygen() -> Vec<u8> {
        crypto_impl::stream_xsalsa20_keygen()
    }

    fn keystream(
        len: u32,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::stream_xsalsa20(len, &nonce, &key).map_err(to_wit_error)
    }

    fn xor(
        message: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::stream_xsalsa20_xor(&message, &nonce, &key).map_err(to_wit_error)
    }
}

// ============================================================================
// Cipher XChaCha20
// ============================================================================

impl exports::libsodium::crypto::cipher_xchacha20::Guest for Component {
    fn key_bytes() -> u32 {
        crypto_impl::stream_xchacha20_key_bytes()
    }

    fn nonce_bytes() -> u32 {
        crypto_impl::stream_xchacha20_nonce_bytes()
    }

    fn keygen() -> Vec<u8> {
        crypto_impl::stream_xchacha20_keygen()
    }

    fn keystream(
        len: u32,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::stream_xchacha20(len, &nonce, &key).map_err(to_wit_error)
    }

    fn xor(
        message: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::stream_xchacha20_xor(&message, &nonce, &key).map_err(to_wit_error)
    }

    fn xor_ic(
        message: Vec<u8>,
        nonce: Vec<u8>,
        ic: u64,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::stream_xchacha20_xor_ic(&message, &nonce, ic, &key).map_err(to_wit_error)
    }
}

// ============================================================================
// Secret Stream (XChaCha20-Poly1305 streaming)
// ============================================================================

impl exports::libsodium::crypto::secret_stream::Guest for Component {
    fn key_bytes() -> u32 {
        crypto_impl::secretstream_key_bytes()
    }

    fn header_bytes() -> u32 {
        crypto_impl::secretstream_header_bytes()
    }

    fn a_bytes() -> u32 {
        crypto_impl::secretstream_a_bytes()
    }

    fn tag_message() -> u8 {
        crypto_impl::secretstream_tag_message()
    }

    fn tag_push() -> u8 {
        crypto_impl::secretstream_tag_push()
    }

    fn tag_rekey() -> u8 {
        crypto_impl::secretstream_tag_rekey()
    }

    fn tag_final() -> u8 {
        crypto_impl::secretstream_tag_final()
    }

    fn messagebytes_max() -> u64 {
        crypto_impl::secretstream_messagebytes_max()
    }

    fn keygen() -> Vec<u8> {
        crypto_impl::secretstream_keygen()
    }

    fn init_push(
        key: Vec<u8>,
    ) -> Result<(u64, Vec<u8>), exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::secretstream_init_push(&key).map_err(to_wit_error)
    }

    fn push(
        state_id: u64,
        message: Vec<u8>,
        additional_data: Vec<u8>,
        tag: u8,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::secretstream_push(state_id, &message, &additional_data, tag)
            .map_err(to_wit_error)
    }

    fn init_pull(
        header: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<u64, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::secretstream_init_pull(&header, &key).map_err(to_wit_error)
    }

    fn pull(
        state_id: u64,
        ciphertext: Vec<u8>,
        additional_data: Vec<u8>,
    ) -> Result<(Vec<u8>, u8), exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::secretstream_pull(state_id, &ciphertext, &additional_data)
            .map_err(to_wit_error)
    }

    fn rekey(state_id: u64) -> Result<(), exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::secretstream_rekey(state_id).map_err(to_wit_error)
    }

    fn destroy(state_id: u64) {
        crypto_impl::secretstream_destroy(state_id);
    }
}

// ============================================================================
// Generichash State (streaming BLAKE2b)
// ============================================================================

impl exports::libsodium::crypto::generichash_state::Guest for Component {
    fn state_bytes() -> u32 {
        crypto_impl::generichash_state_bytes()
    }

    fn init(
        out_len: u32,
        key: Vec<u8>,
    ) -> Result<u64, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::generichash_state_init(out_len, &key).map_err(to_wit_error)
    }

    fn update(
        state_id: u64,
        data: Vec<u8>,
    ) -> Result<(), exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::generichash_state_update(state_id, &data).map_err(to_wit_error)
    }

    fn final_(state_id: u64) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::generichash_state_final(state_id).map_err(to_wit_error)
    }

    fn destroy(state_id: u64) {
        crypto_impl::generichash_state_destroy(state_id)
    }
}

// ============================================================================
// SHA-256 State (streaming)
// ============================================================================

impl exports::libsodium::crypto::sha256_state::Guest for Component {
    fn state_bytes() -> u32 {
        crypto_impl::sha256_state_bytes()
    }

    fn init() -> Result<u64, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::sha256_state_init().map_err(to_wit_error)
    }

    fn update(
        state_id: u64,
        data: Vec<u8>,
    ) -> Result<(), exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::sha256_state_update(state_id, &data).map_err(to_wit_error)
    }

    fn final_(state_id: u64) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::sha256_state_final(state_id).map_err(to_wit_error)
    }

    fn destroy(state_id: u64) {
        crypto_impl::sha256_state_destroy(state_id)
    }
}

// ============================================================================
// SHA-512 State (streaming)
// ============================================================================

impl exports::libsodium::crypto::sha512_state::Guest for Component {
    fn state_bytes() -> u32 {
        crypto_impl::sha512_state_bytes()
    }

    fn init() -> Result<u64, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::sha512_state_init().map_err(to_wit_error)
    }

    fn update(
        state_id: u64,
        data: Vec<u8>,
    ) -> Result<(), exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::sha512_state_update(state_id, &data).map_err(to_wit_error)
    }

    fn final_(state_id: u64) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::sha512_state_final(state_id).map_err(to_wit_error)
    }

    fn destroy(state_id: u64) {
        crypto_impl::sha512_state_destroy(state_id)
    }
}

// ============================================================================
// Auth State (streaming HMAC-SHA512-256)
// ============================================================================

impl exports::libsodium::crypto::auth_state::Guest for Component {
    fn state_bytes() -> u32 {
        crypto_impl::auth_state_bytes()
    }

    fn init(key: Vec<u8>) -> Result<u64, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::auth_state_init(&key).map_err(to_wit_error)
    }

    fn update(
        state_id: u64,
        data: Vec<u8>,
    ) -> Result<(), exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::auth_state_update(state_id, &data).map_err(to_wit_error)
    }

    fn final_(state_id: u64) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::auth_state_final(state_id).map_err(to_wit_error)
    }

    fn destroy(state_id: u64) {
        crypto_impl::auth_state_destroy(state_id)
    }
}

// ============================================================================
// Onetimeauth State (streaming Poly1305)
// ============================================================================

impl exports::libsodium::crypto::onetimeauth_state::Guest for Component {
    fn state_bytes() -> u32 {
        crypto_impl::onetimeauth_state_bytes()
    }

    fn init(key: Vec<u8>) -> Result<u64, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::onetimeauth_state_init(&key).map_err(to_wit_error)
    }

    fn update(
        state_id: u64,
        data: Vec<u8>,
    ) -> Result<(), exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::onetimeauth_state_update(state_id, &data).map_err(to_wit_error)
    }

    fn final_(state_id: u64) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::onetimeauth_state_final(state_id).map_err(to_wit_error)
    }

    fn destroy(state_id: u64) {
        crypto_impl::onetimeauth_state_destroy(state_id)
    }
}

// ============================================================================
// AEAD AES-256-GCM
// ============================================================================

impl exports::libsodium::crypto::aead_aes256gcm::Guest for Component {
    fn is_available() -> bool {
        crypto_impl::aead_aes256gcm_is_available()
    }

    fn key_bytes() -> u32 {
        crypto_impl::aead_aes256gcm_key_bytes()
    }

    fn nonce_bytes() -> u32 {
        crypto_impl::aead_aes256gcm_nonce_bytes()
    }

    fn a_bytes() -> u32 {
        crypto_impl::aead_aes256gcm_a_bytes()
    }

    fn keygen() -> Vec<u8> {
        crypto_impl::aead_aes256gcm_keygen()
    }

    fn encrypt(
        message: Vec<u8>,
        additional_data: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::aead_aes256gcm_encrypt(&message, &additional_data, &nonce, &key)
            .map_err(to_wit_error)
    }

    fn decrypt(
        ciphertext: Vec<u8>,
        additional_data: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::aead_aes256gcm_decrypt(&ciphertext, &additional_data, &nonce, &key)
            .map_err(to_wit_error)
    }

    fn encrypt_detached(
        message: Vec<u8>,
        additional_data: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<(Vec<u8>, Vec<u8>), exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::aead_aes256gcm_encrypt_detached(&message, &additional_data, &nonce, &key)
            .map_err(to_wit_error)
    }

    fn decrypt_detached(
        ciphertext: Vec<u8>,
        mac: Vec<u8>,
        additional_data: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::aead_aes256gcm_decrypt_detached(
            &ciphertext,
            &mac,
            &additional_data,
            &nonce,
            &key,
        )
        .map_err(to_wit_error)
    }
}

// ============================================================================
// Verify (constant-time comparison)
// ============================================================================

impl exports::libsodium::crypto::verify::Guest for Component {
    fn verify16(x: Vec<u8>, y: Vec<u8>) -> bool {
        crypto_impl::verify16(&x, &y)
    }

    fn verify32(x: Vec<u8>, y: Vec<u8>) -> bool {
        crypto_impl::verify32(&x, &y)
    }

    fn verify64(x: Vec<u8>, y: Vec<u8>) -> bool {
        crypto_impl::verify64(&x, &y)
    }
}

// ============================================================================
// Ristretto255 group operations
// ============================================================================

impl exports::libsodium::crypto::ristretto255::Guest for Component {
    fn bytes() -> u32 {
        crypto_impl::ristretto255_bytes()
    }

    fn hash_bytes() -> u32 {
        crypto_impl::ristretto255_hash_bytes()
    }

    fn scalar_bytes() -> u32 {
        crypto_impl::ristretto255_scalar_bytes()
    }

    fn non_reduced_scalar_bytes() -> u32 {
        crypto_impl::ristretto255_non_reduced_scalar_bytes()
    }

    fn is_valid_point(p: Vec<u8>) -> bool {
        crypto_impl::ristretto255_is_valid_point(&p)
    }

    fn add(
        p: Vec<u8>,
        q: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::ristretto255_add(&p, &q).map_err(to_wit_error)
    }

    fn sub(
        p: Vec<u8>,
        q: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::ristretto255_sub(&p, &q).map_err(to_wit_error)
    }

    fn from_hash(h: Vec<u8>) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::ristretto255_from_hash(&h).map_err(to_wit_error)
    }

    fn random() -> Vec<u8> {
        crypto_impl::ristretto255_random()
    }

    fn scalar_random() -> Vec<u8> {
        crypto_impl::ristretto255_scalar_random()
    }

    fn scalar_invert(
        s: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::ristretto255_scalar_invert(&s).map_err(to_wit_error)
    }

    fn scalar_negate(s: Vec<u8>) -> Vec<u8> {
        crypto_impl::ristretto255_scalar_negate(&s)
    }

    fn scalar_complement(s: Vec<u8>) -> Vec<u8> {
        crypto_impl::ristretto255_scalar_complement(&s)
    }

    fn scalar_add(x: Vec<u8>, y: Vec<u8>) -> Vec<u8> {
        crypto_impl::ristretto255_scalar_add(&x, &y)
    }

    fn scalar_sub(x: Vec<u8>, y: Vec<u8>) -> Vec<u8> {
        crypto_impl::ristretto255_scalar_sub(&x, &y)
    }

    fn scalar_mul(x: Vec<u8>, y: Vec<u8>) -> Vec<u8> {
        crypto_impl::ristretto255_scalar_mul(&x, &y)
    }

    fn scalar_reduce(s: Vec<u8>) -> Vec<u8> {
        crypto_impl::ristretto255_scalar_reduce(&s)
    }
}

// ============================================================================
// Ed25519 group operations
// ============================================================================

impl exports::libsodium::crypto::ed25519::Guest for Component {
    fn bytes() -> u32 {
        crypto_impl::ed25519_bytes()
    }

    fn uniform_bytes() -> u32 {
        crypto_impl::ed25519_uniform_bytes()
    }

    fn hash_bytes() -> u32 {
        crypto_impl::ed25519_hash_bytes()
    }

    fn scalar_bytes() -> u32 {
        crypto_impl::ed25519_scalar_bytes()
    }

    fn non_reduced_scalar_bytes() -> u32 {
        crypto_impl::ed25519_non_reduced_scalar_bytes()
    }

    fn is_valid_point(p: Vec<u8>) -> bool {
        crypto_impl::ed25519_is_valid_point(&p)
    }

    fn add(
        p: Vec<u8>,
        q: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::ed25519_add(&p, &q).map_err(to_wit_error)
    }

    fn sub(
        p: Vec<u8>,
        q: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::ed25519_sub(&p, &q).map_err(to_wit_error)
    }

    fn from_uniform(u: Vec<u8>) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::ed25519_from_uniform(&u).map_err(to_wit_error)
    }

    fn from_hash(h: Vec<u8>) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::ed25519_from_hash(&h).map_err(to_wit_error)
    }

    fn random() -> Vec<u8> {
        crypto_impl::ed25519_random()
    }

    fn scalar_random() -> Vec<u8> {
        crypto_impl::ed25519_scalar_random()
    }

    fn scalar_invert(
        s: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::ed25519_scalar_invert(&s).map_err(to_wit_error)
    }

    fn scalar_negate(s: Vec<u8>) -> Vec<u8> {
        crypto_impl::ed25519_scalar_negate(&s)
    }

    fn scalar_complement(s: Vec<u8>) -> Vec<u8> {
        crypto_impl::ed25519_scalar_complement(&s)
    }

    fn scalar_add(x: Vec<u8>, y: Vec<u8>) -> Vec<u8> {
        crypto_impl::ed25519_scalar_add(&x, &y)
    }

    fn scalar_sub(x: Vec<u8>, y: Vec<u8>) -> Vec<u8> {
        crypto_impl::ed25519_scalar_sub(&x, &y)
    }

    fn scalar_mul(x: Vec<u8>, y: Vec<u8>) -> Vec<u8> {
        crypto_impl::ed25519_scalar_mul(&x, &y)
    }

    fn scalar_reduce(s: Vec<u8>) -> Vec<u8> {
        crypto_impl::ed25519_scalar_reduce(&s)
    }
}

// ============================================================================
// Scalarmult Ed25519
// ============================================================================

impl exports::libsodium::crypto::scalarmult_ed25519::Guest for Component {
    fn bytes() -> u32 {
        crypto_impl::scalarmult_ed25519_bytes()
    }

    fn scalar_bytes() -> u32 {
        crypto_impl::scalarmult_ed25519_scalar_bytes()
    }

    fn scalarmult(
        n: Vec<u8>,
        p: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::scalarmult_ed25519(&n, &p).map_err(to_wit_error)
    }

    fn scalarmult_noclamp(
        n: Vec<u8>,
        p: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::scalarmult_ed25519_noclamp(&n, &p).map_err(to_wit_error)
    }

    fn base(n: Vec<u8>) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::scalarmult_ed25519_base(&n).map_err(to_wit_error)
    }

    fn base_noclamp(n: Vec<u8>) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::scalarmult_ed25519_base_noclamp(&n).map_err(to_wit_error)
    }
}

// ============================================================================
// Scalarmult Ristretto255
// ============================================================================

impl exports::libsodium::crypto::scalarmult_ristretto255::Guest for Component {
    fn bytes() -> u32 {
        crypto_impl::scalarmult_ristretto255_bytes()
    }

    fn scalar_bytes() -> u32 {
        crypto_impl::scalarmult_ristretto255_scalar_bytes()
    }

    fn scalarmult(
        n: Vec<u8>,
        p: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::scalarmult_ristretto255(&n, &p).map_err(to_wit_error)
    }

    fn base(n: Vec<u8>) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::scalarmult_ristretto255_base(&n).map_err(to_wit_error)
    }
}

// ============================================================================
// KDF HKDF-SHA512
// ============================================================================

impl exports::libsodium::crypto::kdf_hkdf_sha512::Guest for Component {
    fn key_bytes() -> u32 {
        crypto_impl::kdf_hkdf_sha512_key_bytes()
    }

    fn extract(salt: Vec<u8>, ikm: Vec<u8>) -> Vec<u8> {
        // extract cannot fail, so unwrap is safe here
        crypto_impl::kdf_hkdf_sha512_extract(&salt, &ikm).unwrap()
    }

    fn expand(
        out_len: u32,
        prk: Vec<u8>,
        info: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::kdf_hkdf_sha512_expand(&prk, &info, out_len).map_err(to_wit_error)
    }

    fn bytes_min() -> u32 {
        crypto_impl::kdf_hkdf_sha512_bytes_min()
    }

    fn bytes_max() -> u32 {
        crypto_impl::kdf_hkdf_sha512_bytes_max()
    }

    fn keygen() -> Vec<u8> {
        crypto_impl::kdf_hkdf_sha512_keygen()
    }

    fn extract_init(salt: Vec<u8>) -> Result<u64, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::kdf_hkdf_sha512_extract_init(&salt).map_err(to_wit_error)
    }

    fn extract_update(
        state_id: u64,
        ikm: Vec<u8>,
    ) -> Result<(), exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::kdf_hkdf_sha512_extract_update(state_id, &ikm).map_err(to_wit_error)
    }

    fn extract_final(
        state_id: u64,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::kdf_hkdf_sha512_extract_final(state_id).map_err(to_wit_error)
    }
}

// ============================================================================
// Password Hashing (scrypt)
// ============================================================================

impl exports::libsodium::crypto::pwhash_scrypt::Guest for Component {
    fn salt_bytes() -> u32 {
        crypto_impl::pwhash_scrypt_salt_bytes()
    }

    fn str_bytes() -> u32 {
        crypto_impl::pwhash_scrypt_str_bytes()
    }

    fn opslimit_min() -> u64 {
        crypto_impl::pwhash_scrypt_opslimit_min()
    }

    fn opslimit_max() -> u64 {
        crypto_impl::pwhash_scrypt_opslimit_max()
    }

    fn opslimit_interactive() -> u64 {
        crypto_impl::pwhash_scrypt_opslimit_interactive()
    }

    fn opslimit_sensitive() -> u64 {
        crypto_impl::pwhash_scrypt_opslimit_sensitive()
    }

    fn memlimit_min() -> u64 {
        crypto_impl::pwhash_scrypt_memlimit_min()
    }

    fn memlimit_interactive() -> u64 {
        crypto_impl::pwhash_scrypt_memlimit_interactive()
    }

    fn memlimit_sensitive() -> u64 {
        crypto_impl::pwhash_scrypt_memlimit_sensitive()
    }

    fn derive(
        out_len: u32,
        password: Vec<u8>,
        salt: Vec<u8>,
        opslimit: u64,
        memlimit: u64,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::pwhash_scrypt(out_len, &password, &salt, opslimit, memlimit)
            .map_err(to_wit_error)
    }

    fn str(
        password: Vec<u8>,
        opslimit: u64,
        memlimit: u64,
    ) -> Result<String, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::pwhash_scrypt_str(&password, opslimit, memlimit).map_err(to_wit_error)
    }

    fn str_verify(
        hash: String,
        password: Vec<u8>,
    ) -> Result<(), exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::pwhash_scrypt_str_verify(&hash, &password).map_err(to_wit_error)
    }

    fn str_needs_rehash(
        hash: String,
        opslimit: u64,
        memlimit: u64,
    ) -> Result<bool, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::pwhash_scrypt_str_needs_rehash(&hash, opslimit, memlimit).map_err(to_wit_error)
    }

    fn bytes_min() -> u32 {
        crypto_impl::pwhash_scrypt_bytes_min()
    }

    fn bytes_max() -> u32 {
        crypto_impl::pwhash_scrypt_bytes_max()
    }

    fn passwd_min() -> u32 {
        crypto_impl::pwhash_scrypt_passwd_min()
    }

    fn passwd_max() -> u32 {
        crypto_impl::pwhash_scrypt_passwd_max()
    }

    fn memlimit_max() -> u64 {
        crypto_impl::pwhash_scrypt_memlimit_max()
    }

    fn strprefix() -> String {
        crypto_impl::pwhash_scrypt_str_prefix().to_string()
    }

    fn derive_ll(
        out_len: u32,
        password: Vec<u8>,
        salt: Vec<u8>,
        n: u64,
        r: u32,
        p: u32,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::pwhash_scrypt_derive_ll(out_len, &password, &salt, n, r, p)
            .map_err(to_wit_error)
    }
}

// ============================================================================
// Cipher Salsa20
// ============================================================================

impl exports::libsodium::crypto::cipher_salsa20::Guest for Component {
    fn key_bytes() -> u32 {
        crypto_impl::stream_salsa20_key_bytes()
    }

    fn nonce_bytes() -> u32 {
        crypto_impl::stream_salsa20_nonce_bytes()
    }

    fn keygen() -> Vec<u8> {
        crypto_impl::stream_salsa20_keygen()
    }

    fn keystream(
        len: u32,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::stream_salsa20(len, &nonce, &key).map_err(to_wit_error)
    }

    fn xor(
        message: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::stream_salsa20_xor(&message, &nonce, &key).map_err(to_wit_error)
    }

    fn xor_ic(
        message: Vec<u8>,
        nonce: Vec<u8>,
        ic: u64,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::stream_salsa20_xor_ic(&message, &nonce, ic, &key).map_err(to_wit_error)
    }
}

// ============================================================================
// Cipher ChaCha20
// ============================================================================

impl exports::libsodium::crypto::cipher_chacha20::Guest for Component {
    fn key_bytes() -> u32 {
        crypto_impl::stream_chacha20_key_bytes()
    }

    fn nonce_bytes() -> u32 {
        crypto_impl::stream_chacha20_nonce_bytes()
    }

    fn keygen() -> Vec<u8> {
        crypto_impl::stream_chacha20_keygen()
    }

    fn keystream(
        len: u32,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::stream_chacha20(len, &nonce, &key).map_err(to_wit_error)
    }

    fn xor(
        message: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::stream_chacha20_xor(&message, &nonce, &key).map_err(to_wit_error)
    }

    fn xor_ic(
        message: Vec<u8>,
        nonce: Vec<u8>,
        ic: u64,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::stream_chacha20_xor_ic(&message, &nonce, ic, &key).map_err(to_wit_error)
    }
}

// ============================================================================
// Cipher ChaCha20 IETF
// ============================================================================

impl exports::libsodium::crypto::cipher_chacha20_ietf::Guest for Component {
    fn key_bytes() -> u32 {
        crypto_impl::stream_chacha20_ietf_key_bytes()
    }

    fn nonce_bytes() -> u32 {
        crypto_impl::stream_chacha20_ietf_nonce_bytes()
    }

    fn keygen() -> Vec<u8> {
        crypto_impl::stream_chacha20_ietf_keygen()
    }

    fn keystream(
        len: u32,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::stream_chacha20_ietf(len, &nonce, &key).map_err(to_wit_error)
    }

    fn xor(
        message: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::stream_chacha20_ietf_xor(&message, &nonce, &key).map_err(to_wit_error)
    }

    fn xor_ic(
        message: Vec<u8>,
        nonce: Vec<u8>,
        ic: u32,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::stream_chacha20_ietf_xor_ic(&message, &nonce, ic, &key).map_err(to_wit_error)
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
        crypto_impl::xof_shake128_state_bytes()
    }

    fn hash(out_len: u32, message: Vec<u8>) -> Vec<u8> {
        crypto_impl::xof_shake128(&message, out_len)
    }

    fn init() -> Result<u64, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::xof_shake128_init().map_err(to_wit_error)
    }

    fn update(
        state_id: u64,
        data: Vec<u8>,
    ) -> Result<(), exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::xof_shake128_update(state_id, &data).map_err(to_wit_error)
    }

    fn squeeze(
        state_id: u64,
        out_len: u32,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::xof_shake128_squeeze(state_id, out_len).map_err(to_wit_error)
    }

    fn destroy(state_id: u64) {
        crypto_impl::xof_shake128_destroy(state_id)
    }

    fn init_with_domain(
        domain_sep: u8,
    ) -> Result<u64, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::xof_shake128_init_with_domain(domain_sep).map_err(to_wit_error)
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
        crypto_impl::xof_shake256_state_bytes()
    }

    fn hash(out_len: u32, message: Vec<u8>) -> Vec<u8> {
        crypto_impl::xof_shake256(&message, out_len)
    }

    fn init() -> Result<u64, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::xof_shake256_init().map_err(to_wit_error)
    }

    fn update(
        state_id: u64,
        data: Vec<u8>,
    ) -> Result<(), exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::xof_shake256_update(state_id, &data).map_err(to_wit_error)
    }

    fn squeeze(
        state_id: u64,
        out_len: u32,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::xof_shake256_squeeze(state_id, out_len).map_err(to_wit_error)
    }

    fn destroy(state_id: u64) {
        crypto_impl::xof_shake256_destroy(state_id)
    }

    fn init_with_domain(
        domain_sep: u8,
    ) -> Result<u64, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::xof_shake256_init_with_domain(domain_sep).map_err(to_wit_error)
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
        crypto_impl::xof_turboshake128_state_bytes()
    }

    fn hash(out_len: u32, message: Vec<u8>) -> Vec<u8> {
        crypto_impl::xof_turboshake128(&message, out_len)
    }

    fn init() -> Result<u64, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::xof_turboshake128_init().map_err(to_wit_error)
    }

    fn update(
        state_id: u64,
        data: Vec<u8>,
    ) -> Result<(), exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::xof_turboshake128_update(state_id, &data).map_err(to_wit_error)
    }

    fn squeeze(
        state_id: u64,
        out_len: u32,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::xof_turboshake128_squeeze(state_id, out_len).map_err(to_wit_error)
    }

    fn destroy(state_id: u64) {
        crypto_impl::xof_turboshake128_destroy(state_id)
    }

    fn init_with_domain(
        domain_sep: u8,
    ) -> Result<u64, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::xof_turboshake128_init_with_domain(domain_sep).map_err(to_wit_error)
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
        crypto_impl::xof_turboshake256_state_bytes()
    }

    fn hash(out_len: u32, message: Vec<u8>) -> Vec<u8> {
        crypto_impl::xof_turboshake256(&message, out_len)
    }

    fn init() -> Result<u64, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::xof_turboshake256_init().map_err(to_wit_error)
    }

    fn update(
        state_id: u64,
        data: Vec<u8>,
    ) -> Result<(), exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::xof_turboshake256_update(state_id, &data).map_err(to_wit_error)
    }

    fn squeeze(
        state_id: u64,
        out_len: u32,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::xof_turboshake256_squeeze(state_id, out_len).map_err(to_wit_error)
    }

    fn init_with_domain(
        domain_sep: u8,
    ) -> Result<u64, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::xof_turboshake256_init_with_domain(domain_sep).map_err(to_wit_error)
    }

    fn destroy(state_id: u64) {
        crypto_impl::xof_turboshake256_destroy(state_id)
    }
}

// ============================================================================
// Secretbox XChaCha20-Poly1305
// ============================================================================

impl exports::libsodium::crypto::secretbox_xchacha20poly1305::Guest for Component {
    fn key_bytes() -> u32 {
        crypto_impl::secretbox_xchacha20poly1305_key_bytes()
    }

    fn nonce_bytes() -> u32 {
        crypto_impl::secretbox_xchacha20poly1305_nonce_bytes()
    }

    fn mac_bytes() -> u32 {
        crypto_impl::secretbox_xchacha20poly1305_mac_bytes()
    }

    fn easy(
        message: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::secretbox_xchacha20poly1305_easy(&message, &nonce, &key).map_err(to_wit_error)
    }

    fn open_easy(
        ciphertext: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::secretbox_xchacha20poly1305_open_easy(&ciphertext, &nonce, &key)
            .map_err(to_wit_error)
    }

    fn detached(
        message: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<(Vec<u8>, Vec<u8>), exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::secretbox_xchacha20poly1305_detached(&message, &nonce, &key)
            .map_err(to_wit_error)
    }

    fn open_detached(
        ciphertext: Vec<u8>,
        mac: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::secretbox_xchacha20poly1305_open_detached(&ciphertext, &mac, &nonce, &key)
            .map_err(to_wit_error)
    }

    fn keygen() -> Vec<u8> {
        crypto_impl::secretbox_xchacha20poly1305_keygen()
    }
}

// ============================================================================
// Crypto Box XChaCha20-Poly1305
// ============================================================================

impl exports::libsodium::crypto::crypto_box_xchacha20poly1305::Guest for Component {
    fn public_key_bytes() -> u32 {
        crypto_impl::box_xchacha20poly1305_public_key_bytes()
    }

    fn secret_key_bytes() -> u32 {
        crypto_impl::box_xchacha20poly1305_secret_key_bytes()
    }

    fn nonce_bytes() -> u32 {
        crypto_impl::box_xchacha20poly1305_nonce_bytes()
    }

    fn mac_bytes() -> u32 {
        crypto_impl::box_xchacha20poly1305_mac_bytes()
    }

    fn seed_bytes() -> u32 {
        crypto_impl::box_xchacha20poly1305_seed_bytes()
    }

    fn seal_bytes() -> u32 {
        crypto_impl::box_xchacha20poly1305_seal_bytes()
    }

    fn keypair() -> exports::libsodium::crypto::types::KeyPair {
        let (pk, sk) = crypto_impl::box_xchacha20poly1305_keypair();
        exports::libsodium::crypto::types::KeyPair {
            public_key: pk,
            secret_key: sk,
        }
    }

    fn seed_keypair(
        seed: Vec<u8>,
    ) -> Result<
        exports::libsodium::crypto::types::KeyPair,
        exports::libsodium::crypto::types::CryptoError,
    > {
        let (pk, sk) =
            crypto_impl::box_xchacha20poly1305_seed_keypair(&seed).map_err(to_wit_error)?;
        Ok(exports::libsodium::crypto::types::KeyPair {
            public_key: pk,
            secret_key: sk,
        })
    }

    fn easy(
        message: Vec<u8>,
        nonce: Vec<u8>,
        recipient_pk: Vec<u8>,
        sender_sk: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::box_xchacha20poly1305_easy(&message, &nonce, &recipient_pk, &sender_sk)
            .map_err(to_wit_error)
    }

    fn open_easy(
        ciphertext: Vec<u8>,
        nonce: Vec<u8>,
        sender_pk: Vec<u8>,
        recipient_sk: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::box_xchacha20poly1305_open_easy(&ciphertext, &nonce, &sender_pk, &recipient_sk)
            .map_err(to_wit_error)
    }

    fn detached(
        message: Vec<u8>,
        nonce: Vec<u8>,
        recipient_pk: Vec<u8>,
        sender_sk: Vec<u8>,
    ) -> Result<(Vec<u8>, Vec<u8>), exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::box_xchacha20poly1305_detached(&message, &nonce, &recipient_pk, &sender_sk)
            .map_err(to_wit_error)
    }

    fn open_detached(
        ciphertext: Vec<u8>,
        mac: Vec<u8>,
        nonce: Vec<u8>,
        sender_pk: Vec<u8>,
        recipient_sk: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::box_xchacha20poly1305_open_detached(
            &ciphertext,
            &mac,
            &nonce,
            &sender_pk,
            &recipient_sk,
        )
        .map_err(to_wit_error)
    }

    fn beforenm(
        recipient_pk: Vec<u8>,
        sender_sk: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::box_xchacha20poly1305_beforenm(&recipient_pk, &sender_sk).map_err(to_wit_error)
    }

    fn easy_afternm(
        message: Vec<u8>,
        nonce: Vec<u8>,
        shared_key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::box_xchacha20poly1305_easy_afternm(&message, &nonce, &shared_key)
            .map_err(to_wit_error)
    }

    fn open_easy_afternm(
        ciphertext: Vec<u8>,
        nonce: Vec<u8>,
        shared_key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::box_xchacha20poly1305_open_easy_afternm(&ciphertext, &nonce, &shared_key)
            .map_err(to_wit_error)
    }

    fn seal(
        message: Vec<u8>,
        recipient_pk: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::box_xchacha20poly1305_seal(&message, &recipient_pk).map_err(to_wit_error)
    }

    fn seal_open(
        ciphertext: Vec<u8>,
        recipient_pk: Vec<u8>,
        recipient_sk: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::box_xchacha20poly1305_seal_open(&ciphertext, &recipient_pk, &recipient_sk)
            .map_err(to_wit_error)
    }

    fn beforenm_bytes() -> u32 {
        crypto_impl::box_xchacha20poly1305_beforenm_bytes()
    }

    fn detached_afternm(
        message: Vec<u8>,
        nonce: Vec<u8>,
        shared_key: Vec<u8>,
    ) -> Result<(Vec<u8>, Vec<u8>), exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::box_xchacha20poly1305_detached_afternm(&message, &nonce, &shared_key)
            .map_err(to_wit_error)
    }

    fn open_detached_afternm(
        ciphertext: Vec<u8>,
        mac: Vec<u8>,
        nonce: Vec<u8>,
        shared_key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::box_xchacha20poly1305_open_detached_afternm(
            &ciphertext,
            &mac,
            &nonce,
            &shared_key,
        )
        .map_err(to_wit_error)
    }
}

// ============================================================================
// IPCrypt
// ============================================================================

impl exports::libsodium::crypto::ipcrypt::Guest for Component {
    fn bytes() -> u32 {
        crypto_impl::ipcrypt_bytes()
    }

    fn key_bytes() -> u32 {
        crypto_impl::ipcrypt_key_bytes()
    }

    fn keygen() -> Vec<u8> {
        crypto_impl::ipcrypt_keygen()
    }

    fn encrypt(
        input: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::ipcrypt_encrypt(&input, &key).map_err(to_wit_error)
    }

    fn decrypt(
        input: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::ipcrypt_decrypt(&input, &key).map_err(to_wit_error)
    }

    fn ip2bin(ip: String) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::ip2bin(&ip).map_err(to_wit_error)
    }

    fn bin2ip(bin: Vec<u8>) -> Result<String, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::bin2ip(&bin).map_err(to_wit_error)
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

    fn nd_encrypt(
        input: Vec<u8>,
        tweak: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::ipcrypt_nd_encrypt(&input, &tweak, &key).map_err(to_wit_error)
    }

    fn nd_decrypt(
        ciphertext: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::ipcrypt_nd_decrypt(&ciphertext, &key).map_err(to_wit_error)
    }

    fn ndx_key_bytes() -> u32 {
        crypto_impl::ipcrypt_ndx_key_bytes()
    }

    fn ndx_tweak_bytes() -> u32 {
        crypto_impl::ipcrypt_ndx_tweak_bytes()
    }

    fn ndx_input_bytes() -> u32 {
        crypto_impl::ipcrypt_ndx_input_bytes()
    }

    fn ndx_output_bytes() -> u32 {
        crypto_impl::ipcrypt_ndx_output_bytes()
    }

    fn ndx_keygen() -> Vec<u8> {
        crypto_impl::ipcrypt_ndx_keygen()
    }

    fn ndx_encrypt(
        input: Vec<u8>,
        tweak: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::ipcrypt_ndx_encrypt(&input, &tweak, &key).map_err(to_wit_error)
    }

    fn ndx_decrypt(
        ciphertext: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::ipcrypt_ndx_decrypt(&ciphertext, &key).map_err(to_wit_error)
    }

    fn pfx_key_bytes() -> u32 {
        crypto_impl::ipcrypt_pfx_key_bytes()
    }

    fn pfx_bytes() -> u32 {
        crypto_impl::ipcrypt_pfx_bytes()
    }

    fn pfx_keygen() -> Vec<u8> {
        crypto_impl::ipcrypt_pfx_keygen()
    }

    fn pfx_encrypt(
        input: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::ipcrypt_pfx_encrypt(&input, &key).map_err(to_wit_error)
    }

    fn pfx_decrypt(
        input: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::ipcrypt_pfx_decrypt(&input, &key).map_err(to_wit_error)
    }
}

// ============================================================================
// Auth HMAC-SHA256
// ============================================================================

impl exports::libsodium::crypto::auth_hmacsha256::Guest for Component {
    fn bytes() -> u32 {
        crypto_impl::auth_hmacsha256_bytes()
    }

    fn key_bytes() -> u32 {
        crypto_impl::auth_hmacsha256_key_bytes()
    }

    fn keygen() -> Vec<u8> {
        crypto_impl::auth_hmacsha256_keygen()
    }

    fn auth(
        message: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::auth_hmacsha256(&message, &key).map_err(to_wit_error)
    }

    fn verify(
        tag: Vec<u8>,
        message: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<(), exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::auth_hmacsha256_verify(&tag, &message, &key).map_err(to_wit_error)
    }

    fn state_bytes() -> u32 {
        crypto_impl::auth_hmacsha256_state_bytes()
    }

    fn init(key: Vec<u8>) -> Result<u64, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::auth_hmacsha256_state_init(&key).map_err(to_wit_error)
    }

    fn update(
        state_id: u64,
        data: Vec<u8>,
    ) -> Result<(), exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::auth_hmacsha256_state_update(state_id, &data).map_err(to_wit_error)
    }

    fn final_(state_id: u64) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::auth_hmacsha256_state_final(state_id).map_err(to_wit_error)
    }

    fn destroy(state_id: u64) {
        crypto_impl::auth_hmacsha256_state_destroy(state_id);
    }
}

// ============================================================================
// Auth HMAC-SHA512
// ============================================================================

impl exports::libsodium::crypto::auth_hmacsha512::Guest for Component {
    fn bytes() -> u32 {
        crypto_impl::auth_hmacsha512_bytes()
    }

    fn key_bytes() -> u32 {
        crypto_impl::auth_hmacsha512_key_bytes()
    }

    fn keygen() -> Vec<u8> {
        crypto_impl::auth_hmacsha512_keygen()
    }

    fn auth(
        message: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::auth_hmacsha512(&message, &key).map_err(to_wit_error)
    }

    fn verify(
        tag: Vec<u8>,
        message: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<(), exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::auth_hmacsha512_verify(&tag, &message, &key).map_err(to_wit_error)
    }

    fn state_bytes() -> u32 {
        crypto_impl::auth_hmacsha512_state_bytes()
    }

    fn init(key: Vec<u8>) -> Result<u64, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::auth_hmacsha512_state_init(&key).map_err(to_wit_error)
    }

    fn update(
        state_id: u64,
        data: Vec<u8>,
    ) -> Result<(), exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::auth_hmacsha512_state_update(state_id, &data).map_err(to_wit_error)
    }

    fn final_(state_id: u64) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::auth_hmacsha512_state_final(state_id).map_err(to_wit_error)
    }

    fn destroy(state_id: u64) {
        crypto_impl::auth_hmacsha512_state_destroy(state_id);
    }
}

// ============================================================================
// HMAC-SHA512-256 Auth
// ============================================================================

impl exports::libsodium::crypto::auth_hmacsha512256::Guest for Component {
    fn bytes() -> u32 {
        crypto_impl::auth_hmacsha512256_bytes()
    }

    fn key_bytes() -> u32 {
        crypto_impl::auth_hmacsha512256_key_bytes()
    }

    fn keygen() -> Vec<u8> {
        crypto_impl::auth_hmacsha512256_keygen()
    }

    fn auth(
        message: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::auth_hmacsha512256(&message, &key).map_err(to_wit_error)
    }

    fn verify(
        tag: Vec<u8>,
        message: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<(), exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::auth_hmacsha512256_verify(&tag, &message, &key).map_err(to_wit_error)
    }

    fn state_bytes() -> u32 {
        crypto_impl::auth_hmacsha512256_state_bytes()
    }

    fn init(key: Vec<u8>) -> Result<u64, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::auth_hmacsha512256_state_init(&key).map_err(to_wit_error)
    }

    fn update(
        state_id: u64,
        data: Vec<u8>,
    ) -> Result<(), exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::auth_hmacsha512256_state_update(state_id, &data).map_err(to_wit_error)
    }

    fn final_(state_id: u64) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::auth_hmacsha512256_state_final(state_id).map_err(to_wit_error)
    }

    fn destroy(state_id: u64) {
        crypto_impl::auth_hmacsha512256_state_destroy(state_id);
    }
}

// ============================================================================
// Random Extended
// ============================================================================

impl exports::libsodium::crypto::random_extended::Guest for Component {
    fn seed_bytes() -> u32 {
        crypto_impl::random_seedbytes()
    }

    fn buf_deterministic(
        len: u32,
        seed: Vec<u8>,
    ) -> Result<Vec<u8>, exports::libsodium::crypto::types::CryptoError> {
        crypto_impl::random_buf_deterministic(len, &seed).map_err(to_wit_error)
    }
}

// ============================================================================
// Export all implementations
// ============================================================================

// The component struct that implements all interface Guest traits
struct Component;

// Export the component
export_libsodium!(Component);
