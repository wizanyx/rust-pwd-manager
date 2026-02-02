use clap::{Parser, Subcommand};

use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2
};

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};

use zeroize::Zeroize;

pub struct CryptoHandler {
    cipher: Aes256Gcm
}

impl CryptoHandler {
    pub fn new() -> Self {
        let mut derived_key = [0u8; 32];
        let argon2 = Argon2::default();

        // Derive the key
        argon2
            .hash_password(master_password.as_bytes(), salt)
            .expect("Failed to hash password")
            .serialize_hash() // Simplification for the example
            .as_bytes()[..32]
            .copy_from_slice(&mut derived_key);

        let cipher = Aes256Gcm::new_from_slice(&derived_key).expect("Invalid key length");

        // Security: Zero out the derived key from RAM
        derived_key.zeroize();
        Self { cipher }
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bits
        let mut ciphertext = self.cipher
            .encrypt(&nonce, plaintext)
            .expect("Encryption failure");

        // Prepend nonce to ciphertext so we have it for decryption later
        let mut final_data = nonce.to_vec();
        final_data.append(&mut ciphertext);
        final_data
    }

    pub fn decrypt(&self, encrypted_data: &[u8]) -> Vec<u8> {
        let (nonce_part, ciphertext) = encrypted_data.split_at(12);
        let nonce = Nonce::from_slice(nonce_part);

        self.cipher
            .decrypt(nonce, ciphertext)
            .expect("Decryption failure - wrong password or corrupted data")
    }
}