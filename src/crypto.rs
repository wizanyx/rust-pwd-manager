use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2, Params,
};
use zeroize::Zeroize;

pub struct CryptoHandler {
    cipher: Aes256Gcm,
}

impl CryptoHandler {
    pub fn new(master_password: &mut String, salt: &SaltString) -> Self {
        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            Params::default(),
        );

        let password_hash = argon2
            .hash_password(master_password.as_bytes(), salt)
            .expect("Failed to hash password");

        let mut derived_key = [0u8; 32];
        let hash_bytes = password_hash.hash.expect("Hash output missing");
        derived_key.copy_from_slice(&hash_bytes.as_bytes()[..32]);

        let cipher = Aes256Gcm::new_from_slice(&derived_key).expect("Invalid key length");
        derived_key.zeroize();

        Self { cipher }
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng); 
        
        let mut ciphertext = self.cipher
            .encrypt(&nonce, plaintext)
            .expect("Encryption failure");

        let mut final_data = nonce.to_vec();
        final_data.append(&mut ciphertext);
        final_data
    }

    pub fn decrypt(&self, encrypted_data: &[u8]) -> Vec<u8> {
        // AES-GCM nonces are 12 bytes (96 bits)
        if encrypted_data.len() < 12 {
            panic!("Encrypted data is too short");
        }

        let (nonce_part, ciphertext) = encrypted_data.split_at(12);
        let nonce = Nonce::from_slice(nonce_part);

        self.cipher
            .decrypt(nonce, ciphertext)
            .expect("Decryption failure - wrong password or corrupted data")
    }
}