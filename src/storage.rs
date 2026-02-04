use std::fs::File;
use std::io::{Read, Write};
use crate::models::Vault;
use crate::crypto::CryptoHandler;

pub const VAULT_PATH: &str = "vault.json.enc";

pub fn save_vault(vault: &Vault, crypto: &CryptoHandler) -> std::io::Result<()> {
    // 1. Serialize the Vault struct to a JSON string
    let json = serde_json::to_string(vault).expect("Failed to serialize vault");
    
    // 2. Encrypt the JSON string
    let encrypted_data = crypto.encrypt(json.as_bytes());
    
    // 3. Write to file
    let mut file = File::create(VAULT_PATH)?;
    file.write_all(&encrypted_data)?;
    Ok(())
}

pub fn load_vault(crypto: &CryptoHandler) -> std::io::Result<Vault> {
    let mut file = File::open(VAULT_PATH)?;
    let mut encrypted_data = Vec::new();
    file.read_to_end(&mut encrypted_data)?;
    
    // 1. Decrypt the data
    let decrypted_data = crypto.decrypt(&encrypted_data);
    
    // 2. Deserialize back into a Vault struct
    let vault: Vault = serde_json::from_slice(&decrypted_data)
        .expect("Failed to parse vault - check master password");
        
    Ok(vault)
}