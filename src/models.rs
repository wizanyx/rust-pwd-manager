use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[derive(Serialize, Deserialize, Debug, Zeroize)]
#[zeroize(drop)] // Automatically clears memory when the variable goes out of scope
pub struct PasswordEntry {
    pub service: String,
    pub username: String,
    pub password: String,
    pub note: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Vault {
    pub version: String,
    pub entries: Vec<PasswordEntry>,
}

impl Vault {
    pub fn new() -> Self {
        Self {
            version: "1.0".to_string(),
            entries: Vec::new(),
        }
    }
}