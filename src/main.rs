mod models;
mod crypto;
mod storage;

use clap::{Parser, Subcommand};
use crypto::CryptoHandler;
use models::{Vault, PasswordEntry};
use argon2::password_hash::SaltString;
use std::path::Path;

#[derive(Parser)]
#[command(name = "Vault")]
#[command(about = "A secure Rust-based password manager", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Add a new password entry (e.g., add github my_username)
    Add { 
        service: String, 
        username: String,
        /// Optional note for the entry
        #[arg(short, long)]
        note: Option<String> 
    },
    /// Retrieve a password by service name
    Get { service: String },
    /// List all services in the vault
    List {},
}

fn main() {
    let cli = Cli::parse();

    // 1. Get Master Password
    let mut master_password = rpassword::prompt_password("Enter Master Password: ")
        .expect("Failed to read password");

    // 2. Setup Salt and CryptoHandler
    let salt = SaltString::from_b64("staticsaltfordev").unwrap();
    let crypto = CryptoHandler::new(&mut master_password, &salt);

    // 3. Initialize or Load the Vault
    let mut vault = if Path::new(storage::VAULT_PATH).exists() {
        storage::load_vault(&crypto).expect("Decryption failed. Wrong password?")
    } else {
        Vault::new()
    };

    match &cli.command {
        Commands::Add { service, username, note } => {
            let password = rpassword::prompt_password(format!("Enter password for {}: ", service))
                .expect("Failed to read password");

            let new_entry = PasswordEntry {
                service: service.clone(),
                username: username.clone(),
                password,
                note: note.clone(),
            };

            vault.entries.push(new_entry);
            storage::save_vault(&vault, &crypto).expect("Failed to save vault");
            println!("✅ Successfully added {} to your vault.", service);
        }

        Commands::Get { service } => {
            if let Some(entry) = vault.entries.iter().find(|e| e.service == *service) {
                println!("--- {} ---", entry.service);
                println!("User:  {}", entry.username);
                println!("Pass:  {}", entry.password);
                if let Some(n) = &entry.note {
                    println!("Note:  {}", n);
                }
                println!("-------------");
            } else {
                println!("❌ No entry found for '{}'.", service);
            }
        }

        Commands::List {} => {
            println!("Vault (v{}) - {} entries:", vault.version, vault.entries.len());
            for entry in &vault.entries {
                println!(" • {}", entry.service);
            }
        }
    }
}