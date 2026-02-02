use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "Vault")]
#[command(about = "A secure CLI password manager", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Add a new password entry
    Add { name: String, username: String },
    /// Retrieve a password
    Get { name: String },
    /// List all saved services
    List {},
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Add { name, username } => {
            println!("Adding password for {} (user: {})", name, username);
            // TODO: Prompt for password securely and save
        }
        Commands::Get { name } => {
            println!("Searching for {}...", name);
            // TODO: Decrypt and retrieve
        }
        Commands::List {} => {
            println!("Listing all entries...");
        }
    }
}