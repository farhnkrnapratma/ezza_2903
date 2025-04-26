// SPDX-License-Identifier: GPL-3.0-or-later

use clap::{Parser, Subcommand};
use ezza_2903::{Ezza2903, Ezza2903Error};
use std::fs;

#[derive(Parser)]
#[command(name = "Ezza2903")]
#[command(version = None)]
#[command(about = "CLI for encrypting and decrypting files with XChaCha20Poly1305", long_about = None)]
#[command(disable_version_flag = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    GenKey {
        #[arg(short, long)]
        out: String,
    },
    Encrypt {
        #[arg(short, long)]
        input: String,
        #[arg(short, long)]
        output: String,
        #[arg(short = 'k', long)]
        keyfile: String,
    },
    Decrypt {
        #[arg(short, long)]
        input: String,
        #[arg(short, long)]
        output: String,
        #[arg(short = 'k', long)]
        keyfile: String,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::GenKey { out } => {
            let key = Ezza2903::generate_key();
            fs::write(out, &*key)?;
            println!("Key successfully generated and saved to '{}'", out);
        }
        Commands::Encrypt {
            input,
            output,
            keyfile,
        } => {
            let plaintext = fs::read(input)?;
            let key = load_key(keyfile)?;
            let ciphertext =
                Ezza2903::encrypt(&key, &plaintext).map_err(|_| "Failed to encrypt the file")?;
            fs::write(output, &ciphertext)?;
            println!("Encrypted file saved to '{}'", output);
        }
        Commands::Decrypt {
            input,
            output,
            keyfile,
        } => {
            let ciphertext = fs::read(input)?;
            let key = load_key(keyfile)?;
            let plaintext =
                Ezza2903::decrypt(&key, &ciphertext).map_err(|_| "Failed to decrypt the file")?;
            fs::write(output, &plaintext)?;
            println!("File decrypted and saved to '{}'", output);
        }
    }

    Ok(())
}

fn load_key(path: &str) -> Result<[u8; 32], Ezza2903Error> {
    let key_data = fs::read(path).map_err(|_| Ezza2903Error::InvalidKey)?;
    if key_data.len() != 32 {
        return Err(Ezza2903Error::InvalidKey);
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&key_data);
    Ok(key)
}
