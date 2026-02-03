use base64::Engine as _;
use base64::engine::general_purpose;
use clap::Parser;
use rand::TryRngCore;
use rand::rngs::OsRng;
use secrecy::ExposeSecret;
use std::fs;
use zeroize::Zeroize;

use crate::cli::{Cli, Commands, GetArgs, KeygenArgs, SetArgs};
use crate::crypto::{decrypt_value, encrypt_value, is_encrypted};
use crate::envfile::{read_var, upsert_var};
use crate::error::SealedError;
use crate::input::{read_key, read_value, select_key_input};

mod cli;
mod crypto;
mod envfile;
mod error;
mod input;

fn main() {
    let code = match run() {
        Ok(()) => 0,
        Err(err) => {
            eprintln!("{}", err);
            err.exit_code()
        }
    };

    std::process::exit(code);
}

fn run() -> Result<(), SealedError> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Set(args) => run_set(args),
        Commands::Get(args) => run_get(args),
        Commands::Keygen(args) => run_keygen(args),
    }
}

fn run_set(args: SetArgs) -> Result<(), SealedError> {
    let mut args = args;

    if args.stdin && args.key_stdin {
        return Err(SealedError::Arg(
            "stdin may be used only once; --stdin and --key-stdin cannot be used together"
                .to_string(),
        ));
    }

    let plaintext = read_value(&mut args)?;
    let key_input =
        select_key_input(args.key, args.key_file, args.key_stdin)?.ok_or_else(|| {
            SealedError::Arg(
                "key required; provide --key, --key-file, --key-stdin, or set SEALED_KEY"
                    .to_string(),
            )
        })?;

    let key = read_key(key_input)?;
    let encrypted = encrypt_value(&key, &args.var_name, &plaintext)?;

    upsert_var(&args.env_file, &args.var_name, &encrypted)?;

    Ok(())
}

fn run_get(args: GetArgs) -> Result<(), SealedError> {
    let value = read_var(&args.env_file, &args.var_name)?.ok_or_else(|| {
        SealedError::VarNotFound(format!(
            "variable '{}' not found in {}",
            args.var_name,
            args.env_file.display()
        ))
    })?;

    if !is_encrypted(&value) {
        println!("{}", value);
        return Ok(());
    }

    let key_input = select_key_input(args.key, args.key_file, args.key_stdin)?;
    let key = match key_input {
        Some(input) => read_key(input)?,
        None => {
            return Err(SealedError::Crypto(
                "encrypted value requires a key; provide --key, --key-file, --key-stdin, or set SEALED_KEY".to_string(),
            ));
        }
    };

    let decrypted = decrypt_value(&key, &args.var_name, &value)?;

    if args.reveal {
        let plaintext = String::from_utf8(decrypted.expose_secret().to_vec())
            .map_err(|_| SealedError::Crypto("decrypted value is not valid UTF-8".to_string()))?;
        println!("{}", plaintext);
    } else {
        eprintln!("value is encrypted; use --reveal to print plaintext");
    }

    Ok(())
}

fn run_keygen(args: KeygenArgs) -> Result<(), SealedError> {
    let mut key = [0u8; 32];
    let mut rng = OsRng;
    rng.try_fill_bytes(&mut key)
        .map_err(|_| SealedError::Crypto("failed to generate key".to_string()))?;

    let b64 = general_purpose::STANDARD.encode(key);

    key.zeroize();

    if let Some(path) = args.out_file {
        fs::write(&path, format!("{}\n", b64)).map_err(|e| {
            SealedError::EnvFile(format!(
                "failed to write key file {}: {}",
                path.display(),
                e
            ))
        })?;
    } else {
        println!("{}", b64);
    }

    Ok(())
}
