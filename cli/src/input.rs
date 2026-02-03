use secrecy::{SecretSlice, SecretString};
use std::env;
use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;
use zeroize::Zeroize;

use crate::cli::SetArgs;
use crate::crypto::decode_key;
use crate::error::SealedError;

pub enum KeyInput {
    Direct(String),
    File(PathBuf),
    Stdin,
    Env(String),
}

pub fn read_value(args: &mut SetArgs) -> Result<SecretString, SealedError> {
    let mut count = 0;

    if args.stdin {
        count += 1;
    }
    if args.value.is_some() {
        count += 1;
    }
    if args.value_file.is_some() {
        count += 1;
    }

    if count != 1 {
        return Err(SealedError::Arg(
            "value required; choose exactly one of --stdin, --value (with --allow-argv), or --value-file".to_string(),
        ));
    }

    if args.value.is_some() && !args.allow_argv {
        return Err(SealedError::Arg(
            "--value requires --allow-argv".to_string(),
        ));
    }

    if args.stdin {
        let mut raw = read_stdin().map_err(SealedError::Arg)?;
        let trimmed = trim_end_newlines(&raw).to_string();
        raw.zeroize();
        return Ok(SecretString::from(trimmed));
    }

    if let Some(path) = &args.value_file {
        let mut raw = fs::read_to_string(path).map_err(|e| {
            SealedError::Arg(format!(
                "failed to read value file {}: {}",
                path.display(),
                e
            ))
        })?;
        let trimmed = trim_end_newlines(&raw).to_string();
        raw.zeroize();
        return Ok(SecretString::from(trimmed));
    }

    if let Some(value) = args.value.take() {
        return Ok(SecretString::from(value));
    }

    Err(SealedError::Arg(
        "value required; choose exactly one of --stdin, --value (with --allow-argv), or --value-file".to_string(),
    ))
}

pub fn select_key_input(
    key: Option<String>,
    key_file: Option<PathBuf>,
    key_stdin: bool,
) -> Result<Option<KeyInput>, SealedError> {
    let env_key = env::var("SEALED_KEY").ok().filter(|s| !s.is_empty());

    let mut count = 0;

    if key.is_some() {
        count += 1;
    }
    if key_file.is_some() {
        count += 1;
    }
    if key_stdin {
        count += 1;
    }
    if env_key.is_some() {
        count += 1;
    }

    if count > 1 {
        return Err(SealedError::Arg(
            "choose exactly one key source: --key, --key-file, --key-stdin, or SEALED_KEY"
                .to_string(),
        ));
    }

    if let Some(k) = key {
        return Ok(Some(KeyInput::Direct(k)));
    }
    if let Some(kf) = key_file {
        return Ok(Some(KeyInput::File(kf)));
    }
    if key_stdin {
        return Ok(Some(KeyInput::Stdin));
    }
    if let Some(ek) = env_key {
        return Ok(Some(KeyInput::Env(ek)));
    }

    Ok(None)
}

pub fn read_key(input: KeyInput) -> Result<SecretSlice<u8>, SealedError> {
    let b64 = match input {
        KeyInput::Direct(s) => SecretString::from(s),
        KeyInput::Env(s) => SecretString::from(s),
        KeyInput::File(path) => {
            let mut raw = fs::read_to_string(&path).map_err(|e| {
                SealedError::Arg(format!("failed to read key file {}: {}", path.display(), e))
            })?;
            let trimmed = trim_end_newlines(&raw).to_string();
            raw.zeroize();
            SecretString::from(trimmed)
        }
        KeyInput::Stdin => {
            let mut raw = read_stdin().map_err(SealedError::Arg)?;
            let trimmed = trim_end_newlines(&raw).to_string();
            raw.zeroize();
            SecretString::from(trimmed)
        }
    };

    decode_key(&b64)
}

fn read_stdin() -> Result<String, String> {
    let mut input = String::new();

    io::stdin()
        .read_to_string(&mut input)
        .map_err(|e| format!("failed to read stdin: {}", e))?;

    Ok(input)
}

fn trim_end_newlines(s: &str) -> &str {
    s.trim_end_matches(['\n', '\r'])
}
