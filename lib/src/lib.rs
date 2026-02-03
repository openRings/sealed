//! Read and decrypt sealed environment variables.
//!
//! This crate mirrors the ergonomics of `std::env::var`, but understands values stored
//! in the `ENCv1:<base64(nonce)>:<base64(ciphertext)>` format. If a value is encrypted,
//! `SEALED_KEY` must be present in the environment for decryption.
//!
//! # Quick start
//! ```rust,no_run
//! use sealed_env::{var, var_or_plain, var_optional};
//!
//! std::env::set_var("SEALED_KEY", "<base64-key>");
//! std::env::set_var("DATABASE_PASSWORD", "ENCv1:...:...");
//!
//! let secret = var("DATABASE_PASSWORD")?;
//! let maybe_plain = var_or_plain("MAYBE_PLAINTEXT")?;
//! let optional = var_optional("OPTIONAL_SECRET")?;
//! # Ok::<(), sealed_env::SealedEnvError>(())
//! ```
//!
//! # Behavior summary
//! - `var`: requires the variable to be present and encrypted.
//! - `var_or_plain`: returns plaintext as-is if it is not encrypted.
//! - `var_optional`: returns `Ok(None)` if not set; otherwise decrypts if needed.
use base64::Engine as _;
use base64::engine::general_purpose;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use secrecy::{ExposeSecret, SecretSlice, SecretString};
use std::env;
use thiserror::Error;

/// Errors returned by `sealed-env`.
#[derive(Debug, Error)]
pub enum SealedEnvError {
    /// The requested environment variable is not set.
    #[error("{0}")]
    MissingVar(String),
    /// `SEALED_KEY` is missing from the environment.
    #[error("{0}")]
    MissingKey(String),
    /// The variable is set but does not start with `ENCv1:`.
    #[error("{0}")]
    NotEncrypted(String),
    /// Any cryptographic or decoding error.
    #[error("{0}")]
    Crypto(String),
}

/// Read an encrypted variable from the process environment.
///
/// This is the strict variant: the variable must be present and encrypted.
/// Use `var_or_plain` if you want plaintext values to pass through.
///
/// # Examples
/// ```rust,no_run
/// use sealed_env::var;
///
/// std::env::set_var("SEALED_KEY", "<base64-key>");
/// std::env::set_var("DATABASE_PASSWORD", "ENCv1:...:...");
///
/// let value = var("DATABASE_PASSWORD")?;
/// # Ok::<(), sealed_env::SealedEnvError>(())
/// ```
pub fn var(name: &str) -> Result<String, SealedEnvError> {
    let value = env::var(name).map_err(|_| {
        SealedEnvError::MissingVar(format!("environment variable '{}' is not set", name))
    })?;

    if !is_encrypted(&value) {
        return Err(SealedEnvError::NotEncrypted(format!(
            "environment variable '{}' is not encrypted",
            name
        )));
    }

    let key_b64 = env::var("SEALED_KEY")
        .map_err(|_| SealedEnvError::MissingKey("SEALED_KEY is not set".to_string()))?;

    let key = decode_key(&SecretString::from(key_b64))?;
    let decrypted = decrypt_value(&key, name, &value)?;

    String::from_utf8(decrypted.expose_secret().to_vec())
        .map_err(|_| SealedEnvError::Crypto("decrypted value is not valid UTF-8".to_string()))
}

/// Read a variable and return plaintext as-is if it is not encrypted.
///
/// # Examples
/// ```rust,no_run
/// use sealed_env::var_or_plain;
///
/// std::env::set_var("SEALED_KEY", "<base64-key>");
/// std::env::set_var("FEATURE_FLAG", "true");
///
/// let value = var_or_plain("FEATURE_FLAG")?;
/// # Ok::<(), sealed_env::SealedEnvError>(())
/// ```
pub fn var_or_plain(name: &str) -> Result<String, SealedEnvError> {
    let value = env::var(name).map_err(|_| {
        SealedEnvError::MissingVar(format!("environment variable '{}' is not set", name))
    })?;

    if !is_encrypted(&value) {
        return Ok(value);
    }

    let key_b64 = env::var("SEALED_KEY")
        .map_err(|_| SealedEnvError::MissingKey("SEALED_KEY is not set".to_string()))?;

    let key = decode_key(&SecretString::from(key_b64))?;
    let decrypted = decrypt_value(&key, name, &value)?;

    String::from_utf8(decrypted.expose_secret().to_vec())
        .map_err(|_| SealedEnvError::Crypto("decrypted value is not valid UTF-8".to_string()))
}

/// Read a variable, returning `Ok(None)` if it is not set.
///
/// If the variable exists and is encrypted, it will be decrypted. If it is not encrypted,
/// the plaintext is returned.
///
/// # Examples
/// ```rust,no_run
/// use sealed_env::var_optional;
///
/// std::env::set_var("SEALED_KEY", "<base64-key>");
///
/// let value = var_optional("OPTIONAL_SECRET")?;
/// # Ok::<(), sealed_env::SealedEnvError>(())
/// ```
pub fn var_optional(name: &str) -> Result<Option<String>, SealedEnvError> {
    let value = match env::var(name) {
        Ok(value) => value,
        Err(env::VarError::NotPresent) => return Ok(None),
        Err(_) => {
            return Err(SealedEnvError::MissingVar(format!(
                "environment variable '{}' is not set",
                name
            )));
        }
    };

    if !is_encrypted(&value) {
        return Ok(Some(value));
    }

    let key_b64 = env::var("SEALED_KEY")
        .map_err(|_| SealedEnvError::MissingKey("SEALED_KEY is not set".to_string()))?;

    let key = decode_key(&SecretString::from(key_b64))?;
    let decrypted = decrypt_value(&key, name, &value)?;

    String::from_utf8(decrypted.expose_secret().to_vec())
        .map_err(|_| SealedEnvError::Crypto("decrypted value is not valid UTF-8".to_string()))
        .map(Some)
}

fn decode_key(b64: &SecretString) -> Result<SecretSlice<u8>, SealedEnvError> {
    let decoded = general_purpose::STANDARD
        .decode(b64.expose_secret())
        .map_err(|_| SealedEnvError::Crypto("invalid base64 key".to_string()))?;

    if decoded.len() != 32 {
        return Err(SealedEnvError::Crypto(
            "key must be 32 bytes after base64 decode".to_string(),
        ));
    }

    Ok(SecretSlice::from(decoded))
}

fn decrypt_value(
    key: &SecretSlice<u8>,
    var_name: &str,
    encrypted: &str,
) -> Result<SecretSlice<u8>, SealedEnvError> {
    let (nonce, ciphertext) = parse_encrypted(encrypted)?;
    let key_bytes = key.expose_secret();

    if key_bytes.len() != 32 {
        return Err(SealedEnvError::Crypto(
            "key must be 32 bytes after base64 decode".to_string(),
        ));
    }

    let cipher = ChaCha20Poly1305::new(Key::from_slice(key_bytes));
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad: var_name.as_bytes(),
            },
        )
        .map_err(|_| SealedEnvError::Crypto("decryption failed (bad key or data)".to_string()))?;

    Ok(SecretSlice::from(plaintext))
}

fn parse_encrypted(value: &str) -> Result<(Vec<u8>, Vec<u8>), SealedEnvError> {
    let mut parts = value.splitn(3, ':');

    let tag = parts.next();
    let nonce_b64 = parts.next();
    let ct_b64 = parts.next();

    if tag != Some("ENCv1") || nonce_b64.is_none() || ct_b64.is_none() {
        return Err(SealedEnvError::Crypto(
            "invalid encrypted value format".to_string(),
        ));
    }

    let nonce = general_purpose::STANDARD
        .decode(nonce_b64.unwrap())
        .map_err(|_| SealedEnvError::Crypto("invalid base64 nonce".to_string()))?;

    if nonce.len() != 12 {
        return Err(SealedEnvError::Crypto(
            "nonce must be 12 bytes after base64 decode".to_string(),
        ));
    }

    let ciphertext = general_purpose::STANDARD
        .decode(ct_b64.unwrap())
        .map_err(|_| SealedEnvError::Crypto("invalid base64 ciphertext".to_string()))?;

    Ok((nonce, ciphertext))
}

fn is_encrypted(value: &str) -> bool {
    value.starts_with("ENCv1:")
}
