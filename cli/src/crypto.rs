use base64::Engine as _;
use base64::engine::general_purpose;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::TryRngCore;
use rand::rngs::OsRng;
use secrecy::{ExposeSecret, SecretSlice, SecretString};

use crate::error::SealedError;

pub fn decode_key(b64: &SecretString) -> Result<SecretSlice<u8>, SealedError> {
    let decoded = general_purpose::STANDARD
        .decode(b64.expose_secret())
        .map_err(|_| SealedError::Crypto("invalid base64 key".to_string()))?;

    if decoded.len() != 32 {
        return Err(SealedError::Crypto(
            "key must be 32 bytes after base64 decode".to_string(),
        ));
    }

    Ok(SecretSlice::from(decoded))
}

pub fn encrypt_value(
    key: &SecretSlice<u8>,
    var_name: &str,
    plaintext: &SecretString,
) -> Result<String, SealedError> {
    let key_bytes = key.expose_secret();
    if key_bytes.len() != 32 {
        return Err(SealedError::Crypto(
            "key must be 32 bytes after base64 decode".to_string(),
        ));
    }

    let cipher = ChaCha20Poly1305::new(Key::from_slice(key_bytes));

    let mut nonce = [0u8; 12];
    let mut rng = OsRng;
    rng.try_fill_bytes(&mut nonce)
        .map_err(|_| SealedError::Crypto("failed to generate nonce".to_string()))?;

    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext.expose_secret().as_bytes(),
                aad: var_name.as_bytes(),
            },
        )
        .map_err(|_| SealedError::Crypto("encryption failed".to_string()))?;

    let nonce_b64 = general_purpose::STANDARD.encode(nonce);
    let ct_b64 = general_purpose::STANDARD.encode(ciphertext);

    Ok(format!("ENCv1:{}:{}", nonce_b64, ct_b64))
}

pub fn decrypt_value(
    key: &SecretSlice<u8>,
    var_name: &str,
    encrypted: &str,
) -> Result<SecretSlice<u8>, SealedError> {
    let (nonce, ciphertext) = parse_encrypted(encrypted)?;
    let key_bytes = key.expose_secret();

    if key_bytes.len() != 32 {
        return Err(SealedError::Crypto(
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
        .map_err(|_| SealedError::Crypto("decryption failed (bad key or data)".to_string()))?;

    Ok(SecretSlice::from(plaintext))
}

pub fn parse_encrypted(value: &str) -> Result<(Vec<u8>, Vec<u8>), SealedError> {
    let mut parts = value.splitn(3, ':');

    let tag = parts.next();
    let nonce_b64 = parts.next();
    let ct_b64 = parts.next();

    if tag != Some("ENCv1") || nonce_b64.is_none() || ct_b64.is_none() {
        return Err(SealedError::Crypto(
            "invalid encrypted value format".to_string(),
        ));
    }

    let nonce = general_purpose::STANDARD
        .decode(nonce_b64.unwrap())
        .map_err(|_| SealedError::Crypto("invalid base64 nonce".to_string()))?;

    if nonce.len() != 12 {
        return Err(SealedError::Crypto(
            "nonce must be 12 bytes after base64 decode".to_string(),
        ));
    }

    let ciphertext = general_purpose::STANDARD
        .decode(ct_b64.unwrap())
        .map_err(|_| SealedError::Crypto("invalid base64 ciphertext".to_string()))?;

    Ok((nonce, ciphertext))
}

pub fn is_encrypted(value: &str) -> bool {
    value.starts_with("ENCv1:")
}
