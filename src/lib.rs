// SPDX-License-Identifier: GPL-3.0-or-later

use aead::{Aead, KeyInit, OsRng, rand_core::RngCore};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use std::fmt;
use xchacha20poly1305::{Key, XChaCha20Poly1305 as Cipher, XNonce};
use zeroize::Zeroizing;

#[derive(Debug)]
pub enum Ezza2903Error {
    EncryptionFailed,
    DecryptionFailed,
    InvalidKey,
}

impl fmt::Display for Ezza2903Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Ezza2903Error::EncryptionFailed => write!(f, "Encryption failed"),
            Ezza2903Error::DecryptionFailed => write!(f, "Decryption failed"),
            Ezza2903Error::InvalidKey => write!(f, "Invalid key"),
        }
    }
}

impl std::error::Error for Ezza2903Error {}

pub struct Ezza2903;

impl Ezza2903 {
    #[must_use]
    pub fn generate_key() -> Zeroizing<[u8; 32]> {
        let mut key = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(&mut *key);
        key
    }

    pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, Ezza2903Error> {
        let cipher = Cipher::new(Key::from_slice(key));
        let mut nonce_bytes = [0u8; 24];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);

        let mut out = Vec::with_capacity(24 + plaintext.len() + 16);
        out.extend_from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| Ezza2903Error::EncryptionFailed)?;

        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    pub fn decrypt(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, Ezza2903Error> {
        if data.len() < 24 + 16 {
            return Err(Ezza2903Error::DecryptionFailed);
        }
        let (nonce_bytes, ciphertext) = data.split_at(24);
        let cipher = Cipher::new(Key::from_slice(key));
        let nonce = XNonce::from_slice(nonce_bytes);

        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| Ezza2903Error::DecryptionFailed)
    }

    pub fn encrypt_base64(key: &[u8; 32], plaintext: &[u8]) -> Result<String, Ezza2903Error> {
        let raw = Self::encrypt(key, plaintext)?;
        Ok(URL_SAFE_NO_PAD.encode(&raw))
    }

    pub fn decrypt_base64(key: &[u8; 32], b64: &str) -> Result<Vec<u8>, Ezza2903Error> {
        let raw = URL_SAFE_NO_PAD
            .decode(b64)
            .map_err(|_| Ezza2903Error::DecryptionFailed)?;
        Self::decrypt(key, &raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cycle() {
        let key = Ezza2903::generate_key();
        let msg = b"Secure EZZA-2903";

        let raw = Ezza2903::encrypt(&key, msg).unwrap();
        let dec = Ezza2903::decrypt(&key, &raw).unwrap();
        assert_eq!(msg, &dec[..]);

        let b64 = Ezza2903::encrypt_base64(&key, msg).unwrap();
        let dec2 = Ezza2903::decrypt_base64(&key, &b64).unwrap();
        assert_eq!(msg, &dec2[..]);
    }
}
