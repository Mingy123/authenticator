use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::aead::OsRng;
use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256};
use totp_rs::{Algorithm, Secret, TOTP};

use crate::AuthenticatorApp;

impl AuthenticatorApp {
    pub fn generate_totp(&mut self) {
        if self.secret.trim().is_empty() {
            self.error_message_app = Some("Please enter a secret".to_string());
            return;
        }

        // Create TOTP instance with 30-second time step
        let secret = Secret::Encoded(self.secret.trim().to_string());
        let secret_bytes = match secret.to_bytes() {
            Ok(bytes) => bytes,
            Err(e) => {
                self.error_message_app = Some(format!("Invalid secret format: {}", e));
                return;
            }
        };

        let totp = TOTP::new_unchecked(Algorithm::SHA1, 6, 1, 30, secret_bytes);

        // Get current timestamp
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Generate TOTP code
        match totp.generate_current() {
            Ok(code) => {
                self.totp_code = code;
                self.last_update = now;
                self.error_message_app = None;
            }
            Err(e) => {
                self.error_message_app = Some(format!("Failed to generate TOTP: {}", e));
            }
        }
    }
}

pub fn encrypt(json: &str, key_bytes: &[u8; 32]) -> Result<(String, String), String> {
    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    match cipher.encrypt(nonce, json.as_bytes()) {
        Ok(ciphertext) => Ok((STANDARD.encode(ciphertext), STANDARD.encode(nonce_bytes))),
        Err(e) => Err(format!("Encryption failed: {:?}", e)),
    }
}

pub fn decrypt(cipher_b64: &str, nonce_b64: &str, key_bytes: &[u8; 32]) -> Result<String, String> {
    let cipher_bytes = STANDARD
        .decode(cipher_b64)
        .map_err(|e| format!("Base64 decode error: {}", e))?;
    let nonce_bytes = STANDARD
        .decode(nonce_b64)
        .map_err(|e| format!("Base64 decode error: {}", e))?;

    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let cipher = Aes256Gcm::new(key);

    cipher
        .decrypt(nonce, cipher_bytes.as_ref())
        .map_err(|e| format!("Decryption failed: {:?}", e))
        .and_then(|plain| String::from_utf8(plain).map_err(|e| format!("UTF8 error: {}", e)))
}

pub fn derive_key_from_password(password: &str) -> [u8; 32] {
    let result = Sha256::digest(password.as_bytes());
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_key_deterministic() {
        let key1 = derive_key_from_password("mypassword");
        let key2 = derive_key_from_password("mypassword");
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_derive_key_length() {
        let key = derive_key_from_password("anything");
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_derive_key_different_passwords() {
        let key1 = derive_key_from_password("password1");
        let key2 = derive_key_from_password("password2");
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = derive_key_from_password("test-password");
        let original = r#"{"hello":"world"}"#;
        let (ciphertext, nonce) = encrypt(original, &key).unwrap();
        let decrypted = decrypt(&ciphertext, &nonce, &key).unwrap();
        assert_eq!(decrypted, original);
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let correct_key = derive_key_from_password("correct");
        let wrong_key = derive_key_from_password("wrong");
        let (ciphertext, nonce) = encrypt("data", &correct_key).unwrap();
        assert!(decrypt(&ciphertext, &nonce, &wrong_key).is_err());
    }

    #[test]
    fn test_encrypt_produces_different_ciphertexts() {
        let key = derive_key_from_password("password");
        let (c1, _) = encrypt("same", &key).unwrap();
        let (c2, _) = encrypt("same", &key).unwrap();
        assert_ne!(c1, c2); // random nonce
    }

    #[test]
    fn test_generate_totp_empty_secret() {
        let mut app = crate::AuthenticatorApp::default();
        app.generate_totp();
        assert!(app.error_message_app.is_some());
    }

    #[test]
    fn test_generate_totp_valid_secret() {
        let mut app = crate::AuthenticatorApp::default();
        app.secret = "JBSWY3DPEHPK3PXP".into();
        app.generate_totp();
        assert_eq!(app.totp_code.len(), 6);
        assert!(app.totp_code.chars().all(|c| c.is_ascii_digit()));
        assert!(app.error_message_app.is_none());
    }

    #[test]
    fn test_generate_totp_invalid_secret() {
        let mut app = crate::AuthenticatorApp::default();
        app.secret = "!!invalid!!".into();
        app.generate_totp();
        assert!(app.error_message_app.is_some());
    }
}
