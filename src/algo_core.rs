use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256};
use totp_rs::{Algorithm, Secret, TOTP};

/// Derive a 256-bit key from a password using SHA-256.
pub fn derive_key_from_password(password: &str) -> [u8; 32] {
    let result = Sha256::digest(password.as_bytes());
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

/// Encrypt plaintext JSON with AES-256-GCM.
/// Returns (base64_ciphertext, base64_nonce).
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

/// Decrypt AES-256-GCM ciphertext.
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

/// Generate a TOTP code from a base32-encoded secret.
pub fn generate_totp_code(secret: &str) -> Result<String, String> {
    let secret_obj = Secret::Encoded(secret.trim().to_string());
    let secret_bytes = secret_obj
        .to_bytes()
        .map_err(|e| format!("Invalid secret format: {}", e))?;

    let totp = TOTP::new_unchecked(Algorithm::SHA1, 6, 1, 30, secret_bytes);
    totp.generate_current()
        .map_err(|e| format!("Failed to generate TOTP: {}", e))
}

/// Get seconds remaining in the current 30-second TOTP window.
pub fn get_time_remaining() -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    30 - (now % 30)
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
    fn test_generate_totp_valid_secret() {
        let code = generate_totp_code("JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_generate_totp_invalid_secret() {
        assert!(generate_totp_code("!!invalid!!").is_err());
    }

    #[test]
    fn test_get_time_remaining_range() {
        let remaining = get_time_remaining();
        assert!(remaining < 30);
    }
}
