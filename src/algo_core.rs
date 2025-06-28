use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::OsRng;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use totp_rs::{Algorithm, Secret, TOTP};
use sha2::{Digest, Sha256};

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
    
    let totp = TOTP::new_unchecked(
      Algorithm::SHA1,
      6,
      1,
      30,
      secret_bytes,
    );

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
    Ok(ciphertext) => {
      Ok((
        STANDARD.encode(ciphertext),
        STANDARD.encode(nonce_bytes)
      ))
    }
    Err(e) => Err(format!("Encryption failed: {:?}", e))
  }
}

pub fn decrypt(cipher_b64: &str, nonce_b64: &str, key_bytes: &[u8; 32]) -> Result<String, String> {
  let cipher_bytes = STANDARD.decode(cipher_b64).map_err(|e| format!("Base64 decode error: {}", e))?;
  let nonce_bytes = STANDARD.decode(nonce_b64).map_err(|e| format!("Base64 decode error: {}", e))?;

  let key = Key::<Aes256Gcm>::from_slice(key_bytes);
  let nonce = Nonce::from_slice(&nonce_bytes);
  let cipher = Aes256Gcm::new(key);

  cipher.decrypt(nonce, cipher_bytes.as_ref())
    .map_err(|e| format!("Decryption failed: {:?}", e))
    .and_then(|plain| String::from_utf8(plain).map_err(|e| format!("UTF8 error: {}", e)))
}

pub fn derive_key_from_password(password: &str) -> [u8; 32] {
  let result = Sha256::digest(password.as_bytes());
  let mut key = [0u8; 32];
  key.copy_from_slice(&result);
  key
}
