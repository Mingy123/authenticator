use std::{fs, path::PathBuf};

use serde::{Deserialize, Serialize};

use crate::{algo_core::{decrypt, derive_key_from_password, encrypt}, AuthenticatorApp, TotpEntry};


#[derive(Serialize, Deserialize, Clone)]
pub struct SaveFile {
  pub filename: String,
  pub entries: Vec<TotpEntry>,
}

pub enum LoadSaveFileError {
  NotFound(PathBuf),
  FileAccessError(PathBuf),
  WrongPassword,
}

impl ToString for LoadSaveFileError {
  fn to_string(&self) -> String {
    match self {
      Self::NotFound(path) => format!("File not found: {}", path.display()),
      Self::FileAccessError(path) => format!("Could not open file: {}", path.display()),
      Self::WrongPassword => String::from("Wrong password"),
    }
  }
}

impl AuthenticatorApp {

  pub fn load_entries_encrypted(path: PathBuf, password: &str) -> Result<SaveFile, LoadSaveFileError> {
    if !path.exists() {
      return Err(LoadSaveFileError::NotFound(path));
    }
    if let Ok(data) = fs::read_to_string(&path) {
      if let Ok(enc) = serde_json::from_str::<serde_json::Value>(&data) {
        if let (Some(cipher), Some(nonce)) = (enc.get("ciphertext"), enc.get("nonce")) {
          let cipher = cipher.as_str().unwrap_or("");
          let nonce = nonce.as_str().unwrap_or("");
          let key = derive_key_from_password(password);
          match decrypt(cipher, nonce, &key) {
            Ok(json) => {
              let entries = serde_json::from_str(&json).unwrap_or_default();
              return Ok(SaveFile {
                filename: path.file_name().unwrap().to_string_lossy().to_string(),
                entries,
              });
            }
            Err(_) => {
              // Wrong password
              return Err(LoadSaveFileError::WrongPassword);
            }
          }
        }
      }
    }
    Err(LoadSaveFileError::FileAccessError(path))
  }

  pub fn save_entries_encrypted(&self, path: PathBuf, password: &str) -> Result<(), String> {
    if let Ok(json) = serde_json::to_string_pretty(&self.entries) {
      let key = derive_key_from_password(password);
      if let Ok((cipher, nonce)) = encrypt(&json, &key) {
        let enc = serde_json::json!({
          "ciphertext": cipher,
          "nonce": nonce
        });
        if let Err(e) = fs::write(path, serde_json::to_string_pretty(&enc).unwrap()) {
          return Err(format!("Failed to write file: {}", e));
        }
      }
    }
    Ok(())
  }

}