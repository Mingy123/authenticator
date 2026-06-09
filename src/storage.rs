use std::{fs, path::PathBuf};

use serde::{Deserialize, Serialize};

use crate::{
    AuthenticatorApp, TotpEntry,
    algo_core::{decrypt, derive_key_from_password, encrypt},
};

#[derive(Serialize, Deserialize, Clone)]
pub struct SaveFile {
    pub filename: String,
    pub entries: Vec<TotpEntry>,
}

#[derive(Debug)]
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
    pub fn load_entries_encrypted(
        path: PathBuf,
        password: &str,
    ) -> Result<SaveFile, LoadSaveFileError> {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn test_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir()
            .join("authenticator_test")
            .join(name);
        let _ = fs::create_dir_all(&dir);
        dir
    }

    #[test]
    fn test_save_and_load_roundtrip() {
        let mut app = AuthenticatorApp::default();
        app.entries.push(TotpEntry {
            label: "GitHub".into(),
            secret: "JBSWY3DPEHPK3PXP".into(),
        });
        app.entries.push(TotpEntry {
            label: "Email".into(),
            secret: "GEZDGNBVGY3TQOJQ".into(),
        });

        let dir = test_dir("roundtrip");
        let path = dir.join("test_save.totp");

        app.save_entries_encrypted(path.clone(), "test-password")
            .expect("save should succeed");

        let saved = AuthenticatorApp::load_entries_encrypted(path.clone(), "test-password")
            .expect("load should succeed");

        assert_eq!(saved.entries.len(), 2);
        assert_eq!(saved.entries[0].label, "GitHub");
        assert_eq!(saved.entries[0].secret, "JBSWY3DPEHPK3PXP");
        assert_eq!(saved.entries[1].label, "Email");
        assert_eq!(saved.entries[1].secret, "GEZDGNBVGY3TQOJQ");

        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_load_non_existent_file() {
        let path = PathBuf::from("/tmp/does_not_exist_12345.totp");
        let result = AuthenticatorApp::load_entries_encrypted(path, "password");
        assert!(matches!(result, Err(LoadSaveFileError::NotFound(_))));
    }

    #[test]
    fn test_load_wrong_password() {
        let dir = test_dir("wrong_pw");
        let path = dir.join("test_wrong_pw.totp");

        let mut app = AuthenticatorApp::default();
        app.entries.push(TotpEntry {
            label: "test".into(),
            secret: "SECRET".into(),
        });
        app.save_entries_encrypted(path.clone(), "correct-password")
            .expect("save should succeed");

        let result = AuthenticatorApp::load_entries_encrypted(path.clone(), "wrong-password");
        assert!(matches!(result, Err(LoadSaveFileError::WrongPassword)));

        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir_all(&dir);
    }
}
