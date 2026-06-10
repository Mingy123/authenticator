use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::algo_core::{decrypt, derive_key_from_password, encrypt};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct TotpEntry {
    pub label: String,
    pub secret: String,
}

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

/// Serialize entries to an encrypted JSON file.
pub fn save_entries_encrypted(
    entries: &[TotpEntry],
    path: PathBuf,
    password: &str,
) -> Result<(), String> {
    let json = serde_json::to_string_pretty(entries)
        .map_err(|e| format!("JSON serialization failed: {}", e))?;
    let key = derive_key_from_password(password);
    let (cipher, nonce) = encrypt(&json, &key)?;
    let enc = serde_json::json!({
        "ciphertext": cipher,
        "nonce": nonce
    });
    let data = serde_json::to_string_pretty(&enc)
        .map_err(|e| format!("JSON serialization failed: {}", e))?;
    #[cfg(not(target_arch = "wasm32"))]
    {
        std::fs::write(&path, data).map_err(|e| format!("Failed to write file: {}", e))?;
    }
    // Web: not supported for file write (could use IndexedDB or download)
    Ok(())
}

/// Deserialize entries from an encrypted JSON file.
pub fn load_entries_encrypted(
    path: PathBuf,
    password: &str,
) -> Result<SaveFile, LoadSaveFileError> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        use std::fs;
        if !path.exists() {
            return Err(LoadSaveFileError::NotFound(path));
        }
        let data = fs::read_to_string(&path)
            .map_err(|_| LoadSaveFileError::FileAccessError(path.clone()))?;
        let enc: serde_json::Value = serde_json::from_str(&data)
            .map_err(|_| LoadSaveFileError::FileAccessError(path.clone()))?;
        let cipher = enc["ciphertext"].as_str().unwrap_or("");
        let nonce = enc["nonce"].as_str().unwrap_or("");
        let key = derive_key_from_password(password);
        match decrypt(cipher, nonce, &key) {
            Ok(json) => {
                let entries = serde_json::from_str(&json).unwrap_or_default();
                Ok(SaveFile {
                    filename: path.file_name().unwrap().to_string_lossy().to_string(),
                    entries,
                })
            }
            Err(_) => Err(LoadSaveFileError::WrongPassword),
        }
    }
    #[cfg(target_arch = "wasm32")]
    {
        Err(LoadSaveFileError::FileAccessError(path))
    }
}

/// Serialize entries to encrypted JSON bytes (for web download/IndexedDB).
pub fn serialize_encrypted(entries: &[TotpEntry], password: &str) -> Result<Vec<u8>, String> {
    let json = serde_json::to_string_pretty(entries)
        .map_err(|e| format!("JSON serialization failed: {}", e))?;
    let key = derive_key_from_password(password);
    let (cipher, nonce) = encrypt(&json, &key)?;
    let enc = serde_json::json!({
        "ciphertext": cipher,
        "nonce": nonce
    });
    let data = serde_json::to_string_pretty(&enc)
        .map_err(|e| format!("JSON serialization failed: {}", e))?;
    Ok(data.into_bytes())
}

/// Deserialize entries from encrypted JSON bytes (for web upload/IndexedDB).
pub fn deserialize_encrypted(data: &[u8], password: &str) -> Result<Vec<TotpEntry>, String> {
    let data = String::from_utf8(data.to_vec()).map_err(|e| format!("Invalid UTF-8: {}", e))?;
    let enc: serde_json::Value =
        serde_json::from_str(&data).map_err(|e| format!("Invalid JSON: {}", e))?;
    let cipher = enc["ciphertext"].as_str().unwrap_or("");
    let nonce = enc["nonce"].as_str().unwrap_or("");
    let key = derive_key_from_password(password);
    let json = decrypt(cipher, nonce, &key)
        .map_err(|_| "Failed to decrypt - wrong password?".to_string())?;
    let entries: Vec<TotpEntry> =
        serde_json::from_str(&json).map_err(|e| format!("Failed to parse entries: {}", e))?;
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join("authenticator_test").join(name);
        let _ = std::fs::create_dir_all(&dir);
        dir
    }

    #[test]
    fn test_save_and_load_roundtrip() {
        let entries = vec![
            TotpEntry {
                label: "GitHub".into(),
                secret: "JBSWY3DPEHPK3PXP".into(),
            },
            TotpEntry {
                label: "Email".into(),
                secret: "GEZDGNBVGY3TQOJQ".into(),
            },
        ];

        let dir = test_dir("roundtrip");
        let path = dir.join("test_save.totp");

        save_entries_encrypted(&entries, path.clone(), "test-password")
            .expect("save should succeed");

        let saved =
            load_entries_encrypted(path.clone(), "test-password").expect("load should succeed");

        assert_eq!(saved.entries.len(), 2);
        assert_eq!(saved.entries[0].label, "GitHub");
        assert_eq!(saved.entries[0].secret, "JBSWY3DPEHPK3PXP");
        assert_eq!(saved.entries[1].label, "Email");
        assert_eq!(saved.entries[1].secret, "GEZDGNBVGY3TQOJQ");

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_load_non_existent_file() {
        let path = PathBuf::from("/tmp/does_not_exist_12345.totp");
        let result = load_entries_encrypted(path, "password");
        assert!(matches!(result, Err(LoadSaveFileError::NotFound(_))));
    }

    #[test]
    fn test_load_wrong_password() {
        let dir = test_dir("wrong_pw");
        let path = dir.join("test_wrong_pw.totp");

        let entries = vec![TotpEntry {
            label: "test".into(),
            secret: "SECRET".into(),
        }];
        save_entries_encrypted(&entries, path.clone(), "correct-password")
            .expect("save should succeed");

        let result = load_entries_encrypted(path.clone(), "wrong-password");
        assert!(matches!(result, Err(LoadSaveFileError::WrongPassword)));

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_serialize_deserialize_roundtrip() {
        let entries = vec![
            TotpEntry {
                label: "GitHub".into(),
                secret: "JBSWY3DPEHPK3PXP".into(),
            },
            TotpEntry {
                label: "Email".into(),
                secret: "GEZDGNBVGY3TQOJQ".into(),
            },
        ];

        let serialized = serialize_encrypted(&entries, "test-password").unwrap();
        let loaded = deserialize_encrypted(&serialized, "test-password").unwrap();

        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].label, "GitHub");
        assert_eq!(loaded[0].secret, "JBSWY3DPEHPK3PXP");
    }

    #[test]
    fn test_deserialize_wrong_password() {
        let entries = vec![TotpEntry {
            label: "test".into(),
            secret: "SECRET".into(),
        }];

        let serialized = serialize_encrypted(&entries, "correct-password").unwrap();
        let result = deserialize_encrypted(&serialized, "wrong-password");
        assert!(result.is_err());
    }
}
