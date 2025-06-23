#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")] // hide console

use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::OsRng;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use eframe::egui;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use totp_rs::{Algorithm, Secret, TOTP};
use sha2::{Digest, Sha256};

#[derive(Serialize, Deserialize, Clone)]
struct TotpEntry {
    label: String,
    secret: String,
}

struct AuthenticatorApp {
    secret: String,
    totp_code: String,
    last_update: u64,
    error_message: Option<String>,
    entries: Vec<TotpEntry>,
    selected_entry: Option<usize>,
    new_entry_label: String,
    new_entry_secret: String,
    password: String,
    password_confirm: String,
    is_authenticated: bool,
    needs_new_password: bool,
    encrypted_error: Option<String>,
    pending_delete: Option<usize>,
}

impl Default for AuthenticatorApp {
    fn default() -> Self {
        let (needs_new_password, entries) = Self::try_load_encrypted_entries(None);
        Self {
            secret: String::new(),
            totp_code: String::new(),
            last_update: 0,
            error_message: None,
            entries,
            selected_entry: None,
            new_entry_label: String::new(),
            new_entry_secret: String::new(),
            password: String::new(),
            password_confirm: String::new(),
            is_authenticated: false,
            needs_new_password,
            encrypted_error: None,
            pending_delete: None,
        }
    }
}

impl AuthenticatorApp {
    fn entries_file_path() -> PathBuf {
        let mut path = dirs_next::config_dir().unwrap_or_else(|| PathBuf::from("."));
        path.push("authenticator");
        std::fs::create_dir_all(&path).expect("Failed to create config directory");
        path.push("totp_entries_encrypted.json");
        path
    }

    fn try_load_encrypted_entries(password: Option<&str>) -> (bool, Vec<TotpEntry>) {
        let path = Self::entries_file_path();
        if !path.exists() {
            // No file: need new password
            return (true, Vec::new());
        }
        if let Some(password) = password {
            if let Ok(data) = fs::read_to_string(&path) {
                if let Ok(enc) = serde_json::from_str::<serde_json::Value>(&data) {
                    if let (Some(cipher), Some(nonce)) = (enc.get("ciphertext"), enc.get("nonce")) {
                        let cipher = cipher.as_str().unwrap_or("");
                        let nonce = nonce.as_str().unwrap_or("");
                        let key = derive_key_from_password(password);
                        match decrypt(cipher, nonce, &key) {
                            Ok(json) => {
                                let entries = serde_json::from_str(&json).unwrap_or_default();
                                return (false, entries);
                            }
                            Err(_) => {
                                // Wrong password
                                return (false, Vec::new());
                            }
                        }
                    }
                }
            }
        }
        (false, Vec::new())
    }

    fn save_entries_encrypted(&self, password: &str) {
        let path = Self::entries_file_path();
        if let Ok(json) = serde_json::to_string_pretty(&self.entries) {
            let key = derive_key_from_password(password);
            if let Ok((cipher, nonce)) = encrypt(&json, &key) {
                let enc = serde_json::json!({
                    "ciphertext": cipher,
                    "nonce": nonce
                });
                let _ = fs::write(path, serde_json::to_string_pretty(&enc).unwrap());
            }
        }
    }

    fn add_entry(&mut self, label: String, secret: String) {
        self.entries.push(TotpEntry { label, secret });
        if self.is_authenticated {
            self.save_entries_encrypted(&self.password);
        }
    }

    fn remove_entry(&mut self, index: usize) {
        if index < self.entries.len() {
            self.entries.remove(index);
            if self.is_authenticated {
                self.save_entries_encrypted(&self.password);
            }
        }
    }

    fn select_entry(&mut self, index: usize) {
        if let Some(entry) = self.entries.get(index) {
            self.secret = entry.secret.clone();
            self.selected_entry = Some(index);
            self.generate_totp();
        }
    }

    fn generate_totp(&mut self) {
        if self.secret.trim().is_empty() {
            self.error_message = Some("Please enter a secret".to_string());
            return;
        }

        // Create TOTP instance with 30-second time step
        let secret = Secret::Encoded(self.secret.trim().to_string());
        let secret_bytes = match secret.to_bytes() {
            Ok(bytes) => bytes,
            Err(e) => {
                self.error_message = Some(format!("Invalid secret format: {}", e));
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
                self.error_message = None;
            }
            Err(e) => {
                self.error_message = Some(format!("Failed to generate TOTP: {}", e));
            }
        }
    }

    fn get_time_remaining(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        30 - (now % 30)
    }
}

impl eframe::App for AuthenticatorApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Password prompt UI
        if !self.is_authenticated {
            egui::CentralPanel::default().show(ctx, |ui| {
                ui.heading("TOTP Authenticator - Locked");
                ui.add_space(10.0);
                if self.needs_new_password {
                    ui.label("Set a new password:");
                    let resp_pw = ui.add(egui::TextEdit::singleline(&mut self.password).password(true));
                    ui.label("Confirm password:");
                    let resp_confirm = ui.add(egui::TextEdit::singleline(&mut self.password_confirm).password(true));
                    let mut set_password = false;
                    if ui.button("Set Password").clicked() {
                        set_password = true;
                    }
                    if (resp_pw.lost_focus() || resp_confirm.lost_focus()) && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                        set_password = true;
                    }
                    if set_password {
                        if self.password.is_empty() {
                            self.encrypted_error = Some("Password cannot be empty".to_string());
                        } else if self.password != self.password_confirm {
                            self.encrypted_error = Some("Passwords do not match".to_string());
                        } else {
                            self.is_authenticated = true;
                            self.save_entries_encrypted(&self.password);
                        }
                    }
                } else {
                    ui.label("Enter password:");
                    let resp_pw = ui.add(egui::TextEdit::singleline(&mut self.password).password(true));
                    let mut unlock = false;
                    if ui.button("Unlock").clicked() {
                        unlock = true;
                    }
                    if resp_pw.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                        unlock = true;
                    }
                    if unlock {
                        let (_, entries) = Self::try_load_encrypted_entries(Some(&self.password));
                        if !entries.is_empty() {
                            self.entries = entries;
                            self.is_authenticated = true;
                            self.encrypted_error = None;
                        } else {
                            self.encrypted_error = Some("Incorrect password or corrupted file".to_string());
                        }
                    }
                }
                if let Some(err) = &self.encrypted_error {
                    ui.add_space(10.0);
                    ui.colored_label(egui::Color32::RED, err);
                }
            });
            return;
        }

        let mut add_label: Option<String> = None;
        let mut add_secret: Option<String> = None;
        let mut clear_fields = false;
        let mut new_entry_label = self.new_entry_label.clone();
        let mut new_entry_secret = self.new_entry_secret.clone();
        let mut select_index: Option<usize> = None;
        egui::SidePanel::left("totp_menu").show(ctx, |ui| {
            ui.heading("Accounts");
            ui.add_space(10.0);
            for (i, entry) in self.entries.iter().enumerate() {
                let selected = self.selected_entry == Some(i);
                if ui.selectable_label(selected, &entry.label).clicked() {
                    if selected {
                        // Deselect if already selected
                        self.selected_entry = None;
                        self.secret.clear();
                        self.totp_code.clear();
                    } else {
                        select_index = Some(i);
                    }
                }
            }
            ui.add_space(10.0);
            ui.separator();
            ui.label("Add new account:");
            ui.label("Label:");
            let resp_label = ui.text_edit_singleline(&mut new_entry_label);
            ui.label("Secret:");
            let resp_secret = ui.text_edit_singleline(&mut new_entry_secret);
            let mut add_clicked = false;
            if ui.button("Add").clicked() {
                add_clicked = true;
            }
            if (resp_label.lost_focus() || resp_secret.lost_focus()) && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                add_clicked = true;
            }
            if add_clicked {
                if !new_entry_label.trim().is_empty() && !new_entry_secret.trim().is_empty() {
                    // Validate secret before adding
                    let secret = totp_rs::Secret::Encoded(new_entry_secret.trim().to_string());
                    match secret.to_bytes() {
                        Ok(secret_bytes) => {
                            let totp = totp_rs::TOTP::new_unchecked(
                                totp_rs::Algorithm::SHA1,
                                6,
                                1,
                                30,
                                secret_bytes,
                            );
                            match totp.generate_current() {
                                Ok(_) => {
                                    add_label = Some(new_entry_label.trim().to_string());
                                    add_secret = Some(new_entry_secret.trim().to_string());
                                    clear_fields = true;
                                    self.error_message = None;
                                }
                                Err(e) => {
                                    self.error_message = Some(format!("Invalid secret: cannot generate TOTP ({})", e));
                                }
                            }
                        }
                        Err(e) => {
                            self.error_message = Some(format!("Invalid secret format: {}", e));
                        }
                    }
                }
            }
        });
        if let Some(i) = select_index {
            self.select_entry(i);
        }
        if let (Some(label), Some(secret)) = (add_label, add_secret) {
            self.add_entry(label, secret);
        }
        if clear_fields {
            self.new_entry_label.clear();
            self.new_entry_secret.clear();
        } else {
            self.new_entry_label = new_entry_label;
            self.new_entry_secret = new_entry_secret;
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("TOTP Authenticator");
            ui.add_space(20.0);

            // Auto-generate new TOTP code when timer runs out
            if self.selected_entry.is_some() {
                let time_remaining = self.get_time_remaining();
                if time_remaining >= 30 || self.totp_code.is_empty() {
                    self.generate_totp();
                }
            }

            // Only show TOTP if an entry is selected
            if let Some(selected) = self.selected_entry {
                // Show label of selected entry
                if let Some(entry) = self.entries.get(selected) {
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new(&entry.label).strong().size(20.0));
                        ui.add_space(10.0);
                        if ui.button("Delete").clicked() {
                            self.pending_delete = Some(selected);
                        }
                    });
                    ui.add_space(10.0);
                }
                // Display TOTP code
                if !self.totp_code.is_empty() {
                    ui.label("TOTP Code:");
                    ui.add_space(5.0);
                    ui.allocate_ui(egui::vec2(ui.available_width(), 50.0), |ui| {
                        ui.centered_and_justified(|ui| {
                            ui.label(
                                egui::RichText::new(&self.totp_code)
                                    .monospace()
                                    .size(32.0)
                                    .strong(),
                            );
                        });
                    });

                    // Display time remaining with progress bar, showing seconds remaining as text
                    let time_remaining = self.get_time_remaining();
                    ui.add_space(10.0);
                    let progress = time_remaining as f32 / 30.0;
                    ui.add(
                        egui::ProgressBar::new(progress)
                            .text(format!("{} seconds remaining", time_remaining))
                    );
                }
            } else {
                ui.label("Select an account or add a new one.");
            }

            // Confirmation dialog for deletion
            if let Some(idx) = self.pending_delete {
                egui::Window::new("Confirm Delete")
                    .collapsible(false)
                    .resizable(false)
                    .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
                    .show(ctx, |ui| {
                        ui.label("Are you sure you want to delete this entry?");
                        ui.horizontal(|ui| {
                            if ui.button("Yes, delete").clicked() {
                                self.remove_entry(idx);
                                self.selected_entry = None;
                                self.secret.clear();
                                self.totp_code.clear();
                                self.pending_delete = None;
                            }
                            if ui.button("Cancel").clicked() {
                                self.pending_delete = None;
                            }
                        });
                    });
            }

            // Display error message if any
            if let Some(error) = &self.error_message {
                ui.add_space(10.0);
                ui.colored_label(egui::Color32::RED, error);
            }

            // Auto-refresh every second
            ctx.request_repaint_after(std::time::Duration::from_secs(1));
        });
    }
}

fn encrypt(json: &str, key_bytes: &[u8; 32]) -> Result<(String, String), String> {
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

fn decrypt(cipher_b64: &str, nonce_b64: &str, key_bytes: &[u8; 32]) -> Result<String, String> {
    let cipher_bytes = STANDARD.decode(cipher_b64).map_err(|e| format!("Base64 decode error: {}", e))?;
    let nonce_bytes = STANDARD.decode(nonce_b64).map_err(|e| format!("Base64 decode error: {}", e))?;

    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let cipher = Aes256Gcm::new(key);

    cipher.decrypt(nonce, cipher_bytes.as_ref())
        .map_err(|e| format!("Decryption failed: {:?}", e))
        .and_then(|plain| String::from_utf8(plain).map_err(|e| format!("UTF8 error: {}", e)))
}

fn derive_key_from_password(password: &str) -> [u8; 32] {
    let result = Sha256::digest(password.as_bytes());
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

fn main() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([400.0, 300.0])
            .with_resizable(true),
        ..Default::default()
    };

    eframe::run_native(
        "TOTP Authenticator",
        options,
        Box::new(|_cc| Ok(Box::new(AuthenticatorApp::default()))),
    )
}
