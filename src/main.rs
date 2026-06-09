#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")] // hide console

use eframe::egui;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

mod algo_core;
mod storage;
mod ui;

use ui::auth_ui::{AuthResult, AuthUI};
use ui::{main_ui, qr_ui};

#[derive(Serialize, Deserialize, Clone)]
struct TotpEntry {
    label: String,
    secret: String,
}

struct AuthenticatorApp {
    entries: Vec<TotpEntry>,
    error_message_app: Option<String>,
    is_authenticated: bool,
    last_update: u64,
    new_entry_label: String,
    new_entry_secret: String,
    pending_delete: Option<usize>,
    secret: String,
    selected_entry: Option<usize>,
    totp_code: String,
    auth_ui: AuthUI,
    current_file_path: Option<PathBuf>,
    current_password: String,
    show_secret: bool,
    qr_scanner: qr_ui::QrUI,
    launch_qr_scanner: bool,
}

impl Default for AuthenticatorApp {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
            error_message_app: None,
            is_authenticated: false,
            last_update: 0,
            new_entry_label: String::new(),
            new_entry_secret: String::new(),
            pending_delete: None,
            secret: String::new(),
            selected_entry: None,
            totp_code: String::new(),
            auth_ui: AuthUI::default(),
            current_file_path: None,
            current_password: String::new(),
            show_secret: false,
            qr_scanner: qr_ui::QrUI::default(),
            launch_qr_scanner: false,
        }
    }
}

impl AuthenticatorApp {
    fn add_entry(&mut self, label: String, secret: String) {
        self.entries.push(TotpEntry { label, secret });
        if let Some(path) = &self.current_file_path {
            if self
                .save_entries_encrypted(path.clone(), &self.current_password)
                .is_err()
            {
                eprintln!("Error while saving entries");
            }
        }
    }

    fn remove_entry(&mut self, index: usize) {
        if index < self.entries.len() {
            self.entries.remove(index);
            if let Some(path) = &self.current_file_path {
                if self
                    .save_entries_encrypted(path.clone(), &self.current_password)
                    .is_err()
                {
                    eprintln!("Error while saving entries");
                }
            }
        }
    }

    fn select_entry(&mut self, index: usize) {
        if let Some(entry) = self.entries.get(index) {
            self.secret = entry.secret.clone();
            self.selected_entry = Some(index);
            self.show_secret = false;
            self.generate_totp();
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
        // Authentication gate
        if !self.is_authenticated {
            if let Some(auth_result) = self.auth_ui.show(ctx) {
                match auth_result {
                    AuthResult::CreateNew { path, password } => {
                        match self.save_entries_encrypted(path.clone(), &password) {
                            Ok(_) => {
                                self.error_message_app = None;
                                self.is_authenticated = true;
                                self.current_file_path = Some(path.clone());
                                self.current_password = password;
                                if let Err(e) = self.auth_ui.persist_last_used_file_path(&path) {
                                    self.error_message_app = Some(format!(
                                        "File created, but failed to store last used path: {}",
                                        e
                                    ));
                                }
                            }
                            Err(e) => {
                                self.auth_ui.error_message =
                                    Some(format!("Failed to create file: {}", e));
                            }
                        }
                    }
                    AuthResult::UseExisting { path, password } => {
                        match AuthenticatorApp::load_entries_encrypted(path.clone(), &password) {
                            Ok(save_file) => {
                                self.error_message_app = None;
                                self.entries = save_file.entries;
                                self.is_authenticated = true;
                                self.current_file_path = Some(path.clone());
                                self.current_password = password;
                                if let Err(e) = self.auth_ui.persist_last_used_file_path(&path) {
                                    self.error_message_app = Some(format!(
                                        "File loaded, but failed to store last used path: {}",
                                        e
                                    ));
                                }
                            }
                            Err(e) => {
                                self.auth_ui.error_message =
                                    Some(format!("Failed to load file: {}", e.to_string()));
                            }
                        }
                    }
                }
            }
            return;
        }

        // Show QR scanner if triggered
        if self.launch_qr_scanner {
            let result = self.qr_scanner.show(ctx);
            if let Some(qr_ui::QrResult::TotpUri { label, secret }) = result {
                self.new_entry_label = label;
                self.new_entry_secret = secret;
                self.launch_qr_scanner = false;
                self.qr_scanner = qr_ui::QrUI::default();
            } else if self.qr_scanner.is_cancelled() {
                self.launch_qr_scanner = false;
                self.qr_scanner = qr_ui::QrUI::default();
            }
        }

        // Main authenticated UI
        main_ui::show_main_ui(self, ctx);
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_entry() {
        let mut app = AuthenticatorApp::default();
        assert!(app.entries.is_empty());

        app.add_entry("Test Label".into(), "JBSWY3DPEHPK3PXP".into());
        assert_eq!(app.entries.len(), 1);
        assert_eq!(app.entries[0].label, "Test Label");
        assert_eq!(app.entries[0].secret, "JBSWY3DPEHPK3PXP");
    }

    #[test]
    fn test_add_multiple_entries() {
        let mut app = AuthenticatorApp::default();
        app.add_entry("Alpha".into(), "SECRET1".into());
        app.add_entry("Beta".into(), "SECRET2".into());
        app.add_entry("Gamma".into(), "SECRET3".into());
        assert_eq!(app.entries.len(), 3);
    }

    #[test]
    fn test_remove_entry() {
        let mut app = AuthenticatorApp::default();
        app.add_entry("Entry1".into(), "SECRET1".into());
        app.add_entry("Entry2".into(), "SECRET2".into());
        app.add_entry("Entry3".into(), "SECRET3".into());

        app.remove_entry(1);
        assert_eq!(app.entries.len(), 2);
        assert_eq!(app.entries[0].label, "Entry1");
        assert_eq!(app.entries[1].label, "Entry3");
    }

    #[test]
    fn test_remove_entry_out_of_bounds() {
        let mut app = AuthenticatorApp::default();
        app.add_entry("Only".into(), "SECRET".into());
        app.remove_entry(5);
        assert_eq!(app.entries.len(), 1);
    }

    #[test]
    fn test_remove_entry_from_empty() {
        let mut app = AuthenticatorApp::default();
        app.remove_entry(0);
        assert!(app.entries.is_empty());
    }

    #[test]
    fn test_select_entry() {
        let mut app = AuthenticatorApp::default();
        app.entries.push(TotpEntry {
            label: "test".into(),
            secret: "JBSWY3DPEHPK3PXP".into(),
        });

        app.select_entry(0);
        assert_eq!(app.selected_entry, Some(0));
        assert_eq!(app.totp_code.len(), 6);
    }

    #[test]
    fn test_get_time_remaining_range() {
        let app = AuthenticatorApp::default();
        let remaining = app.get_time_remaining();
        assert!(remaining < 30);
    }

    #[test]
    fn test_default_app_state() {
        let app = AuthenticatorApp::default();
        assert!(app.entries.is_empty());
        assert!(app.error_message_app.is_none());
        assert!(!app.is_authenticated);
        assert!(app.selected_entry.is_none());
        assert!(app.totp_code.is_empty());
        assert!(app.current_file_path.is_none());
        assert!(app.current_password.is_empty());
        assert!(!app.show_secret);
        assert!(!app.launch_qr_scanner);
    }
}
