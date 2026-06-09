#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")] // hide console

use eframe::egui;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

mod algo_core;
mod storage;
mod ui;

use ui::auth_ui::{AuthResult, AuthUI};
use ui::main_ui;

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
