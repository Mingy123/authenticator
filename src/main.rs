#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")] // hide console

use eframe::egui;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

mod storage;
mod algo_core;
mod auth_ui;

use auth_ui::{AuthUI, AuthResult};
use std::path::PathBuf;

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
    }
  }
}

impl AuthenticatorApp {

  fn add_entry(&mut self, label: String, secret: String) {
    self.entries.push(TotpEntry { label, secret });
    if let Some(path) = &self.current_file_path {
      if self.save_entries_encrypted(path.clone(), &self.current_password).is_err() {
        eprintln!("Error while saving entries");
      }
    }
  }

  fn remove_entry(&mut self, index: usize) {
    if index < self.entries.len() {
      self.entries.remove(index);
      if let Some(path) = &self.current_file_path {
        if self.save_entries_encrypted(path.clone(), &self.current_password).is_err() {
          eprintln!("Error while saving entries");
        }
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
      if let Some(auth_result) = self.auth_ui.show(ctx) {
        match auth_result {
          AuthResult::CreateNew { path, password } => {
            // Create new encrypted file
            match self.save_entries_encrypted(path.clone(), &password) {
              Ok(_) => {
                self.is_authenticated = true;
                self.current_file_path = Some(path);
                self.current_password = password;
              }
              Err(e) => {
                self.auth_ui.error_message = Some(format!("Failed to create file: {}", e));
              }
            }
          }
          AuthResult::UseExisting { path, password } => {
            // Load existing encrypted file
            match AuthenticatorApp::load_entries_encrypted(path.clone(), &password) {
              Ok(save_file) => {
                self.entries = save_file.entries;
                self.is_authenticated = true;
                self.current_file_path = Some(path);
                self.current_password = password;
              }
              Err(e) => {
                self.auth_ui.error_message = Some(format!("Failed to load file: {}", e.to_string()));
              }
            }
          }
        }
      }
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
                  self.error_message_app = None;
                }
                Err(e) => {
                  self.error_message_app = Some(format!("Invalid secret: cannot generate TOTP ({})", e));
                }
              }
            }
            Err(e) => {
              self.error_message_app = Some(format!("Invalid secret format: {}", e));
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
      if let Some(error) = &self.error_message_app {
        ui.add_space(10.0);
        ui.colored_label(egui::Color32::RED, error);
      }

      // Auto-refresh every second
      ctx.request_repaint_after(std::time::Duration::from_secs(1));
    });
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
