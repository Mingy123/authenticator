use eframe::egui;
use std::path::PathBuf;
use egui_file::FileDialog;
use dirs_next::config_dir;


#[derive(PartialEq, Eq)]
pub enum AuthAction {
  CreateNew,
  UseExisting,
}

pub struct AuthUI {
  pub password: String,
  pub password_confirm: String,
  pub file_path: String,
  pub error_message: Option<String>,
  pub action: AuthAction,
  pub file_dialog: Option<FileDialog>,
  pub config_dir: Option<PathBuf>,
}

impl Default for AuthUI {
  fn default() -> Self {
    let mut config_dir = dirs_next::config_dir().unwrap_or_else(|| PathBuf::from("."));
    config_dir.push("authenticator");
    Self {
      password: String::new(),
      password_confirm: String::new(),
      file_path: String::new(),
      error_message: None,
      action: AuthAction::CreateNew,
      file_dialog: None,
      config_dir: Some(config_dir),
    }
  }
}

impl AuthUI {
  pub fn show(&mut self, ctx: &egui::Context) -> Option<AuthResult> {
    let mut result = None;
    
    egui::CentralPanel::default().show(ctx, |ui| {
      ui.heading("TOTP Authenticator - Locked");
      ui.add_space(10.0);
      
      // Action selection
      ui.label("Choose an option:");
      ui.add_space(5.0);
      
      ui.horizontal(|ui| {
        if ui.radio(self.action == AuthAction::CreateNew, "Create new file").clicked() {
          self.action = AuthAction::CreateNew;
          self.clear_error();
        }
        if ui.radio(self.action == AuthAction::UseExisting, "Use existing file").clicked() {
          self.action = AuthAction::UseExisting;
          self.clear_error();
        }
      });
      
      ui.add_space(10.0);
      
      match self.action {
        AuthAction::CreateNew => {
          self.show_create_new_ui(ui, ctx, &mut result);
        }
        AuthAction::UseExisting => {
          self.show_use_existing_ui(ui, ctx, &mut result);
        }
      }
      
      // Display error message if any
      if let Some(err) = &self.error_message {
        ui.add_space(10.0);
        ui.colored_label(egui::Color32::RED, err);
      }
    });
    
    result
  }
  
  fn show_create_new_ui(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, result: &mut Option<AuthResult>) {
    ui.label("Create a new encrypted file:");
    ui.add_space(5.0);
    
    // File path selection
    ui.label("File path:");
    ui.horizontal(|ui| {
      ui.label(&self.file_path);
      if ui.button("Browse...").clicked() {
        let mut dialog = FileDialog::save_file(self.config_dir.clone());
        dialog.open();
        self.file_dialog = Some(dialog);
      }
    });
    
    // Handle file dialog
    if let Some(dialog) = &mut self.file_dialog {
      if dialog.show(ctx).selected() {
        if let Some(path) = dialog.path() {
          self.file_path = path.to_string_lossy().to_string();
        }
        self.file_dialog = None;
      }
    }
    
    ui.label("Set password:");
    let resp_pw = ui.add(egui::TextEdit::singleline(&mut self.password).password(true));
    
    ui.label("Confirm password:");
    let resp_confirm = ui.add(egui::TextEdit::singleline(&mut self.password_confirm).password(true));
    
    let mut create_file = false;
    if ui.button("Create File").clicked() {
      create_file = true;
    }
    if (resp_pw.lost_focus() || resp_confirm.lost_focus()) 
      && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
      create_file = true;
    }
    
    if create_file {
      if self.file_path.trim().is_empty() {
        self.error_message = Some("File path cannot be empty".to_string());
      } else if self.password.is_empty() {
        self.error_message = Some("Password cannot be empty".to_string());
      } else if self.password != self.password_confirm {
        self.error_message = Some("Passwords do not match".to_string());
      } else {
        let path = PathBuf::from(self.file_path.trim());
        *result = Some(AuthResult::CreateNew {
          path,
          password: self.password.clone(),
        });
      }
    }
  }
  
  fn show_use_existing_ui(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, result: &mut Option<AuthResult>) {
    ui.label("Use an existing encrypted file:");
    ui.add_space(5.0);
    
    // Initialize config directory if not set
    if self.config_dir.is_none() {
      self.config_dir = config_dir();
    }
    
    // File path selection
    ui.label("File path:");
    ui.horizontal(|ui| {
      ui.label(&self.file_path);
      if ui.button("Browse...").clicked() {
        let mut dialog = FileDialog::open_file(self.config_dir.clone());
        dialog.open();
        self.file_dialog = Some(dialog);
      }
    });
    
    // Handle file dialog
    if let Some(dialog) = &mut self.file_dialog {
      if dialog.show(ctx).selected() {
        if let Some(path) = dialog.path() {
          self.file_path = path.to_string_lossy().to_string();
        }
        self.file_dialog = None;
      }
    }
    
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
      if self.file_path.trim().is_empty() {
        self.error_message = Some("File path cannot be empty".to_string());
      } else if self.password.is_empty() {
        self.error_message = Some("Password cannot be empty".to_string());
      } else {
        let path = PathBuf::from(self.file_path.trim());
        *result = Some(AuthResult::UseExisting {
          path,
          password: self.password.clone(),
        });
      }
    }
  }
  
  fn clear_error(&mut self) {
    self.error_message = None;
  }
}

pub enum AuthResult {
  CreateNew {
    path: PathBuf,
    password: String,
  },
  UseExisting {
    path: PathBuf,
    password: String,
  },
} 