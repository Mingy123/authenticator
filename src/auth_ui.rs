use eframe::egui;
use egui_file::FileDialog;
use std::{
    fs,
    path::{Path, PathBuf},
};

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
        let config_dir = Self::default_config_dir();
        let file_path = Self::load_last_used_file_path(&config_dir).unwrap_or_default();
        Self {
            password: String::new(),
            password_confirm: String::new(),
            file_path,
            error_message: None,
            action: AuthAction::UseExisting,
            file_dialog: None,
            config_dir: Some(config_dir),
        }
    }
}

impl AuthUI {
    const LAST_USED_FILE_PATH_FILE: &'static str = "last_used_file_path";

    fn default_config_dir() -> PathBuf {
        let mut config_dir = dirs_next::config_dir().unwrap_or_else(|| PathBuf::from("."));
        config_dir.push("authenticator");
        config_dir
    }

    fn last_used_file_path_file(config_dir: &Path) -> PathBuf {
        config_dir.join(Self::LAST_USED_FILE_PATH_FILE)
    }

    fn load_last_used_file_path(config_dir: &Path) -> Option<String> {
        let record_path = Self::last_used_file_path_file(config_dir);
        fs::read_to_string(record_path)
            .ok()
            .map(|path| path.trim().to_string())
            .filter(|path| !path.is_empty())
    }

    pub fn persist_last_used_file_path(&mut self, path: &Path) -> Result<(), String> {
        if self.config_dir.is_none() {
            self.config_dir = Some(Self::default_config_dir());
        }
        let config_dir = self
            .config_dir
            .as_ref()
            .ok_or_else(|| "Config directory is not initialized".to_string())?;
        fs::create_dir_all(config_dir).map_err(|e| {
            format!(
                "Failed to create config directory {}: {}",
                config_dir.display(),
                e
            )
        })?;
        let record_path = Self::last_used_file_path_file(config_dir);
        let path_value = path.to_string_lossy().to_string();
        fs::write(&record_path, &path_value)
            .map_err(|e| format!("Failed to write {}: {}", record_path.display(), e))?;
        self.file_path = path_value;
        Ok(())
    }

    pub fn show(&mut self, ctx: &egui::Context) -> Option<AuthResult> {
        let mut result = None;

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("TOTP Authenticator - Locked");
            ui.add_space(10.0);

            // Action selection
            ui.label("Choose an option:");
            ui.add_space(5.0);

            ui.horizontal(|ui| {
                if ui
                    .radio(self.action == AuthAction::CreateNew, "Create new file")
                    .clicked()
                {
                    self.action = AuthAction::CreateNew;
                    self.clear_error();
                }
                if ui
                    .radio(self.action == AuthAction::UseExisting, "Use existing file")
                    .clicked()
                {
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

    fn show_create_new_ui(
        &mut self,
        ui: &mut egui::Ui,
        ctx: &egui::Context,
        result: &mut Option<AuthResult>,
    ) {
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
        let resp_confirm =
            ui.add(egui::TextEdit::singleline(&mut self.password_confirm).password(true));

        let mut create_file = false;
        if ui.button("Create File").clicked() {
            create_file = true;
        }
        if (resp_pw.lost_focus() || resp_confirm.lost_focus())
            && ui.input(|i| i.key_pressed(egui::Key::Enter))
        {
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

    fn show_use_existing_ui(
        &mut self,
        ui: &mut egui::Ui,
        ctx: &egui::Context,
        result: &mut Option<AuthResult>,
    ) {
        ui.label("Use an existing encrypted file:");
        ui.add_space(5.0);

        // Initialize config directory if not set
        if self.config_dir.is_none() {
            self.config_dir = Some(Self::default_config_dir());
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
    CreateNew { path: PathBuf, password: String },
    UseExisting { path: PathBuf, password: String },
}
