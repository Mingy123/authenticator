use crate::AuthenticatorApp;
use eframe::egui;

/// Show the main side panel and central panel after authentication.
pub fn show_main_ui(app: &mut AuthenticatorApp, ctx: &egui::Context) {
    let mut add_label: Option<String> = None;
    let mut add_secret: Option<String> = None;
    let mut clear_fields = false;
    let mut new_entry_label = app.new_entry_label.clone();
    let mut new_entry_secret = app.new_entry_secret.clone();
    let mut select_index: Option<usize> = None;

    // Side panel: account list + add new entry
    egui::SidePanel::left("totp_menu").show(ctx, |ui| {
        ui.heading("Accounts");
        ui.add_space(10.0);
        for (i, entry) in app.entries.iter().enumerate() {
            let selected = app.selected_entry == Some(i);
            if ui.selectable_label(selected, &entry.label).clicked() {
                if selected {
                    app.selected_entry = None;
                    app.secret.clear();
                    app.totp_code.clear();
                    app.show_secret = false;
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
        ui.horizontal(|ui| {
            if ui.button("Add").clicked() {
                add_clicked = true;
            }
            ui.label("or");
            if ui.button("Scan QR code").clicked() {
                app.launch_qr_scanner = true;
            }
        });
        if (resp_label.lost_focus() || resp_secret.lost_focus())
            && ui.input(|i| i.key_pressed(egui::Key::Enter))
        {
            add_clicked = true;
        }
        if add_clicked {
            if !new_entry_label.trim().is_empty() && !new_entry_secret.trim().is_empty() {
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
                                app.error_message_app = None;
                            }
                            Err(e) => {
                                app.error_message_app =
                                    Some(format!("Invalid secret: cannot generate TOTP ({})", e));
                            }
                        }
                    }
                    Err(e) => {
                        app.error_message_app = Some(format!("Invalid secret format: {}", e));
                    }
                }
            }
        }
    });

    if let Some(i) = select_index {
        app.select_entry(i);
    }
    if let (Some(label), Some(secret)) = (add_label, add_secret) {
        app.add_entry(label, secret);
    }
    if clear_fields {
        app.new_entry_label.clear();
        app.new_entry_secret.clear();
    } else {
        app.new_entry_label = new_entry_label;
        app.new_entry_secret = new_entry_secret;
    }

    // Central panel: TOTP display
    egui::CentralPanel::default().show(ctx, |ui| {
        ui.heading("TOTP Authenticator");
        ui.add_space(20.0);

        if app.selected_entry.is_some() {
            let time_remaining = app.get_time_remaining();
            if time_remaining >= 30 || app.totp_code.is_empty() {
                app.generate_totp();
            }
        }

        if let Some(selected) = app.selected_entry {
            if let Some(entry) = app.entries.get(selected) {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(&entry.label).strong().size(20.0));
                    ui.add_space(10.0);
                    if ui
                        .button(if app.show_secret {
                            "Hide Secret"
                        } else {
                            "Show Secret"
                        })
                        .clicked()
                    {
                        app.show_secret = !app.show_secret;
                    }
                    ui.add_space(10.0);
                    if ui.button("Delete").clicked() {
                        app.pending_delete = Some(selected);
                    }
                });
                if app.show_secret {
                    ui.add_space(6.0);
                    ui.label("Secret:");
                    ui.label(egui::RichText::new(&app.secret).monospace());
                }
                ui.add_space(10.0);
            }
            if !app.totp_code.is_empty() {
                ui.label("TOTP Code:");
                ui.add_space(5.0);
                ui.allocate_ui(egui::vec2(ui.available_width(), 50.0), |ui| {
                    ui.centered_and_justified(|ui| {
                        ui.label(
                            egui::RichText::new(&app.totp_code)
                                .monospace()
                                .size(32.0)
                                .strong(),
                        );
                    });
                });

                let time_remaining = app.get_time_remaining();
                ui.add_space(10.0);
                let progress = time_remaining as f32 / 30.0;
                ui.add(
                    egui::ProgressBar::new(progress)
                        .text(format!("{} seconds remaining", time_remaining)),
                );
            }
        } else {
            ui.label("Select an account or add a new one.");
        }

        if let Some(idx) = app.pending_delete {
            egui::Window::new("Confirm Delete")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
                .show(ctx, |ui| {
                    ui.label("Are you sure you want to delete this entry?");
                    ui.horizontal(|ui| {
                        if ui.button("Yes, delete").clicked() {
                            app.remove_entry(idx);
                            app.selected_entry = None;
                            app.secret.clear();
                            app.totp_code.clear();
                            app.show_secret = false;
                            app.pending_delete = None;
                        }
                        if ui.button("Cancel").clicked() {
                            app.pending_delete = None;
                        }
                    });
                });
        }

        if let Some(error) = &app.error_message_app {
            ui.add_space(10.0);
            ui.colored_label(egui::Color32::RED, error);
        }

        ctx.request_repaint_after(std::time::Duration::from_secs(1));
    });
}
