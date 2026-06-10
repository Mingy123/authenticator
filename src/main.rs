//! TOTP Authenticator - Dioxus cross-platform app
//! Supports web, desktop, and mobile.

use dioxus::prelude::*;

mod algo_core;
mod qr_parser;
mod storage;

use std::path::PathBuf;
use std::time::Duration;

use algo_core::{generate_totp_code, get_time_remaining};
use storage::{load_entries_encrypted, save_entries_encrypted, TotpEntry};

// ---------------------------------------------------------------------------
// Entry Point
// ---------------------------------------------------------------------------

fn main() {
    dioxus::launch(app);
}

// ---------------------------------------------------------------------------
// App State
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
enum Screen {
    Auth,
    Main,
}

#[derive(Clone, Debug, PartialEq)]
enum AuthView {
    Create,
    Open,
}

#[derive(Clone, Default)]
struct AppState {
    screen: Screen,
    auth_view: AuthView,
    entries: Vec<TotpEntry>,
    selected_entry: Option<usize>,
    password: String,
    password_confirm: String,
    file_path: String,
    error: Option<String>,
    new_label: String,
    new_secret: String,
    show_secret: bool,
    pending_delete: Option<usize>,
    totp_code: String,
    time_remaining: u64,
}

// ---------------------------------------------------------------------------
// Root App Component
// ---------------------------------------------------------------------------

fn app() -> Element {
    use_context_provider(|| Signal::new(AppState::default()));

    let state = use_context::<Signal<AppState>>();

    // Timer effect to update TOTP code every second
    use_future(move || {
        let state_clone = state;
        async move {
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                state_clone.with_mut(|s| {
                    if let Some(idx) = s.selected_entry {
                        if let Some(entry) = s.entries.get(idx) {
                            if let Ok(code) = generate_totp_code(&entry.secret) {
                                s.totp_code = code;
                            }
                        }
                    }
                    s.time_remaining = get_time_remaining();
                });
            }
        }
    });

    let current_screen = state.read().screen.clone();
    match current_screen {
        Screen::Auth => rsx! { AuthScreen {} },
        Screen::Main => rsx! { MainScreen {} },
    }
}

// ---------------------------------------------------------------------------
// Auth Screen
// ---------------------------------------------------------------------------

#[component]
fn AuthScreen() -> Element {
    let state = use_context::<Signal<AppState>>();
    let auth_view = state.read().auth_view.clone();

    rsx! {
        div {
            style: "display: flex; flex-direction: column; align-items: center; justify-content: center; height: 100vh; padding: 20px; background: #f5f5f5;",
            div {
                style: "background: white; padding: 40px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.1); width: 100%; max-width: 400px;",
                h1 { style: "text-align: center; margin-bottom: 24px; color: #333;", "TOTP Authenticator" }
                div {
                    style: "display: flex; margin-bottom: 24px; border-radius: 8px; overflow: hidden; border: 1px solid #ddd;",
                    TabButton { label: "Open Existing", active: matches!(auth_view, AuthView::Open), target: AuthView::Open }
                    TabButton { label: "Create New", active: matches!(auth_view, AuthView::Create), target: AuthView::Create }
                }
                match auth_view {
                    AuthView::Open => rsx! { OpenFileForm {} },
                    AuthView::Create => rsx! { CreateFileForm {} },
                }
                ErrorDisplay {}
            }
        }
    }
}

#[component]
fn TabButton(label: String, active: bool, target: AuthView) -> Element {
    let mut state = use_context::<Signal<AppState>>();
    let bg = if active { "background: #007bff; color: white;" } else { "background: white; color: #333;" };

    rsx! {
        button {
            style: "flex: 1; padding: 10px; border: none; cursor: pointer; {bg}",
            onclick: move |_| state.with_mut(|s| s.auth_view = target.clone()),
            "{label}"
        }
    }
}

#[component]
fn OpenFileForm() -> Element {
    let mut state = use_context::<Signal<AppState>>();

    rsx! {
        div { style: "display: flex; flex-direction: column; gap: 12px;",
            AuthInput {
                label: "File path:",
                value: state.read().file_path.clone(),
                oninput: Box::new(move |val: String| state.with_mut(|s| s.file_path = val)),
                placeholder: "/path/to/file.totp",
                password: false,
            }
            AuthInput {
                label: "Password:",
                value: state.read().password.clone(),
                oninput: Box::new(move |val: String| state.with_mut(|s| s.password = val)),
                placeholder: "Enter password",
                password: true,
            }
            button {
                style: "padding: 12px; background: #007bff; color: white; border: none; border-radius: 6px; font-size: 16px; cursor: pointer; margin-top: 8px;",
                onclick: move |_| try_unlock(&mut state),
                "Unlock"
            }
        }
    }
}

fn try_unlock(state: &mut Signal<AppState>) {
    let password = state.read().password.clone();
    let path_str = state.read().file_path.clone();
    if password.is_empty() || path_str.is_empty() {
        state.with_mut(|s| s.error = Some("Password and file path required".into()));
        return;
    }
    let path = PathBuf::from(path_str);
    match load_entries_encrypted(path, &password) {
        Ok(save_file) => {
            state.with_mut(|s| {
                s.entries = save_file.entries;
                s.screen = Screen::Main;
                s.error = None;
            });
        }
        Err(e) => {
            state.with_mut(|s| s.error = Some(e.to_string()));
        }
    }
}

#[component]
fn CreateFileForm() -> Element {
    let mut state = use_context::<Signal<AppState>>();

    rsx! {
        div { style: "display: flex; flex-direction: column; gap: 12px;",
            AuthInput {
                label: "File path:",
                value: state.read().file_path.clone(),
                oninput: Box::new(move |val: String| state.with_mut(|s| s.file_path = val)),
                placeholder: "/path/to/file.totp",
                password: false,
            }
            AuthInput {
                label: "Set password:",
                value: state.read().password.clone(),
                oninput: Box::new(move |val: String| state.with_mut(|s| s.password = val)),
                placeholder: "Enter password",
                password: true,
            }
            AuthInput {
                label: "Confirm password:",
                value: state.read().password_confirm.clone(),
                oninput: Box::new(move |val: String| state.with_mut(|s| s.password_confirm = val)),
                placeholder: "Confirm password",
                password: true,
            }
            button {
                style: "padding: 12px; background: #28a745; color: white; border: none; border-radius: 6px; font-size: 16px; cursor: pointer; margin-top: 8px;",
                onclick: move |_| try_create(&mut state),
                "Create"
            }
        }
    }
}

fn try_create(state: &mut Signal<AppState>) {
    let password = state.read().password.clone();
    let confirm = state.read().password_confirm.clone();
    let path_str = state.read().file_path.clone();
    if password.is_empty() || path_str.is_empty() {
        state.with_mut(|s| s.error = Some("Password and file path required".into()));
        return;
    }
    if password != confirm {
        state.with_mut(|s| s.error = Some("Passwords do not match".into()));
        return;
    }
    let path = PathBuf::from(path_str);
    match save_entries_encrypted(&[], path, &password) {
        Ok(()) => {
            state.with_mut(|s| {
                s.entries.clear();
                s.screen = Screen::Main;
                s.error = None;
            });
        }
        Err(e) => {
            state.with_mut(|s| s.error = Some(e));
        }
    }
}

#[component]
fn AuthInput(label: String, value: String, oninput: Box<dyn Fn(String)>, placeholder: String, password: bool) -> Element {
    let type_attr = if password { "password" } else { "text" };

    rsx! {
        label { style: "font-weight: 500; color: #555;", "{label}" }
        input {
            style: "padding: 10px; border: 1px solid #ddd; border-radius: 6px; font-size: 14px; width: 100%; box-sizing: border-box;",
            value: "{value}",
            oninput: move |evt| oninput(evt.value().clone()),
            r#type: "{type_attr}",
            placeholder: "{placeholder}"
        }
    }
}

#[component]
fn ErrorDisplay() -> Element {
    let state = use_context::<Signal<AppState>>();
    let error = state.read().error.clone();

    if let Some(err) = error {
        rsx! {
            div { style: "background: #f8d7da; color: #721c24; padding: 10px; border-radius: 6px; margin-top: 12px; font-size: 14px;",
                "{err}"
            }
        }
    } else {
        rsx! {}
    }
}

// ---------------------------------------------------------------------------
// Main Screen
// ---------------------------------------------------------------------------

#[component]
fn MainScreen() -> Element {
    rsx! {
        div { style: "display: flex; height: 100vh; overflow: hidden;",
            Sidebar {}
            MainContent {}
        }
    }
}

#[component]
fn Sidebar() -> Element {
    let mut state = use_context::<Signal<AppState>>();
    let entries = state.read().entries.clone();
    let selected = state.read().selected_entry;

    rsx! {
        div {
            style: "width: 280px; min-width: 280px; background: #f8f9fa; border-right: 1px solid #dee2e6; display: flex; flex-direction: column; overflow: hidden;",
            div { style: "padding: 16px; border-bottom: 1px solid #dee2e6;",
                h2 { style: "margin: 0; font-size: 18px; color: #333;", "Accounts" }
            }
            div { style: "flex: 1; overflow-y: auto; padding: 8px;",
                for (i, entry) in entries.iter().enumerate() {
                    SidebarItem { entry: entry.clone(), index: i, selected: selected == Some(i) }
                }
            }
            div { style: "padding: 16px; border-top: 1px solid #dee2e6; background: white;",
                h3 { style: "margin: 0 0 12px 0; font-size: 14px; color: #666;", "Add Account" }
                input {
                    style: "width: 100%; padding: 8px; margin-bottom: 8px; border: 1px solid #ddd; border-radius: 6px; box-sizing: border-box; font-size: 13px;",
                    value: "{state.read().new_label}",
                    oninput: move |evt| state.with_mut(|s| s.new_label = evt.value().clone()),
                    placeholder: "Label"
                }
                input {
                    style: "width: 100%; padding: 8px; margin-bottom: 8px; border: 1px solid #ddd; border-radius: 6px; box-sizing: border-box; font-size: 13px;",
                    value: "{state.read().new_secret}",
                    oninput: move |evt| state.with_mut(|s| s.new_secret = evt.value().clone()),
                    placeholder: "Secret (base32)"
                }
                button {
                    style: "width: 100%; padding: 10px; background: #007bff; color: white; border: none; border-radius: 6px; cursor: pointer; font-size: 14px;",
                    onclick: move |_| add_entry(&mut state),
                    "Add"
                }
            }
        }
    }
}

#[component]
fn SidebarItem(entry: TotpEntry, index: usize, selected: bool) -> Element {
    let mut state = use_context::<Signal<AppState>>();
    let style = if selected {
        "padding: 12px; margin-bottom: 4px; border-radius: 8px; background: #007bff; color: white; cursor: pointer; font-weight: 500;"
    } else {
        "padding: 12px; margin-bottom: 4px; border-radius: 8px; background: white; color: #333; cursor: pointer; border: 1px solid #e9ecef;"
    };

    rsx! {
        div {
            style: "{style}",
            onclick: move |_| {
                state.with_mut(|s| {
                    s.selected_entry = Some(index);
                    s.show_secret = false;
                    if let Some(e) = s.entries.get(index) {
                        if let Ok(code) = generate_totp_code(&e.secret) {
                            s.totp_code = code;
                        }
                    }
                });
            },
            "{entry.label}"
        }
    }
}

fn add_entry(state: &mut Signal<AppState>) {
    let label = state.read().new_label.trim().to_string();
    let secret = state.read().new_secret.trim().to_string();
    if label.is_empty() || secret.is_empty() {
        state.with_mut(|s| s.error = Some("Label and secret required".into()));
        return;
    }
    if generate_totp_code(&secret).is_err() {
        state.with_mut(|s| s.error = Some("Invalid secret format".into()));
        return;
    }
    state.with_mut(|s| {
        s.entries.push(TotpEntry { label, secret });
        s.new_label.clear();
        s.new_secret.clear();
        s.error = None;
    });
}

#[component]
fn MainContent() -> Element {
    let mut state = use_context::<Signal<AppState>>();
    let selected = state.read().selected_entry;
    let show_secret = state.read().show_secret;
    let totp_code = state.read().totp_code.clone();
    let time_remaining = state.read().time_remaining;
    let pending_delete = state.read().pending_delete;

    if let Some(idx) = selected {
        let entry = state.read().entries.get(idx).cloned();
        if let Some(entry) = entry {
            let progress = (time_remaining as f64 / 30.0) * 100.0;
            return rsx! {
                div {
                    style: "flex: 1; display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 40px; background: white;",
                    div {
                        style: "text-align: center; max-width: 400px; width: 100%;",
                        h2 { style: "font-size: 28px; color: #333; margin-bottom: 24px;", "{entry.label}" }
                        div {
                            style: "font-size: 56px; font-family: monospace; font-weight: bold; color: #007bff; letter-spacing: 8px; margin: 24px 0;",
                            "{totp_code}"
                        }
                        div {
                            style: "width: 100%; height: 8px; background: #e9ecef; border-radius: 4px; overflow: hidden; margin: 16px 0;",
                            div {
                                style: "height: 100%; background: linear-gradient(90deg, #dc3545, #ffc107, #28a745); border-radius: 4px; transition: width 1s linear;",
                                width: "{progress}%"
                            }
                        }
                        div { style: "color: #666; font-size: 14px; margin-bottom: 24px;",
                            "{time_remaining}s remaining"
                        }
                        div {
                            style: "display: flex; gap: 12px; justify-content: center;",
                            button {
                                style: "padding: 10px 20px; background: #6c757d; color: white; border: none; border-radius: 6px; cursor: pointer;",
                                onclick: move |_| state.with_mut(|s| s.show_secret = !s.show_secret),
                                if show_secret { "Hide Secret" } else { "Show Secret" }
                            }
                            button {
                                style: "padding: 10px 20px; background: #dc3545; color: white; border: none; border-radius: 6px; cursor: pointer;",
                                onclick: move |_| state.with_mut(|s| s.pending_delete = Some(idx)),
                                "Delete"
                            }
                        }
                        if show_secret {
                            div {
                                style: "margin-top: 16px; padding: 12px; background: #f8f9fa; border-radius: 6px; font-family: monospace; color: #666; font-size: 14px; word-break: break-all;",
                                "{entry.secret}"
                            }
                        }
                    }
                    if let Some(del_idx) = pending_delete {
                        ConfirmDeleteDialog { idx: del_idx }
                    }
                }
            };
        }
    }

    rsx! {
        div { style: "flex: 1; display: flex; align-items: center; justify-content: center; color: #999; font-size: 16px; background: white;",
            "Select an account or add a new one."
        }
    }
}

#[component]
fn ConfirmDeleteDialog(idx: usize) -> Element {
    let mut state = use_context::<Signal<AppState>>();

    rsx! {
        div {
            style: "position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.5); display: flex; align-items: center; justify-content: center; z-index: 1000;",
            div {
                style: "background: white; padding: 32px; border-radius: 12px; box-shadow: 0 8px 32px rgba(0,0,0,0.2); text-align: center; max-width: 360px;",
                h3 { style: "margin: 0 0 12px 0; color: #333;", "Confirm Delete" }
                p { style: "color: #666; margin-bottom: 24px;", "Are you sure you want to delete this account?" }
                div {
                    style: "display: flex; gap: 12px; justify-content: center;",
                    button {
                        style: "padding: 10px 20px; background: #dc3545; color: white; border: none; border-radius: 6px; cursor: pointer;",
                        onclick: move |_| {
                            state.with_mut(|s| {
                                s.entries.remove(idx);
                                s.selected_entry = None;
                                s.pending_delete = None;
                                s.show_secret = false;
                                s.totp_code.clear();
                            });
                        },
                        "Yes, delete"
                    }
                    button {
                        style: "padding: 10px 20px; background: #6c757d; color: white; border: none; border-radius: 6px; cursor: pointer;",
                        onclick: move |_| state.with_mut(|s| s.pending_delete = None),
                        "Cancel"
                    }
                }
            }
        }
    }
}
