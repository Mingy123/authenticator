use std::io::Read;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use eframe::egui::{self, ColorImage, TextureHandle};

/// Result from a successful QR scan
#[derive(Clone)]
pub enum QrResult {
    /// A valid TOTP URI was decoded
    TotpUri { label: String, secret: String },
}

/// QR scanner UI state
pub struct QrUI {
    scanner: Option<QrScannerHandle>,
    decoded_result: Option<QrResult>,
    error: Option<String>,
    frame_texture: Option<TextureHandle>,
    cancelled: bool,
}

struct QrScannerHandle {
    stop_flag: Arc<AtomicBool>,
    frame_data: Arc<Mutex<Option<(Vec<u8>, u32, u32)>>>,
    decoded_text: Arc<Mutex<Option<String>>>,
    thread_handle: Option<thread::JoinHandle<()>>,
}

impl Default for QrUI {
    fn default() -> Self {
        Self {
            scanner: None,
            decoded_result: None,
            error: None,
            frame_texture: None,
            cancelled: false,
        }
    }
}

impl Drop for QrUI {
    fn drop(&mut self) {
        self.cleanup();
    }
}

impl QrUI {
    /// Show the QR scanner window. Returns `Some(QrResult)` when a QR code is successfully scanned.
    pub fn show(&mut self, ctx: &egui::Context) -> Option<QrResult> {
        // Return cached result if already decoded
        if let Some(ref result) = self.decoded_result {
            return Some(result.clone());
        }

        // Start camera on first call
        if self.scanner.is_none() {
            match start_camera_thread() {
                Ok(handle) => {
                    self.scanner = Some(handle);
                    self.error = None;
                }
                Err(e) => {
                    self.error = Some(format!("Camera error: {}", e));
                }
            }
        }

        // Check for camera errors from the background thread
        if let Some(ref scanner) = self.scanner {
            if let Ok(mut decoded) = scanner.decoded_text.lock() {
                if let Some(ref text) = *decoded {
                    if text.starts_with("__CAMERA_ERROR__:") {
                        let err_msg = text.trim_start_matches("__CAMERA_ERROR__:");
                        self.error = Some(err_msg.to_string());
                        *decoded = None;
                        return None;
                    }
                }
            }
        }

        // Show the scanner window
        let mut closed = false;
        egui::Window::new("Scan QR Code")
            .id("qr_scanner_window".into())
            .collapsible(false)
            .resizable(true)
            .default_size([480.0, 400.0])
            .show(ctx, |ui| {
                if let Some(ref error) = self.error {
                    ui.colored_label(egui::Color32::RED, error);
                    if ui.button("Close").clicked() {
                        closed = true;
                    }
                    return;
                }

                if let Some(ref scanner) = self.scanner {
                    // Poll for new frame
                    if let Ok(frame_data) = scanner.frame_data.lock() {
                        if let Some((ref bytes, w, h)) = *frame_data {
                            let image =
                                ColorImage::from_rgb([w as usize, h as usize], bytes);
                            let needs_texture = self.frame_texture.is_none();
                            if needs_texture {
                                let texture = ctx.load_texture(
                                    "camera_preview",
                                    image,
                                    egui::TextureOptions::LINEAR,
                                );
                                self.frame_texture = Some(texture);
                            } else if let Some(ref mut tex) = self.frame_texture {
                                tex.set(image, egui::TextureOptions::LINEAR);
                            }
                        }
                    }

                    // Display camera texture
                    if let Some(ref tex) = self.frame_texture {
                        let available = ui.available_size();
                        let tex_size = tex.size_vec2();
                        let aspect = tex_size.x / tex_size.y;
                        let desired = if available.x / available.y > aspect {
                            egui::vec2(available.y * aspect, available.y)
                        } else {
                            egui::vec2(available.x, available.x / aspect)
                        };
                        ui.add(
                            egui::Image::new((tex.id(), desired))
                                .fit_to_exact_size(desired),
                        );
                    } else {
                        ui.label("Starting camera...");
                        ctx.request_repaint_after(Duration::from_millis(100));
                    }

                    // Check for decoded result
                    if let Ok(mut decoded) = scanner.decoded_text.lock() {
                        if let Some(ref text) = *decoded {
                            match parse_totp_uri(text) {
                                Ok((label, secret)) => {
                                    self.decoded_result = Some(QrResult::TotpUri {
                                        label,
                                        secret,
                                    });
                                }
                                Err(e) => {
                                    self.error = Some(format!(
                                        "Decoded QR but failed to parse: {}",
                                        e
                                    ));
                                    *decoded = None;
                                }
                            }
                        }
                    }

                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        if ui.button("Cancel").clicked() {
                            self.cancelled = true;
                            closed = true;
                        }
                        if self.decoded_result.is_some() {
                            if ui.button("Use This Code").clicked() {
                                closed = true;
                            }
                        }
                    });

                    // Keep repainting while scanning
                    ctx.request_repaint_after(Duration::from_millis(33));
                }
            });

        if closed {
            self.cleanup();
        }

        None
    }

    /// Check if the user clicked Cancel.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled
    }

    fn cleanup(&mut self) {
        if let Some(scanner) = self.scanner.take() {
            scanner.stop_flag.store(true, Ordering::SeqCst);
            if let Some(handle) = scanner.thread_handle {
                let _ = handle.join();
            }
        }
        self.frame_texture = None;
    }
}

/// Background camera capture thread using ffmpeg
fn start_camera_thread() -> Result<QrScannerHandle, String> {
    let stop_flag = Arc::new(AtomicBool::new(false));
    let frame_data = Arc::new(Mutex::new(None::<(Vec<u8>, u32, u32)>));
    let decoded_text = Arc::new(Mutex::new(None::<String>));

    let stop = stop_flag.clone();
    let frames = frame_data.clone();
    let decoded = decoded_text.clone();

    let handle = thread::Builder::new()
        .name("qr-camera".into())
        .spawn(move || {
            const W: u32 = 640;
            const H: u32 = 480;
            let frame_size = (W * H * 3) as usize;

            let mut child: Option<Child> = None;
            let mut stdout: Option<Box<dyn Read + Send>> = None;

            // Try first available camera device
            for dev_idx in 0..=3 {
                let device = format!("/dev/video{}", dev_idx);
                if !std::path::Path::new(&device).exists() {
                    continue;
                }

                match Command::new("ffmpeg")
                    .args([
                        "-hide_banner",
                        "-loglevel",
                        "error",
                        "-f",
                        "v4l2",
                        "-video_size",
                        &format!("{}x{}", W, H),
                        "-i",
                        &device,
                        "-f",
                        "rawvideo",
                        "-pix_fmt",
                        "rgb24",
                        "-",
                    ])
                    .stdout(Stdio::piped())
                    .stderr(Stdio::null())
                    .spawn()
                {
                    Ok(mut c) => {
                        if let Some(pipe) = c.stdout.take() {
                            child = Some(c);
                            stdout = Some(Box::new(pipe));
                            break;
                        }
                    }
                    Err(_) => continue,
                }
            }

            if stdout.is_none() {
                if let Ok(mut d) = decoded.lock() {
                    *d = Some(format!(
                        "__CAMERA_ERROR__:No camera found. Connect a camera or use /dev/videoN device."
                    ));
                }
                return;
            }

            let mut reader = stdout.unwrap();
            let mut buf = vec![0u8; frame_size];
            let mut read_offset = 0;

            loop {
                if stop.load(Ordering::SeqCst) {
                    break;
                }

                // Read a full frame of raw RGB data
                while read_offset < frame_size {
                    match reader.read(&mut buf[read_offset..]) {
                        Ok(0) => {
                            if let Ok(mut d) = decoded.lock() {
                                *d = Some(format!("__CAMERA_ERROR__:Camera disconnected."));
                            }
                            return;
                        }
                        Ok(n) => read_offset += n,
                        Err(_) => {
                            thread::sleep(Duration::from_millis(10));
                            continue;
                        }
                    }
                }
                read_offset = 0;

                // Store the frame
                if let Ok(mut f) = frames.lock() {
                    *f = Some((buf.clone(), W, H));
                }

                // Try QR decode (panic-safe — bardecoder can panic on bad frame data)
                let decode_result = std::panic::catch_unwind(|| {
                    decode_qr_from_rgb(&buf, W, H)
                });
                match decode_result {
                    Ok(Ok(Some(text))) => {
                        if let Ok(mut d) = decoded.lock() {
                            *d = Some(text);
                        }
                    }
                    Ok(Ok(None)) => {}
                    Ok(Err(e)) => {
                        eprintln!("QR decode error: {}", e);
                    }
                    Err(panic_err) => {
                        let msg = if let Some(s) = panic_err.downcast_ref::<&str>() {
                            s.to_string()
                        } else if let Some(s) = panic_err.downcast_ref::<String>() {
                            s.clone()
                        } else {
                            "unknown panic".to_string()
                        };
                        eprintln!("QR decode panic (bad frame): {}", msg);
                    }
                }
            }

            // Cleanup ffmpeg
            if let Some(mut c) = child {
                let _ = c.kill();
                let _ = c.wait();
            }
        })
        .map_err(|e| format!("Failed to spawn camera thread: {}", e))?;

    Ok(QrScannerHandle {
        stop_flag,
        frame_data,
        decoded_text,
        thread_handle: Some(handle),
    })
}

/// Decode a QR code from raw RGB image data
fn decode_qr_from_rgb(
    bytes: &[u8],
    width: u32,
    height: u32,
) -> Result<Option<String>, String> {
    let img_buffer = match image::ImageBuffer::<image::Rgb<u8>, Vec<u8>>::from_raw(
        width,
        height,
        bytes.to_vec(),
    ) {
        Some(buf) => buf,
        None => return Err("Failed to create image buffer".into()),
    };
    let dyn_img = image::DynamicImage::ImageRgb8(img_buffer);

    let decoder = bardecoder::default_decoder();
    let results = decoder.decode(&dyn_img);

    for qr_code in &results {
        if let Ok(text) = qr_code {
            if !text.is_empty() {
                return Ok(Some(text.clone()));
            }
        }
    }

    Ok(None)
}

/// Parse a TOTP URI of the form:
/// `otpauth://totp/{label}?secret={BASE32_SECRET}[&issuer={issuer}]`
///
/// Also handles:
/// `otpauth://totp/{issuer}:{label}?secret={BASE32_SECRET}&issuer={issuer}`
fn parse_totp_uri(uri: &str) -> Result<(String, String), String> {
    let parsed =
        url::Url::parse(uri).map_err(|e| format!("Invalid URI: {}", e))?;

    if parsed.scheme() != "otpauth" {
        return Err(format!("Not an otpauth URI: {}", uri));
    }

    let host = parsed.host_str().unwrap_or("");
    if host != "totp" {
        return Err(format!("Only totp type is supported, got: {}", host));
    }

    // Extract secret
    let secret = parsed
        .query_pairs()
        .find(|(k, _)| k == "secret")
        .map(|(_, v)| v.to_uppercase().to_string())
        .ok_or_else(|| "No secret found in URI".to_string())?;

    // Extract label from path. When issuer is present, use "issuer - label" format.
    let path = parsed.path().trim_start_matches('/');
    let issuer = parsed
        .query_pairs()
        .find(|(k, _)| k == "issuer")
        .map(|(_, v)| v.to_string());
    let label = if let Some(ref issuer) = issuer {
        let label_part = if path.contains(':') {
            path.splitn(2, ':').nth(1).unwrap_or(path).to_string()
        } else {
            path.to_string()
        };
        format!("{} - {}", issuer, label_part)
    } else {
        path.to_string()
    };

    if label.is_empty() {
        return Err("Empty label in URI".to_string());
    }
    if secret.is_empty() {
        return Err("Empty secret in URI".to_string());
    }

    Ok((label, secret))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_totp_uri_simple() {
        let uri = "otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP";
        let (label, secret) = parse_totp_uri(uri).unwrap();
        assert_eq!(label, "Example");
        assert_eq!(secret, "JBSWY3DPEHPK3PXP");
    }

    #[test]
    fn test_parse_totp_uri_with_issuer() {
        let uri =
            "otpauth://totp/ACME%20Inc:john@example.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME%20Inc";
        let (label, secret) = parse_totp_uri(uri).unwrap();
        assert_eq!(label, "ACME Inc - john@example.com");
        assert_eq!(secret, "JBSWY3DPEHPK3PXP");
    }

    #[test]
    fn test_parse_totp_uri_missing_secret() {
        let uri = "otpauth://totp/Example?issuer=Test";
        assert!(parse_totp_uri(uri).is_err());
    }

    #[test]
    fn test_parse_totp_uri_wrong_scheme() {
        let uri = "http://example.com";
        assert!(parse_totp_uri(uri).is_err());
    }
}
