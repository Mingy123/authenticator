use url::Url;

/// Result from parsing a QR code scan.
#[derive(Clone, Debug)]
pub enum QrResult {
    /// A valid TOTP URI was decoded.
    TotpUri { label: String, secret: String },
}

/// Parse a TOTP URI of the form:
/// `otpauth://totp/{label}?secret={BASE32_SECRET}[&issuer={issuer}]`
///
/// Also handles:
/// `otpauth://totp/{issuer}:{label}?secret={BASE32_SECRET}&issuer={issuer}`
pub fn parse_totp_uri(uri: &str) -> Result<(String, String), String> {
    let parsed = Url::parse(uri).map_err(|e| format!("Invalid URI: {}", e))?;

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
