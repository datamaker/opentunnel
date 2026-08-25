//! macOS: hand the session off to the OpenTunnel GUI app via a custom URL
//! scheme, so CLI-driven login/connect is reflected in the app's UI.
//!
//! Scheme contract (agreed with the app):
//! `opentunnel://session?token=<urlencoded JWT>&server=<host>&port=<port>&connect=<0|1>`
//!
//! Only a deep-link-aware app build (the new TestFlight build) acts on this;
//! older builds accept the `open` but ignore the URL.

/// App bundle path used to detect whether the GUI app is installed.
pub const APP_PATH: &str = "/Applications/OpenTunnel.app";

/// Percent-encode a query-parameter value per RFC 3986: keep the unreserved
/// set (`A-Za-z0-9-._~`) verbatim, percent-encode every other byte. A base64url
/// JWT is already unreserved, but encoding keeps the builder correct for any
/// value (hostnames, future fields).
pub fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for &byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Build the `opentunnel://session?...` deep-link URL.
pub fn build_url(token: &str, host: &str, port: u16, connect: bool) -> String {
    format!(
        "opentunnel://session?token={}&server={}&port={}&connect={}",
        percent_encode(token),
        percent_encode(host),
        port,
        if connect { 1 } else { 0 }
    )
}

#[cfg(target_os = "macos")]
pub use macos::{app_installed, hand_off_to_app};

#[cfg(target_os = "macos")]
mod macos {
    use super::{build_url, APP_PATH};

    /// Whether the GUI app is present. Used to decide if a deep-link handoff is
    /// even worth attempting before falling back to direct control.
    pub fn app_installed() -> bool {
        std::path::Path::new(APP_PATH).exists()
    }

    /// Fire the deep link at the app via `open`. `server` is `host:port`;
    /// a missing port defaults to 1194. Returns Ok(()) when `open` reported
    /// success (a registered scheme handler exists), Err otherwise.
    pub fn hand_off_to_app(token: &str, server: &str, connect: bool) -> Result<(), String> {
        let (host, port) = crate::vpn::split_host_port(server)?;
        let url = build_url(token, &host, port, connect);

        // Log the URL with the token redacted (it is a live credential).
        println!(
            "앱 딥링크 호출: opentunnel://session?token=<redacted>&server={host}&port={port}&connect={}",
            if connect { 1 } else { 0 }
        );

        let status = std::process::Command::new("open")
            .arg(&url)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map_err(|e| format!("open 실행 실패: {e}"))?;

        if status.success() {
            Ok(())
        } else {
            Err("open이 URL scheme 핸들러를 찾지 못했습니다 (앱 미설치/미등록)".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_only_reserved_bytes() {
        assert_eq!(percent_encode("Abc-._~9"), "Abc-._~9"); // unreserved untouched
        assert_eq!(percent_encode("a b"), "a%20b");
        assert_eq!(percent_encode("a/b?c=d&e"), "a%2Fb%3Fc%3Dd%26e");
        assert_eq!(percent_encode("한"), "%ED%95%9C"); // UTF-8 multibyte
    }

    #[test]
    fn base64url_jwt_is_left_intact() {
        // JWT chars are all unreserved (base64url + '.'), so no escaping.
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc-_DEF123";
        assert_eq!(percent_encode(jwt), jwt);
    }

    #[test]
    fn builds_expected_url() {
        let url = build_url("tok.en-value", "vpn.datasee.co.kr", 1194, true);
        assert_eq!(
            url,
            "opentunnel://session?token=tok.en-value&server=vpn.datasee.co.kr&port=1194&connect=1"
        );

        let login_only = build_url("t", "h", 1194, false);
        assert!(login_only.ends_with("&connect=0"));
    }

    #[test]
    fn special_chars_in_token_are_escaped() {
        // Defensive: a token containing reserved bytes must not break the query.
        let url = build_url("a+b/c=d", "host", 443, true);
        assert!(url.contains("token=a%2Bb%2Fc%3Dd"));
        assert!(url.contains("&port=443&connect=1"));
    }
}
