//! OAuth 2.0 Device Authorization Grant (RFC 8628) against the Datasee IdP.
//!
//! Mirrors `clients/macos/.../Services/DeviceFlowService.swift`:
//! POST {issuer}/oidc/device/auth, then poll POST {issuer}/oidc/token with
//! grant_type=urn:ietf:params:oauth:grant-type:device_code, honoring
//! authorization_pending / slow_down (+5s) / expired_token / access_denied.

use serde::Deserialize;
use std::time::Duration;
use tokio::time::Instant;

pub const SCOPE: &str = "openid email profile";

const DEVICE_CODE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";

/// Response of POST /oidc/device/auth.
#[derive(Debug, Deserialize)]
pub struct DeviceAuthorization {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: Option<String>,
    pub expires_in: u64,
    pub interval: Option<u64>,
}

impl DeviceAuthorization {
    /// URL the user must open (complete variant carries the pre-filled code).
    pub fn verification_url(&self) -> &str {
        self.verification_uri_complete
            .as_deref()
            .unwrap_or(&self.verification_uri)
    }
}

pub struct DeviceFlow {
    issuer: String,
    client_id: String,
    http: reqwest::Client,
}

impl DeviceFlow {
    pub fn new(issuer: &str, client_id: &str) -> Result<Self, String> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|e| format!("HTTP 클라이언트 초기화 실패: {e}"))?;
        Ok(DeviceFlow {
            issuer: issuer.trim_end_matches('/').to_string(),
            client_id: client_id.to_string(),
            http,
        })
    }

    /// Step 1: request a device/user code pair from the IdP.
    pub async fn start(&self) -> Result<DeviceAuthorization, String> {
        let (status, body) = self
            .post(
                "/oidc/device/auth",
                &[("client_id", self.client_id.as_str()), ("scope", SCOPE)],
            )
            .await?;
        if !status.is_success() {
            return Err(format!(
                "device auth 실패: {}",
                error_code(&body).unwrap_or_else(|| format!("HTTP {status}"))
            ));
        }
        serde_json::from_slice(&body).map_err(|e| format!("device auth 응답 해석 실패: {e}"))
    }

    /// Step 2: poll the token endpoint until the user approves in the browser.
    /// Returns the OIDC id_token. Respects the server's `interval` (plus
    /// `slow_down` back-off) and gives up once `expires_in` elapses.
    pub async fn poll_for_id_token(&self, auth: &DeviceAuthorization) -> Result<String, String> {
        let mut interval = auth.interval.unwrap_or(5).max(1);
        let deadline = Instant::now() + Duration::from_secs(auth.expires_in);

        while Instant::now() < deadline {
            tokio::time::sleep(Duration::from_secs(interval)).await;

            let (status, body) = self
                .post(
                    "/oidc/token",
                    &[
                        ("grant_type", DEVICE_CODE_GRANT),
                        ("device_code", auth.device_code.as_str()),
                        ("client_id", self.client_id.as_str()),
                    ],
                )
                .await?;

            if status.is_success() {
                let json: serde_json::Value = serde_json::from_slice(&body)
                    .map_err(|e| format!("토큰 응답 해석 실패: {e}"))?;
                match json.get("id_token").and_then(|v| v.as_str()) {
                    Some(id_token) if !id_token.is_empty() => return Ok(id_token.to_string()),
                    _ => return Err("토큰 응답에 id_token이 없습니다".to_string()),
                }
            }

            match error_code(&body).as_deref() {
                Some("authorization_pending") => continue, // not approved yet — keep polling
                Some("slow_down") => interval += 5,
                Some("expired_token") => {
                    return Err("로그인 요청이 만료되었습니다. 다시 시도해 주세요".to_string())
                }
                Some("access_denied") => return Err("로그인이 거부되었습니다".to_string()),
                Some(code) => return Err(format!("로그인 실패: {code}")),
                None => return Err(format!("로그인 실패: HTTP {status}")),
            }
        }
        Err("로그인 요청이 만료되었습니다. 다시 시도해 주세요".to_string())
    }

    async fn post(
        &self,
        path: &str,
        form: &[(&str, &str)],
    ) -> Result<(reqwest::StatusCode, Vec<u8>), String> {
        let url = format!("{}{}", self.issuer, path);
        let resp = self
            .http
            .post(&url)
            .form(form)
            .send()
            .await
            .map_err(|e| format!("{url} 요청 실패: {e}"))?;
        let status = resp.status();
        let body = resp
            .bytes()
            .await
            .map_err(|e| format!("{url} 응답 수신 실패: {e}"))?;
        Ok((status, body.to_vec()))
    }
}

/// Best-effort read of the OAuth `error` code from a response body.
fn error_code(body: &[u8]) -> Option<String> {
    let json: serde_json::Value = serde_json::from_slice(body).ok()?;
    json.get("error")?.as_str().map(|s| s.to_string())
}
