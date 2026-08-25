//! Auth-only handshake with the OpenTunnel VPN server.
//!
//! Wire protocol (see `server-rust/src/protocol/`):
//! `[type: 1 byte][length: 4 bytes big-endian][payload: N bytes]` over TLS.
//! We send one AUTH_REQUEST (0x01), wait for the AUTH_RESPONSE (0x02), then
//! politely send DISCONNECT (0x06) and close — no tunnel is ever established.

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

const MSG_AUTH_REQUEST: u8 = 0x01;
const MSG_AUTH_RESPONSE: u8 = 0x02;
const MSG_DISCONNECT: u8 = 0x06;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const AUTH_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_FRAME_PAYLOAD: usize = 1_000_000;

/// The server's `AuthRequest` (server-rust/src/protocol/types.rs) only accepts
/// platform values ios/android/macos/windows — there is no linux/cli variant.
/// macOS reports truthfully; other unixes fall back to "android" (the closest
/// Linux-kernel value, and it keeps CLI-on-Linux sessions distinguishable from
/// the native macOS app in the admin panel). The real platform is carried in
/// `clientVersion`.
#[cfg(target_os = "macos")]
const PLATFORM: &str = "macos";
#[cfg(target_os = "windows")]
const PLATFORM: &str = "windows";
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
const PLATFORM: &str = "android";

pub fn client_version() -> String {
    format!("cli-{}-{}", env!("CARGO_PKG_VERSION"), std::env::consts::OS)
}

/// Field names must match the server's serde definitions exactly
/// (`AuthRequest` in server-rust/src/protocol/types.rs).
#[derive(Serialize)]
struct AuthRequest<'a> {
    username: &'a str,
    password: &'a str,
    #[serde(rename = "clientVersion")]
    client_version: String,
    platform: &'a str,
    #[serde(rename = "authType")]
    auth_type: &'a str,
    token: &'a str,
}

#[derive(Deserialize)]
struct AuthResponse {
    success: bool,
    #[serde(rename = "errorMessage")]
    error_message: Option<String>,
    #[serde(rename = "sessionToken")]
    session_token: Option<String>,
}

/// Authenticate against the VPN server with `authType` = "sso" (id_token) or
/// "session" (previously issued session JWT). Returns the (rotated) session
/// token the server minted for this login.
pub async fn authenticate(server: &str, auth_type: &str, token: &str) -> Result<String, String> {
    let (host, port) = split_host_port(server)?;

    let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((host.as_str(), port)))
        .await
        .map_err(|_| format!("{host}:{port} 연결 시간 초과"))?
        .map_err(|e| format!("{host}:{port} 연결 실패: {e}"))?;

    // Standard certificate verification against the Mozilla root store
    // (the server uses a real Let's Encrypt certificate).
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server_name = ServerName::try_from(host.clone())
        .map_err(|_| format!("잘못된 서버 이름: {host}"))?;
    let mut tls = TlsConnector::from(Arc::new(config))
        .connect(server_name, tcp)
        .await
        .map_err(|e| format!("TLS 핸드셰이크 실패: {e}"))?;

    let request = AuthRequest {
        username: "",
        password: "",
        client_version: client_version(),
        platform: PLATFORM,
        auth_type,
        token,
    };
    let payload =
        serde_json::to_vec(&request).map_err(|e| format!("인증 요청 직렬화 실패: {e}"))?;

    let result = tokio::time::timeout(AUTH_TIMEOUT, async {
        write_frame(&mut tls, MSG_AUTH_REQUEST, &payload).await?;

        // Read frames until the AUTH_RESPONSE arrives. On success the server
        // also pushes CONFIG_PUSH — ignore everything that is not 0x02.
        loop {
            let (frame_type, body) = read_frame(&mut tls).await?;
            if frame_type != MSG_AUTH_RESPONSE {
                continue;
            }
            let response: AuthResponse = serde_json::from_slice(&body)
                .map_err(|e| format!("인증 응답 해석 실패: {e}"))?;
            if !response.success {
                return Err(response
                    .error_message
                    .unwrap_or_else(|| "인증이 거부되었습니다".to_string()));
            }
            return response
                .session_token
                .ok_or_else(|| "서버가 세션 토큰을 반환하지 않았습니다".to_string());
        }
    })
    .await
    .map_err(|_| "인증 응답 대기 시간 초과".to_string())?;

    // Politely end the server-side session: DISCONNECT (empty payload, same
    // as the server's own serializer::disconnect()) then TLS close_notify.
    // The server frees the allocated tunnel IP and closes the session row.
    if result.is_ok() {
        let _ = write_frame(&mut tls, MSG_DISCONNECT, &[]).await;
    }
    let _ = tls.shutdown().await;

    result
}

fn split_host_port(server: &str) -> Result<(String, u16), String> {
    match server.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() => {
            let port: u16 = port
                .parse()
                .map_err(|_| format!("잘못된 포트: {server}"))?;
            Ok((host.to_string(), port))
        }
        _ => Ok((server.to_string(), 1194)),
    }
}

async fn write_frame<S>(stream: &mut S, frame_type: u8, payload: &[u8]) -> Result<(), String>
where
    S: AsyncWriteExt + Unpin,
{
    let mut buf = Vec::with_capacity(5 + payload.len());
    buf.push(frame_type);
    buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    buf.extend_from_slice(payload);
    stream
        .write_all(&buf)
        .await
        .map_err(|e| format!("전송 실패: {e}"))
}

async fn read_frame<S>(stream: &mut S) -> Result<(u8, Vec<u8>), String>
where
    S: AsyncReadExt + Unpin,
{
    let mut header = [0u8; 5];
    stream
        .read_exact(&mut header)
        .await
        .map_err(|e| format!("서버가 연결을 종료했습니다: {e}"))?;
    let length = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
    if length > MAX_FRAME_PAYLOAD {
        return Err(format!("비정상적으로 큰 프레임({length} bytes)"));
    }
    let mut payload = vec![0u8; length];
    stream
        .read_exact(&mut payload)
        .await
        .map_err(|e| format!("수신 실패: {e}"))?;
    Ok((header[0], payload))
}
