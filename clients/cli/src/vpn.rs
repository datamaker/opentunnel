//! Wire protocol + auth handshake with the OpenTunnel VPN server.
//!
//! Wire protocol (see `server-rust/src/protocol/`):
//! `[type: 1 byte][length: 4 bytes big-endian][payload: N bytes]` over TLS.
//!
//! Two modes:
//! - [`authenticate`]: auth-only handshake (login/renew) — send one
//!   AUTH_REQUEST (0x01), wait for AUTH_RESPONSE (0x02), politely send
//!   DISCONNECT (0x06) and close. No tunnel is established.
//! - [`connect_for_tunnel`]: same handshake but keeps the TLS stream open and
//!   also waits for CONFIG_PUSH (0x03) — used by the standalone Linux tunnel.

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

pub const MSG_AUTH_REQUEST: u8 = 0x01;
pub const MSG_AUTH_RESPONSE: u8 = 0x02;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))] // Linux tunnel only
pub const MSG_CONFIG_PUSH: u8 = 0x03;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))] // Linux tunnel only
pub const MSG_KEEPALIVE: u8 = 0x04;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))] // Linux tunnel only
pub const MSG_KEEPALIVE_ACK: u8 = 0x05;
pub const MSG_DISCONNECT: u8 = 0x06;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))] // Linux tunnel only
pub const MSG_DATA_PACKET: u8 = 0x10;

pub const HEADER_SIZE: usize = 5;

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

/// Server's `ConfigPush` (server-rust/src/protocol/types.rs). Optional fields
/// are tolerated for compatibility with older servers, like the app clients do.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))] // Linux tunnel only
#[derive(Debug, Deserialize)]
pub struct ConfigPush {
    #[serde(rename = "assignedIP")]
    pub assigned_ip: String,
    #[serde(rename = "subnetMask")]
    pub subnet_mask: String,
    #[allow(dead_code)] // pushed by the server; the CLI routes by CIDR instead
    pub gateway: String,
    #[serde(default)]
    pub dns: Vec<String>,
    pub mtu: u32,
    #[serde(rename = "keepaliveInterval", default)]
    #[allow(dead_code)] // CLI uses its own fixed keepalive cadence
    pub keepalive_interval: u32,
    #[serde(rename = "splitTunnel", default)]
    pub split_tunnel: bool,
    #[serde(rename = "includedRoutes", default)]
    pub included_routes: Vec<String>,
    #[serde(rename = "includedDomains", default)]
    pub included_domains: Vec<String>,
}

/// Encode one wire frame: `[type][len: u32 BE][payload]`.
pub fn encode_frame(frame_type: u8, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(HEADER_SIZE + payload.len());
    buf.push(frame_type);
    buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    buf.extend_from_slice(payload);
    buf
}

/// Stream reassembly buffer — port of the server's `MessageBuffer`
/// (server-rust/src/protocol/message.rs): a frame is always consumed once
/// fully received, even with an unknown type byte, so the stream never desyncs.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))] // Linux tunnel only
#[derive(Default)]
pub struct MessageBuffer {
    buffer: Vec<u8>,
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))] // Linux tunnel only
impl MessageBuffer {
    pub fn new() -> Self {
        MessageBuffer { buffer: Vec::new() }
    }

    pub fn append(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    /// Extract a single complete `(type_byte, payload)`, or `None` if more
    /// bytes are needed.
    pub fn extract(&mut self) -> Option<(u8, Vec<u8>)> {
        if self.buffer.len() < HEADER_SIZE {
            return None;
        }
        let length = u32::from_be_bytes([
            self.buffer[1],
            self.buffer[2],
            self.buffer[3],
            self.buffer[4],
        ]) as usize;
        let total = HEADER_SIZE + length;
        if self.buffer.len() < total {
            return None;
        }
        let type_byte = self.buffer[0];
        let payload = self.buffer[HEADER_SIZE..total].to_vec();
        self.buffer.drain(..total);
        Some((type_byte, payload))
    }
}

pub fn split_host_port(server: &str) -> Result<(String, u16), String> {
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

/// TCP + TLS to the VPN server with standard certificate verification against
/// the Mozilla root store (the server uses a real Let's Encrypt certificate).
pub async fn connect_tls(server: &str) -> Result<TlsStream<TcpStream>, String> {
    let (host, port) = split_host_port(server)?;

    let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((host.as_str(), port)))
        .await
        .map_err(|_| format!("{host}:{port} 연결 시간 초과"))?
        .map_err(|e| format!("{host}:{port} 연결 실패: {e}"))?;

    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server_name = ServerName::try_from(host.clone())
        .map_err(|_| format!("잘못된 서버 이름: {host}"))?;
    TlsConnector::from(Arc::new(config))
        .connect(server_name, tcp)
        .await
        .map_err(|e| format!("TLS 핸드셰이크 실패: {e}"))
}

/// Send AUTH_REQUEST and wait for AUTH_RESPONSE on an established stream.
/// Returns the (rotated) session token. Non-0x02 frames are ignored.
async fn auth_handshake(
    tls: &mut TlsStream<TcpStream>,
    auth_type: &str,
    token: &str,
) -> Result<String, String> {
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

    tokio::time::timeout(AUTH_TIMEOUT, async {
        write_frame(tls, MSG_AUTH_REQUEST, &payload).await?;
        loop {
            let (frame_type, body) = read_frame(tls).await?;
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
    .map_err(|_| "인증 응답 대기 시간 초과".to_string())?
}

/// Authenticate against the VPN server with `authType` = "sso" (id_token) or
/// "session" (previously issued session JWT). Returns the (rotated) session
/// token the server minted for this login. No tunnel is established.
pub async fn authenticate(server: &str, auth_type: &str, token: &str) -> Result<String, String> {
    let mut tls = connect_tls(server).await?;
    let result = auth_handshake(&mut tls, auth_type, token).await;

    // Politely end the server-side session: DISCONNECT (empty payload, same
    // as the server's own serializer::disconnect()) then TLS close_notify.
    // The server frees the allocated tunnel IP and closes the session row.
    if result.is_ok() {
        let _ = write_frame(&mut tls, MSG_DISCONNECT, &[]).await;
    }
    let _ = tls.shutdown().await;

    result
}

/// Authenticate and keep the stream open for a real tunnel: waits for the
/// CONFIG_PUSH that the server sends right after a successful auth.
/// Returns `(stream, rotated session token, tunnel config)`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))] // Linux tunnel only
pub async fn connect_for_tunnel(
    server: &str,
    auth_type: &str,
    token: &str,
) -> Result<(TlsStream<TcpStream>, String, ConfigPush), String> {
    let mut tls = connect_tls(server).await?;
    let session_token = auth_handshake(&mut tls, auth_type, token).await?;

    let config = tokio::time::timeout(AUTH_TIMEOUT, async {
        loop {
            let (frame_type, body) = read_frame(&mut tls).await?;
            if frame_type != MSG_CONFIG_PUSH {
                continue;
            }
            return serde_json::from_slice::<ConfigPush>(&body)
                .map_err(|e| format!("서버 설정(ConfigPush) 해석 실패: {e}"));
        }
    })
    .await
    .map_err(|_| "서버 설정(ConfigPush) 대기 시간 초과".to_string())??;

    Ok((tls, session_token, config))
}

pub async fn write_frame<S>(stream: &mut S, frame_type: u8, payload: &[u8]) -> Result<(), String>
where
    S: AsyncWriteExt + Unpin,
{
    stream
        .write_all(&encode_frame(frame_type, payload))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip_through_buffer() {
        let mut buf = MessageBuffer::new();
        let a = encode_frame(MSG_DATA_PACKET, &[9, 9]);
        let b = encode_frame(MSG_KEEPALIVE, &[]);
        let combined = [a, b].concat();

        // Feed in two arbitrary chunks to exercise reassembly.
        buf.append(&combined[..3]);
        assert!(buf.extract().is_none());
        buf.append(&combined[3..]);

        let (t1, p1) = buf.extract().unwrap();
        assert_eq!((t1, p1.as_slice()), (MSG_DATA_PACKET, &[9u8, 9][..]));
        let (t2, p2) = buf.extract().unwrap();
        assert_eq!((t2, p2.len()), (MSG_KEEPALIVE, 0));
        assert!(buf.extract().is_none());
    }

    #[test]
    fn encode_frame_layout_matches_server() {
        // Mirrors server-rust/src/protocol/serializer.rs::roundtrip_frame.
        let framed = encode_frame(MSG_DATA_PACKET, &[1, 2, 3, 4]);
        assert_eq!(framed[0], 0x10);
        assert_eq!(&framed[1..5], &[0, 0, 0, 4]);
        assert_eq!(&framed[5..], &[1, 2, 3, 4]);
    }

    #[test]
    fn config_push_parses_server_shape() {
        // Field names exactly as serialized by server-rust/src/protocol/types.rs.
        let json = r#"{
            "assignedIP": "10.8.0.5",
            "subnetMask": "255.255.255.0",
            "gateway": "10.8.0.1",
            "dns": ["10.8.0.1"],
            "mtu": 1400,
            "keepaliveInterval": 10,
            "splitTunnel": true,
            "includedRoutes": ["11.0.0.0/16"],
            "includedDomains": ["internal.datasee.co.kr"]
        }"#;
        let config: ConfigPush = serde_json::from_str(json).unwrap();
        assert_eq!(config.assigned_ip, "10.8.0.5");
        assert_eq!(config.subnet_mask, "255.255.255.0");
        assert_eq!(config.mtu, 1400);
        assert!(config.split_tunnel);
        assert_eq!(config.included_routes, vec!["11.0.0.0/16"]);

        // Older servers omit the split-tunnel fields entirely.
        let legacy = r#"{
            "assignedIP": "10.8.0.5",
            "subnetMask": "255.255.255.0",
            "gateway": "10.8.0.1",
            "dns": [],
            "mtu": 1400
        }"#;
        let config: ConfigPush = serde_json::from_str(legacy).unwrap();
        assert!(!config.split_tunnel);
        assert!(config.included_routes.is_empty());
    }

    #[test]
    fn split_host_port_defaults() {
        assert_eq!(
            split_host_port("vpn.datasee.co.kr:1194").unwrap(),
            ("vpn.datasee.co.kr".to_string(), 1194)
        );
        assert_eq!(
            split_host_port("vpn.datasee.co.kr").unwrap(),
            ("vpn.datasee.co.kr".to_string(), 1194)
        );
        assert!(split_host_port("host:notaport").is_err());
    }
}
