//! VPN wire protocol types.
//!
//! The framing and JSON payloads are byte-for-byte compatible with the original
//! TypeScript implementation so existing clients keep working.

use serde::{Deserialize, Serialize};

/// Message type discriminant, matching `protocol/types.ts`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    // Control messages (0x01 - 0x0F)
    AuthRequest = 0x01,
    AuthResponse = 0x02,
    ConfigPush = 0x03,
    Keepalive = 0x04,
    KeepaliveAck = 0x05,
    Disconnect = 0x06,
    Error = 0x0f,

    // Data messages (0x10+)
    DataPacket = 0x10,
}

impl MessageType {
    pub fn from_u8(value: u8) -> Option<MessageType> {
        match value {
            0x01 => Some(MessageType::AuthRequest),
            0x02 => Some(MessageType::AuthResponse),
            0x03 => Some(MessageType::ConfigPush),
            0x04 => Some(MessageType::Keepalive),
            0x05 => Some(MessageType::KeepaliveAck),
            0x06 => Some(MessageType::Disconnect),
            0x0f => Some(MessageType::Error),
            0x10 => Some(MessageType::DataPacket),
            _ => None,
        }
    }
}

/// Supported client platforms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ClientPlatform {
    Ios,
    Android,
    Macos,
    Windows,
}

impl ClientPlatform {
    /// Value stored in the `client_platform` DB column.
    pub fn as_str(&self) -> &'static str {
        match self {
            ClientPlatform::Ios => "ios",
            ClientPlatform::Android => "android",
            ClientPlatform::Macos => "macos",
            ClientPlatform::Windows => "windows",
        }
    }
}

/// Authentication request sent by the client.
#[derive(Debug, Clone, Deserialize)]
pub struct AuthRequest {
    pub username: String,
    pub password: String,
    #[serde(rename = "clientVersion", default)]
    pub client_version: String,
    pub platform: ClientPlatform,
}

/// Authentication response returned to the client.
#[derive(Debug, Clone, Serialize)]
pub struct AuthResponse {
    pub success: bool,
    #[serde(rename = "errorMessage", skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    #[serde(rename = "sessionToken", skip_serializing_if = "Option::is_none")]
    pub session_token: Option<String>,
}

/// VPN configuration pushed to the client after successful authentication.
#[derive(Debug, Clone, Serialize)]
pub struct ConfigPush {
    #[serde(rename = "assignedIP")]
    pub assigned_ip: String,
    #[serde(rename = "subnetMask")]
    pub subnet_mask: String,
    pub gateway: String,
    pub dns: Vec<String>,
    pub mtu: u32,
    #[serde(rename = "keepaliveInterval")]
    pub keepalive_interval: u32,
}

/// Structured error payload.
#[allow(dead_code)] // reserved for structured error replies
#[derive(Debug, Clone, Serialize)]
pub struct ErrorMessage {
    pub code: u16,
    pub message: String,
}
