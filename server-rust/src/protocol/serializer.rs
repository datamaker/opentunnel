//! Wire framing: `[type: 1 byte][length: 4 bytes big-endian][payload: N bytes]`.

use super::types::{AuthResponse, ConfigPush, ErrorMessage, MessageType};

pub const HEADER_SIZE: usize = 5;

/// Serialize a message type and raw payload bytes into a framed buffer.
pub fn serialize(msg_type: MessageType, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(HEADER_SIZE + payload.len());
    buf.push(msg_type as u8);
    buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    buf.extend_from_slice(payload);
    buf
}

/// Serialize a value as a JSON payload wrapped in the given message type.
pub fn serialize_json<T: serde::Serialize>(msg_type: MessageType, value: &T) -> Vec<u8> {
    let payload = serde_json::to_vec(value).unwrap_or_default();
    serialize(msg_type, &payload)
}

pub fn auth_response(response: &AuthResponse) -> Vec<u8> {
    serialize_json(MessageType::AuthResponse, response)
}

pub fn config_push(config: &ConfigPush) -> Vec<u8> {
    serialize_json(MessageType::ConfigPush, config)
}

pub fn keepalive() -> Vec<u8> {
    serialize(MessageType::Keepalive, &[])
}

pub fn keepalive_ack() -> Vec<u8> {
    serialize(MessageType::KeepaliveAck, &[])
}

#[allow(dead_code)] // part of the protocol API; server does not initiate disconnects yet
pub fn disconnect() -> Vec<u8> {
    serialize(MessageType::Disconnect, &[])
}

#[allow(dead_code)] // reserved for structured error replies
pub fn error(err: &ErrorMessage) -> Vec<u8> {
    serialize_json(MessageType::Error, err)
}

pub fn data_packet(data: &[u8]) -> Vec<u8> {
    serialize(MessageType::DataPacket, data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_frame() {
        let framed = serialize(MessageType::DataPacket, &[1, 2, 3, 4]);
        assert_eq!(framed[0], MessageType::DataPacket as u8);
        assert_eq!(&framed[1..5], &[0, 0, 0, 4]);
        assert_eq!(&framed[5..], &[1, 2, 3, 4]);
    }

    #[test]
    fn empty_payload() {
        let framed = keepalive();
        assert_eq!(framed.len(), HEADER_SIZE);
        assert_eq!(&framed[1..5], &[0, 0, 0, 0]);
    }
}
