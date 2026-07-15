//! Stream reassembly buffer: accumulates bytes and extracts complete frames.
//!
//! Equivalent to `MessageBuffer` in `protocol/messageHandler.ts`.

use super::serializer::{RawMessage, HEADER_SIZE};
use super::types::MessageType;

#[derive(Default)]
pub struct MessageBuffer {
    buffer: Vec<u8>,
}

impl MessageBuffer {
    pub fn new() -> Self {
        MessageBuffer { buffer: Vec::new() }
    }

    /// Append freshly-read bytes from the socket.
    pub fn append(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    /// Extract a single complete frame if one is fully buffered.
    ///
    /// Returns `Ok(Some(_))` for a complete frame, `Ok(None)` if more bytes are
    /// needed, and `Err(_)` if the type byte is unknown (protocol violation).
    pub fn extract(&mut self) -> Result<Option<RawMessage>, u8> {
        if self.buffer.len() < HEADER_SIZE {
            return Ok(None);
        }

        let length = u32::from_be_bytes([
            self.buffer[1],
            self.buffer[2],
            self.buffer[3],
            self.buffer[4],
        ]) as usize;

        let total = HEADER_SIZE + length;
        if self.buffer.len() < total {
            return Ok(None);
        }

        let type_byte = self.buffer[0];
        let msg_type = MessageType::from_u8(type_byte).ok_or(type_byte)?;

        let payload = self.buffer[HEADER_SIZE..total].to_vec();
        // Drop the consumed frame from the front of the buffer.
        self.buffer.drain(..total);

        Ok(Some(RawMessage { msg_type, payload }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::serializer;

    #[test]
    fn extracts_multiple_frames_across_chunks() {
        let mut buf = MessageBuffer::new();
        let frame_a = serializer::data_packet(&[9, 9]);
        let frame_b = serializer::keepalive();
        let combined = [frame_a, frame_b].concat();

        // Feed in two arbitrary chunks to exercise reassembly.
        buf.append(&combined[..3]);
        assert!(matches!(buf.extract(), Ok(None)));
        buf.append(&combined[3..]);

        let first = buf.extract().unwrap().unwrap();
        assert_eq!(first.msg_type, MessageType::DataPacket);
        assert_eq!(first.payload, vec![9, 9]);

        let second = buf.extract().unwrap().unwrap();
        assert_eq!(second.msg_type, MessageType::Keepalive);
        assert!(second.payload.is_empty());

        assert!(matches!(buf.extract(), Ok(None)));
    }
}
