//! Stream reassembly buffer: accumulates bytes and extracts complete frames.
//!
//! Equivalent to `MessageBuffer` in `protocol/messageHandler.ts`.

use super::serializer::HEADER_SIZE;

/// A framed message: the raw type byte plus its payload. Mapping the type byte
/// to a [`MessageType`](super::types::MessageType) is left to the caller so that
/// unknown types can be logged and skipped rather than desyncing the stream.
#[derive(Debug, Clone)]
pub struct Frame {
    pub type_byte: u8,
    pub payload: Vec<u8>,
}

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

    /// Extract a single complete frame, or `None` if more bytes are needed.
    ///
    /// The frame is always consumed from the buffer once fully received —
    /// including frames with an unrecognized type byte — so a bad type can never
    /// stall the stream. The length field is trusted regardless of type, matching
    /// the framing of the original server.
    pub fn extract(&mut self) -> Option<Frame> {
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
        // Drop the consumed frame from the front of the buffer.
        self.buffer.drain(..total);

        Some(Frame { type_byte, payload })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::serializer;
    use crate::protocol::types::MessageType;

    #[test]
    fn extracts_multiple_frames_across_chunks() {
        let mut buf = MessageBuffer::new();
        let frame_a = serializer::data_packet(&[9, 9]);
        let frame_b = serializer::keepalive();
        let combined = [frame_a, frame_b].concat();

        // Feed in two arbitrary chunks to exercise reassembly.
        buf.append(&combined[..3]);
        assert!(buf.extract().is_none());
        buf.append(&combined[3..]);

        let first = buf.extract().unwrap();
        assert_eq!(first.type_byte, MessageType::DataPacket as u8);
        assert_eq!(first.payload, vec![9, 9]);

        let second = buf.extract().unwrap();
        assert_eq!(second.type_byte, MessageType::Keepalive as u8);
        assert!(second.payload.is_empty());

        assert!(buf.extract().is_none());
    }

    #[test]
    fn unknown_type_is_consumed_not_stalled() {
        let mut buf = MessageBuffer::new();
        // An unknown type byte (0x7f) framed with a 2-byte payload, then a valid keepalive.
        buf.append(&[0x7f, 0, 0, 0, 2, 0xaa, 0xbb]);
        buf.append(&serializer::keepalive());

        let bad = buf.extract().unwrap();
        assert_eq!(bad.type_byte, 0x7f);
        assert_eq!(bad.payload, vec![0xaa, 0xbb]);

        // The following valid frame is still parseable — the stream did not desync.
        let ka = buf.extract().unwrap();
        assert_eq!(ka.type_byte, MessageType::Keepalive as u8);
    }
}
