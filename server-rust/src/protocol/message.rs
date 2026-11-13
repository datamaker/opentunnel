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

/// A frame header announced a payload larger than the current limit. The
/// stream cannot be resynchronised after this; the connection must be closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameTooLarge {
    pub type_byte: u8,
    pub length: usize,
    pub limit: usize,
}

pub struct MessageBuffer {
    buffer: Vec<u8>,
    /// Largest payload length accepted by [`extract`](Self::extract).
    max_payload: usize,
}

impl MessageBuffer {
    /// Create a buffer that rejects frames whose payload exceeds `max_payload`.
    pub fn new(max_payload: usize) -> Self {
        MessageBuffer {
            buffer: Vec::new(),
            max_payload,
        }
    }

    /// Change the payload limit (e.g. raise it once the peer has
    /// authenticated). Applies to every frame extracted from now on.
    pub fn set_max_payload(&mut self, max_payload: usize) {
        self.max_payload = max_payload;
    }

    /// Append freshly-read bytes from the socket.
    ///
    /// Callers must drain with [`extract`](Self::extract) after every append
    /// and stop on error: that is what keeps the buffer bounded by one maximum
    /// frame plus one read chunk.
    pub fn append(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    /// Extract a single complete frame, or `Ok(None)` if more bytes are needed.
    ///
    /// The length field is checked against the limit as soon as the 5-byte
    /// header is available — before waiting for, buffering or allocating the
    /// body — so a peer cannot make the server hold more than one maximum
    /// frame by announcing a huge length.
    ///
    /// A frame within the limit is always consumed once fully received,
    /// including frames with an unrecognized type byte, so a bad type can
    /// never stall the stream.
    pub fn extract(&mut self) -> Result<Option<Frame>, FrameTooLarge> {
        if self.buffer.len() < HEADER_SIZE {
            return Ok(None);
        }

        let length = u32::from_be_bytes([
            self.buffer[1],
            self.buffer[2],
            self.buffer[3],
            self.buffer[4],
        ]) as usize;

        if length > self.max_payload {
            return Err(FrameTooLarge {
                type_byte: self.buffer[0],
                length,
                limit: self.max_payload,
            });
        }

        let total = HEADER_SIZE + length;
        if self.buffer.len() < total {
            return Ok(None);
        }

        let type_byte = self.buffer[0];
        let payload = self.buffer[HEADER_SIZE..total].to_vec();
        // Drop the consumed frame from the front of the buffer.
        self.buffer.drain(..total);

        Ok(Some(Frame { type_byte, payload }))
    }

    #[cfg(test)]
    fn capacity(&self) -> usize {
        self.buffer.capacity()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::serializer;
    use crate::protocol::types::MessageType;

    #[test]
    fn extracts_multiple_frames_across_chunks() {
        let mut buf = MessageBuffer::new(65_535);
        let frame_a = serializer::data_packet(&[9, 9]);
        let frame_b = serializer::keepalive();
        let combined = [frame_a, frame_b].concat();

        // Feed in two arbitrary chunks to exercise reassembly.
        buf.append(&combined[..3]);
        assert!(buf.extract().unwrap().is_none());
        buf.append(&combined[3..]);

        let first = buf.extract().unwrap().unwrap();
        assert_eq!(first.type_byte, MessageType::DataPacket as u8);
        assert_eq!(first.payload, vec![9, 9]);

        let second = buf.extract().unwrap().unwrap();
        assert_eq!(second.type_byte, MessageType::Keepalive as u8);
        assert!(second.payload.is_empty());

        assert!(buf.extract().unwrap().is_none());
    }

    #[test]
    fn unknown_type_is_consumed_not_stalled() {
        let mut buf = MessageBuffer::new(65_535);
        // An unknown type byte (0x7f) framed with a 2-byte payload, then a valid keepalive.
        buf.append(&[0x7f, 0, 0, 0, 2, 0xaa, 0xbb]);
        buf.append(&serializer::keepalive());

        let bad = buf.extract().unwrap().unwrap();
        assert_eq!(bad.type_byte, 0x7f);
        assert_eq!(bad.payload, vec![0xaa, 0xbb]);

        // The following valid frame is still parseable — the stream did not desync.
        let ka = buf.extract().unwrap().unwrap();
        assert_eq!(ka.type_byte, MessageType::Keepalive as u8);
    }

    #[test]
    fn oversized_length_is_rejected_from_the_header_alone() {
        let mut buf = MessageBuffer::new(16 * 1024);
        // Only the 5-byte header of a "4 GiB" auth request has arrived.
        buf.append(&[MessageType::AuthRequest as u8, 0xff, 0xff, 0xff, 0xff]);
        let err = buf.extract().unwrap_err();
        assert_eq!(
            err,
            FrameTooLarge {
                type_byte: MessageType::AuthRequest as u8,
                length: 0xffff_ffff,
                limit: 16 * 1024,
            }
        );
        // Nothing was reserved for the announced body.
        assert!(buf.capacity() < 1024, "capacity {}", buf.capacity());
        // The error is sticky: the stream cannot be resynchronised.
        assert!(buf.extract().is_err());
    }

    #[test]
    fn limit_is_inclusive_and_applies_to_any_type() {
        let mut buf = MessageBuffer::new(8);
        buf.append(&serializer::data_packet(&[7u8; 8]));
        assert_eq!(buf.extract().unwrap().unwrap().payload.len(), 8);

        // One byte over, with an unknown type byte.
        buf.append(&[0x7f, 0, 0, 0, 9]);
        assert_eq!(buf.extract().unwrap_err().length, 9);
    }

    #[test]
    fn pre_auth_limit_is_tighter_than_post_auth_limit() {
        let pre_auth = 16 * 1024;
        let post_auth = 65_535;
        let packet = serializer::data_packet(&vec![0u8; 20_000]);

        // Before authentication a 20 kB frame is refused...
        let mut buf = MessageBuffer::new(pre_auth);
        buf.append(&packet[..HEADER_SIZE]);
        assert_eq!(buf.extract().unwrap_err().limit, pre_auth);

        // ...after it (limit raised) the same frame is accepted...
        let mut buf = MessageBuffer::new(pre_auth);
        buf.set_max_payload(post_auth);
        buf.append(&packet);
        assert_eq!(buf.extract().unwrap().unwrap().payload.len(), 20_000);

        // ...up to the largest IP packet, and not one byte more.
        buf.append(&serializer::data_packet(&vec![0u8; post_auth]));
        assert_eq!(buf.extract().unwrap().unwrap().payload.len(), post_auth);
        buf.append(&[MessageType::DataPacket as u8, 0, 1, 0, 0]); // 65536
        assert_eq!(buf.extract().unwrap_err().length, 65_536);
    }

    #[test]
    fn raising_the_limit_applies_to_frames_already_buffered() {
        // An auth request and the first data packet can arrive in one read.
        let mut buf = MessageBuffer::new(4);
        buf.append(&serializer::keepalive());
        buf.append(&serializer::data_packet(&[1u8; 32]));
        assert!(buf.extract().unwrap().is_some());
        buf.set_max_payload(64);
        assert_eq!(buf.extract().unwrap().unwrap().payload.len(), 32);
    }
}
