import {
  MessageType,
  VpnMessage,
  AuthRequest,
  AuthResponse,
  ConfigPush,
  ErrorMessage,
} from './types';

// Message format:
// [type: 1 byte][length: 4 bytes (big-endian)][payload: N bytes]
const HEADER_SIZE = 5;

export class ProtocolSerializer {
  // Serialize a VPN message to buffer
  static serialize(type: MessageType, payload: Buffer | object): Buffer {
    const payloadBuffer =
      payload instanceof Buffer ? payload : Buffer.from(JSON.stringify(payload));

    const header = Buffer.alloc(HEADER_SIZE);
    header.writeUInt8(type, 0);
    header.writeUInt32BE(payloadBuffer.length, 1);

    return Buffer.concat([header, payloadBuffer]);
  }

  // Deserialize buffer to VPN message
  static deserialize(data: Buffer): VpnMessage | null {
    if (data.length < HEADER_SIZE) {
      return null;
    }

    const type = data.readUInt8(0) as MessageType;
    const length = data.readUInt32BE(1);

    if (data.length < HEADER_SIZE + length) {
      return null;
    }

    const payload = data.subarray(HEADER_SIZE, HEADER_SIZE + length);

    return { type, length, payload };
  }

  // Get the expected message length from header
  static getExpectedLength(header: Buffer): number {
    if (header.length < HEADER_SIZE) {
      return -1;
    }
    return HEADER_SIZE + header.readUInt32BE(1);
  }

  // Helper methods for specific message types
  static serializeAuthRequest(request: AuthRequest): Buffer {
    return this.serialize(MessageType.AUTH_REQUEST, request);
  }

  static serializeAuthResponse(response: AuthResponse): Buffer {
    return this.serialize(MessageType.AUTH_RESPONSE, response);
  }

  static serializeConfigPush(config: ConfigPush): Buffer {
    return this.serialize(MessageType.CONFIG_PUSH, config);
  }

  static serializeKeepalive(): Buffer {
    return this.serialize(MessageType.KEEPALIVE, Buffer.alloc(0));
  }

  static serializeKeepaliveAck(): Buffer {
    return this.serialize(MessageType.KEEPALIVE_ACK, Buffer.alloc(0));
  }

  static serializeDisconnect(): Buffer {
    return this.serialize(MessageType.DISCONNECT, Buffer.alloc(0));
  }

  static serializeError(error: ErrorMessage): Buffer {
    return this.serialize(MessageType.ERROR, error);
  }

  static serializeDataPacket(data: Buffer): Buffer {
    return this.serialize(MessageType.DATA_PACKET, data);
  }

  // Parse payload based on message type
  static parsePayload(message: VpnMessage): unknown {
    switch (message.type) {
      case MessageType.AUTH_REQUEST:
      case MessageType.AUTH_RESPONSE:
      case MessageType.CONFIG_PUSH:
      case MessageType.ERROR:
        return JSON.parse(message.payload.toString('utf-8'));

      case MessageType.KEEPALIVE:
      case MessageType.KEEPALIVE_ACK:
      case MessageType.DISCONNECT:
        return null;

      case MessageType.DATA_PACKET:
        return message.payload;

      default:
        return message.payload;
    }
  }
}
