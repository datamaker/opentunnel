import { EventEmitter } from 'events';
import { VpnMessage, MessageType, AuthRequest } from './types';
import { ProtocolSerializer } from './serializer';
import { logger } from '../utils/logger';

// Buffer handler for accumulating partial messages
export class MessageBuffer {
  private buffer: Buffer = Buffer.alloc(0);

  append(data: Buffer): void {
    this.buffer = Buffer.concat([this.buffer, data]);
  }

  // Try to extract a complete message
  extractMessage(): VpnMessage | null {
    if (this.buffer.length < 5) {
      return null;
    }

    const expectedLength = ProtocolSerializer.getExpectedLength(this.buffer);
    if (expectedLength === -1 || this.buffer.length < expectedLength) {
      return null;
    }

    const message = ProtocolSerializer.deserialize(this.buffer);
    if (message) {
      this.buffer = this.buffer.subarray(5 + message.length);
    }
    return message;
  }

  // Extract all complete messages
  extractAllMessages(): VpnMessage[] {
    const messages: VpnMessage[] = [];
    let message: VpnMessage | null;

    while ((message = this.extractMessage()) !== null) {
      messages.push(message);
    }

    return messages;
  }

  clear(): void {
    this.buffer = Buffer.alloc(0);
  }
}

// Event-based message handler
export class MessageHandler extends EventEmitter {
  private messageBuffer: MessageBuffer = new MessageBuffer();

  constructor() {
    super();
  }

  // Feed raw data from socket
  handleData(data: Buffer): void {
    this.messageBuffer.append(data);

    const messages = this.messageBuffer.extractAllMessages();
    for (const message of messages) {
      this.processMessage(message);
    }
  }

  private processMessage(message: VpnMessage): void {
    try {
      // Debug: log raw message
      logger.info(`Raw message type: ${message.type}, length: ${message.length}`);
      logger.info(`Raw payload: ${message.payload.toString('utf-8')}`);

      const payload = ProtocolSerializer.parsePayload(message);

      switch (message.type) {
        case MessageType.AUTH_REQUEST:
          logger.info(`Parsed auth request: ${JSON.stringify(payload)}`);
          this.emit('auth', payload as AuthRequest);
          break;

        case MessageType.KEEPALIVE:
          this.emit('keepalive');
          break;

        case MessageType.DISCONNECT:
          this.emit('disconnect');
          break;

        case MessageType.DATA_PACKET:
          this.emit('data', payload as Buffer);
          break;

        default:
          logger.warn(`Unknown message type: ${message.type}`);
      }
    } catch (error) {
      logger.error('Error processing message', error);
      this.emit('error', error);
    }
  }

  reset(): void {
    this.messageBuffer.clear();
    this.removeAllListeners();
  }
}
