// VPN Protocol Message Types
export enum MessageType {
  // Control messages (0x01 - 0x0F)
  AUTH_REQUEST = 0x01,
  AUTH_RESPONSE = 0x02,
  CONFIG_PUSH = 0x03,
  KEEPALIVE = 0x04,
  KEEPALIVE_ACK = 0x05,
  DISCONNECT = 0x06,
  ERROR = 0x0f,

  // Data messages (0x10+)
  DATA_PACKET = 0x10,
}

// Client platforms
export type ClientPlatform = 'ios' | 'android' | 'macos' | 'windows';

// Authentication request from client
export interface AuthRequest {
  username: string;
  password: string;
  clientVersion: string;
  platform: ClientPlatform;
}

// Authentication response to client
export interface AuthResponse {
  success: boolean;
  errorMessage?: string;
  sessionToken?: string;
}

// VPN configuration pushed to client after successful auth
export interface ConfigPush {
  assignedIP: string;
  subnetMask: string;
  gateway: string;
  dns: string[];
  mtu: number;
  keepaliveInterval: number;
}

// Error message
export interface ErrorMessage {
  code: number;
  message: string;
}

// Raw VPN message structure
export interface VpnMessage {
  type: MessageType;
  length: number;
  payload: Buffer;
}

// Parsed message union type
export type ParsedMessage =
  | { type: MessageType.AUTH_REQUEST; data: AuthRequest }
  | { type: MessageType.AUTH_RESPONSE; data: AuthResponse }
  | { type: MessageType.CONFIG_PUSH; data: ConfigPush }
  | { type: MessageType.KEEPALIVE; data: null }
  | { type: MessageType.KEEPALIVE_ACK; data: null }
  | { type: MessageType.DISCONNECT; data: null }
  | { type: MessageType.ERROR; data: ErrorMessage }
  | { type: MessageType.DATA_PACKET; data: Buffer };
