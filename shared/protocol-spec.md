# VPN Protocol Specification

## Overview
This document describes the custom VPN protocol used for communication between clients and the server.

## Transport Layer
- **Protocol**: TLS 1.2/1.3 over TCP
- **Default Port**: 1194
- **Encryption**: AES-256-GCM or ChaCha20-Poly1305

## Message Format

All messages follow this format:

```
+--------+----------+------------------+
| Type   | Length   | Payload          |
| 1 byte | 4 bytes  | N bytes          |
+--------+----------+------------------+
```

- **Type**: Message type identifier (1 byte)
- **Length**: Payload length in bytes (4 bytes, big-endian)
- **Payload**: Message-specific data (variable length)

## Message Types

### Control Messages (0x01 - 0x0F)

| Type | Name           | Description                    |
|------|----------------|--------------------------------|
| 0x01 | AUTH_REQUEST   | Client authentication request  |
| 0x02 | AUTH_RESPONSE  | Server authentication response |
| 0x03 | CONFIG_PUSH    | VPN configuration from server  |
| 0x04 | KEEPALIVE      | Keepalive ping                 |
| 0x05 | KEEPALIVE_ACK  | Keepalive acknowledgment       |
| 0x06 | DISCONNECT     | Graceful disconnect            |
| 0x0F | ERROR          | Error message                  |

### Data Messages (0x10+)

| Type | Name        | Description           |
|------|-------------|-----------------------|
| 0x10 | DATA_PACKET | Encapsulated IP packet|

## Message Payloads

### AUTH_REQUEST (0x01)
```json
{
  "username": "string",
  "password": "string",
  "clientVersion": "string",
  "platform": "ios|android|macos|windows"
}
```

### AUTH_RESPONSE (0x02)
```json
{
  "success": true|false,
  "errorMessage": "string (optional)",
  "sessionToken": "string (optional)"
}
```

### CONFIG_PUSH (0x03)
```json
{
  "assignedIP": "10.8.0.x",
  "subnetMask": "255.255.255.0",
  "gateway": "10.8.0.1",
  "dns": ["8.8.8.8", "8.8.4.4"],
  "mtu": 1400,
  "keepaliveInterval": 10
}
```

### ERROR (0x0F)
```json
{
  "code": 1001,
  "message": "Error description"
}
```

### DATA_PACKET (0x10)
Raw IP packet (IPv4)

## Connection Flow

```
Client                          Server
  |                               |
  |-------- TLS Handshake ------->|
  |<------- TLS Established ------|
  |                               |
  |-------- AUTH_REQUEST -------->|
  |<------- AUTH_RESPONSE --------|
  |<------- CONFIG_PUSH ----------|
  |                               |
  |<======= DATA_PACKET =========>|
  |<======= DATA_PACKET =========>|
  |                               |
  |-------- KEEPALIVE ----------->|
  |<------- KEEPALIVE_ACK --------|
  |                               |
  |-------- DISCONNECT ---------->|
  |                               |
```

## Error Codes

| Code | Description              |
|------|--------------------------|
| 1001 | Invalid credentials      |
| 1002 | Account disabled         |
| 1003 | Max connections reached  |
| 1004 | IP pool exhausted        |
| 1005 | Internal server error    |
| 1006 | Session timeout          |

## Keepalive

- Client sends KEEPALIVE every 30 seconds of inactivity
- Server responds with KEEPALIVE_ACK
- Connection is terminated if no activity for 120 seconds
