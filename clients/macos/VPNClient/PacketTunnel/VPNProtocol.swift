//
//  VPNProtocol.swift
//  VPNClient
//
//  VPN Protocol message types and serialization
//

import Foundation

// MARK: - Message Types

enum VPNMessageType: UInt8 {
    case authRequest = 0x01
    case authResponse = 0x02
    case configPush = 0x03
    case keepAlive = 0x04
    case keepAliveAck = 0x05
    case disconnect = 0x06
    case dataPacket = 0x10

    var description: String {
        switch self {
        case .authRequest: return "AUTH_REQUEST"
        case .authResponse: return "AUTH_RESPONSE"
        case .configPush: return "CONFIG_PUSH"
        case .keepAlive: return "KEEP_ALIVE"
        case .keepAliveAck: return "KEEP_ALIVE_ACK"
        case .disconnect: return "DISCONNECT"
        case .dataPacket: return "DATA_PACKET"
        }
    }
}

// MARK: - VPN Message Protocol

protocol VPNMessage {
    var type: VPNMessageType { get }
}

// MARK: - Message Types

struct AuthRequest: VPNMessage, Codable {
    let type = VPNMessageType.authRequest
    let username: String
    let password: String
    let platform: String
    let clientVersion: String

    enum CodingKeys: String, CodingKey {
        case username, password, platform, clientVersion
    }

    init(username: String, password: String) {
        self.username = username
        self.password = password
        self.platform = "macos"
        self.clientVersion = "1.0.0"
    }
}

struct AuthResponse: VPNMessage, Codable {
    let type = VPNMessageType.authResponse
    let success: Bool
    let sessionToken: String?
    let errorMessage: String?

    enum CodingKeys: String, CodingKey {
        case success, sessionToken, errorMessage
    }
}

struct ConfigPush: VPNMessage, Codable {
    let type = VPNMessageType.configPush
    let assignedIP: String
    let subnetMask: String
    let gateway: String
    let dns: [String]
    let mtu: Int
    // Split-tunnel policy (optional for backward compatibility with older servers).
    let splitTunnel: Bool?
    let includedRoutes: [String]?
    let includedDomains: [String]?

    enum CodingKeys: String, CodingKey {
        case assignedIP
        case subnetMask, gateway, dns, mtu
        case splitTunnel, includedRoutes, includedDomains
    }
}

struct KeepAlive: VPNMessage {
    let type = VPNMessageType.keepAlive
}

struct KeepAliveAck: VPNMessage {
    let type = VPNMessageType.keepAliveAck
}

struct Disconnect: VPNMessage, Codable {
    let type = VPNMessageType.disconnect
    let reason: String?

    enum CodingKeys: String, CodingKey {
        case reason
    }

    init(reason: String? = nil) {
        self.reason = reason
    }
}

struct DataPacket: VPNMessage {
    let type = VPNMessageType.dataPacket
    let payload: Data
}

// MARK: - VPN Error

enum VPNError: LocalizedError {
    case connectionFailed(String)
    case authenticationFailed(String)
    case configurationFailed(String)
    case tunnelSetupFailed(String)
    case disconnected(String)
    case timeout
    case serializationError

    var errorDescription: String? {
        switch self {
        case .connectionFailed(let msg): return "Connection failed: \(msg)"
        case .authenticationFailed(let msg): return "Authentication failed: \(msg)"
        case .configurationFailed(let msg): return "Configuration failed: \(msg)"
        case .tunnelSetupFailed(let msg): return "Tunnel setup failed: \(msg)"
        case .disconnected(let msg): return "Disconnected: \(msg)"
        case .timeout: return "Connection timeout"
        case .serializationError: return "Message serialization error"
        }
    }
}

// MARK: - Message Serializer

struct VPNMessageSerializer {
    static let headerSize = 5 // 1 byte type + 4 bytes length

    static func serialize(_ message: VPNMessage) throws -> Data {
        var data = Data()
        data.append(message.type.rawValue)

        let payload: Data
        switch message {
        case let msg as AuthRequest:
            payload = try JSONEncoder().encode(msg)
        case let msg as Disconnect:
            payload = try JSONEncoder().encode(msg)
        case let msg as DataPacket:
            payload = msg.payload
        case is KeepAlive, is KeepAliveAck:
            payload = Data()
        default:
            throw VPNError.serializationError
        }

        // Append length as big-endian 4 bytes
        var length = UInt32(payload.count).bigEndian
        data.append(Data(bytes: &length, count: 4))
        data.append(payload)

        return data
    }

    static func deserialize(_ data: Data) throws -> VPNMessage {
        guard data.count >= headerSize else {
            throw VPNError.serializationError
        }

        guard let messageType = VPNMessageType(rawValue: data[0]) else {
            throw VPNError.serializationError
        }

        let lengthData = data.subdata(in: 1..<5)
        let length = lengthData.withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }

        guard data.count >= headerSize + Int(length) else {
            throw VPNError.serializationError
        }

        let payload = data.subdata(in: headerSize..<(headerSize + Int(length)))

        switch messageType {
        case .authResponse:
            return try JSONDecoder().decode(AuthResponse.self, from: payload)
        case .configPush:
            return try JSONDecoder().decode(ConfigPush.self, from: payload)
        case .keepAlive:
            return KeepAlive()
        case .keepAliveAck:
            return KeepAliveAck()
        case .disconnect:
            return try JSONDecoder().decode(Disconnect.self, from: payload)
        case .dataPacket:
            return DataPacket(payload: payload)
        default:
            throw VPNError.serializationError
        }
    }
}

// MARK: - Message Buffer

class VPNMessageBuffer {
    private var buffer = Data()

    func append(_ data: Data) {
        buffer.append(data)
    }

    func clear() {
        buffer.removeAll()
    }

    func extractMessage() throws -> VPNMessage? {
        guard buffer.count >= VPNMessageSerializer.headerSize else {
            return nil
        }

        // Use Array to avoid Data index issues
        let bytes = Array(buffer)

        // Read length from bytes 1-4 (big-endian)
        let length = Int(UInt32(bytes[1]) << 24 | UInt32(bytes[2]) << 16 | UInt32(bytes[3]) << 8 | UInt32(bytes[4]))
        let totalSize = VPNMessageSerializer.headerSize + length

        // Sanity check for length
        guard length >= 0 && length < 1_000_000 else {
            // Invalid message length, clear buffer
            buffer.removeAll()
            throw VPNError.serializationError
        }

        guard buffer.count >= totalSize else {
            return nil
        }

        let messageData = Data(bytes[0..<totalSize])
        buffer.removeFirst(totalSize)

        return try VPNMessageSerializer.deserialize(messageData)
    }
}
