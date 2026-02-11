//
//  VPNMessage.swift
//  VPNClient
//
//  VPN Protocol Message Types
//  Shared between main app and PacketTunnelExtension
//

import Foundation

// MARK: - Message Types
/// VPN protocol message types
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
        case .keepAlive: return "KEEPALIVE"
        case .keepAliveAck: return "KEEPALIVE_ACK"
        case .disconnect: return "DISCONNECT"
        case .dataPacket: return "DATA_PACKET"
        }
    }
}

// MARK: - Message Protocol
/// Protocol for all VPN messages
protocol VPNMessageProtocol {
    var type: VPNMessageType { get }
    func encode() throws -> Data
    static func decode(from data: Data) throws -> Self
}

// MARK: - Auth Request
/// Authentication request message
struct AuthRequest: VPNMessageProtocol, Codable {
    let type: VPNMessageType = .authRequest
    let username: String
    let password: String
    let clientVersion: String
    let platform: String

    enum CodingKeys: String, CodingKey {
        case username
        case password
        case clientVersion
        case platform
    }

    init(username: String, password: String, clientVersion: String = "1.0", platform: String = "ios") {
        self.username = username
        self.password = password
        self.clientVersion = clientVersion
        self.platform = platform
    }

    func encode() throws -> Data {
        return try JSONEncoder().encode(self)
    }

    static func decode(from data: Data) throws -> AuthRequest {
        return try JSONDecoder().decode(AuthRequest.self, from: data)
    }
}

// MARK: - Auth Response
/// Authentication response message
struct AuthResponse: VPNMessageProtocol, Codable {
    let type: VPNMessageType = .authResponse
    let success: Bool
    let sessionToken: String?
    let errorMessage: String?

    enum CodingKeys: String, CodingKey {
        case success
        case sessionToken
        case errorMessage
    }

    init(success: Bool, sessionToken: String? = nil, errorMessage: String? = nil) {
        self.success = success
        self.sessionToken = sessionToken
        self.errorMessage = errorMessage
    }

    func encode() throws -> Data {
        return try JSONEncoder().encode(self)
    }

    static func decode(from data: Data) throws -> AuthResponse {
        return try JSONDecoder().decode(AuthResponse.self, from: data)
    }
}

// MARK: - Config Push
/// Configuration push message from server
struct ConfigPush: VPNMessageProtocol, Codable {
    let type: VPNMessageType = .configPush
    let assignedIP: String
    let subnetMask: String
    let gateway: String
    let dns: [String]
    let mtu: Int

    enum CodingKeys: String, CodingKey {
        case assignedIP
        case subnetMask
        case gateway
        case dns
        case mtu
    }

    init(assignedIP: String, subnetMask: String, gateway: String, dns: [String], mtu: Int = 1400) {
        self.assignedIP = assignedIP
        self.subnetMask = subnetMask
        self.gateway = gateway
        self.dns = dns
        self.mtu = mtu
    }

    func encode() throws -> Data {
        return try JSONEncoder().encode(self)
    }

    static func decode(from data: Data) throws -> ConfigPush {
        return try JSONDecoder().decode(ConfigPush.self, from: data)
    }
}

// MARK: - Keep Alive
/// Keep alive message
struct KeepAlive: VPNMessageProtocol {
    let type: VPNMessageType = .keepAlive
    let timestamp: UInt64

    init(timestamp: UInt64 = UInt64(Date().timeIntervalSince1970 * 1000)) {
        self.timestamp = timestamp
    }

    func encode() throws -> Data {
        var data = Data()
        var ts = timestamp.bigEndian
        data.append(Data(bytes: &ts, count: MemoryLayout<UInt64>.size))
        return data
    }

    static func decode(from data: Data) throws -> KeepAlive {
        guard data.count >= MemoryLayout<UInt64>.size else {
            throw VPNMessageError.invalidPayload
        }

        let timestamp = data.withUnsafeBytes { ptr -> UInt64 in
            ptr.load(as: UInt64.self).bigEndian
        }

        return KeepAlive(timestamp: timestamp)
    }
}

// MARK: - Keep Alive Ack
/// Keep alive acknowledgment message
struct KeepAliveAck: VPNMessageProtocol {
    let type: VPNMessageType = .keepAliveAck
    let timestamp: UInt64

    init(timestamp: UInt64 = UInt64(Date().timeIntervalSince1970 * 1000)) {
        self.timestamp = timestamp
    }

    func encode() throws -> Data {
        var data = Data()
        var ts = timestamp.bigEndian
        data.append(Data(bytes: &ts, count: MemoryLayout<UInt64>.size))
        return data
    }

    static func decode(from data: Data) throws -> KeepAliveAck {
        guard data.count >= MemoryLayout<UInt64>.size else {
            throw VPNMessageError.invalidPayload
        }

        let timestamp = data.withUnsafeBytes { ptr -> UInt64 in
            ptr.load(as: UInt64.self).bigEndian
        }

        return KeepAliveAck(timestamp: timestamp)
    }
}

// MARK: - Disconnect
/// Disconnect message
struct DisconnectMessage: VPNMessageProtocol {
    let type: VPNMessageType = .disconnect
    let reason: DisconnectReason

    enum DisconnectReason: UInt8 {
        case userRequested = 0x00
        case serverShutdown = 0x01
        case authenticationFailed = 0x02
        case sessionExpired = 0x03
        case error = 0xFF
    }

    init(reason: DisconnectReason = .userRequested) {
        self.reason = reason
    }

    func encode() throws -> Data {
        return Data([reason.rawValue])
    }

    static func decode(from data: Data) throws -> DisconnectMessage {
        guard data.count >= 1 else {
            throw VPNMessageError.invalidPayload
        }

        let reasonValue = data[0]
        let reason = DisconnectReason(rawValue: reasonValue) ?? .error

        return DisconnectMessage(reason: reason)
    }
}

// MARK: - Data Packet
/// Raw IP data packet
struct DataPacket: VPNMessageProtocol {
    let type: VPNMessageType = .dataPacket
    let payload: Data

    init(payload: Data) {
        self.payload = payload
    }

    func encode() throws -> Data {
        return payload
    }

    static func decode(from data: Data) throws -> DataPacket {
        return DataPacket(payload: data)
    }
}

// MARK: - Message Errors
enum VPNMessageError: LocalizedError {
    case invalidMessageType
    case invalidPayload
    case encodingFailed
    case decodingFailed
    case insufficientData
    case checksumMismatch

    var errorDescription: String? {
        switch self {
        case .invalidMessageType:
            return "Invalid message type"
        case .invalidPayload:
            return "Invalid message payload"
        case .encodingFailed:
            return "Message encoding failed"
        case .decodingFailed:
            return "Message decoding failed"
        case .insufficientData:
            return "Insufficient data in message"
        case .checksumMismatch:
            return "Message checksum mismatch"
        }
    }
}

// MARK: - Message Factory
/// Factory for creating VPN messages
enum VPNMessageFactory {
    /// Create a message from raw data
    static func createMessage(type: VPNMessageType, payload: Data) throws -> any VPNMessageProtocol {
        switch type {
        case .authRequest:
            return try AuthRequest.decode(from: payload)
        case .authResponse:
            return try AuthResponse.decode(from: payload)
        case .configPush:
            return try ConfigPush.decode(from: payload)
        case .keepAlive:
            return try KeepAlive.decode(from: payload)
        case .keepAliveAck:
            return try KeepAliveAck.decode(from: payload)
        case .disconnect:
            return try DisconnectMessage.decode(from: payload)
        case .dataPacket:
            return try DataPacket.decode(from: payload)
        }
    }
}
