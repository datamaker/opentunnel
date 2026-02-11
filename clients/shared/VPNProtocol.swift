//
//  VPNProtocol.swift
//  VPN Client - Shared Code
//
//  Shared VPN Protocol definitions for iOS and macOS
//  This file can be shared between platforms using Xcode file references
//

import Foundation

// MARK: - Message Types
/// VPN protocol message types - shared between platforms
public enum SharedVPNMessageType: UInt8, Sendable {
    case authRequest = 0x01
    case authResponse = 0x02
    case configPush = 0x03
    case keepAlive = 0x04
    case keepAliveAck = 0x05
    case disconnect = 0x06
    case dataPacket = 0x10

    public var description: String {
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

// MARK: - Protocol Constants
public enum VPNProtocolConstants {
    /// Header size: 1 byte type + 4 bytes length (big endian)
    public static let headerSize = 5

    /// Maximum payload size (64KB)
    public static let maxPayloadSize: UInt32 = 65535

    /// Default MTU
    public static let defaultMTU = 1400

    /// Keep alive interval in seconds
    public static let keepAliveInterval: TimeInterval = 30.0

    /// Connection timeout in seconds
    public static let connectionTimeout: TimeInterval = 30.0

    /// Default VPN port
    public static let defaultPort = 443

    /// Client platform identifiers
    public static let platformiOS = "ios"
    public static let platformMacOS = "macos"
}

// MARK: - Auth Request Payload
/// Authentication request payload - JSON encoded
public struct AuthRequestPayload: Codable, Sendable {
    public let username: String
    public let password: String
    public let clientVersion: String
    public let platform: String

    public init(username: String, password: String, clientVersion: String, platform: String) {
        self.username = username
        self.password = password
        self.clientVersion = clientVersion
        self.platform = platform
    }
}

// MARK: - Auth Response Payload
/// Authentication response payload - JSON encoded
public struct AuthResponsePayload: Codable, Sendable {
    public let success: Bool
    public let sessionToken: String?
    public let errorMessage: String?

    public init(success: Bool, sessionToken: String? = nil, errorMessage: String? = nil) {
        self.success = success
        self.sessionToken = sessionToken
        self.errorMessage = errorMessage
    }
}

// MARK: - Config Push Payload
/// Configuration push payload - JSON encoded
public struct ConfigPushPayload: Codable, Sendable {
    public let assignedIP: String
    public let subnetMask: String
    public let gateway: String
    public let dns: [String]
    public let mtu: Int

    public init(assignedIP: String, subnetMask: String, gateway: String, dns: [String], mtu: Int = VPNProtocolConstants.defaultMTU) {
        self.assignedIP = assignedIP
        self.subnetMask = subnetMask
        self.gateway = gateway
        self.dns = dns
        self.mtu = mtu
    }
}

// MARK: - Disconnect Reasons
/// Disconnect reason codes
public enum DisconnectReasonCode: UInt8, Sendable {
    case userRequested = 0x00
    case serverShutdown = 0x01
    case authenticationFailed = 0x02
    case sessionExpired = 0x03
    case protocolError = 0x04
    case unknown = 0xFF

    public var description: String {
        switch self {
        case .userRequested: return "User requested disconnect"
        case .serverShutdown: return "Server shutdown"
        case .authenticationFailed: return "Authentication failed"
        case .sessionExpired: return "Session expired"
        case .protocolError: return "Protocol error"
        case .unknown: return "Unknown reason"
        }
    }
}

// MARK: - Message Header
/// VPN message header - shared implementation
public struct SharedMessageHeader: Sendable {
    public let type: SharedVPNMessageType
    public let length: UInt32

    public init(type: SharedVPNMessageType, length: UInt32) {
        self.type = type
        self.length = length
    }

    /// Encode header to wire format
    public func encode() -> Data {
        var data = Data()
        data.append(type.rawValue)

        var lengthBE = length.bigEndian
        withUnsafeBytes(of: &lengthBE) { data.append(contentsOf: $0) }

        return data
    }

    /// Decode header from wire format
    public static func decode(from data: Data) throws -> SharedMessageHeader {
        guard data.count >= VPNProtocolConstants.headerSize else {
            throw SharedProtocolError.insufficientData
        }

        guard let type = SharedVPNMessageType(rawValue: data[0]) else {
            throw SharedProtocolError.invalidMessageType(data[0])
        }

        let length = data.subdata(in: 1..<5).withUnsafeBytes { ptr -> UInt32 in
            ptr.load(as: UInt32.self).bigEndian
        }

        return SharedMessageHeader(type: type, length: length)
    }
}

// MARK: - Protocol Errors
/// Shared protocol errors
public enum SharedProtocolError: LocalizedError, Sendable {
    case insufficientData
    case invalidMessageType(UInt8)
    case encodingFailed
    case decodingFailed
    case bufferOverflow
    case connectionFailed(String)
    case authenticationFailed(String)

    public var errorDescription: String? {
        switch self {
        case .insufficientData:
            return "Insufficient data"
        case .invalidMessageType(let value):
            return "Invalid message type: 0x\(String(format: "%02X", value))"
        case .encodingFailed:
            return "Message encoding failed"
        case .decodingFailed:
            return "Message decoding failed"
        case .bufferOverflow:
            return "Buffer overflow"
        case .connectionFailed(let message):
            return "Connection failed: \(message)"
        case .authenticationFailed(let message):
            return "Authentication failed: \(message)"
        }
    }
}

// MARK: - Utility Functions
public enum VPNProtocolUtils {
    /// Format bytes to human readable string
    public static func formatBytes(_ bytes: UInt64) -> String {
        let units = ["B", "KB", "MB", "GB", "TB"]
        var value = Double(bytes)
        var unitIndex = 0

        while value >= 1024 && unitIndex < units.count - 1 {
            value /= 1024
            unitIndex += 1
        }

        if unitIndex == 0 {
            return "\(Int(value)) \(units[unitIndex])"
        } else {
            return String(format: "%.2f %@", value, units[unitIndex])
        }
    }

    /// Format duration to human readable string
    public static func formatDuration(_ seconds: TimeInterval) -> String {
        let hours = Int(seconds) / 3600
        let minutes = (Int(seconds) % 3600) / 60
        let secs = Int(seconds) % 60

        return String(format: "%02d:%02d:%02d", hours, minutes, secs)
    }

    /// Get current platform identifier
    public static var currentPlatform: String {
        #if os(iOS)
        return VPNProtocolConstants.platformiOS
        #elseif os(macOS)
        return VPNProtocolConstants.platformMacOS
        #else
        return "unknown"
        #endif
    }

    /// Get app version
    public static var appVersion: String {
        Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "1.0"
    }

    /// Get build number
    public static var buildNumber: String {
        Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "1"
    }

    /// Get full version string
    public static var fullVersion: String {
        "\(appVersion) (\(buildNumber))"
    }
}

// MARK: - IP Address Utilities
public enum IPAddressUtils {
    /// Validate IPv4 address
    public static func isValidIPv4(_ address: String) -> Bool {
        let parts = address.split(separator: ".")
        guard parts.count == 4 else { return false }

        for part in parts {
            guard let value = Int(part), value >= 0, value <= 255 else {
                return false
            }
        }

        return true
    }

    /// Convert subnet mask to CIDR prefix length
    public static func subnetMaskToCIDR(_ mask: String) -> Int? {
        let parts = mask.split(separator: ".").compactMap { UInt8($0) }
        guard parts.count == 4 else { return nil }

        var cidr = 0
        for byte in parts {
            var b = byte
            while b != 0 {
                cidr += Int(b & 1)
                b >>= 1
            }
        }

        return cidr
    }

    /// Convert CIDR prefix length to subnet mask
    public static func cidrToSubnetMask(_ cidr: Int) -> String? {
        guard cidr >= 0, cidr <= 32 else { return nil }

        var mask: UInt32 = cidr == 0 ? 0 : ~((1 << (32 - cidr)) - 1)
        mask = mask.bigEndian

        let bytes = withUnsafeBytes(of: mask) { Array($0) }
        return bytes.map { String($0) }.joined(separator: ".")
    }
}
