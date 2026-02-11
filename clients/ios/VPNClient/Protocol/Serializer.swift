//
//  Serializer.swift
//  VPNClient
//
//  Message Serialization/Deserialization
//  Shared between main app and PacketTunnelExtension
//
//  Protocol Format:
//  - Header: [type:1byte][length:4bytes BE][payload]
//

import Foundation

// MARK: - Message Header
/// VPN message header structure
struct VPNMessageHeader {
    let type: VPNMessageType
    let length: UInt32

    static let size = 5  // 1 byte type + 4 bytes length

    init(type: VPNMessageType, length: UInt32) {
        self.type = type
        self.length = length
    }

    func encode() -> Data {
        var data = Data()
        data.append(type.rawValue)

        var lengthBE = length.bigEndian
        data.append(Data(bytes: &lengthBE, count: MemoryLayout<UInt32>.size))

        return data
    }

    static func decode(from data: Data) throws -> VPNMessageHeader {
        guard data.count >= size else {
            throw SerializerError.insufficientHeaderData
        }

        guard let type = VPNMessageType(rawValue: data[0]) else {
            throw SerializerError.invalidMessageType(data[0])
        }

        let length = data.subdata(in: 1..<5).withUnsafeBytes { ptr -> UInt32 in
            ptr.load(as: UInt32.self).bigEndian
        }

        return VPNMessageHeader(type: type, length: length)
    }
}

// MARK: - Serializer Errors
enum SerializerError: LocalizedError {
    case insufficientHeaderData
    case insufficientPayloadData(expected: Int, actual: Int)
    case invalidMessageType(UInt8)
    case encodingFailed(String)
    case decodingFailed(String)
    case bufferOverflow

    var errorDescription: String? {
        switch self {
        case .insufficientHeaderData:
            return "Insufficient data for message header"
        case .insufficientPayloadData(let expected, let actual):
            return "Insufficient payload data: expected \(expected) bytes, got \(actual)"
        case .invalidMessageType(let value):
            return "Invalid message type: 0x\(String(format: "%02X", value))"
        case .encodingFailed(let message):
            return "Encoding failed: \(message)"
        case .decodingFailed(let message):
            return "Decoding failed: \(message)"
        case .bufferOverflow:
            return "Buffer overflow during serialization"
        }
    }
}

// MARK: - Message Serializer
/// Serializes and deserializes VPN protocol messages
class VPNMessageSerializer {
    // MARK: - Constants
    static let maxPayloadSize: UInt32 = 65535  // 64KB max payload
    static let headerSize = VPNMessageHeader.size

    // MARK: - Serialization
    /// Serialize a VPN message to wire format
    static func serialize(_ message: any VPNMessageProtocol) throws -> Data {
        let payload = try message.encode()

        guard payload.count <= maxPayloadSize else {
            throw SerializerError.bufferOverflow
        }

        let header = VPNMessageHeader(type: message.type, length: UInt32(payload.count))

        var data = header.encode()
        data.append(payload)

        return data
    }

    /// Serialize multiple messages into a single data buffer
    static func serializeMultiple(_ messages: [any VPNMessageProtocol]) throws -> Data {
        var data = Data()

        for message in messages {
            let serialized = try serialize(message)
            data.append(serialized)
        }

        return data
    }

    // MARK: - Deserialization
    /// Deserialize a VPN message from wire format
    static func deserialize(from data: Data) throws -> (message: any VPNMessageProtocol, bytesConsumed: Int) {
        // Parse header
        let header = try VPNMessageHeader.decode(from: data)

        let totalSize = headerSize + Int(header.length)

        guard data.count >= totalSize else {
            throw SerializerError.insufficientPayloadData(
                expected: totalSize,
                actual: data.count
            )
        }

        // Extract payload
        let payloadStart = headerSize
        let payloadEnd = payloadStart + Int(header.length)
        let payload = data.subdata(in: payloadStart..<payloadEnd)

        // Create message
        let message = try VPNMessageFactory.createMessage(type: header.type, payload: payload)

        return (message, totalSize)
    }

    /// Deserialize all messages from a data buffer
    static func deserializeAll(from data: Data) throws -> [any VPNMessageProtocol] {
        var messages: [any VPNMessageProtocol] = []
        var offset = 0

        while offset < data.count {
            let remainingData = data.subdata(in: offset..<data.count)

            // Check if we have enough data for at least a header
            guard remainingData.count >= headerSize else {
                break
            }

            let (message, bytesConsumed) = try deserialize(from: remainingData)
            messages.append(message)
            offset += bytesConsumed
        }

        return messages
    }

    /// Check if buffer contains a complete message
    static func hasCompleteMessage(in data: Data) -> Bool {
        guard data.count >= headerSize else {
            return false
        }

        do {
            let header = try VPNMessageHeader.decode(from: data)
            return data.count >= headerSize + Int(header.length)
        } catch {
            return false
        }
    }

    /// Get the expected total size of a message from header
    static func getExpectedSize(from data: Data) throws -> Int {
        let header = try VPNMessageHeader.decode(from: data)
        return headerSize + Int(header.length)
    }
}

// MARK: - Stream Buffer
/// Buffer for handling streaming data and extracting complete messages
class StreamBuffer {
    private var buffer = Data()
    private let maxBufferSize: Int

    init(maxBufferSize: Int = 1024 * 1024) {  // 1MB default
        self.maxBufferSize = maxBufferSize
    }

    /// Append data to buffer
    func append(_ data: Data) throws {
        guard buffer.count + data.count <= maxBufferSize else {
            throw SerializerError.bufferOverflow
        }
        buffer.append(data)
    }

    /// Extract all complete messages from buffer
    func extractMessages() throws -> [any VPNMessageProtocol] {
        var messages: [any VPNMessageProtocol] = []

        while VPNMessageSerializer.hasCompleteMessage(in: buffer) {
            let (message, bytesConsumed) = try VPNMessageSerializer.deserialize(from: buffer)
            messages.append(message)
            buffer.removeFirst(bytesConsumed)
        }

        return messages
    }

    /// Check if buffer has any complete messages
    var hasCompleteMessage: Bool {
        return VPNMessageSerializer.hasCompleteMessage(in: buffer)
    }

    /// Current buffer size
    var count: Int {
        return buffer.count
    }

    /// Clear the buffer
    func clear() {
        buffer.removeAll()
    }
}

// MARK: - Data Packet Serializer
/// Optimized serializer for data packets (no JSON overhead)
class DataPacketSerializer {
    /// Serialize IP packet data
    static func serialize(_ ipPacket: Data) -> Data {
        let header = VPNMessageHeader(type: .dataPacket, length: UInt32(ipPacket.count))
        var data = header.encode()
        data.append(ipPacket)
        return data
    }

    /// Deserialize IP packet data
    static func deserialize(from data: Data) throws -> (payload: Data, bytesConsumed: Int) {
        let header = try VPNMessageHeader.decode(from: data)

        guard header.type == .dataPacket else {
            throw SerializerError.invalidMessageType(header.type.rawValue)
        }

        let totalSize = VPNMessageHeader.size + Int(header.length)

        guard data.count >= totalSize else {
            throw SerializerError.insufficientPayloadData(
                expected: totalSize,
                actual: data.count
            )
        }

        let payload = data.subdata(in: VPNMessageHeader.size..<totalSize)
        return (payload, totalSize)
    }
}

// MARK: - Helper Extensions
extension Data {
    /// Create data from UInt32 in big endian format
    init(bigEndian value: UInt32) {
        var v = value.bigEndian
        self = Data(bytes: &v, count: MemoryLayout<UInt32>.size)
    }

    /// Read UInt32 from big endian data
    func readUInt32BigEndian(at offset: Int) -> UInt32? {
        guard count >= offset + MemoryLayout<UInt32>.size else {
            return nil
        }

        return subdata(in: offset..<(offset + MemoryLayout<UInt32>.size))
            .withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }
    }

    /// Read UInt64 from big endian data
    func readUInt64BigEndian(at offset: Int) -> UInt64? {
        guard count >= offset + MemoryLayout<UInt64>.size else {
            return nil
        }

        return subdata(in: offset..<(offset + MemoryLayout<UInt64>.size))
            .withUnsafeBytes { $0.load(as: UInt64.self).bigEndian }
    }

    /// Hex string representation
    var hexString: String {
        return map { String(format: "%02x", $0) }.joined()
    }
}
