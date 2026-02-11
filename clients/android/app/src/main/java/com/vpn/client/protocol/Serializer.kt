package com.vpn.client.protocol

import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * VPN Message Serializer
 *
 * Handles serialization and deserialization of VPN protocol messages.
 * Uses JSON for structured payloads and raw bytes for data packets.
 *
 * Protocol format:
 * - Header: [type:1byte][length:4bytes BE][payload]
 * - Payload varies by message type
 */
object VpnMessageSerializer {

    private val json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
        isLenient = true
    }

    // ============ Serialization ============

    /**
     * Serializes an AuthRequest to JSON bytes.
     */
    fun serializeAuthRequest(request: AuthRequest): ByteArray {
        val jsonString = json.encodeToString(request)
        return jsonString.toByteArray(Charsets.UTF_8)
    }

    /**
     * Serializes an AuthResponse to JSON bytes.
     */
    fun serializeAuthResponse(response: AuthResponse): ByteArray {
        val jsonString = json.encodeToString(response)
        return jsonString.toByteArray(Charsets.UTF_8)
    }

    /**
     * Serializes a ConfigRequest to JSON bytes.
     */
    fun serializeConfigRequest(request: ConfigRequest): ByteArray {
        val jsonString = json.encodeToString(request)
        return jsonString.toByteArray(Charsets.UTF_8)
    }

    /**
     * Serializes a VpnConfig to JSON bytes.
     */
    fun serializeVpnConfig(config: VpnConfig): ByteArray {
        val jsonString = json.encodeToString(config)
        return jsonString.toByteArray(Charsets.UTF_8)
    }

    /**
     * Serializes a complete VPN message including header.
     */
    fun serializeMessage(type: VpnMessageType, payload: ByteArray): ByteArray {
        val buffer = ByteBuffer.allocate(5 + payload.size)
        buffer.order(ByteOrder.BIG_ENDIAN)

        // Type (1 byte)
        buffer.put(type.value)

        // Length (4 bytes, big endian)
        buffer.putInt(payload.size)

        // Payload
        buffer.put(payload)

        return buffer.array()
    }

    // ============ Deserialization ============

    /**
     * Deserializes JSON bytes to AuthRequest.
     */
    fun deserializeAuthRequest(data: ByteArray): AuthRequest {
        val jsonString = data.toString(Charsets.UTF_8)
        return json.decodeFromString(jsonString)
    }

    /**
     * Deserializes JSON bytes to AuthResponse.
     */
    fun deserializeAuthResponse(data: ByteArray): AuthResponse {
        val jsonString = data.toString(Charsets.UTF_8)
        return json.decodeFromString(jsonString)
    }

    /**
     * Deserializes JSON bytes to ConfigRequest.
     */
    fun deserializeConfigRequest(data: ByteArray): ConfigRequest {
        val jsonString = data.toString(Charsets.UTF_8)
        return json.decodeFromString(jsonString)
    }

    /**
     * Deserializes JSON bytes to VpnConfig.
     */
    fun deserializeVpnConfig(data: ByteArray): VpnConfig {
        val jsonString = data.toString(Charsets.UTF_8)
        return json.decodeFromString(jsonString)
    }

    /**
     * Parses a message header from bytes.
     *
     * @param headerBytes 5 bytes: [type:1][length:4]
     * @return Pair of message type and payload length
     */
    fun parseHeader(headerBytes: ByteArray): Pair<VpnMessageType, Int> {
        require(headerBytes.size >= 5) { "Header must be at least 5 bytes" }

        val buffer = ByteBuffer.wrap(headerBytes)
        buffer.order(ByteOrder.BIG_ENDIAN)

        val typeByte = buffer.get()
        val length = buffer.int

        val type = VpnMessageType.fromValue(typeByte)
            ?: throw IllegalArgumentException("Unknown message type: $typeByte")

        return Pair(type, length)
    }

    /**
     * Deserializes a complete VPN message.
     *
     * @param type The message type
     * @param payload The message payload
     * @return Parsed VpnMessage
     */
    fun deserializeMessage(type: VpnMessageType, payload: ByteArray): VpnMessage {
        return when (type) {
            VpnMessageType.AUTH_REQUEST -> {
                VpnMessage.Auth(deserializeAuthRequest(payload))
            }
            VpnMessageType.AUTH_RESPONSE -> {
                VpnMessage.AuthResp(deserializeAuthResponse(payload))
            }
            VpnMessageType.CONFIG_PUSH -> {
                VpnMessage.Config(deserializeVpnConfig(payload))
            }
            VpnMessageType.KEEPALIVE -> {
                VpnMessage.KeepAlive
            }
            VpnMessageType.KEEPALIVE_ACK -> {
                VpnMessage.KeepAliveAck
            }
            VpnMessageType.DISCONNECT -> {
                VpnMessage.DisconnectMsg
            }
            VpnMessageType.DATA_PACKET -> {
                VpnMessage.Data(DataPacket(payload))
            }
        }
    }

    // ============ Utility Methods ============

    /**
     * Creates a keepalive message (header only, no payload).
     */
    fun createKeepaliveMessage(): ByteArray {
        return serializeMessage(VpnMessageType.KEEPALIVE, ByteArray(0))
    }

    /**
     * Creates a keepalive ack message (header only, no payload).
     */
    fun createKeepaliveAckMessage(): ByteArray {
        return serializeMessage(VpnMessageType.KEEPALIVE_ACK, ByteArray(0))
    }

    /**
     * Creates a disconnect message (header only, no payload).
     */
    fun createDisconnectMessage(): ByteArray {
        return serializeMessage(VpnMessageType.DISCONNECT, ByteArray(0))
    }

    /**
     * Creates a data packet message.
     */
    fun createDataPacketMessage(data: ByteArray): ByteArray {
        return serializeMessage(VpnMessageType.DATA_PACKET, data)
    }

    /**
     * Validates message payload size.
     */
    fun validatePayloadSize(type: VpnMessageType, size: Int): Boolean {
        return when (type) {
            VpnMessageType.KEEPALIVE,
            VpnMessageType.KEEPALIVE_ACK,
            VpnMessageType.DISCONNECT -> size == 0
            VpnMessageType.DATA_PACKET -> size in 1..65535
            else -> size in 0..65535
        }
    }

    /**
     * Gets the expected payload size range for a message type.
     */
    fun getExpectedPayloadSizeRange(type: VpnMessageType): IntRange {
        return when (type) {
            VpnMessageType.KEEPALIVE,
            VpnMessageType.KEEPALIVE_ACK,
            VpnMessageType.DISCONNECT -> 0..0
            VpnMessageType.AUTH_REQUEST -> 10..1024
            VpnMessageType.AUTH_RESPONSE -> 10..1024
            VpnMessageType.CONFIG_PUSH -> 50..4096
            VpnMessageType.DATA_PACKET -> 1..65535
        }
    }
}

/**
 * Extension function to convert VpnMessage to wire format.
 */
fun VpnMessage.toWireFormat(): ByteArray {
    return when (this) {
        is VpnMessage.Auth -> {
            val payload = VpnMessageSerializer.serializeAuthRequest(request)
            VpnMessageSerializer.serializeMessage(VpnMessageType.AUTH_REQUEST, payload)
        }
        is VpnMessage.AuthResp -> {
            val payload = VpnMessageSerializer.serializeAuthResponse(response)
            VpnMessageSerializer.serializeMessage(VpnMessageType.AUTH_RESPONSE, payload)
        }
        is VpnMessage.Config -> {
            val payload = VpnMessageSerializer.serializeVpnConfig(config)
            VpnMessageSerializer.serializeMessage(VpnMessageType.CONFIG_PUSH, payload)
        }
        is VpnMessage.KeepAlive -> {
            VpnMessageSerializer.createKeepaliveMessage()
        }
        is VpnMessage.KeepAliveAck -> {
            VpnMessageSerializer.createKeepaliveAckMessage()
        }
        is VpnMessage.DisconnectMsg -> {
            VpnMessageSerializer.createDisconnectMessage()
        }
        is VpnMessage.Data -> {
            VpnMessageSerializer.createDataPacketMessage(packet.data)
        }
    }
}
