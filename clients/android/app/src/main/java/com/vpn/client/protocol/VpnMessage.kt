package com.vpn.client.protocol

import kotlinx.serialization.Serializable

/**
 * VPN Protocol Message Types
 *
 * Message format: [type:1byte][length:4bytes BE][payload]
 */
enum class VpnMessageType(val value: Byte) {
    AUTH_REQUEST(0x01),
    AUTH_RESPONSE(0x02),
    CONFIG_PUSH(0x03),
    KEEPALIVE(0x04),
    KEEPALIVE_ACK(0x05),
    DISCONNECT(0x06),
    DATA_PACKET(0x10);

    companion object {
        fun fromValue(value: Byte): VpnMessageType? {
            return entries.find { it.value == value }
        }
    }
}

/**
 * Authentication request payload.
 *
 * JSON format:
 * {"username":"","password":"","clientVersion":"","platform":"android"}
 */
@Serializable
data class AuthRequest(
    val username: String,
    val password: String,
    val clientVersion: String,
    val platform: String = "android"
)

/**
 * Authentication response payload.
 *
 * JSON format:
 * {"success":true,"sessionToken":"","errorMessage":""}
 */
@Serializable
data class AuthResponse(
    val success: Boolean,
    val sessionToken: String = "",
    val errorMessage: String? = null
)

/**
 * Configuration request (sent after successful auth).
 */
@Serializable
data class ConfigRequest(
    val sessionToken: String
)

/**
 * VPN configuration pushed by server.
 *
 * JSON format:
 * {"assignedIP":"","subnetMask":"","gateway":"","dns":[],"mtu":1400}
 */
@Serializable
data class VpnConfig(
    val assignedIP: String,
    val subnetMask: String,
    val gateway: String,
    val dns: List<String>,
    val mtu: Int = 1400
)

/**
 * Keepalive message (empty payload, just the type).
 */
object Keepalive

/**
 * Disconnect message (empty payload, just the type).
 */
object Disconnect

/**
 * Data packet container.
 * The payload is raw IP packet data.
 */
data class DataPacket(
    val data: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as DataPacket
        return data.contentEquals(other.data)
    }

    override fun hashCode(): Int {
        return data.contentHashCode()
    }
}

/**
 * Generic VPN message wrapper.
 */
sealed class VpnMessage {
    data class Auth(val request: AuthRequest) : VpnMessage()
    data class AuthResp(val response: AuthResponse) : VpnMessage()
    data class Config(val config: VpnConfig) : VpnMessage()
    data object KeepAlive : VpnMessage()
    data object KeepAliveAck : VpnMessage()
    data object DisconnectMsg : VpnMessage()
    data class Data(val packet: DataPacket) : VpnMessage()
}

/**
 * Connection statistics.
 */
data class ConnectionStats(
    val bytesReceived: Long = 0,
    val bytesSent: Long = 0,
    val packetsReceived: Long = 0,
    val packetsSent: Long = 0,
    val connectedAt: Long = 0,
    val lastActivityAt: Long = 0
)

/**
 * VPN connection state for UI.
 */
data class VpnState(
    val isConnected: Boolean = false,
    val isConnecting: Boolean = false,
    val assignedIp: String = "",
    val serverAddress: String = "",
    val stats: ConnectionStats = ConnectionStats(),
    val error: String? = null
)
