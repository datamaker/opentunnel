package com.vpn.client.network

import android.util.Log
import com.vpn.client.protocol.VpnMessageType
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer
import java.security.KeyStore
import java.security.SecureRandom
import javax.net.ssl.*

/**
 * TLS 1.3 connection handler for VPN communication.
 *
 * Uses SSLSocket with TLS 1.3 protocol for secure communication.
 * Implements the custom VPN protocol message format:
 * - Header: [type:1byte][length:4bytes BE][payload]
 */
class TlsConnection {

    companion object {
        private const val TAG = "TlsConnection"
        private const val CONNECT_TIMEOUT_MS = 10000
        private const val READ_TIMEOUT_MS = 60000
        private const val HEADER_SIZE = 5 // 1 byte type + 4 bytes length
        private const val MAX_PAYLOAD_SIZE = 65535
    }

    private var socket: SSLSocket? = null
    private var inputStream: DataInputStream? = null
    private var outputStream: DataOutputStream? = null

    private val lock = Any()
    private var isConnected = false

    /**
     * Establishes a TLS 1.3 connection to the VPN server.
     */
    suspend fun connect(host: String, port: Int) = withContext(Dispatchers.IO) {
        synchronized(lock) {
            if (isConnected) {
                throw IllegalStateException("Already connected")
            }
        }

        try {
            // Create SSL context with TLS 1.3
            val sslContext = createSslContext()
            val sslSocketFactory = sslContext.socketFactory

            // Create base socket with timeout
            val baseSocket = Socket()
            baseSocket.connect(InetSocketAddress(host, port), CONNECT_TIMEOUT_MS)

            // Wrap with SSL
            val sslSocket = sslSocketFactory.createSocket(
                baseSocket,
                host,
                port,
                true
            ) as SSLSocket

            // Configure for TLS 1.3
            configureSslSocket(sslSocket)

            // Perform handshake
            sslSocket.startHandshake()

            // Verify connection
            verifyConnection(sslSocket)

            synchronized(lock) {
                socket = sslSocket
                inputStream = DataInputStream(sslSocket.inputStream)
                outputStream = DataOutputStream(sslSocket.outputStream)
                isConnected = true
            }

            Log.i(TAG, "TLS 1.3 connection established to $host:$port")
            Log.d(TAG, "Cipher suite: ${sslSocket.session.cipherSuite}")
            Log.d(TAG, "Protocol: ${sslSocket.session.protocol}")

        } catch (e: Exception) {
            Log.e(TAG, "Failed to connect: ${e.message}", e)
            disconnect()
            throw e
        }
    }

    /**
     * Sends a VPN protocol message.
     *
     * Message format: [type:1byte][length:4bytes BE][payload]
     */
    suspend fun send(type: VpnMessageType, payload: ByteArray) = withContext(Dispatchers.IO) {
        synchronized(lock) {
            if (!isConnected) {
                throw IOException("Not connected")
            }
        }

        if (payload.size > MAX_PAYLOAD_SIZE) {
            throw IllegalArgumentException("Payload too large: ${payload.size} > $MAX_PAYLOAD_SIZE")
        }

        try {
            val output = outputStream ?: throw IOException("Output stream not available")

            synchronized(output) {
                // Write message type (1 byte)
                output.writeByte(type.value.toInt())

                // Write payload length (4 bytes, big endian)
                output.writeInt(payload.size)

                // Write payload
                if (payload.isNotEmpty()) {
                    output.write(payload)
                }

                output.flush()
            }

            Log.d(TAG, "Sent message: type=${type.name}, length=${payload.size}")

        } catch (e: Exception) {
            Log.e(TAG, "Failed to send message", e)
            handleError(e)
            throw e
        }
    }

    /**
     * Receives a VPN protocol message.
     *
     * @return Pair of message type and payload
     */
    suspend fun receive(): Pair<VpnMessageType, ByteArray> = withContext(Dispatchers.IO) {
        synchronized(lock) {
            if (!isConnected) {
                throw IOException("Not connected")
            }
        }

        try {
            val input = inputStream ?: throw IOException("Input stream not available")

            // Read header
            val typeByte = input.readByte()
            val length = input.readInt()

            // Validate
            val type = VpnMessageType.fromValue(typeByte)
                ?: throw IOException("Unknown message type: $typeByte")

            if (length < 0 || length > MAX_PAYLOAD_SIZE) {
                throw IOException("Invalid payload length: $length")
            }

            // Read payload
            val payload = if (length > 0) {
                val buffer = ByteArray(length)
                input.readFully(buffer)
                buffer
            } else {
                ByteArray(0)
            }

            Log.d(TAG, "Received message: type=${type.name}, length=${payload.size}")

            Pair(type, payload)

        } catch (e: Exception) {
            Log.e(TAG, "Failed to receive message", e)
            handleError(e)
            throw e
        }
    }

    /**
     * Closes the TLS connection.
     */
    fun disconnect() {
        synchronized(lock) {
            isConnected = false

            try {
                outputStream?.close()
            } catch (e: Exception) {
                Log.w(TAG, "Error closing output stream", e)
            }

            try {
                inputStream?.close()
            } catch (e: Exception) {
                Log.w(TAG, "Error closing input stream", e)
            }

            try {
                socket?.close()
            } catch (e: Exception) {
                Log.w(TAG, "Error closing socket", e)
            }

            outputStream = null
            inputStream = null
            socket = null

            Log.i(TAG, "Connection closed")
        }
    }

    /**
     * Checks if the connection is active.
     */
    fun isConnected(): Boolean {
        synchronized(lock) {
            return isConnected && socket?.isConnected == true && socket?.isClosed == false
        }
    }

    /**
     * Creates an SSL context configured for TLS 1.3.
     */
    private fun createSslContext(): SSLContext {
        // Use default trust manager (system CA certificates)
        val trustManagerFactory = TrustManagerFactory.getInstance(
            TrustManagerFactory.getDefaultAlgorithm()
        )
        trustManagerFactory.init(null as KeyStore?)

        val sslContext = SSLContext.getInstance("TLSv1.3")
        sslContext.init(null, trustManagerFactory.trustManagers, SecureRandom())

        return sslContext
    }

    /**
     * Configures the SSL socket for optimal security.
     */
    private fun configureSslSocket(sslSocket: SSLSocket) {
        // Enable only TLS 1.3
        sslSocket.enabledProtocols = arrayOf("TLSv1.3")

        // Set preferred cipher suites for TLS 1.3
        val supportedCiphers = sslSocket.supportedCipherSuites
        val tls13Ciphers = supportedCiphers.filter { cipher ->
            cipher.startsWith("TLS_AES_") || cipher.startsWith("TLS_CHACHA20_")
        }.toTypedArray()

        if (tls13Ciphers.isNotEmpty()) {
            sslSocket.enabledCipherSuites = tls13Ciphers
        }

        // Configure timeouts
        sslSocket.soTimeout = READ_TIMEOUT_MS

        // Enable keep-alive
        sslSocket.keepAlive = true

        // Disable Nagle's algorithm for lower latency
        sslSocket.tcpNoDelay = true
    }

    /**
     * Verifies the TLS connection after handshake.
     */
    private fun verifyConnection(sslSocket: SSLSocket) {
        val session = sslSocket.session

        // Verify protocol is TLS 1.3
        if (session.protocol != "TLSv1.3") {
            Log.w(TAG, "Expected TLSv1.3, got ${session.protocol}")
        }

        // Log certificate info
        try {
            val certs = session.peerCertificates
            if (certs.isNotEmpty()) {
                Log.d(TAG, "Server certificate: ${certs[0].type}")
            }
        } catch (e: SSLPeerUnverifiedException) {
            Log.w(TAG, "Could not verify peer certificate", e)
        }
    }

    /**
     * Handles connection errors.
     */
    private fun handleError(e: Exception) {
        when (e) {
            is SSLHandshakeException -> {
                Log.e(TAG, "SSL handshake failed - possible certificate issue", e)
            }
            is SSLException -> {
                Log.e(TAG, "SSL error", e)
            }
            is IOException -> {
                Log.e(TAG, "IO error - connection may be lost", e)
            }
        }

        // Mark as disconnected on error
        synchronized(lock) {
            isConnected = false
        }
    }

    /**
     * Gets the current connection statistics.
     */
    fun getConnectionInfo(): ConnectionInfo? {
        synchronized(lock) {
            val sslSocket = socket ?: return null
            val session = sslSocket.session

            return ConnectionInfo(
                protocol = session.protocol,
                cipherSuite = session.cipherSuite,
                peerHost = session.peerHost,
                peerPort = session.peerPort,
                creationTime = session.creationTime,
                lastAccessedTime = session.lastAccessedTime
            )
        }
    }

    data class ConnectionInfo(
        val protocol: String,
        val cipherSuite: String,
        val peerHost: String,
        val peerPort: Int,
        val creationTime: Long,
        val lastAccessedTime: Long
    )
}
