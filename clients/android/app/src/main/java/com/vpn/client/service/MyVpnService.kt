package com.vpn.client.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import com.vpn.client.MainActivity
import com.vpn.client.R
import com.vpn.client.network.TlsConnection
import com.vpn.client.protocol.*
import kotlinx.coroutines.*
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

class MyVpnService : VpnService() {

    companion object {
        const val ACTION_CONNECT = "com.vpn.client.CONNECT"
        const val ACTION_DISCONNECT = "com.vpn.client.DISCONNECT"
        const val EXTRA_SERVER_ADDRESS = "server_address"
        const val EXTRA_SERVER_PORT = "server_port"
        const val EXTRA_SESSION_TOKEN = "session_token"

        private const val TAG = "MyVpnService"
        private const val NOTIFICATION_CHANNEL_ID = "vpn_service_channel"
        private const val NOTIFICATION_ID = 1
        private const val KEEPALIVE_INTERVAL_MS = 30000L
        private const val READ_BUFFER_SIZE = 32767
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private var tlsConnection: TlsConnection? = null

    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val isRunning = AtomicBoolean(false)

    private var serverAddress: String = ""
    private var serverPort: Int = 443
    private var sessionToken: String = ""

    // Traffic statistics
    private val bytesReceived = AtomicLong(0)
    private val bytesSent = AtomicLong(0)

    // VPN configuration received from server
    private var vpnConfig: VpnConfig? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_CONNECT -> {
                serverAddress = intent.getStringExtra(EXTRA_SERVER_ADDRESS) ?: ""
                serverPort = intent.getIntExtra(EXTRA_SERVER_PORT, 443)
                sessionToken = intent.getStringExtra(EXTRA_SESSION_TOKEN) ?: ""

                if (serverAddress.isNotEmpty()) {
                    startVpn()
                }
            }
            ACTION_DISCONNECT -> {
                stopVpn()
            }
        }
        return START_STICKY
    }

    override fun onDestroy() {
        super.onDestroy()
        stopVpn()
        serviceScope.cancel()
    }

    private fun startVpn() {
        if (isRunning.getAndSet(true)) {
            Log.w(TAG, "VPN is already running")
            return
        }

        startForeground(NOTIFICATION_ID, createNotification("Connecting..."))

        serviceScope.launch {
            try {
                // Establish TLS connection
                tlsConnection = TlsConnection().apply {
                    connect(serverAddress, serverPort)
                }

                // Request configuration from server
                requestConfiguration()

                // Wait for configuration
                val config = receiveConfiguration()
                vpnConfig = config

                // Build and establish VPN interface
                vpnInterface = buildVpnInterface(config)

                if (vpnInterface == null) {
                    throw Exception("Failed to establish VPN interface")
                }

                updateNotification("Connected to $serverAddress")

                // Start tunnel operations
                launch { readFromTunnel() }
                launch { readFromServer() }
                launch { sendKeepalive() }

                Log.i(TAG, "VPN connection established")

            } catch (e: Exception) {
                Log.e(TAG, "VPN connection failed", e)
                handleConnectionError(e)
            }
        }
    }

    private fun stopVpn() {
        if (!isRunning.getAndSet(false)) {
            return
        }

        serviceScope.launch {
            try {
                // Send disconnect message
                tlsConnection?.let { conn ->
                    try {
                        conn.send(VpnMessageType.DISCONNECT, ByteArray(0))
                    } catch (e: Exception) {
                        Log.w(TAG, "Failed to send disconnect message", e)
                    }
                }

                // Close connections
                tlsConnection?.disconnect()
                tlsConnection = null

                vpnInterface?.close()
                vpnInterface = null

            } catch (e: Exception) {
                Log.e(TAG, "Error during VPN shutdown", e)
            }
        }

        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private suspend fun requestConfiguration() {
        val request = ConfigRequest(sessionToken = sessionToken)
        val requestBytes = VpnMessageSerializer.serializeConfigRequest(request)
        tlsConnection?.send(VpnMessageType.AUTH_REQUEST, requestBytes)
    }

    private suspend fun receiveConfiguration(): VpnConfig = withContext(Dispatchers.IO) {
        val connection = tlsConnection ?: throw Exception("Connection not established")

        val response = connection.receive()
        if (response.first != VpnMessageType.CONFIG_PUSH) {
            throw Exception("Expected CONFIG_PUSH, got ${response.first}")
        }

        VpnMessageSerializer.deserializeVpnConfig(response.second)
    }

    private fun buildVpnInterface(config: VpnConfig): ParcelFileDescriptor? {
        val builder = Builder()
            .setSession("VPN Client")
            .setMtu(config.mtu)
            .addAddress(config.assignedIP, getSubnetPrefix(config.subnetMask))

        // Add DNS servers
        config.dns.forEach { dns ->
            builder.addDnsServer(dns)
        }

        // Route all traffic through VPN
        builder.addRoute("0.0.0.0", 0)

        // Exclude VPN server from routing to prevent routing loops
        builder.addDisallowedApplication(packageName)

        return builder.establish()
    }

    private fun getSubnetPrefix(subnetMask: String): Int {
        return when (subnetMask) {
            "255.255.255.255" -> 32
            "255.255.255.254" -> 31
            "255.255.255.252" -> 30
            "255.255.255.248" -> 29
            "255.255.255.240" -> 28
            "255.255.255.224" -> 27
            "255.255.255.192" -> 26
            "255.255.255.128" -> 25
            "255.255.255.0" -> 24
            "255.255.254.0" -> 23
            "255.255.252.0" -> 22
            "255.255.248.0" -> 21
            "255.255.240.0" -> 20
            "255.255.224.0" -> 19
            "255.255.192.0" -> 18
            "255.255.128.0" -> 17
            "255.255.0.0" -> 16
            "255.254.0.0" -> 15
            "255.252.0.0" -> 14
            "255.248.0.0" -> 13
            "255.240.0.0" -> 12
            "255.224.0.0" -> 11
            "255.192.0.0" -> 10
            "255.128.0.0" -> 9
            "255.0.0.0" -> 8
            else -> 24
        }
    }

    private suspend fun readFromTunnel() = withContext(Dispatchers.IO) {
        val buffer = ByteBuffer.allocate(READ_BUFFER_SIZE)
        val vpnInput = FileInputStream(vpnInterface?.fileDescriptor)

        try {
            while (isRunning.get() && isActive) {
                buffer.clear()
                val length = vpnInput.read(buffer.array())

                if (length > 0) {
                    val packet = ByteArray(length)
                    buffer.get(packet, 0, length)

                    // Send packet to server
                    tlsConnection?.send(VpnMessageType.DATA_PACKET, packet)
                    bytesSent.addAndGet(length.toLong())
                }
            }
        } catch (e: Exception) {
            if (isRunning.get()) {
                Log.e(TAG, "Error reading from tunnel", e)
                handleConnectionError(e)
            }
        }
    }

    private suspend fun readFromServer() = withContext(Dispatchers.IO) {
        val vpnOutput = FileOutputStream(vpnInterface?.fileDescriptor)

        try {
            while (isRunning.get() && isActive) {
                val connection = tlsConnection ?: break

                val (type, payload) = connection.receive()

                when (type) {
                    VpnMessageType.DATA_PACKET -> {
                        vpnOutput.write(payload)
                        bytesReceived.addAndGet(payload.size.toLong())
                    }
                    VpnMessageType.KEEPALIVE -> {
                        // Respond with keepalive ack
                        connection.send(VpnMessageType.KEEPALIVE_ACK, ByteArray(0))
                    }
                    VpnMessageType.KEEPALIVE_ACK -> {
                        // Server acknowledged our keepalive
                        Log.d(TAG, "Received keepalive ack")
                    }
                    VpnMessageType.DISCONNECT -> {
                        Log.i(TAG, "Server requested disconnect")
                        stopVpn()
                        break
                    }
                    else -> {
                        Log.w(TAG, "Received unexpected message type: $type")
                    }
                }
            }
        } catch (e: Exception) {
            if (isRunning.get()) {
                Log.e(TAG, "Error reading from server", e)
                handleConnectionError(e)
            }
        }
    }

    private suspend fun sendKeepalive() = withContext(Dispatchers.IO) {
        try {
            while (isRunning.get() && isActive) {
                delay(KEEPALIVE_INTERVAL_MS)

                tlsConnection?.send(VpnMessageType.KEEPALIVE, ByteArray(0))
                Log.d(TAG, "Sent keepalive")
            }
        } catch (e: Exception) {
            if (isRunning.get()) {
                Log.e(TAG, "Error sending keepalive", e)
            }
        }
    }

    private fun handleConnectionError(e: Exception) {
        Log.e(TAG, "Connection error: ${e.message}")
        stopVpn()

        // Broadcast error to UI
        val intent = Intent("com.vpn.client.VPN_ERROR").apply {
            putExtra("error_message", e.message)
        }
        sendBroadcast(intent)
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                NOTIFICATION_CHANNEL_ID,
                "VPN Service",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Shows VPN connection status"
                setShowBadge(false)
            }

            val notificationManager = getSystemService(NotificationManager::class.java)
            notificationManager.createNotificationChannel(channel)
        }
    }

    private fun createNotification(status: String): Notification {
        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val disconnectIntent = PendingIntent.getService(
            this,
            0,
            Intent(this, MyVpnService::class.java).apply {
                action = ACTION_DISCONNECT
            },
            PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setContentTitle("VPN Client")
            .setContentText(status)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(pendingIntent)
            .addAction(
                android.R.drawable.ic_menu_close_clear_cancel,
                "Disconnect",
                disconnectIntent
            )
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .build()
    }

    private fun updateNotification(status: String) {
        val notificationManager = getSystemService(NotificationManager::class.java)
        notificationManager.notify(NOTIFICATION_ID, createNotification(status))
    }

    fun getTrafficStats(): Pair<Long, Long> {
        return Pair(bytesReceived.get(), bytesSent.get())
    }
}
