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
import com.vpn.client.split.CidrUtils
import com.vpn.client.split.DnsSniffer
import com.vpn.client.split.DomainMatcher
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.io.FileInputStream
import java.io.FileOutputStream
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

class MyVpnService : VpnService() {

    companion object {
        const val ACTION_CONNECT = "com.vpn.client.CONNECT"
        const val ACTION_DISCONNECT = "com.vpn.client.DISCONNECT"
        const val EXTRA_SERVER_ADDRESS = "server_address"
        const val EXTRA_SERVER_PORT = "server_port"
        const val EXTRA_USERNAME = "username"
        const val EXTRA_PASSWORD = "password"

        private const val TAG = "MyVpnService"
        private const val NOTIFICATION_CHANNEL_ID = "vpn_service_channel"
        private const val NOTIFICATION_ID = 1
        private const val KEEPALIVE_INTERVAL_MS = 30000L
        private const val READ_BUFFER_SIZE = 32767

        // Live service state so the UI can re-sync after the app process is
        // force-quit and relaunched (the VpnService keeps running in background).
        @Volatile var isConnected: Boolean = false
            private set
        @Volatile var assignedIp: String = ""
            private set
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private var tlsConnection: TlsConnection? = null

    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val isRunning = AtomicBoolean(false)

    private var serverAddress: String = ""
    private var serverPort: Int = 443
    private var username: String = ""
    private var password: String = ""

    // Traffic statistics
    private val bytesReceived = AtomicLong(0)
    private val bytesSent = AtomicLong(0)

    // VPN configuration received from server
    private var vpnConfig: VpnConfig? = null

    // Tunnel I/O streams over the current interface fd. Volatile so they can be
    // swapped atomically when the interface is re-established for split routing.
    @Volatile private var tunInput: FileInputStream? = null
    @Volatile private var tunOutput: FileOutputStream? = null

    // Split-tunnel: hostname matcher for domain rules, and the set of IPs learned
    // by sniffing DNS answers for those domains (dynamic /32 routes).
    private var domainMatcher: DomainMatcher? = null
    private val dynamicRoutes = java.util.Collections.synchronizedSet(HashSet<String>())
    private val reestablishMutex = Mutex()

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_CONNECT -> {
                serverAddress = intent.getStringExtra(EXTRA_SERVER_ADDRESS) ?: ""
                serverPort = intent.getIntExtra(EXTRA_SERVER_PORT, 443)
                username = intent.getStringExtra(EXTRA_USERNAME) ?: ""
                password = intent.getStringExtra(EXTRA_PASSWORD) ?: ""

                if (serverAddress.isNotEmpty() && username.isNotEmpty()) {
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

                // Authenticate with server
                authenticate()

                // Receive VPN configuration (sent right after auth response)
                val config = receiveConfiguration()
                vpnConfig = config
                domainMatcher = if (config.splitTunnel && config.includedDomains.isNotEmpty()) {
                    DomainMatcher(config.includedDomains)
                } else {
                    null
                }
                dynamicRoutes.clear()

                // Build and establish VPN interface
                val iface = buildVpnInterface(config)
                    ?: throw Exception("Failed to establish VPN interface")
                vpnInterface = iface
                tunInput = FileInputStream(iface.fileDescriptor)
                tunOutput = FileOutputStream(iface.fileDescriptor)

                updateNotification("Connected to $serverAddress")

                // Publish live state so the UI can re-sync after an app restart.
                isConnected = true
                assignedIp = config.assignedIP

                // Notify UI of successful connection
                val successIntent = Intent("com.vpn.client.VPN_CONNECTED").apply {
                    setPackage(packageName)
                    putExtra("assigned_ip", config.assignedIP)
                    putExtra("gateway", config.gateway)
                    putExtra("dns", config.dns.joinToString(", "))
                    putExtra("mtu", config.mtu)
                }
                sendBroadcast(successIntent)
                Log.i(TAG, "Sent VPN_CONNECTED broadcast with IP: ${config.assignedIP}")

                // Start tunnel operations
                launch { readFromTunnel() }
                launch { readFromServer() }
                launch { sendKeepalive() }
                launch { sendTrafficStats() }

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

        isConnected = false
        assignedIp = ""

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
                tunInput = null
                tunOutput = null
                domainMatcher = null
                dynamicRoutes.clear()

            } catch (e: Exception) {
                Log.e(TAG, "Error during VPN shutdown", e)
            }
        }

        // Notify UI of disconnect
        sendBroadcast(Intent("com.vpn.client.VPN_DISCONNECTED").apply {
            setPackage(packageName)
        })

        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private suspend fun authenticate(): String = withContext(Dispatchers.IO) {
        val connection = tlsConnection ?: throw Exception("Connection not established")

        // Send auth request with credentials
        val authRequest = AuthRequest(
            username = username,
            password = password,
            clientVersion = "1.0.0",
            platform = "android"
        )
        val requestBytes = VpnMessageSerializer.serializeAuthRequest(authRequest)
        connection.send(VpnMessageType.AUTH_REQUEST, requestBytes)

        // Receive auth response
        val response = connection.receive()
        if (response.first != VpnMessageType.AUTH_RESPONSE) {
            throw Exception("Expected AUTH_RESPONSE, got ${response.first}")
        }

        val authResponse = VpnMessageSerializer.deserializeAuthResponse(response.second)
        if (!authResponse.success) {
            throw Exception(authResponse.errorMessage ?: "Authentication failed")
        }

        authResponse.sessionToken
    }

    private suspend fun receiveConfiguration(): VpnConfig = withContext(Dispatchers.IO) {
        val connection = tlsConnection ?: throw Exception("Connection not established")

        // Server sends CONFIG_PUSH right after AUTH_RESPONSE
        val response = connection.receive()
        if (response.first != VpnMessageType.CONFIG_PUSH) {
            throw Exception("Expected CONFIG_PUSH, got ${response.first}")
        }

        VpnMessageSerializer.deserializeVpnConfig(response.second)
    }

    private fun buildVpnInterface(config: VpnConfig): ParcelFileDescriptor? {
        val builder = Builder()
            .setSession("OpenTunnel")
            .setMtu(config.mtu)
            .addAddress(config.assignedIP, getSubnetPrefix(config.subnetMask))

        // Add DNS servers
        config.dns.forEach { dns ->
            builder.addDnsServer(dns)
        }

        if (config.splitTunnel) {
            applySplitRoutes(builder, config)
        } else {
            // Full tunnel: route everything through the VPN.
            builder.addRoute("0.0.0.0", 0)
        }

        // Exclude VPN server from routing to prevent routing loops
        builder.addDisallowedApplication(packageName)

        return builder.establish()
    }

    /**
     * Split tunneling: route only the server-provided include list plus any IPs
     * we've learned by sniffing DNS answers for matched domains.
     */
    private fun applySplitRoutes(builder: Builder, config: VpnConfig) {
        var routeCount = 0

        // Static CIDRs + server-resolved (dedicated-IP) domain routes.
        config.includedRoutes.forEach { cidr ->
            CidrUtils.parse(cidr)?.let { builder.addRoute(it.address, it.prefix); routeCount++ }
        }

        val matcher = domainMatcher
        if (matcher != null && !matcher.isEmpty()) {
            // Route DNS servers through the tunnel so their answers pass through
            // readFromServer, where we snoop them for domain-based rules. This is
            // what makes CDN domains work: we route the exact IPs the client
            // resolves, not a stale/geo-wrong server-side guess.
            config.dns.forEach { dns ->
                CidrUtils.parse(dns)?.let { builder.addRoute(it.address, 32) }
            }
            // Dynamic /32 routes learned so far.
            synchronized(dynamicRoutes) {
                dynamicRoutes.forEach { ip -> builder.addRoute(ip, 32); routeCount++ }
            }
        }

        Log.i(TAG, "Split tunnel: $routeCount route(s), ${config.includedDomains.size} domain rule(s)")
        if (routeCount == 0 && (matcher == null || matcher.isEmpty())) {
            Log.w(TAG, "Split tunnel enabled but no routes configured; no traffic will be tunneled")
        }
    }

    /**
     * Rebuild the interface with the current dynamic routes and atomically swap
     * the tunnel fd/streams. Called when DNS sniffing learns a new IP for a
     * matched domain.
     */
    private suspend fun reestablishInterface() = reestablishMutex.withLock {
        if (!isRunning.get()) return@withLock
        val config = vpnConfig ?: return@withLock
        try {
            val old = vpnInterface
            val iface = buildVpnInterface(config) ?: run {
                Log.e(TAG, "Re-establish failed to build interface")
                return@withLock
            }
            vpnInterface = iface
            tunInput = FileInputStream(iface.fileDescriptor)
            tunOutput = FileOutputStream(iface.fileDescriptor)
            old?.close() // invalidates old streams; the tunnel loops re-fetch
            Log.i(TAG, "Interface re-established with ${dynamicRoutes.size} dynamic route(s)")
        } catch (e: Exception) {
            Log.e(TAG, "Re-establish error", e)
        }
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
        val buffer = ByteArray(READ_BUFFER_SIZE)

        while (isRunning.get() && isActive) {
            val input = tunInput
            if (input == null) {
                delay(50)
                continue
            }
            try {
                val length = input.read(buffer)
                if (length > 0) {
                    val packet = buffer.copyOf(length)
                    tlsConnection?.send(VpnMessageType.DATA_PACKET, packet)
                    bytesSent.addAndGet(length.toLong())
                }
            } catch (e: Exception) {
                if (!isRunning.get()) break
                // A read failure caused by a re-establishment swap is expected —
                // the fd changed under us. Pick up the new stream and continue.
                if (reestablishMutex.isLocked || tunInput !== input) {
                    continue
                }
                Log.e(TAG, "Error reading from tunnel", e)
                handleConnectionError(e)
                break
            }
        }
    }

    private suspend fun readFromServer() = withContext(Dispatchers.IO) {
        try {
            while (isRunning.get() && isActive) {
                val connection = tlsConnection ?: break

                val (type, payload) = connection.receive()

                when (type) {
                    VpnMessageType.DATA_PACKET -> {
                        bytesReceived.addAndGet(payload.size.toLong())
                        // Gate: if this is a DNS answer for a matched domain with
                        // new IPs, re-establish the interface (installing the
                        // route) BEFORE delivering the answer to the app, so its
                        // first connection to the freshly-resolved IP uses the
                        // tunnel instead of leaking (WAF 403).
                        if (!maybeLearnRoute(payload)) {
                            writeToTun(payload)
                        }
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

    /**
     * For split tunneling with domain rules: inspect a packet coming from the
     * server for a DNS answer, and if it resolves a matched domain to a new IP,
     * add a route for it and re-establish the interface. This is what makes CDN
     * domains (CloudFront/Cloudflare) route correctly — we tunnel exactly the IPs
     * the client actually resolved, by hostname.
     */
    /**
     * Write a packet to the current tunnel fd, tolerating the transient failure
     * window while the interface is being re-established (the fd is swapped under
     * us). Only a genuine, non-swap write failure is propagated as fatal.
     */
    private fun writeToTun(payload: ByteArray) {
        val out = tunOutput ?: return
        try {
            out.write(payload)
        } catch (e: Exception) {
            if (isRunning.get() && !reestablishMutex.isLocked && tunOutput === out) {
                throw e
            }
            // else: fd swapped during re-establishment — drop this packet.
        }
    }

    /**
     * Snoop a DNS answer for a matched (CDN/wildcard) domain. If it carries IPs
     * we have not routed yet, re-establish the interface to install the routes
     * and deliver the answer to the app only *after* they are active, then
     * return true (the caller must not deliver the packet itself). Returns false
     * for any packet that is not a gated DNS answer, which the caller delivers
     * normally.
     *
     * Gating closes a race: the DNS answer reaches the app and the snooper at
     * the same instant, so without it the app opens its connection to the
     * freshly resolved IP before the route exists — the first request leaks
     * outside the tunnel and the WAF rejects the client's real IP (403).
     */
    private suspend fun maybeLearnRoute(packet: ByteArray): Boolean {
        val matcher = domainMatcher ?: return false
        if (matcher.isEmpty()) return false
        val dns = DnsSniffer.parse(packet) ?: return false
        if (!matcher.matches(dns.qname)) return false
        val added = dns.addresses.filter { dynamicRoutes.add(it) }
        if (added.isEmpty()) return false
        Log.i(TAG, "Split tunnel: learned ${added.size} route(s) for ${dns.qname}: $added")
        reestablishInterface()
        writeToTun(packet)
        return true
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

    private suspend fun sendTrafficStats() = withContext(Dispatchers.IO) {
        try {
            while (isRunning.get() && isActive) {
                delay(1000) // Update every second

                val statsIntent = Intent("com.vpn.client.VPN_STATS").apply {
                    setPackage(packageName)
                    putExtra("bytes_received", bytesReceived.get())
                    putExtra("bytes_sent", bytesSent.get())
                }
                sendBroadcast(statsIntent)
            }
        } catch (e: Exception) {
            if (isRunning.get()) {
                Log.e(TAG, "Error sending traffic stats", e)
            }
        }
    }

    private fun handleConnectionError(e: Exception) {
        Log.e(TAG, "Connection error: ${e.message}")
        stopVpn()

        // Broadcast error to UI
        val intent = Intent("com.vpn.client.VPN_ERROR").apply {
            setPackage(packageName)
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
            .setContentTitle("OpenTunnel")
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
