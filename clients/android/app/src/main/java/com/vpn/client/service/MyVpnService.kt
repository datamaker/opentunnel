package com.vpn.client.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.SystemClock
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
import java.io.IOException
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

        // SSO: auth_type "session" + the stored 30-day session token replaces
        // username/password for Datasee SSO users.
        const val EXTRA_AUTH_TYPE = "auth_type"
        const val EXTRA_TOKEN = "token"

        const val AUTH_TYPE_PASSWORD = "password"
        const val AUTH_TYPE_SESSION = "session"

        // Settings passed from the UI (persisted in SharedPreferences by the
        // VpnViewModel; the service only trusts the intent extras).
        const val EXTRA_AUTO_RECONNECT = "auto_reconnect"
        const val EXTRA_DISCONNECT_NOTIFY = "disconnect_notify"

        private const val TAG = "MyVpnService"
        private const val NOTIFICATION_CHANNEL_ID = "vpn_service_channel"
        private const val NOTIFICATION_ID = 1
        private const val KEEPALIVE_INTERVAL_MS = 30000L
        private const val READ_BUFFER_SIZE = 32767

        // High-importance channel for the one notification that must actually be
        // seen: the tunnel dropped and is not coming back on its own. Separate
        // from the silent ongoing service channel.
        private const val ALERT_CHANNEL_ID = "vpn_alerts"
        private const val ALERT_NOTIFICATION_ID = 2

        // Dead-peer detection: the server keepalives every 30s and acks ours, so
        // a healthy link never goes 90s without a single inbound message. When it
        // does, the TCP socket is a zombie (e.g. network path silently died) and
        // waiting for the 60s soTimeout on a socket that still acks at the kernel
        // level would hang forever.
        private const val IDLE_TIMEOUT_MS = 90000L

        private const val MAX_RECONNECT_ATTEMPTS = 10
        private val RECONNECT_DELAYS_MS = longArrayOf(
            2000, 4000, 8000, 16000, 30000, 30000, 30000, 30000, 30000, 30000
        )

        /**
         * The live tunnel, published so the UI can re-sync after the app process
         * is backgrounded, force-quit or relaunched — the VpnService keeps
         * running either way. Null while disconnected.
         */
        @Volatile var liveState: LiveState? = null
            private set

        /**
         * Traffic counters for the live tunnel, kept out of [liveState] so the
         * once-a-second update is a plain volatile write rather than a
         * read-modify-write that could republish a tunnel torn down in between.
         * Reset when a tunnel comes up; only meaningful while [liveState] is
         * non-null.
         */
        @Volatile var liveBytesReceived: Long = 0L
            private set
        @Volatile var liveBytesSent: Long = 0L
            private set

        /**
         * Non-zero while the service is retrying a dropped connection (the
         * current attempt number). Lets a resuming UI show "reconnecting"
         * instead of a stale "connected" while [liveState] is still published.
         */
        @Volatile var liveReconnectAttempt: Int = 0
            private set

        val isConnected: Boolean get() = liveState != null
    }

    /**
     * Immutable description of the tunnel currently up.
     *
     * [connectedSinceElapsedMs] is on the SystemClock.elapsedRealtime base so
     * the session duration keeps counting from the real connect time (and is
     * immune to wall-clock changes) rather than restarting at zero every time
     * the user reopens the app.
     */
    data class LiveState(
        val assignedIp: String,
        val gateway: String,
        val dns: String,
        val mtu: Int,
        val connectedSinceElapsedMs: Long
    )

    private var vpnInterface: ParcelFileDescriptor? = null
    private var tlsConnection: TlsConnection? = null

    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val isRunning = AtomicBoolean(false)

    private var serverAddress: String = ""
    private var serverPort: Int = 443
    private var username: String = ""
    private var password: String = ""
    private var authType: String = AUTH_TYPE_PASSWORD
    private var token: String = ""
    private var autoReconnect: Boolean = true
    private var disconnectNotify: Boolean = true

    // Set the moment the user asks to disconnect (UI action, notification
    // action, or service teardown) — distinguishes an intentional stop from a
    // dropped connection so we never auto-reconnect or alert on a manual stop.
    private val userStopped = AtomicBoolean(false)

    // True while the reconnect loop owns the connection. Gates the tunnel loops'
    // error paths so the failures of the torn-down connection don't cascade.
    private val reconnecting = AtomicBoolean(false)
    private var reconnectJob: Job? = null

    // elapsedRealtime of the last message received from the server (any type) —
    // the input for dead-peer detection in the keepalive loop.
    private val lastServerActivityMs = AtomicLong(0)

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
                authType = intent.getStringExtra(EXTRA_AUTH_TYPE) ?: AUTH_TYPE_PASSWORD
                token = intent.getStringExtra(EXTRA_TOKEN) ?: ""
                autoReconnect = intent.getBooleanExtra(EXTRA_AUTO_RECONNECT, true)
                disconnectNotify = intent.getBooleanExtra(EXTRA_DISCONNECT_NOTIFY, true)

                val hasCredentials = if (authType == AUTH_TYPE_PASSWORD) {
                    username.isNotEmpty()
                } else {
                    token.isNotEmpty()
                }
                if (serverAddress.isNotEmpty() && hasCredentials) {
                    userStopped.set(false)
                    startVpn()
                }
            }
            ACTION_DISCONNECT -> {
                userStopped.set(true)
                stopVpn()
            }
        }
        return START_STICKY
    }

    override fun onDestroy() {
        super.onDestroy()
        userStopped.set(true)
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
                // TLS connect + auth (rotating the stored session token) + config.
                val config = connectAndAuthenticate()
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
                cancelDisconnectAlert()

                // Publish live state so the UI can re-sync after an app restart.
                val connectedSince = SystemClock.elapsedRealtime()
                liveBytesReceived = 0
                liveBytesSent = 0
                liveState = LiveState(
                    assignedIp = config.assignedIP,
                    gateway = config.gateway,
                    dns = config.dns.joinToString(", "),
                    mtu = config.mtu,
                    connectedSinceElapsedMs = connectedSince
                )

                // Notify UI of successful connection
                val successIntent = Intent("com.vpn.client.VPN_CONNECTED").apply {
                    setPackage(packageName)
                    putExtra("assigned_ip", config.assignedIP)
                    putExtra("gateway", config.gateway)
                    putExtra("dns", config.dns.joinToString(", "))
                    putExtra("mtu", config.mtu)
                    putExtra("connected_since_elapsed_ms", connectedSince)
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

        liveState = null
        liveReconnectAttempt = 0

        // A pending reconnect must not outlive the stop. (Cancelling from
        // within the reconnect job itself is fine — nothing after this call
        // suspends on that path.)
        reconnectJob?.cancel()
        reconnectJob = null
        reconnecting.set(false)

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

    /**
     * Thrown when the stored SSO session token is rejected — the UI clears the
     * session and asks the user to log in with SSO again.
     */
    private class SessionAuthException(message: String) : Exception(message)

    /**
     * Establishes the TLS connection, authenticates (persisting a rotated
     * session token) and receives the pushed VPN configuration. Shared by the
     * initial connect and every reconnect attempt.
     */
    private suspend fun connectAndAuthenticate(): VpnConfig {
        tlsConnection = TlsConnection().apply {
            connect(serverAddress, serverPort)
        }
        val rotatedToken = authenticate()
        persistRotatedToken(rotatedToken)
        val config = receiveConfiguration()
        lastServerActivityMs.set(SystemClock.elapsedRealtime())
        return config
    }

    /**
     * The server rotates the 30-day session token on every authentication.
     * Persist it to the same store the VpnViewModel reads ("vpn_session" /
     * "session_token") so the next connect — from the UI or from this
     * service's own reconnect loop — presents the current token instead of the
     * consumed one.
     */
    private fun persistRotatedToken(newToken: String) {
        if (authType != AUTH_TYPE_SESSION) return
        if (newToken.isEmpty() || newToken == token) return
        token = newToken
        getSharedPreferences("vpn_session", MODE_PRIVATE).edit()
            .putString("session_token", newToken)
            .apply()
        Log.i(TAG, "Session token rotated and persisted")
    }

    private suspend fun authenticate(): String = withContext(Dispatchers.IO) {
        val connection = tlsConnection ?: throw Exception("Connection not established")

        // Send auth request with credentials (password) or session token (SSO)
        val authRequest = if (authType == AUTH_TYPE_PASSWORD) {
            AuthRequest(
                username = username,
                password = password,
                clientVersion = "1.0.0",
                platform = "android"
            )
        } else {
            AuthRequest(
                clientVersion = "1.0.0",
                platform = "android",
                authType = authType,
                token = token
            )
        }
        val requestBytes = VpnMessageSerializer.serializeAuthRequest(authRequest)
        connection.send(VpnMessageType.AUTH_REQUEST, requestBytes)

        // Receive auth response
        val response = connection.receive()
        if (response.first != VpnMessageType.AUTH_RESPONSE) {
            throw Exception("Expected AUTH_RESPONSE, got ${response.first}")
        }

        val authResponse = VpnMessageSerializer.deserializeAuthResponse(response.second)
        if (!authResponse.success) {
            val message = authResponse.errorMessage ?: "Authentication failed"
            if (authType == AUTH_TYPE_SESSION) {
                throw SessionAuthException(message)
            }
            throw Exception(message)
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
                // While the reconnect loop rebuilds the connection, the tun fd
                // stays alive: park briefly and keep the loop running so it can
                // serve the restored connection without being relaunched.
                if (reconnecting.get()) {
                    delay(200)
                    continue
                }
                Log.e(TAG, "Error reading from tunnel", e)
                handleConnectionError(e)
                // If the error kicked off a reconnect, stay alive for it.
                if (reconnecting.get()) continue else break
            }
        }
    }

    private suspend fun readFromServer() = withContext(Dispatchers.IO) {
        // Bind to the connection this loop instance serves. A reconnect launches
        // a fresh loop for the new connection; an old instance dying on the
        // closed socket must not be mistaken for a failure of the current one.
        val connection = tlsConnection ?: return@withContext
        try {
            while (isRunning.get() && isActive) {
                val (type, payload) = connection.receive()

                // Any inbound message proves the peer is alive.
                lastServerActivityMs.set(SystemClock.elapsedRealtime())

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
                        // Deliberate kick from the server — never auto-reconnect,
                        // but the user did not ask for this, so alert (if enabled).
                        notifyDisconnected("서버가 연결을 종료했습니다")
                        stopVpn()
                        break
                    }
                    else -> {
                        Log.w(TAG, "Received unexpected message type: $type")
                    }
                }
            }
        } catch (e: Exception) {
            if (isRunning.get() && !reconnecting.get() && tlsConnection === connection) {
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
        // Bound to one connection, like readFromServer: a stale instance must
        // exit quietly after a reconnect replaces the connection.
        val connection = tlsConnection ?: return@withContext
        try {
            while (isRunning.get() && isActive && tlsConnection === connection) {
                delay(KEEPALIVE_INTERVAL_MS)
                if (!isRunning.get() || tlsConnection !== connection) break

                // Dead-peer detection: nothing received for IDLE_TIMEOUT_MS
                // despite 30s keepalives means the link is silently dead — fail
                // fast into the reconnect path instead of trusting a zombie
                // socket.
                val idleMs = SystemClock.elapsedRealtime() - lastServerActivityMs.get()
                if (idleMs > IDLE_TIMEOUT_MS) {
                    Log.w(TAG, "Dead peer: no server traffic for ${idleMs}ms")
                    if (!reconnecting.get()) {
                        handleConnectionError(
                            IOException("서버 응답 없음 (${idleMs / 1000}초)")
                        )
                    }
                    break
                }

                connection.send(VpnMessageType.KEEPALIVE, ByteArray(0))
                Log.d(TAG, "Sent keepalive")
            }
        } catch (e: Exception) {
            if (isRunning.get() && !reconnecting.get() && tlsConnection === connection) {
                Log.e(TAG, "Error sending keepalive", e)
                handleConnectionError(e)
            }
        }
    }

    private suspend fun sendTrafficStats() = withContext(Dispatchers.IO) {
        try {
            var lastReceived = -1L
            var lastSent = -1L

            while (isRunning.get() && isActive) {
                delay(1000) // Update every second

                val received = bytesReceived.get()
                val sent = bytesSent.get()

                // Keep the published counters current for a UI that re-syncs
                // after being backgrounded.
                liveBytesReceived = received
                liveBytesSent = sent

                // Only broadcast when the counters actually moved. An idle
                // tunnel used to wake every registered receiver once a second
                // for a pair of unchanged numbers, which on a phone is a
                // pointless drain on a screen-off device.
                if (received == lastReceived && sent == lastSent) continue
                lastReceived = received
                lastSent = sent

                val statsIntent = Intent("com.vpn.client.VPN_STATS").apply {
                    setPackage(packageName)
                    putExtra("bytes_received", received)
                    putExtra("bytes_sent", sent)
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
        // Errors raised while a stop or reconnect is already in progress are
        // just the old connection's death throes.
        if (!isRunning.get() || reconnecting.get()) return

        Log.e(TAG, "Connection error: ${e.message}")

        // Reconnect/alert only apply to an ESTABLISHED tunnel dropping. A
        // failed initial connect (wrong address, server down) shows its error
        // in the UI the user is looking at — retrying 10 times or posting a
        // heads-up alert for it would be noise.
        val wasEstablished = liveState != null

        // Unexpected drop with auto-reconnect on: retry in-service. A rejected
        // session token is not retryable — reconnecting would just burn the
        // attempts against a hard auth failure.
        if (wasEstablished && e !is SessionAuthException &&
            autoReconnect && !userStopped.get()
        ) {
            startReconnect()
            return
        }

        val unexpected = wasEstablished && !userStopped.get()
        stopVpn()
        if (unexpected) {
            notifyDisconnected(e.message)
        }
        broadcastError(e.message, sessionAuthFailed = e is SessionAuthException)
    }

    /** Broadcasts VPN_ERROR to the UI. session_auth_failed tells the UI the
     *  stored 30-day SSO session token was rejected (re-login via SSO required). */
    private fun broadcastError(message: String?, sessionAuthFailed: Boolean) {
        val intent = Intent("com.vpn.client.VPN_ERROR").apply {
            setPackage(packageName)
            putExtra("error_message", message)
            putExtra("session_auth_failed", sessionAuthFailed)
        }
        sendBroadcast(intent)
    }

    /**
     * In-service auto-reconnect with backoff (2, 4, 8, 16, then 30s intervals,
     * 10 attempts total). The foreground service already holds everything a
     * retry needs — server address, auth type, current session token — so no
     * UI round-trip is involved and the tun fd is kept up so app sockets can
     * survive a quick recovery.
     */
    private fun startReconnect() {
        if (!reconnecting.compareAndSet(false, true)) return

        reconnectJob = serviceScope.launch {
            try {
                // Drop the broken connection; the tun interface stays up.
                try {
                    tlsConnection?.disconnect()
                } catch (_: Exception) {
                }
                tlsConnection = null

                for (attempt in 1..MAX_RECONNECT_ATTEMPTS) {
                    liveReconnectAttempt = attempt
                    updateNotification("재연결 중 ($attempt/$MAX_RECONNECT_ATTEMPTS)")
                    sendBroadcast(Intent("com.vpn.client.VPN_RECONNECTING").apply {
                        setPackage(packageName)
                        putExtra("attempt", attempt)
                        putExtra("max_attempts", MAX_RECONNECT_ATTEMPTS)
                    })

                    delay(RECONNECT_DELAYS_MS[attempt - 1])
                    if (userStopped.get() || !isRunning.get()) return@launch

                    try {
                        reconnectOnce()

                        // Back to normal operation: clear the flag first so the
                        // freshly launched loops (and the surviving tunnel-read
                        // loop) run, then tell the UI.
                        liveReconnectAttempt = 0
                        reconnecting.set(false)
                        updateNotification("Connected to $serverAddress")
                        cancelDisconnectAlert()

                        val live = liveState
                        val config = vpnConfig
                        if (live != null && config != null) {
                            sendBroadcast(Intent("com.vpn.client.VPN_CONNECTED").apply {
                                setPackage(packageName)
                                putExtra("assigned_ip", config.assignedIP)
                                putExtra("gateway", config.gateway)
                                putExtra("dns", config.dns.joinToString(", "))
                                putExtra("mtu", config.mtu)
                                putExtra(
                                    "connected_since_elapsed_ms",
                                    live.connectedSinceElapsedMs
                                )
                            })
                        }

                        // On serviceScope so the loops are not children of this
                        // (about to complete) reconnect job.
                        serviceScope.launch { readFromServer() }
                        serviceScope.launch { sendKeepalive() }

                        Log.i(TAG, "Reconnected on attempt $attempt")
                        return@launch
                    } catch (e: SessionAuthException) {
                        // The rotated token was rejected — hard stop, back to login.
                        Log.e(TAG, "Reconnect auth failed: ${e.message}")
                        stopVpn()
                        notifyDisconnected("세션이 만료되어 VPN 연결이 끊어졌습니다")
                        broadcastError(e.message, sessionAuthFailed = true)
                        return@launch
                    } catch (e: Exception) {
                        if (e is CancellationException) throw e
                        Log.w(TAG, "Reconnect attempt $attempt failed: ${e.message}")
                        try {
                            tlsConnection?.disconnect()
                        } catch (_: Exception) {
                        }
                        tlsConnection = null
                    }
                }

                // Every attempt failed: give up, alert, stop for good.
                Log.e(TAG, "Reconnect failed after $MAX_RECONNECT_ATTEMPTS attempts")
                notifyDisconnected("재연결에 실패했습니다 ($MAX_RECONNECT_ATTEMPTS 회 시도)")
                stopVpn()
                broadcastError("재연결에 실패했습니다", sessionAuthFailed = false)
            } finally {
                // Covers cancellation (user stop / service destroy) as well.
                reconnecting.set(false)
                liveReconnectAttempt = 0
            }
        }
    }

    /**
     * One reconnect attempt: fresh TLS + re-auth (rotating the session token) +
     * config. The existing tun fd is kept when the pushed config is unchanged;
     * otherwise the interface is rebuilt and swapped like the split-tunnel
     * re-establish path.
     */
    private suspend fun reconnectOnce() {
        val config = connectAndAuthenticate()

        val previousConfig = vpnConfig
        vpnConfig = config
        domainMatcher = if (config.splitTunnel && config.includedDomains.isNotEmpty()) {
            DomainMatcher(config.includedDomains)
        } else {
            null
        }

        if (config != previousConfig || vpnInterface == null) {
            dynamicRoutes.clear()
            val old = vpnInterface
            val iface = buildVpnInterface(config)
                ?: throw Exception("Failed to re-establish VPN interface")
            vpnInterface = iface
            tunInput = FileInputStream(iface.fileDescriptor)
            tunOutput = FileOutputStream(iface.fileDescriptor)
            old?.close()
            Log.i(TAG, "Interface rebuilt after reconnect (config changed)")
        }

        // Same logical session: keep the original connect time.
        val since = liveState?.connectedSinceElapsedMs ?: SystemClock.elapsedRealtime()
        liveState = LiveState(
            assignedIp = config.assignedIP,
            gateway = config.gateway,
            dns = config.dns.joinToString(", "),
            mtu = config.mtu,
            connectedSinceElapsedMs = since
        )
    }

    /**
     * Posts the "VPN 연결 끊김" alert on the high-importance channel. Only for
     * disconnects the user did not ask for; gated on the disconnectNotify
     * setting. Separate id from the (removed) foreground notification so it
     * survives stopForeground.
     */
    private fun notifyDisconnected(reason: String?) {
        if (!disconnectNotify || userStopped.get()) return

        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val notification = NotificationCompat.Builder(this, ALERT_CHANNEL_ID)
            .setContentTitle("VPN 연결 끊김")
            .setContentText(reason ?: "VPN 연결이 예기치 않게 끊어졌습니다")
            .setSmallIcon(android.R.drawable.stat_notify_error)
            .setContentIntent(pendingIntent)
            .setAutoCancel(true)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_ERROR)
            .build()

        try {
            getSystemService(NotificationManager::class.java)
                .notify(ALERT_NOTIFICATION_ID, notification)
        } catch (e: Exception) {
            // POST_NOTIFICATIONS may have been declined — survivable.
            Log.w(TAG, "Could not post disconnect notification", e)
        }
    }

    /** A stale "disconnected" alert makes no sense once a tunnel is up again. */
    private fun cancelDisconnectAlert() {
        try {
            getSystemService(NotificationManager::class.java).cancel(ALERT_NOTIFICATION_ID)
        } catch (_: Exception) {
        }
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

            // Unlike the silent ongoing channel above, an unexpected disconnect
            // must actually get the user's attention (heads-up + sound per the
            // user's system settings).
            val alertChannel = NotificationChannel(
                ALERT_CHANNEL_ID,
                "VPN Alerts",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "Alerts when the VPN disconnects unexpectedly"
            }

            val notificationManager = getSystemService(NotificationManager::class.java)
            notificationManager.createNotificationChannel(channel)
            notificationManager.createNotificationChannel(alertChannel)
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
