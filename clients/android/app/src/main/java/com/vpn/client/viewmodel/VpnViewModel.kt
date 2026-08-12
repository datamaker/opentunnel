package com.vpn.client.viewmodel

import android.app.Application
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.SystemClock
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.vpn.client.auth.DeviceFlowClient
import com.vpn.client.network.TlsConnection
import com.vpn.client.protocol.AuthRequest
import com.vpn.client.protocol.AuthResponse
import com.vpn.client.protocol.VpnMessageSerializer
import com.vpn.client.protocol.VpnMessageType
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import java.util.concurrent.TimeUnit

enum class VpnConnectionState {
    DISCONNECTED,
    CONNECTING,
    CONNECTED,
    ERROR
}

class VpnViewModel(application: Application) : AndroidViewModel(application) {

    // Login State
    private val _isLoggedIn = MutableStateFlow(false)
    val isLoggedIn: StateFlow<Boolean> = _isLoggedIn.asStateFlow()

    private val _isLoggingIn = MutableStateFlow(false)
    val isLoggingIn: StateFlow<Boolean> = _isLoggingIn.asStateFlow()

    private val _loginError = MutableStateFlow<String?>(null)
    val loginError: StateFlow<String?> = _loginError.asStateFlow()

    private val _loginSuccess = MutableSharedFlow<Unit>()
    val loginSuccess: SharedFlow<Unit> = _loginSuccess.asSharedFlow()

    // Session & Credentials
    private val _sessionToken = MutableStateFlow("")
    val sessionToken: StateFlow<String> = _sessionToken.asStateFlow()

    private val _username = MutableStateFlow("")
    val username: StateFlow<String> = _username.asStateFlow()

    private val _password = MutableStateFlow("")
    val password: StateFlow<String> = _password.asStateFlow()

    // Who to show in the header. For password logins this is the username; SSO
    // users have no username at all, so it is the email claim from the
    // id_token (matching the Apple clients) rather than a blank line.
    private val _displayName = MutableStateFlow("")
    val displayName: StateFlow<String> = _displayName.asStateFlow()

    // Auth mode: "password" (username/password) or "sso" (Datasee SSO session token)
    private val _authMode = MutableStateFlow(AUTH_MODE_PASSWORD)
    val authMode: StateFlow<String> = _authMode.asStateFlow()

    // Device-flow SSO state: non-null while waiting for browser approval.
    private val _ssoUserCode = MutableStateFlow<String?>(null)
    val ssoUserCode: StateFlow<String?> = _ssoUserCode.asStateFlow()

    private val _ssoVerificationUri = MutableStateFlow<String?>(null)
    val ssoVerificationUri: StateFlow<String?> = _ssoVerificationUri.asStateFlow()

    private var ssoLoginJob: Job? = null

    // Connection State
    private val _connectionState = MutableStateFlow(VpnConnectionState.DISCONNECTED)
    val connectionState: StateFlow<VpnConnectionState> = _connectionState.asStateFlow()

    // Server Settings
    private val _serverAddress = MutableStateFlow("")
    val serverAddress: StateFlow<String> = _serverAddress.asStateFlow()

    private val _serverPort = MutableStateFlow(1194)
    val serverPort: StateFlow<Int> = _serverPort.asStateFlow()

    // VPN Settings
    private val _autoReconnect = MutableStateFlow(true)
    val autoReconnect: StateFlow<Boolean> = _autoReconnect.asStateFlow()

    private val _killSwitch = MutableStateFlow(false)
    val killSwitch: StateFlow<Boolean> = _killSwitch.asStateFlow()

    private val _splitTunneling = MutableStateFlow(false)
    val splitTunneling: StateFlow<Boolean> = _splitTunneling.asStateFlow()

    // Connection Info
    private val _assignedIp = MutableStateFlow("")
    val assignedIp: StateFlow<String> = _assignedIp.asStateFlow()

    private val _gateway = MutableStateFlow("")
    val gateway: StateFlow<String> = _gateway.asStateFlow()

    private val _dnsServers = MutableStateFlow("")
    val dnsServers: StateFlow<String> = _dnsServers.asStateFlow()

    private val _mtu = MutableStateFlow(0)
    val mtu: StateFlow<Int> = _mtu.asStateFlow()

    private val _bytesReceived = MutableStateFlow(0L)
    val bytesReceived: StateFlow<Long> = _bytesReceived.asStateFlow()

    private val _bytesSent = MutableStateFlow(0L)
    val bytesSent: StateFlow<Long> = _bytesSent.asStateFlow()

    private val _connectionDuration = MutableStateFlow("00:00:00")
    val connectionDuration: StateFlow<String> = _connectionDuration.asStateFlow()

    // SystemClock.elapsedRealtime base — matches what MyVpnService publishes.
    private var connectionStartTime: Long = 0
    private var durationJob: Job? = null

    // App-private session store so the user stays logged in across app restarts.
    private val prefs = application.getSharedPreferences("vpn_session", Context.MODE_PRIVATE)

    companion object {
        const val AUTH_MODE_PASSWORD = "password"
        const val AUTH_MODE_SSO = "sso"
        private const val CLIENT_VERSION = "1.0.0"
    }

    init {
        // Restore a previous session on launch.
        if (prefs.getBoolean("logged_in", false)) {
            _authMode.value = prefs.getString("auth_mode", AUTH_MODE_PASSWORD) ?: AUTH_MODE_PASSWORD
            _serverAddress.value = prefs.getString("server_address", "") ?: ""
            _serverPort.value = prefs.getInt("server_port", 1194)
            if (_authMode.value == AUTH_MODE_SSO) {
                // SSO users have no stored password — only the 30-day session token.
                _sessionToken.value = prefs.getString("session_token", "") ?: ""
            } else {
                _username.value = prefs.getString("username", "") ?: ""
                _password.value = prefs.getString("password", "") ?: ""
            }
            // Sessions stored before display_name existed fall back to the username.
            _displayName.value = prefs.getString("display_name", null) ?: _username.value
            _isLoggedIn.value = true
        }
    }

    fun login(username: String, password: String, serverAddress: String, serverPort: Int) {
        viewModelScope.launch {
            _isLoggingIn.value = true
            _loginError.value = null
            _serverAddress.value = serverAddress
            _serverPort.value = serverPort
            _username.value = username
            _password.value = password

            try {
                val result = performLogin(username, password, serverAddress, serverPort)
                if (result.success) {
                    _sessionToken.value = result.sessionToken
                    _authMode.value = AUTH_MODE_PASSWORD
                    _displayName.value = username
                    _isLoggedIn.value = true
                    prefs.edit()
                        .putBoolean("logged_in", true)
                        .putString("auth_mode", AUTH_MODE_PASSWORD)
                        .putString("display_name", username)
                        .putString("username", username)
                        .putString("password", password)
                        .putString("server_address", serverAddress)
                        .putInt("server_port", serverPort)
                        .apply()
                    _loginSuccess.emit(Unit)
                } else {
                    _loginError.value = result.errorMessage ?: "Authentication failed"
                }
            } catch (e: Exception) {
                _loginError.value = e.message ?: "Connection error"
            } finally {
                _isLoggingIn.value = false
            }
        }
    }

    /**
     * Datasee SSO login via the OAuth device flow:
     * 1. Get a device/user code from the IdP and open the browser for approval.
     * 2. Poll until approval, receiving an OIDC id_token.
     * 3. Verify against the VPN server with a throwaway TLS auth (authType=sso);
     *    the server returns a 30-day sessionToken that is stored for reconnects.
     * No password is ever stored for SSO users.
     */
    fun loginWithSso(serverAddress: String, serverPort: Int) {
        ssoLoginJob?.cancel()
        ssoLoginJob = viewModelScope.launch {
            _isLoggingIn.value = true
            _loginError.value = null
            _serverAddress.value = serverAddress
            _serverPort.value = serverPort

            try {
                val deviceFlow = DeviceFlowClient()
                val authorization = deviceFlow.startDeviceAuthorization()

                // Surface the code + fallback URI in the UI, then open the browser.
                _ssoUserCode.value = authorization.userCode
                _ssoVerificationUri.value = authorization.verificationUri
                openInBrowser(authorization.verificationUriComplete)

                val idToken = deviceFlow.pollForToken(authorization)

                // Verify the id_token against the VPN server on a throwaway
                // connection; it hands back the long-lived session token.
                val result = performSsoLogin(idToken, serverAddress, serverPort)
                if (result.success && result.sessionToken.isNotEmpty()) {
                    val ssoName = DeviceFlowClient.emailFromIdToken(idToken) ?: "Datasee SSO"
                    _sessionToken.value = result.sessionToken
                    _authMode.value = AUTH_MODE_SSO
                    _username.value = ""
                    _password.value = ""
                    _displayName.value = ssoName
                    _isLoggedIn.value = true
                    prefs.edit()
                        .putBoolean("logged_in", true)
                        .putString("auth_mode", AUTH_MODE_SSO)
                        .putString("display_name", ssoName)
                        .putString("session_token", result.sessionToken)
                        .putString("server_address", serverAddress)
                        .putInt("server_port", serverPort)
                        .remove("username")
                        .remove("password")
                        .apply()
                    _loginSuccess.emit(Unit)
                } else {
                    _loginError.value = result.errorMessage ?: "SSO 인증에 실패했습니다"
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                _loginError.value = e.message ?: "SSO 로그인 중 오류가 발생했습니다"
            } finally {
                _ssoUserCode.value = null
                _ssoVerificationUri.value = null
                _isLoggingIn.value = false
            }
        }
    }

    /**
     * Cancels an in-progress SSO device flow (user tapped 취소).
     */
    fun cancelSsoLogin() {
        ssoLoginJob?.cancel()
        ssoLoginJob = null
        _ssoUserCode.value = null
        _ssoVerificationUri.value = null
        _isLoggingIn.value = false
    }

    /**
     * The stored 30-day session token was rejected by the server — clear the
     * session and send the user back to the login screen for SSO 재로그인.
     */
    fun onSessionAuthFailed() {
        _isLoggedIn.value = false
        _sessionToken.value = ""
        _displayName.value = ""
        _connectionState.value = VpnConnectionState.DISCONNECTED
        prefs.edit().clear().apply()
        stopDurationTimer()
        resetConnectionStats()
        _loginError.value = "SSO 세션이 만료되었습니다. Google로 다시 로그인해 주세요."
    }

    private fun openInBrowser(url: String) {
        val intent = Intent(Intent.ACTION_VIEW, Uri.parse(url)).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        try {
            getApplication<Application>().startActivity(intent)
        } catch (e: Exception) {
            // No browser available — the UI still shows user_code + verification_uri
            // so the user can approve from another device.
        }
    }

    private suspend fun performSsoLogin(
        idToken: String,
        serverAddress: String,
        serverPort: Int
    ): AuthResponse = withContext(Dispatchers.IO) {
        val connection = TlsConnection()

        try {
            connection.connect(serverAddress, serverPort)

            val authRequest = AuthRequest(
                clientVersion = CLIENT_VERSION,
                platform = "android",
                authType = "sso",
                token = idToken
            )

            val requestBytes = VpnMessageSerializer.serializeAuthRequest(authRequest)
            connection.send(VpnMessageType.AUTH_REQUEST, requestBytes)

            val response = connection.receive()
            if (response.first == VpnMessageType.AUTH_RESPONSE) {
                VpnMessageSerializer.deserializeAuthResponse(response.second)
            } else {
                AuthResponse(success = false, sessionToken = "", errorMessage = "Unexpected response")
            }
        } finally {
            connection.disconnect()
        }
    }

    private suspend fun performLogin(
        username: String,
        password: String,
        serverAddress: String,
        serverPort: Int
    ): AuthResponse = withContext(Dispatchers.IO) {
        val connection = TlsConnection()

        try {
            connection.connect(serverAddress, serverPort)

            val authRequest = AuthRequest(
                username = username,
                password = password,
                clientVersion = CLIENT_VERSION,
                platform = "android"
            )

            val requestBytes = VpnMessageSerializer.serializeAuthRequest(authRequest)
            connection.send(VpnMessageType.AUTH_REQUEST, requestBytes)

            val response = connection.receive()
            if (response.first == VpnMessageType.AUTH_RESPONSE) {
                VpnMessageSerializer.deserializeAuthResponse(response.second)
            } else {
                AuthResponse(success = false, sessionToken = "", errorMessage = "Unexpected response")
            }
        } finally {
            connection.disconnect()
        }
    }

    fun logout() {
        viewModelScope.launch {
            cancelSsoLogin()
            _isLoggedIn.value = false
            _sessionToken.value = ""
            _username.value = ""
            _password.value = ""
            _displayName.value = ""
            _authMode.value = AUTH_MODE_PASSWORD
            _connectionState.value = VpnConnectionState.DISCONNECTED
            prefs.edit().clear().apply()
            stopDurationTimer()
        }
    }

    fun onVpnConnecting() {
        _connectionState.value = VpnConnectionState.CONNECTING
    }

    /**
     * @param connectedSinceElapsedMs when the tunnel came up, on the
     *   SystemClock.elapsedRealtime base (0 = unknown, start counting now).
     *   Passing the service's value keeps the session duration correct when the
     *   UI re-syncs after being backgrounded or relaunched, instead of
     *   restarting the clock at 00:00:00 on every return to the app.
     */
    fun onVpnConnected(
        assignedIp: String,
        gateway: String = "",
        dns: String = "",
        mtu: Int = 0,
        connectedSinceElapsedMs: Long = 0L
    ) {
        _connectionState.value = VpnConnectionState.CONNECTED
        _assignedIp.value = assignedIp
        _gateway.value = gateway
        _dnsServers.value = dns
        _mtu.value = mtu
        connectionStartTime = if (connectedSinceElapsedMs > 0L) {
            connectedSinceElapsedMs
        } else {
            SystemClock.elapsedRealtime()
        }
        startDurationTimer()
    }

    fun onVpnDisconnected() {
        _connectionState.value = VpnConnectionState.DISCONNECTED
        stopDurationTimer()
        resetConnectionStats()
    }

    fun onVpnError(error: String) {
        _connectionState.value = VpnConnectionState.ERROR
        _loginError.value = error
        stopDurationTimer()
    }

    fun onVpnPermissionDenied() {
        _connectionState.value = VpnConnectionState.DISCONNECTED
        _loginError.value = "VPN permission denied"
    }

    fun updateTrafficStats(received: Long, sent: Long) {
        _bytesReceived.value = received
        _bytesSent.value = sent
    }

    fun updateServerSettings(address: String, port: Int) {
        _serverAddress.value = address
        _serverPort.value = port
    }

    fun setAutoReconnect(enabled: Boolean) {
        _autoReconnect.value = enabled
    }

    fun setKillSwitch(enabled: Boolean) {
        _killSwitch.value = enabled
    }

    fun setSplitTunneling(enabled: Boolean) {
        _splitTunneling.value = enabled
    }

    private fun startDurationTimer() {
        durationJob?.cancel()
        durationJob = viewModelScope.launch {
            while (isActive) {
                val elapsed = SystemClock.elapsedRealtime() - connectionStartTime
                _connectionDuration.value = formatDuration(elapsed)
                delay(1000)
            }
        }
    }

    private fun stopDurationTimer() {
        durationJob?.cancel()
        durationJob = null
    }

    private fun resetConnectionStats() {
        _assignedIp.value = ""
        _gateway.value = ""
        _dnsServers.value = ""
        _mtu.value = 0
        _bytesReceived.value = 0
        _bytesSent.value = 0
        _connectionDuration.value = "00:00:00"
    }

    private fun formatDuration(millis: Long): String {
        val hours = TimeUnit.MILLISECONDS.toHours(millis)
        val minutes = TimeUnit.MILLISECONDS.toMinutes(millis) % 60
        val seconds = TimeUnit.MILLISECONDS.toSeconds(millis) % 60
        return String.format("%02d:%02d:%02d", hours, minutes, seconds)
    }

    override fun onCleared() {
        super.onCleared()
        durationJob?.cancel()
    }
}
