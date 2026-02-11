package com.vpn.client.viewmodel

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
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

    // Session
    private val _sessionToken = MutableStateFlow("")
    val sessionToken: StateFlow<String> = _sessionToken.asStateFlow()

    // Connection State
    private val _connectionState = MutableStateFlow(VpnConnectionState.DISCONNECTED)
    val connectionState: StateFlow<VpnConnectionState> = _connectionState.asStateFlow()

    // Server Settings
    private val _serverAddress = MutableStateFlow("vpn.example.com")
    val serverAddress: StateFlow<String> = _serverAddress.asStateFlow()

    private val _serverPort = MutableStateFlow(443)
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

    private val _bytesReceived = MutableStateFlow(0L)
    val bytesReceived: StateFlow<Long> = _bytesReceived.asStateFlow()

    private val _bytesSent = MutableStateFlow(0L)
    val bytesSent: StateFlow<Long> = _bytesSent.asStateFlow()

    private val _connectionDuration = MutableStateFlow("00:00:00")
    val connectionDuration: StateFlow<String> = _connectionDuration.asStateFlow()

    private var connectionStartTime: Long = 0
    private var durationJob: Job? = null

    fun login(username: String, password: String, serverAddress: String, serverPort: Int) {
        viewModelScope.launch {
            _isLoggingIn.value = true
            _loginError.value = null
            _serverAddress.value = serverAddress
            _serverPort.value = serverPort

            try {
                val result = performLogin(username, password, serverAddress, serverPort)
                if (result.success) {
                    _sessionToken.value = result.sessionToken
                    _isLoggedIn.value = true
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
                clientVersion = "1.0.0",
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
            _isLoggedIn.value = false
            _sessionToken.value = ""
            _connectionState.value = VpnConnectionState.DISCONNECTED
            stopDurationTimer()
        }
    }

    fun onVpnConnecting() {
        _connectionState.value = VpnConnectionState.CONNECTING
    }

    fun onVpnConnected(assignedIp: String) {
        _connectionState.value = VpnConnectionState.CONNECTED
        _assignedIp.value = assignedIp
        connectionStartTime = System.currentTimeMillis()
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
                val elapsed = System.currentTimeMillis() - connectionStartTime
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
