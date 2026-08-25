package com.vpn.client

import android.Manifest
import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.core.content.ContextCompat
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import com.vpn.client.service.MyVpnService
import com.vpn.client.ui.screens.LoginScreen
import com.vpn.client.ui.screens.MainScreen
import com.vpn.client.ui.screens.SettingsScreen
import com.vpn.client.ui.theme.VpnClientTheme
import com.vpn.client.viewmodel.VpnConnectionState
import com.vpn.client.viewmodel.VpnViewModel

class MainActivity : ComponentActivity() {

    // Owned by the activity rather than created inside setContent: the VPN
    // broadcasts below can land before the first composition runs (the service
    // is already connecting when the activity is recreated), and a lateinit
    // field assigned from the composition would still be unset at that point.
    private val vpnViewModel: VpnViewModel by viewModels()

    private val vpnBroadcastReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            Log.d("MainActivity", "Received broadcast: ${intent?.action}")
            when (intent?.action) {
                "com.vpn.client.VPN_CONNECTED" -> {
                    val assignedIp = intent.getStringExtra("assigned_ip") ?: ""
                    val gateway = intent.getStringExtra("gateway") ?: ""
                    val dns = intent.getStringExtra("dns") ?: ""
                    val mtu = intent.getIntExtra("mtu", 0)
                    val connectedSince = intent.getLongExtra("connected_since_elapsed_ms", 0L)
                    Log.d("MainActivity", "VPN Connected with IP: $assignedIp")
                    vpnViewModel.onVpnConnected(assignedIp, gateway, dns, mtu, connectedSince)
                }
                "com.vpn.client.VPN_ERROR" -> {
                    val errorMessage = intent.getStringExtra("error_message") ?: "Connection failed"
                    Log.d("MainActivity", "VPN Error: $errorMessage")
                    if (intent.getBooleanExtra("session_auth_failed", false)) {
                        // Stored SSO session token rejected — clear the session
                        // and send the user back to the login screen.
                        vpnViewModel.onSessionAuthFailed()
                    } else {
                        vpnViewModel.onVpnError(errorMessage)
                    }
                }
                "com.vpn.client.VPN_DISCONNECTED" -> {
                    Log.d("MainActivity", "VPN Disconnected")
                    vpnViewModel.onVpnDisconnected()
                }
                "com.vpn.client.VPN_RECONNECTING" -> {
                    val attempt = intent.getIntExtra("attempt", 0)
                    Log.d("MainActivity", "VPN Reconnecting, attempt $attempt")
                    vpnViewModel.onVpnReconnecting(attempt)
                }
                "com.vpn.client.VPN_STATS" -> {
                    val received = intent.getLongExtra("bytes_received", 0)
                    val sent = intent.getLongExtra("bytes_sent", 0)
                    vpnViewModel.updateTrafficStats(received, sent)
                }
            }
        }
    }

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            startVpnService()
        } else {
            vpnViewModel.onVpnPermissionDenied()
        }
    }

    // Android 13+ requires runtime consent before any notification is shown.
    // Without it the ongoing VPN notification is silently dropped, which on a
    // phone means no status in the shade and no way to disconnect once the app
    // is swiped away — the tunnel keeps running invisibly.
    private val notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { /* Declined is survivable: the tunnel still works, just silently. */ }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        requestNotificationPermissionIfNeeded()

        setContent {
            VpnClientTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    val viewModel = vpnViewModel

                    val navController = rememberNavController()
                    val isLoggedIn by viewModel.isLoggedIn.collectAsState()

                    // If the session is invalidated while inside the app (e.g. the
                    // SSO session token expired), return to the login screen.
                    LaunchedEffect(isLoggedIn) {
                        if (!isLoggedIn &&
                            navController.currentDestination?.route != null &&
                            navController.currentDestination?.route != "login"
                        ) {
                            navController.navigate("login") {
                                popUpTo(0) { inclusive = true }
                            }
                        }
                    }

                    NavHost(
                        navController = navController,
                        startDestination = if (isLoggedIn) "main" else "login"
                    ) {
                        composable("login") {
                            LoginScreen(
                                viewModel = viewModel,
                                onLoginSuccess = {
                                    navController.navigate("main") {
                                        popUpTo("login") { inclusive = true }
                                    }
                                }
                            )
                        }

                        composable("main") {
                            MainScreen(
                                viewModel = viewModel,
                                onConnectClick = { requestVpnPermissionAndConnect() },
                                onDisconnectClick = { stopVpnService() },
                                onSettingsClick = { navController.navigate("settings") },
                                onLogoutClick = {
                                    viewModel.logout()
                                    navController.navigate("login") {
                                        popUpTo("main") { inclusive = true }
                                    }
                                }
                            )
                        }

                        composable("settings") {
                            SettingsScreen(
                                viewModel = viewModel,
                                onBackClick = { navController.popBackStack() }
                            )
                        }
                    }
                }
            }
        }
    }

    override fun onStart() {
        super.onStart()

        // Scoped to the visible lifetime: a backgrounded activity has no UI to
        // update, so there is no reason to keep waking it for stats broadcasts.
        val filter = IntentFilter().apply {
            addAction("com.vpn.client.VPN_CONNECTED")
            addAction("com.vpn.client.VPN_ERROR")
            addAction("com.vpn.client.VPN_DISCONNECTED")
            addAction("com.vpn.client.VPN_RECONNECTING")
            addAction("com.vpn.client.VPN_STATS")
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(vpnBroadcastReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            registerReceiver(vpnBroadcastReceiver, filter)
        }

        // The VpnService keeps running while the app is away, so whatever
        // happened in the meantime is picked up here rather than leaving the UI
        // showing stale state (or Disconnected over a live tunnel).
        syncWithService()
    }

    override fun onStop() {
        super.onStop()
        try {
            unregisterReceiver(vpnBroadcastReceiver)
        } catch (e: IllegalArgumentException) {
            // Already unregistered.
        }
    }

    /** Re-applies the service's live state to the UI. */
    private fun syncWithService() {
        val live = MyVpnService.liveState
        val reconnectAttempt = MyVpnService.liveReconnectAttempt
        if (live != null && reconnectAttempt > 0) {
            // The service is mid-reconnect — show that, not a stale Connected.
            vpnViewModel.onVpnReconnecting(reconnectAttempt)
        } else if (live != null) {
            vpnViewModel.onVpnConnected(
                assignedIp = live.assignedIp,
                gateway = live.gateway,
                dns = live.dns,
                mtu = live.mtu,
                connectedSinceElapsedMs = live.connectedSinceElapsedMs
            )
            vpnViewModel.updateTrafficStats(
                MyVpnService.liveBytesReceived,
                MyVpnService.liveBytesSent
            )
        } else if (vpnViewModel.connectionState.value == VpnConnectionState.CONNECTED ||
            vpnViewModel.connectionState.value == VpnConnectionState.RECONNECTING
        ) {
            // Tunnel went down while we were in the background.
            vpnViewModel.onVpnDisconnected()
        }
    }

    private fun requestNotificationPermissionIfNeeded() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
            == PackageManager.PERMISSION_GRANTED
        ) {
            return
        }
        notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
    }

    private fun requestVpnPermissionAndConnect() {
        val intent = VpnService.prepare(this)
        if (intent != null) {
            vpnPermissionLauncher.launch(intent)
        } else {
            startVpnService()
        }
    }

    private fun startVpnService() {
        val serviceIntent = Intent(this, MyVpnService::class.java).apply {
            action = MyVpnService.ACTION_CONNECT
            putExtra(MyVpnService.EXTRA_SERVER_ADDRESS, vpnViewModel.serverAddress.value)
            putExtra(MyVpnService.EXTRA_SERVER_PORT, vpnViewModel.serverPort.value)
            putExtra(MyVpnService.EXTRA_AUTO_RECONNECT, vpnViewModel.autoReconnect.value)
            putExtra(MyVpnService.EXTRA_DISCONNECT_NOTIFY, vpnViewModel.disconnectNotify.value)
            if (vpnViewModel.authMode.value == VpnViewModel.AUTH_MODE_SSO) {
                // SSO: reconnect with the stored 30-day session token. The
                // server rotates it on every auth (the service persists the
                // rotation), so always read the freshest value.
                putExtra(MyVpnService.EXTRA_AUTH_TYPE, MyVpnService.AUTH_TYPE_SESSION)
                putExtra(MyVpnService.EXTRA_TOKEN, vpnViewModel.latestSessionToken())
            } else {
                putExtra(MyVpnService.EXTRA_USERNAME, vpnViewModel.username.value)
                putExtra(MyVpnService.EXTRA_PASSWORD, vpnViewModel.password.value)
            }
        }
        startForegroundService(serviceIntent)
        vpnViewModel.onVpnConnecting()
    }

    private fun stopVpnService() {
        val serviceIntent = Intent(this, MyVpnService::class.java).apply {
            action = MyVpnService.ACTION_DISCONNECT
        }
        startService(serviceIntent)
        vpnViewModel.onVpnDisconnected()
    }

}
