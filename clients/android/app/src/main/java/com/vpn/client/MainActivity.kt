package com.vpn.client

import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.Surface
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.lifecycle.viewmodel.compose.viewModel
import com.vpn.client.service.MyVpnService
import com.vpn.client.ui.screens.VpnScreen
import com.vpn.client.ui.theme.VpnClientTheme
import com.vpn.client.viewmodel.VpnViewModel

class MainActivity : ComponentActivity() {

    private lateinit var vpnViewModel: VpnViewModel

    private val vpnBroadcastReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            Log.d("MainActivity", "Received broadcast: ${intent?.action}")
            when (intent?.action) {
                "com.vpn.client.VPN_CONNECTED" -> {
                    val assignedIp = intent.getStringExtra("assigned_ip") ?: ""
                    Log.d("MainActivity", "VPN Connected with IP: $assignedIp")
                    vpnViewModel.onVpnConnected(assignedIp)
                }
                "com.vpn.client.VPN_ERROR" -> {
                    val errorMessage = intent.getStringExtra("error_message") ?: "Connection failed"
                    Log.d("MainActivity", "VPN Error: $errorMessage")
                    vpnViewModel.onVpnError(errorMessage)
                }
                "com.vpn.client.VPN_DISCONNECTED" -> {
                    Log.d("MainActivity", "VPN Disconnected")
                    vpnViewModel.onVpnDisconnected()
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

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Draw edge-to-edge so Compose receives IME (keyboard) insets and can lift the content
        androidx.core.view.WindowCompat.setDecorFitsSystemWindows(window, false)

        // Register broadcast receiver for VPN events
        val filter = IntentFilter().apply {
            addAction("com.vpn.client.VPN_CONNECTED")
            addAction("com.vpn.client.VPN_ERROR")
            addAction("com.vpn.client.VPN_DISCONNECTED")
            addAction("com.vpn.client.VPN_STATS")
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(vpnBroadcastReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            registerReceiver(vpnBroadcastReceiver, filter)
        }

        setContent {
            VpnClientTheme(darkTheme = true) {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = Color.Black
                ) {
                    val viewModel: VpnViewModel = viewModel()
                    vpnViewModel = viewModel

                    VpnScreen(
                        viewModel = viewModel,
                        onConnectRequest = { requestVpnPermissionAndConnect() },
                        onDisconnect = { stopVpnService() }
                    )
                }
            }
        }
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
            putExtra(MyVpnService.EXTRA_USERNAME, vpnViewModel.username.value)
            putExtra(MyVpnService.EXTRA_PASSWORD, vpnViewModel.password.value)
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

    override fun onDestroy() {
        super.onDestroy()
        try {
            unregisterReceiver(vpnBroadcastReceiver)
        } catch (e: Exception) {
            // Receiver might not be registered
        }
    }
}
