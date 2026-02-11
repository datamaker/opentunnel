package com.vpn.client

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import com.vpn.client.service.MyVpnService
import com.vpn.client.ui.screens.LoginScreen
import com.vpn.client.ui.screens.MainScreen
import com.vpn.client.ui.screens.SettingsScreen
import com.vpn.client.ui.theme.VpnClientTheme
import com.vpn.client.viewmodel.VpnViewModel

class MainActivity : ComponentActivity() {

    private lateinit var vpnViewModel: VpnViewModel

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

        setContent {
            VpnClientTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    val viewModel: VpnViewModel = viewModel()
                    vpnViewModel = viewModel

                    val navController = rememberNavController()
                    val isLoggedIn by viewModel.isLoggedIn.collectAsState()

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
            putExtra(MyVpnService.EXTRA_SESSION_TOKEN, vpnViewModel.sessionToken.value)
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
