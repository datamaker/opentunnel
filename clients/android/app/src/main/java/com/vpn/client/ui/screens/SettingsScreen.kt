package com.vpn.client.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import com.vpn.client.viewmodel.VpnViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    viewModel: VpnViewModel,
    onBackClick: () -> Unit
) {
    val serverAddress by viewModel.serverAddress.collectAsState()
    val serverPort by viewModel.serverPort.collectAsState()
    val autoReconnect by viewModel.autoReconnect.collectAsState()
    val killSwitch by viewModel.killSwitch.collectAsState()
    val splitTunneling by viewModel.splitTunneling.collectAsState()

    var editedServerAddress by remember { mutableStateOf(serverAddress) }
    var editedServerPort by remember { mutableStateOf(serverPort.toString()) }

    val scrollState = rememberScrollState()

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Settings") },
                navigationIcon = {
                    IconButton(onClick = onBackClick) {
                        Icon(Icons.Default.ArrowBack, contentDescription = "Back")
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface
                )
            )
        }
    ) { paddingValues ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
                .verticalScroll(scrollState)
                .padding(16.dp)
        ) {
            // Server Settings Section
            SettingsSection(title = "Server Configuration") {
                OutlinedTextField(
                    value = editedServerAddress,
                    onValueChange = { editedServerAddress = it },
                    label = { Text("Server Address") },
                    leadingIcon = {
                        Icon(Icons.Outlined.Dns, contentDescription = null)
                    },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(12.dp)
                )

                Spacer(modifier = Modifier.height(12.dp))

                OutlinedTextField(
                    value = editedServerPort,
                    onValueChange = { editedServerPort = it.filter { c -> c.isDigit() } },
                    label = { Text("Port") },
                    leadingIcon = {
                        Icon(Icons.Outlined.Numbers, contentDescription = null)
                    },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    shape = RoundedCornerShape(12.dp)
                )

                Spacer(modifier = Modifier.height(16.dp))

                Button(
                    onClick = {
                        viewModel.updateServerSettings(
                            editedServerAddress,
                            editedServerPort.toIntOrNull() ?: 443
                        )
                    },
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(12.dp),
                    enabled = editedServerAddress != serverAddress ||
                            editedServerPort != serverPort.toString()
                ) {
                    Icon(Icons.Default.Save, contentDescription = null)
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Save Server Settings")
                }
            }

            Spacer(modifier = Modifier.height(24.dp))

            // Connection Settings Section
            SettingsSection(title = "Connection") {
                SettingsSwitch(
                    title = "Auto Reconnect",
                    description = "Automatically reconnect when connection is lost",
                    icon = Icons.Outlined.Refresh,
                    checked = autoReconnect,
                    onCheckedChange = { viewModel.setAutoReconnect(it) }
                )

                HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))

                SettingsSwitch(
                    title = "Kill Switch",
                    description = "Block internet access when VPN disconnects",
                    icon = Icons.Outlined.Block,
                    checked = killSwitch,
                    onCheckedChange = { viewModel.setKillSwitch(it) }
                )

                HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))

                SettingsSwitch(
                    title = "Split Tunneling",
                    description = "Allow some apps to bypass the VPN",
                    icon = Icons.Outlined.CallSplit,
                    checked = splitTunneling,
                    onCheckedChange = { viewModel.setSplitTunneling(it) }
                )
            }

            Spacer(modifier = Modifier.height(24.dp))

            // Protocol Section
            SettingsSection(title = "Security") {
                SettingsInfoRow(
                    title = "Protocol",
                    value = "TLS 1.3",
                    icon = Icons.Outlined.Security
                )

                HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))

                SettingsInfoRow(
                    title = "Encryption",
                    value = "AES-256-GCM",
                    icon = Icons.Outlined.Lock
                )

                HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))

                SettingsInfoRow(
                    title = "Authentication",
                    value = "Username/Password",
                    icon = Icons.Outlined.Key
                )
            }

            Spacer(modifier = Modifier.height(24.dp))

            // About Section
            SettingsSection(title = "About") {
                SettingsInfoRow(
                    title = "Version",
                    value = "1.0.0",
                    icon = Icons.Outlined.Info
                )

                HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))

                SettingsInfoRow(
                    title = "Platform",
                    value = "Android",
                    icon = Icons.Outlined.PhoneAndroid
                )
            }

            Spacer(modifier = Modifier.height(32.dp))
        }
    }
}

@Composable
private fun SettingsSection(
    title: String,
    content: @Composable ColumnScope.() -> Unit
) {
    Text(
        text = title,
        style = MaterialTheme.typography.titleSmall,
        fontWeight = FontWeight.SemiBold,
        color = MaterialTheme.colorScheme.primary,
        modifier = Modifier.padding(bottom = 12.dp, start = 4.dp)
    )

    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surface
        ),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            content = content
        )
    }
}

@Composable
private fun SettingsSwitch(
    title: String,
    description: String,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(
            imageVector = icon,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.primary,
            modifier = Modifier.size(24.dp)
        )

        Spacer(modifier = Modifier.width(16.dp))

        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = title,
                style = MaterialTheme.typography.bodyLarge,
                fontWeight = FontWeight.Medium
            )
            Text(
                text = description,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }

        Switch(
            checked = checked,
            onCheckedChange = onCheckedChange
        )
    }
}

@Composable
private fun SettingsInfoRow(
    title: String,
    value: String,
    icon: androidx.compose.ui.graphics.vector.ImageVector
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(
            imageVector = icon,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.primary,
            modifier = Modifier.size(24.dp)
        )

        Spacer(modifier = Modifier.width(16.dp))

        Text(
            text = title,
            style = MaterialTheme.typography.bodyLarge,
            fontWeight = FontWeight.Medium,
            modifier = Modifier.weight(1f)
        )

        Text(
            text = value,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}
