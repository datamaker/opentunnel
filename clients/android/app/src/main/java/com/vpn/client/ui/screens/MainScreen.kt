package com.vpn.client.ui.screens

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.vpn.client.viewmodel.VpnConnectionState
import com.vpn.client.viewmodel.VpnViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MainScreen(
    viewModel: VpnViewModel,
    onConnectClick: () -> Unit,
    onDisconnectClick: () -> Unit,
    onSettingsClick: () -> Unit,
    onLogoutClick: () -> Unit
) {
    val connectionState by viewModel.connectionState.collectAsState()
    val assignedIp by viewModel.assignedIp.collectAsState()
    val bytesReceived by viewModel.bytesReceived.collectAsState()
    val bytesSent by viewModel.bytesSent.collectAsState()
    val connectionDuration by viewModel.connectionDuration.collectAsState()

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("VPN Client") },
                actions = {
                    IconButton(onClick = onSettingsClick) {
                        Icon(Icons.Default.Settings, contentDescription = "Settings")
                    }
                    IconButton(onClick = onLogoutClick) {
                        Icon(Icons.Default.Logout, contentDescription = "Logout")
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
                .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Spacer(modifier = Modifier.height(32.dp))

            // Connection Button
            ConnectionButton(
                connectionState = connectionState,
                onConnectClick = onConnectClick,
                onDisconnectClick = onDisconnectClick
            )

            Spacer(modifier = Modifier.height(32.dp))

            // Status Text
            ConnectionStatusText(connectionState = connectionState)

            Spacer(modifier = Modifier.height(48.dp))

            // Connection Info Card
            if (connectionState == VpnConnectionState.CONNECTED) {
                ConnectionInfoCard(
                    assignedIp = assignedIp,
                    bytesReceived = bytesReceived,
                    bytesSent = bytesSent,
                    duration = connectionDuration
                )
            }

            Spacer(modifier = Modifier.weight(1f))

            // Server Info
            ServerInfoCard(viewModel = viewModel)
        }
    }
}

@Composable
private fun ConnectionButton(
    connectionState: VpnConnectionState,
    onConnectClick: () -> Unit,
    onDisconnectClick: () -> Unit
) {
    val isConnected = connectionState == VpnConnectionState.CONNECTED
    val isConnecting = connectionState == VpnConnectionState.CONNECTING

    val buttonColor by animateColorAsState(
        targetValue = when (connectionState) {
            VpnConnectionState.CONNECTED -> MaterialTheme.colorScheme.primary
            VpnConnectionState.CONNECTING -> MaterialTheme.colorScheme.tertiary
            VpnConnectionState.DISCONNECTED -> MaterialTheme.colorScheme.surfaceVariant
            VpnConnectionState.ERROR -> MaterialTheme.colorScheme.error
        },
        animationSpec = tween(300),
        label = "buttonColor"
    )

    val scale by animateFloatAsState(
        targetValue = if (isConnecting) 0.95f else 1f,
        animationSpec = tween(300),
        label = "scale"
    )

    Box(
        modifier = Modifier
            .size(200.dp)
            .scale(scale)
            .clip(CircleShape)
            .background(
                brush = Brush.radialGradient(
                    colors = listOf(
                        buttonColor,
                        buttonColor.copy(alpha = 0.7f)
                    )
                )
            ),
        contentAlignment = Alignment.Center
    ) {
        FilledIconButton(
            onClick = {
                when (connectionState) {
                    VpnConnectionState.CONNECTED -> onDisconnectClick()
                    VpnConnectionState.DISCONNECTED, VpnConnectionState.ERROR -> onConnectClick()
                    VpnConnectionState.CONNECTING -> { /* Do nothing while connecting */ }
                }
            },
            modifier = Modifier.size(180.dp),
            colors = IconButtonDefaults.filledIconButtonColors(
                containerColor = Color.Transparent
            ),
            enabled = !isConnecting
        ) {
            Icon(
                imageVector = if (isConnected) Icons.Default.Shield else Icons.Outlined.Shield,
                contentDescription = "VPN Status",
                modifier = Modifier.size(80.dp),
                tint = MaterialTheme.colorScheme.onPrimary
            )
        }
    }
}

@Composable
private fun ConnectionStatusText(connectionState: VpnConnectionState) {
    val statusText = when (connectionState) {
        VpnConnectionState.CONNECTED -> "Connected"
        VpnConnectionState.CONNECTING -> "Connecting..."
        VpnConnectionState.DISCONNECTED -> "Not Connected"
        VpnConnectionState.ERROR -> "Connection Error"
    }

    val statusColor = when (connectionState) {
        VpnConnectionState.CONNECTED -> MaterialTheme.colorScheme.primary
        VpnConnectionState.CONNECTING -> MaterialTheme.colorScheme.tertiary
        VpnConnectionState.DISCONNECTED -> MaterialTheme.colorScheme.onSurfaceVariant
        VpnConnectionState.ERROR -> MaterialTheme.colorScheme.error
    }

    Text(
        text = statusText,
        style = MaterialTheme.typography.headlineMedium,
        fontWeight = FontWeight.Bold,
        color = statusColor
    )

    if (connectionState == VpnConnectionState.DISCONNECTED) {
        Spacer(modifier = Modifier.height(8.dp))
        Text(
            text = "Tap the button to connect",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

@Composable
private fun ConnectionInfoCard(
    assignedIp: String,
    bytesReceived: Long,
    bytesSent: Long,
    duration: String
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant
        )
    ) {
        Column(
            modifier = Modifier.padding(20.dp)
        ) {
            Text(
                text = "Connection Details",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold
            )

            Spacer(modifier = Modifier.height(16.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                InfoItem(
                    icon = Icons.Outlined.Language,
                    label = "IP Address",
                    value = assignedIp
                )
                InfoItem(
                    icon = Icons.Outlined.Timer,
                    label = "Duration",
                    value = duration
                )
            }

            Spacer(modifier = Modifier.height(16.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                InfoItem(
                    icon = Icons.Outlined.ArrowDownward,
                    label = "Downloaded",
                    value = formatBytes(bytesReceived)
                )
                InfoItem(
                    icon = Icons.Outlined.ArrowUpward,
                    label = "Uploaded",
                    value = formatBytes(bytesSent)
                )
            }
        }
    }
}

@Composable
private fun InfoItem(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    label: String,
    value: String
) {
    Row(
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(
            imageVector = icon,
            contentDescription = null,
            modifier = Modifier.size(20.dp),
            tint = MaterialTheme.colorScheme.primary
        )
        Spacer(modifier = Modifier.width(8.dp))
        Column {
            Text(
                text = label,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Text(
                text = value,
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.Medium
            )
        }
    }
}

@Composable
private fun ServerInfoCard(viewModel: VpnViewModel) {
    val serverAddress by viewModel.serverAddress.collectAsState()
    val serverPort by viewModel.serverPort.collectAsState()

    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surface
        )
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                imageVector = Icons.Default.Dns,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary
            )
            Spacer(modifier = Modifier.width(12.dp))
            Column {
                Text(
                    text = "Server",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Text(
                    text = "$serverAddress:$serverPort",
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.Medium
                )
            }
        }
    }
}

private fun formatBytes(bytes: Long): String {
    return when {
        bytes < 1024 -> "$bytes B"
        bytes < 1024 * 1024 -> String.format("%.1f KB", bytes / 1024.0)
        bytes < 1024 * 1024 * 1024 -> String.format("%.1f MB", bytes / (1024.0 * 1024))
        else -> String.format("%.2f GB", bytes / (1024.0 * 1024 * 1024))
    }
}
