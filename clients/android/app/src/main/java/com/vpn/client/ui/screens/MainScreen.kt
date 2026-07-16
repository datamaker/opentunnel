package com.vpn.client.ui.screens

import androidx.compose.animation.core.animateDpAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.vpn.client.viewmodel.VpnConnectionState
import com.vpn.client.viewmodel.VpnViewModel

// Brand gradient: blue -> cyan (iOS parity)
private val BrandGradient = Brush.linearGradient(
    colors = listOf(Color(0xFF007AFF), Color(0xFF32ADE6))
)

// iOS status color palette
private val StatusGreen = Color(0xFF34C759)
private val StatusOrange = Color(0xFFFF9500)
private val StatusGray = Color(0xFF8E8E93)
private val StatusRed = Color(0xFFFF3B30)
private val StatDownBlue = Color(0xFF007AFF)
private val StatUpGreen = Color(0xFF34C759)

@Composable
fun MainScreen(
    viewModel: VpnViewModel,
    onConnectClick: () -> Unit,
    onDisconnectClick: () -> Unit,
    onSettingsClick: () -> Unit,
    onLogoutClick: () -> Unit
) {
    val connectionState by viewModel.connectionState.collectAsState()
    val username by viewModel.username.collectAsState()
    val serverAddress by viewModel.serverAddress.collectAsState()
    val serverPort by viewModel.serverPort.collectAsState()
    val assignedIp by viewModel.assignedIp.collectAsState()
    val bytesReceived by viewModel.bytesReceived.collectAsState()
    val bytesSent by viewModel.bytesSent.collectAsState()
    val connectionDuration by viewModel.connectionDuration.collectAsState()

    val isConnected = connectionState == VpnConnectionState.CONNECTED
    val scrollState = rememberScrollState()

    Column(modifier = Modifier.fillMaxSize()) {
        // ---- Header ----
        Header(
            username = username,
            onSettingsClick = onSettingsClick,
            onLogoutClick = onLogoutClick
        )

        // ---- Scrollable content ----
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(scrollState)
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(24.dp)
        ) {
            ConnectionStatusCard(connectionState = connectionState)

            if (isConnected) {
                ConnectionDetailsCard(
                    serverAddress = "$serverAddress:$serverPort",
                    assignedIp = assignedIp.ifBlank { "—" }
                )

                StatisticsCard(
                    duration = connectionDuration,
                    bytesReceived = bytesReceived,
                    bytesSent = bytesSent
                )
            }

            ConnectionButton(
                connectionState = connectionState,
                onConnectClick = onConnectClick,
                onDisconnectClick = onDisconnectClick
            )

            Spacer(modifier = Modifier.height(8.dp))
        }
    }
}

@Composable
private fun Header(
    username: String,
    onSettingsClick: () -> Unit,
    onLogoutClick: () -> Unit
) {
    Surface(color = MaterialTheme.colorScheme.surface) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = "OpenTunnel",
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold
                )
                Text(
                    text = username.ifBlank { "Not signed in" },
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            IconButton(onClick = onSettingsClick) {
                Icon(Icons.Filled.Settings, contentDescription = "Settings")
            }
            IconButton(onClick = onLogoutClick) {
                Icon(Icons.Filled.Logout, contentDescription = "Logout")
            }
        }
    }
}

@Composable
private fun ConnectionStatusCard(connectionState: VpnConnectionState) {
    val isConnecting = connectionState == VpnConnectionState.CONNECTING

    val statusColor = when (connectionState) {
        VpnConnectionState.CONNECTED -> StatusGreen
        VpnConnectionState.CONNECTING -> StatusOrange
        VpnConnectionState.DISCONNECTED -> StatusGray
        VpnConnectionState.ERROR -> StatusRed
    }

    val statusIcon = when (connectionState) {
        VpnConnectionState.CONNECTED -> Icons.Filled.Check
        VpnConnectionState.CONNECTING -> Icons.Filled.MoreHoriz
        VpnConnectionState.DISCONNECTED -> Icons.Filled.Close
        VpnConnectionState.ERROR -> Icons.Filled.PriorityHigh
    }

    val statusTitle = when (connectionState) {
        VpnConnectionState.CONNECTED -> "Connected"
        VpnConnectionState.CONNECTING -> "Connecting..."
        VpnConnectionState.DISCONNECTED -> "Disconnected"
        VpnConnectionState.ERROR -> "Connection Error"
    }

    val statusDescription = when (connectionState) {
        VpnConnectionState.CONNECTED -> "Your connection is secure"
        VpnConnectionState.CONNECTING -> "Establishing secure tunnel..."
        VpnConnectionState.DISCONNECTED -> "Tap Connect to secure your connection"
        VpnConnectionState.ERROR -> "Something went wrong. Please try again."
    }

    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surface
        ),
        elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = 32.dp, horizontal = 16.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            // Concentric circles with centered status indicator
            val outerSize by animateDpAsState(targetValue = 120.dp, animationSpec = tween(300), label = "outer")
            Box(
                modifier = Modifier.size(outerSize),
                contentAlignment = Alignment.Center
            ) {
                Box(
                    modifier = Modifier
                        .size(120.dp)
                        .clip(CircleShape)
                        .background(statusColor.copy(alpha = 0.2f))
                )
                Box(
                    modifier = Modifier
                        .size(90.dp)
                        .clip(CircleShape)
                        .background(statusColor.copy(alpha = 0.4f))
                )
                Box(
                    modifier = Modifier
                        .size(60.dp)
                        .clip(CircleShape)
                        .background(statusColor),
                    contentAlignment = Alignment.Center
                ) {
                    if (isConnecting) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(28.dp),
                            color = Color.White,
                            strokeWidth = 2.5.dp
                        )
                    } else {
                        Icon(
                            imageVector = statusIcon,
                            contentDescription = null,
                            tint = Color.White,
                            modifier = Modifier.size(28.dp)
                        )
                    }
                }
            }

            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                Text(
                    text = statusTitle,
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.SemiBold
                )
                Text(
                    text = statusDescription,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    textAlign = TextAlign.Center
                )
            }
        }
    }
}

@Composable
private fun ConnectionDetailsCard(
    serverAddress: String,
    assignedIp: String
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surface
        ),
        elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                text = "Connection Details",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold
            )
            Spacer(modifier = Modifier.height(12.dp))
            Divider()
            Spacer(modifier = Modifier.height(12.dp))

            DetailRow(title = "Server", value = serverAddress)
            Spacer(modifier = Modifier.height(12.dp))
            DetailRow(title = "Assigned IP", value = assignedIp)
        }
    }
}

@Composable
private fun DetailRow(title: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            text = title,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Text(
            text = value,
            style = MaterialTheme.typography.bodyMedium,
            fontWeight = FontWeight.Medium
        )
    }
}

@Composable
private fun StatisticsCard(
    duration: String,
    bytesReceived: Long,
    bytesSent: Long
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surface
        ),
        elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "Statistics",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold
                )
                Text(
                    text = duration,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            Spacer(modifier = Modifier.height(12.dp))
            Divider()
            Spacer(modifier = Modifier.height(16.dp))

            Row(modifier = Modifier.fillMaxWidth()) {
                StatisticItem(
                    icon = Icons.Filled.ArrowCircleDown,
                    title = "Downloaded",
                    value = formatBytes(bytesReceived),
                    color = StatDownBlue,
                    modifier = Modifier.weight(1f)
                )
                StatisticItem(
                    icon = Icons.Filled.ArrowCircleUp,
                    title = "Uploaded",
                    value = formatBytes(bytesSent),
                    color = StatUpGreen,
                    modifier = Modifier.weight(1f)
                )
            }
        }
    }
}

@Composable
private fun StatisticItem(
    icon: ImageVector,
    title: String,
    value: String,
    color: Color,
    modifier: Modifier = Modifier
) {
    Column(
        modifier = modifier,
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        Icon(
            imageVector = icon,
            contentDescription = null,
            tint = color,
            modifier = Modifier.size(28.dp)
        )
        Text(
            text = value,
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.SemiBold
        )
        Text(
            text = title,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
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

    val buttonTitle = when (connectionState) {
        VpnConnectionState.CONNECTED -> "Disconnect"
        VpnConnectionState.CONNECTING -> "Connecting..."
        VpnConnectionState.DISCONNECTED -> "Connect"
        VpnConnectionState.ERROR -> "Connect"
    }

    // Background: red when connected, gradient (blue->cyan) otherwise
    val backgroundModifier = if (isConnected) {
        Modifier.background(StatusRed, RoundedCornerShape(12.dp))
    } else if (!isConnecting) {
        Modifier.background(BrandGradient, RoundedCornerShape(12.dp))
    } else {
        Modifier
    }

    Button(
        onClick = {
            when (connectionState) {
                VpnConnectionState.CONNECTED -> onDisconnectClick()
                VpnConnectionState.DISCONNECTED, VpnConnectionState.ERROR -> onConnectClick()
                VpnConnectionState.CONNECTING -> { /* disabled */ }
            }
        },
        modifier = Modifier
            .fillMaxWidth()
            .height(56.dp)
            .then(backgroundModifier),
        enabled = !isConnecting,
        colors = ButtonDefaults.buttonColors(containerColor = Color.Transparent),
        shape = RoundedCornerShape(12.dp)
    ) {
        if (isConnecting) {
            CircularProgressIndicator(
                modifier = Modifier.size(22.dp),
                color = Color.White,
                strokeWidth = 2.dp
            )
            Spacer(modifier = Modifier.width(12.dp))
        } else {
            Icon(
                imageVector = if (isConnected) Icons.Filled.Stop else Icons.Filled.PlayArrow,
                contentDescription = null,
                tint = Color.White,
                modifier = Modifier.size(22.dp)
            )
            Spacer(modifier = Modifier.width(12.dp))
        }
        Text(
            text = buttonTitle,
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.SemiBold,
            color = Color.White
        )
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
