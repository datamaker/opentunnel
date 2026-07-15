package com.vpn.client.ui.screens

import android.content.Context
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.vpn.client.viewmodel.VpnConnectionState
import com.vpn.client.viewmodel.VpnViewModel

// Colors from the iOS/macOS "VPN Client" screen (dark theme)
private val Bg = androidx.compose.ui.graphics.Color(0xFF000000)
private val TextPrimary = androidx.compose.ui.graphics.Color(0xFFFFFFFF)
private val TextSecondary = androidx.compose.ui.graphics.Color(0xFF8E8E93)
private val Green = androidx.compose.ui.graphics.Color(0xFF34C759)
private val Blue = androidx.compose.ui.graphics.Color(0xFF007AFF)
private val Red = androidx.compose.ui.graphics.Color(0xFFFF3B30)
private val FieldBg = androidx.compose.ui.graphics.Color(0xFF1C1C1E)
private val FieldBorder = androidx.compose.ui.graphics.Color(0xFF38383A)

/**
 * Single-screen VPN client UI mirroring the iOS/macOS ContentView:
 * a login form + Connect when disconnected, an info card + Disconnect when connected.
 * Entered values are persisted to SharedPreferences so they survive app restarts.
 * Content is centered in the space above the keyboard (imePadding), so the Connect
 * button keeps a gap from the keyboard instead of being glued to it.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun VpnScreen(
    viewModel: VpnViewModel,
    onConnectRequest: () -> Unit,
    onDisconnect: () -> Unit
) {
    val connectionState by viewModel.connectionState.collectAsState()
    val isLoggingIn by viewModel.isLoggingIn.collectAsState()
    val loginError by viewModel.loginError.collectAsState()
    val username by viewModel.username.collectAsState()
    val serverAddress by viewModel.serverAddress.collectAsState()
    val serverPort by viewModel.serverPort.collectAsState()
    val assignedIp by viewModel.assignedIp.collectAsState()
    val bytesReceived by viewModel.bytesReceived.collectAsState()
    val bytesSent by viewModel.bytesSent.collectAsState()
    val duration by viewModel.connectionDuration.collectAsState()

    // Persist entered values across app restarts
    val context = LocalContext.current
    val prefs = remember { context.getSharedPreferences("vpn_prefs", Context.MODE_PRIVATE) }
    var server by remember { mutableStateOf(prefs.getString("server", "vpn.cacheby.com:1194") ?: "vpn.cacheby.com:1194") }
    var user by remember { mutableStateOf(prefs.getString("user", "") ?: "") }
    var pass by remember { mutableStateOf(prefs.getString("pass", "") ?: "") }

    fun save(key: String, value: String) = prefs.edit().putString(key, value).apply()

    // After a successful login, automatically start the tunnel (one Connect tap, like iOS)
    LaunchedEffect(Unit) {
        viewModel.loginSuccess.collect { onConnectRequest() }
    }

    val isConnected = connectionState == VpnConnectionState.CONNECTED
    val connecting = isLoggingIn || connectionState == VpnConnectionState.CONNECTING

    val statusText = when {
        connecting -> "Connecting..."
        isConnected -> "Connected"
        connectionState == VpnConnectionState.ERROR -> "Error"
        else -> "Disconnected"
    }

    Box(modifier = Modifier.fillMaxSize().background(Bg)) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .systemBarsPadding()
                .imePadding()
                .padding(horizontal = 24.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Spacer(Modifier.weight(1f))

            // Header: lock-in-shield + "VPN Client" + status
            Row(verticalAlignment = Alignment.CenterVertically) {
                LockShield(connected = isConnected, size = 44.dp)
                Spacer(Modifier.width(12.dp))
                Column {
                    Text("VPN Client", color = TextPrimary, fontSize = 22.sp, fontWeight = FontWeight.Bold)
                    Text(statusText, color = TextSecondary, fontSize = 13.sp)
                }
            }

            Spacer(Modifier.height(20.dp))
            HorizontalDivider(color = FieldBorder)
            Spacer(Modifier.height(24.dp))

            if (isConnected) {
                ConnectedCard(
                    server = "$serverAddress:$serverPort",
                    username = username,
                    assignedIp = assignedIp,
                    duration = duration,
                    bytesReceived = bytesReceived,
                    bytesSent = bytesSent
                )
                Spacer(Modifier.height(24.dp))
                Button(
                    onClick = onDisconnect,
                    shape = RoundedCornerShape(20.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = Red.copy(alpha = 0.15f),
                        contentColor = Red
                    )
                ) {
                    Text("Disconnect", fontSize = 16.sp, fontWeight = FontWeight.SemiBold)
                }
            } else {
                DarkField(
                    value = server,
                    onValueChange = { server = it; save("server", it) },
                    placeholder = "Server (host:port)"
                )
                Spacer(Modifier.height(12.dp))
                DarkField(
                    value = user,
                    onValueChange = { user = it; save("user", it) },
                    placeholder = "Username",
                    keyboardType = KeyboardType.Email
                )
                Spacer(Modifier.height(12.dp))
                DarkField(
                    value = pass,
                    onValueChange = { pass = it; save("pass", it) },
                    placeholder = "Password",
                    isPassword = true
                )
                Spacer(Modifier.height(16.dp))

                val canConnect = server.isNotBlank() && user.isNotBlank() && pass.isNotBlank() && !connecting
                Button(
                    onClick = {
                        val (host, port) = parseHostPort(server)
                        viewModel.login(user, pass, host, port)
                    },
                    enabled = canConnect,
                    modifier = Modifier.fillMaxWidth().height(50.dp),
                    shape = RoundedCornerShape(14.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = Blue,
                        contentColor = TextPrimary,
                        disabledContainerColor = Blue.copy(alpha = 0.4f),
                        disabledContentColor = TextPrimary.copy(alpha = 0.6f)
                    )
                ) {
                    if (connecting) {
                        CircularProgressIndicator(modifier = Modifier.size(20.dp), color = TextPrimary, strokeWidth = 2.dp)
                        Spacer(Modifier.width(8.dp))
                        Text("Connecting...", fontSize = 16.sp, fontWeight = FontWeight.SemiBold)
                    } else {
                        Text("Connect", fontSize = 16.sp, fontWeight = FontWeight.SemiBold)
                    }
                }
            }

            if (loginError != null && !isConnected) {
                Spacer(Modifier.height(16.dp))
                Text(
                    text = loginError ?: "",
                    color = Red,
                    fontSize = 13.sp,
                    textAlign = TextAlign.Center
                )
            }

            Spacer(Modifier.weight(1f))
        }
    }
}

/**
 * Custom-drawn "lock.shield" mark approximating the iOS SF Symbol:
 * a filled shield with a lock (body + shackle) knocked out in the contrast color.
 */
@Composable
private fun LockShield(connected: Boolean, size: Dp) {
    val shieldColor = if (connected) Green else TextSecondary
    val lockColor = if (connected) Color.White else Bg
    Canvas(modifier = Modifier.size(size)) {
        val w = this.size.width
        val h = this.size.height

        // Shield
        val shield = Path().apply {
            moveTo(w * 0.5f, h * 0.05f)
            lineTo(w * 0.13f, h * 0.19f)
            lineTo(w * 0.13f, h * 0.49f)
            cubicTo(w * 0.13f, h * 0.73f, w * 0.29f, h * 0.90f, w * 0.5f, h * 0.97f)
            cubicTo(w * 0.71f, h * 0.90f, w * 0.87f, h * 0.73f, w * 0.87f, h * 0.49f)
            lineTo(w * 0.87f, h * 0.19f)
            close()
        }
        drawPath(shield, shieldColor)

        // Lock shackle (open half-ring above the body)
        val shackleStroke = w * 0.05f
        drawArc(
            color = lockColor,
            startAngle = 180f,
            sweepAngle = 180f,
            useCenter = false,
            topLeft = Offset(w * 0.40f, h * 0.34f),
            size = Size(w * 0.20f, h * 0.20f),
            style = Stroke(width = shackleStroke)
        )

        // Lock body
        drawRoundRect(
            color = lockColor,
            topLeft = Offset(w * 0.35f, h * 0.45f),
            size = Size(w * 0.30f, h * 0.22f),
            cornerRadius = CornerRadius(w * 0.035f, w * 0.035f)
        )
    }
}

@Composable
private fun ConnectedCard(
    server: String,
    username: String,
    assignedIp: String,
    duration: String,
    bytesReceived: Long,
    bytesSent: Long
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .background(Green.copy(alpha = 0.12f), RoundedCornerShape(10.dp))
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        InfoRow("Server", server)
        InfoRow("Username", username)
        if (assignedIp.isNotBlank()) InfoRow("Assigned IP", assignedIp)
        InfoRow("Connected", duration)
        HorizontalDivider(color = TextPrimary.copy(alpha = 0.1f))
        InfoRow("↓ Download", formatBytes(bytesReceived))
        InfoRow("↑ Upload", formatBytes(bytesSent))
    }
}

@Composable
private fun InfoRow(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(label, color = TextSecondary, fontSize = 15.sp)
        Spacer(Modifier.width(12.dp))
        Text(
            value,
            color = TextPrimary,
            fontSize = 15.sp,
            fontWeight = FontWeight.Medium,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis
        )
    }
}

@Composable
private fun DarkField(
    value: String,
    onValueChange: (String) -> Unit,
    placeholder: String,
    keyboardType: KeyboardType = KeyboardType.Text,
    isPassword: Boolean = false
) {
    var focused by remember { mutableStateOf(false) }
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .height(48.dp)
            .clip(RoundedCornerShape(10.dp))
            .background(FieldBg)
            .border(1.dp, if (focused) Blue else FieldBorder, RoundedCornerShape(10.dp))
            .padding(horizontal = 14.dp),
        contentAlignment = Alignment.CenterStart
    ) {
        if (value.isEmpty()) {
            Text(placeholder, color = TextSecondary, fontSize = 15.sp)
        }
        BasicTextField(
            value = value,
            onValueChange = onValueChange,
            singleLine = true,
            textStyle = TextStyle(color = TextPrimary, fontSize = 15.sp),
            cursorBrush = SolidColor(Blue),
            visualTransformation = if (isPassword) PasswordVisualTransformation() else VisualTransformation.None,
            keyboardOptions = KeyboardOptions(keyboardType = if (isPassword) KeyboardType.Password else keyboardType),
            modifier = Modifier
                .fillMaxWidth()
                .onFocusChanged { focused = it.isFocused }
        )
    }
}

private fun parseHostPort(input: String): Pair<String, Int> {
    val trimmed = input.trim()
    val idx = trimmed.lastIndexOf(':')
    return if (idx > 0) {
        val host = trimmed.substring(0, idx)
        val port = trimmed.substring(idx + 1).toIntOrNull() ?: 1194
        host to port
    } else {
        trimmed to 1194
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
