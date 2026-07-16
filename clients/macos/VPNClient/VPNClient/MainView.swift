//
//  MainView.swift
//  VPNClient
//
//  Main VPN connection screen for the macOS OpenTunnel client.
//  Visual design matches the iOS MainView (concentric status circles,
//  connection details card, statistics card, gradient action button).
//

import SwiftUI
import Combine

struct MainView: View {
    @EnvironmentObject var session: AppSession
    @StateObject private var vpnManager = VPNManager.shared

    @State private var showingSettings = false
    @State private var showingLogout = false
    @State private var currentTime = Date()

    private let timer = Timer.publish(every: 1, on: .main, in: .common).autoconnect()

    var body: some View {
        VStack(spacing: 0) {
            headerSection

            ScrollView {
                VStack(spacing: 24) {
                    connectionStatusCard

                    if isConnected {
                        serverInfoCard
                        statisticsCard
                    }

                    connectionButton
                }
                .padding()
            }
        }
        .background(Color.groupedBackground)
        .sheet(isPresented: $showingSettings) {
            SettingsView()
                .environmentObject(session)
        }
        .alert("Logout", isPresented: $showingLogout) {
            Button("Cancel", role: .cancel) { }
            Button("Logout", role: .destructive) {
                session.logout()
            }
        } message: {
            Text("Are you sure you want to logout? This will disconnect the VPN if active.")
        }
        .onReceive(timer) { _ in
            if isConnected {
                currentTime = Date()
                Task { await vpnManager.refreshStats() }
            }
        }
    }

    // MARK: - Header Section
    private var headerSection: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Text("OpenTunnel")
                    .font(.title2)
                    .fontWeight(.bold)
                Text(session.username)
                    .font(.subheadline)
                    .foregroundColor(.secondary)
            }

            Spacer()

            Button {
                showingSettings = true
            } label: {
                Image(systemName: "gearshape.fill")
                    .font(.title3)
                    .foregroundColor(.primary)
            }
            .buttonStyle(.plain)

            Button {
                showingLogout = true
            } label: {
                Image(systemName: "rectangle.portrait.and.arrow.right")
                    .font(.title3)
                    .foregroundColor(.primary)
            }
            .buttonStyle(.plain)
            .padding(.leading, 8)
        }
        .padding()
        .background(Color.cardBackground)
    }

    // MARK: - Connection Status Card
    private var connectionStatusCard: some View {
        VStack(spacing: 16) {
            ZStack {
                Circle()
                    .fill(statusColor.opacity(0.2))
                    .frame(width: 120, height: 120)

                Circle()
                    .fill(statusColor.opacity(0.4))
                    .frame(width: 90, height: 90)

                Circle()
                    .fill(statusColor)
                    .frame(width: 60, height: 60)

                if isConnecting || isDisconnecting {
                    ProgressView()
                        .progressViewStyle(CircularProgressViewStyle(tint: .white))
                        .scaleEffect(1.2)
                } else {
                    Image(systemName: statusIcon)
                        .font(.title)
                        .foregroundColor(.white)
                }
            }
            .animation(.easeInOut(duration: 0.3), value: vpnManager.status)

            VStack(spacing: 4) {
                Text(statusTitle)
                    .font(.title3)
                    .fontWeight(.semibold)

                Text(statusDescription)
                    .font(.subheadline)
                    .foregroundColor(.secondary)
                    .multilineTextAlignment(.center)
            }
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 32)
        .background(Color.cardBackground)
        .cornerRadius(16)
        .shadow(color: .black.opacity(0.05), radius: 10, x: 0, y: 4)
    }

    // MARK: - Server Info Card
    private var serverInfoCard: some View {
        VStack(spacing: 16) {
            HStack {
                Text("Connection Details")
                    .font(.headline)
                Spacer()
            }

            Divider()

            InfoRow(title: "Server", value: vpnManager.serverAddress)
            InfoRow(title: "Assigned IP", value: vpnManager.assignedIP.isEmpty ? "—" : vpnManager.assignedIP)
            InfoRow(title: "Gateway", value: vpnManager.gateway.isEmpty ? "—" : vpnManager.gateway)
            InfoRow(title: "DNS", value: vpnManager.dnsServers.isEmpty ? "—" : vpnManager.dnsServers.joined(separator: ", "))
            InfoRow(title: "MTU", value: vpnManager.mtu > 0 ? "\(vpnManager.mtu)" : "—")
        }
        .padding()
        .background(Color.cardBackground)
        .cornerRadius(16)
        .shadow(color: .black.opacity(0.05), radius: 10, x: 0, y: 4)
    }

    // MARK: - Statistics Card
    private var statisticsCard: some View {
        VStack(spacing: 16) {
            HStack {
                Text("Statistics")
                    .font(.headline)
                Spacer()

                Text(connectionDuration)
                    .font(.subheadline)
                    .foregroundColor(.secondary)
            }

            Divider()

            HStack(spacing: 24) {
                StatisticItem(
                    icon: "arrow.down.circle.fill",
                    title: "Downloaded",
                    value: formatBytes(vpnManager.bytesIn),
                    color: .blue
                )

                StatisticItem(
                    icon: "arrow.up.circle.fill",
                    title: "Uploaded",
                    value: formatBytes(vpnManager.bytesOut),
                    color: .green
                )
            }
        }
        .padding()
        .background(Color.cardBackground)
        .cornerRadius(16)
        .shadow(color: .black.opacity(0.05), radius: 10, x: 0, y: 4)
    }

    // MARK: - Connection Button
    private var connectionButton: some View {
        Button {
            if isConnected {
                vpnManager.disconnect()
            } else {
                connect()
            }
        } label: {
            HStack(spacing: 12) {
                if isConnecting || isDisconnecting {
                    ProgressView()
                        .progressViewStyle(CircularProgressViewStyle(tint: .white))
                } else {
                    Image(systemName: isConnected ? "stop.fill" : "play.fill")
                }

                Text(buttonTitle)
                    .fontWeight(.semibold)
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 16)
            .background(buttonColor)
            .foregroundColor(.white)
            .cornerRadius(12)
        }
        .buttonStyle(.plain)
        .disabled(isConnecting || isDisconnecting)
    }

    // MARK: - Actions
    private func connect() {
        vpnManager.serverAddress = "\(session.serverHost):\(session.serverPort)"
        Task {
            try? await vpnManager.connect(username: session.username, password: session.password)
        }
    }

    // MARK: - Derived State
    private var isConnected: Bool { vpnManager.status.isConnected }
    private var isConnecting: Bool {
        vpnManager.status == .connecting || vpnManager.status == .reasserting
    }
    private var isDisconnecting: Bool { vpnManager.status == .disconnecting }

    private var connectionDuration: String {
        guard let start = vpnManager.connectedTime else { return "00:00:00" }
        let interval = currentTime.timeIntervalSince(start)
        let hours = Int(interval) / 3600
        let minutes = Int(interval) / 60 % 60
        let seconds = Int(interval) % 60
        return String(format: "%02d:%02d:%02d", hours, minutes, seconds)
    }

    private func formatBytes(_ bytes: UInt64) -> String {
        let kb = Double(bytes) / 1024
        let mb = kb / 1024
        let gb = mb / 1024
        if gb >= 1 {
            return String(format: "%.2f GB", gb)
        } else if mb >= 1 {
            return String(format: "%.2f MB", mb)
        } else if kb >= 1 {
            return String(format: "%.1f KB", kb)
        } else {
            return "\(bytes) B"
        }
    }

    // MARK: - Computed Properties (status presentation)
    private var statusColor: Color {
        switch vpnManager.status {
        case .connected:
            return .green
        case .connecting, .reasserting:
            return .orange
        case .disconnecting:
            return .yellow
        case .disconnected, .invalid:
            return .gray
        }
    }

    private var statusIcon: String {
        switch vpnManager.status {
        case .connected:
            return "checkmark"
        case .connecting, .reasserting, .disconnecting:
            return "ellipsis"
        case .disconnected, .invalid:
            return "xmark"
        }
    }

    private var statusTitle: String {
        switch vpnManager.status {
        case .connected:
            return "Connected"
        case .connecting:
            return "Connecting..."
        case .disconnecting:
            return "Disconnecting..."
        case .reasserting:
            return "Reconnecting..."
        case .disconnected:
            return "Disconnected"
        case .invalid:
            return "Not Configured"
        }
    }

    private var statusDescription: String {
        switch vpnManager.status {
        case .connected:
            return "Your connection is secure"
        case .connecting:
            return "Establishing secure tunnel..."
        case .disconnecting:
            return "Closing connection..."
        case .reasserting:
            return "Restoring connection..."
        case .disconnected:
            return "Tap Connect to secure your connection"
        case .invalid:
            return "VPN configuration is not set up"
        }
    }

    private var buttonTitle: String {
        switch vpnManager.status {
        case .connected:
            return "Disconnect"
        case .connecting:
            return "Connecting..."
        case .disconnecting:
            return "Disconnecting..."
        case .reasserting:
            return "Reconnecting..."
        case .disconnected, .invalid:
            return "Connect"
        }
    }

    private var buttonColor: Color {
        if isConnected {
            return .red
        } else if isConnecting || isDisconnecting {
            return .gray
        } else {
            return .blue
        }
    }
}

// MARK: - Info Row Component
struct InfoRow: View {
    let title: String
    let value: String

    var body: some View {
        HStack {
            Text(title)
                .foregroundColor(.secondary)
            Spacer()
            Text(value)
                .fontWeight(.medium)
        }
        .font(.subheadline)
    }
}

// MARK: - Statistic Item Component
struct StatisticItem: View {
    let icon: String
    let title: String
    let value: String
    let color: Color

    var body: some View {
        VStack(spacing: 8) {
            Image(systemName: icon)
                .font(.title2)
                .foregroundColor(color)

            Text(value)
                .font(.headline)

            Text(title)
                .font(.caption)
                .foregroundColor(.secondary)
        }
        .frame(maxWidth: .infinity)
    }
}

// MARK: - Preview
#Preview {
    MainView()
        .environmentObject(AppSession())
        .frame(width: 400, height: 640)
}
