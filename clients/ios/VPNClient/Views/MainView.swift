//
//  MainView.swift
//  VPNClient
//
//  Main VPN connection screen
//

import SwiftUI
import NetworkExtension

struct MainView: View {
    @EnvironmentObject var viewModel: VPNViewModel
    @State private var showingSettings = false
    @State private var showingLogout = false

    var body: some View {
        VStack(spacing: 0) {
            // Header
            headerSection

            // Main content
            ScrollView {
                VStack(spacing: 24) {
                    // Connection status card
                    connectionStatusCard

                    // Server info card
                    if viewModel.isConnected {
                        serverInfoCard
                    }

                    // Connection statistics
                    if viewModel.isConnected {
                        statisticsCard
                    }

                    // Connect/Disconnect button
                    connectionButton
                }
                .padding()
            }
        }
        .background(Color(.systemGroupedBackground))
        .sheet(isPresented: $showingSettings) {
            SettingsView()
        }
        .alert("Logout", isPresented: $showingLogout) {
            Button("Cancel", role: .cancel) { }
            Button("Logout", role: .destructive) {
                viewModel.logout()
            }
        } message: {
            Text("Are you sure you want to logout? This will disconnect the VPN if active.")
        }
    }

    // MARK: - Header Section
    private var headerSection: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Text("VPN Client")
                    .font(.title2)
                    .fontWeight(.bold)
                Text(viewModel.username)
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

            Button {
                showingLogout = true
            } label: {
                Image(systemName: "rectangle.portrait.and.arrow.right")
                    .font(.title3)
                    .foregroundColor(.primary)
            }
            .padding(.leading, 8)
        }
        .padding()
        .background(Color(.systemBackground))
    }

    // MARK: - Connection Status Card
    private var connectionStatusCard: some View {
        VStack(spacing: 16) {
            // Status indicator
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

                if viewModel.isConnecting || viewModel.isDisconnecting {
                    ProgressView()
                        .progressViewStyle(CircularProgressViewStyle(tint: .white))
                        .scaleEffect(1.2)
                } else {
                    Image(systemName: statusIcon)
                        .font(.title)
                        .foregroundColor(.white)
                }
            }
            .animation(.easeInOut(duration: 0.3), value: viewModel.connectionStatus)

            // Status text
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
        .background(Color(.systemBackground))
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

            InfoRow(title: "Server", value: viewModel.serverAddress)
            InfoRow(title: "Assigned IP", value: viewModel.assignedIP)
            InfoRow(title: "Gateway", value: viewModel.gateway)
            InfoRow(title: "DNS", value: viewModel.dnsServers.joined(separator: ", "))
            InfoRow(title: "MTU", value: "\(viewModel.mtu)")
        }
        .padding()
        .background(Color(.systemBackground))
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

                Text(viewModel.connectionDuration)
                    .font(.subheadline)
                    .foregroundColor(.secondary)
            }

            Divider()

            HStack(spacing: 24) {
                StatisticItem(
                    icon: "arrow.down.circle.fill",
                    title: "Downloaded",
                    value: viewModel.formattedBytesReceived,
                    color: .blue
                )

                StatisticItem(
                    icon: "arrow.up.circle.fill",
                    title: "Uploaded",
                    value: viewModel.formattedBytesSent,
                    color: .green
                )
            }
        }
        .padding()
        .background(Color(.systemBackground))
        .cornerRadius(16)
        .shadow(color: .black.opacity(0.05), radius: 10, x: 0, y: 4)
    }

    // MARK: - Connection Button
    private var connectionButton: some View {
        Button {
            if viewModel.isConnected {
                viewModel.disconnect()
            } else {
                viewModel.connect()
            }
        } label: {
            HStack(spacing: 12) {
                if viewModel.isConnecting || viewModel.isDisconnecting {
                    ProgressView()
                        .progressViewStyle(CircularProgressViewStyle(tint: .white))
                } else {
                    Image(systemName: viewModel.isConnected ? "stop.fill" : "play.fill")
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
        .disabled(viewModel.isConnecting || viewModel.isDisconnecting)
    }

    // MARK: - Computed Properties
    private var statusColor: Color {
        switch viewModel.connectionStatus {
        case .connected:
            return .green
        case .connecting, .reasserting:
            return .orange
        case .disconnecting:
            return .yellow
        case .disconnected, .invalid:
            return .gray
        @unknown default:
            return .gray
        }
    }

    private var statusIcon: String {
        switch viewModel.connectionStatus {
        case .connected:
            return "checkmark"
        case .connecting, .reasserting, .disconnecting:
            return "ellipsis"
        case .disconnected, .invalid:
            return "xmark"
        @unknown default:
            return "questionmark"
        }
    }

    private var statusTitle: String {
        switch viewModel.connectionStatus {
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
        @unknown default:
            return "Unknown"
        }
    }

    private var statusDescription: String {
        switch viewModel.connectionStatus {
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
        @unknown default:
            return ""
        }
    }

    private var buttonTitle: String {
        switch viewModel.connectionStatus {
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
        @unknown default:
            return "Connect"
        }
    }

    private var buttonColor: Color {
        if viewModel.isConnected {
            return .red
        } else if viewModel.isConnecting || viewModel.isDisconnecting {
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
    NavigationStack {
        MainView()
    }
    .environmentObject(VPNViewModel())
}
