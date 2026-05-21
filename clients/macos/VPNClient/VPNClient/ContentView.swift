//
//  ContentView.swift
//  VPNClient
//

import SwiftUI
import Combine

struct ContentView: View {
    @StateObject private var vpnManager = VPNManager.shared

    @State private var username = ""
    @State private var password = ""
    @State private var serverAddress = "localhost:1194"
    @State private var isConnecting = false
    @State private var showError = false
    @State private var currentTime = Date()

    let timer = Timer.publish(every: 1, on: .main, in: .common).autoconnect()

    var body: some View {
        VStack(spacing: 20) {
            // Header
            HStack {
                Image(systemName: vpnManager.status.isConnected ? "lock.shield.fill" : "lock.shield")
                    .font(.system(size: 40))
                    .foregroundColor(vpnManager.status.isConnected ? .green : .secondary)

                VStack(alignment: .leading) {
                    Text("VPN Client")
                        .font(.title2)
                        .fontWeight(.bold)
                    Text(vpnManager.status.rawValue)
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }
            .padding()

            Divider()

            if vpnManager.status.isConnected {
                // Connected View
                connectedView
            } else {
                // Login View
                loginView
            }

            Spacer()

            // Error Message
            if let error = vpnManager.errorMessage {
                Text(error)
                    .font(.caption)
                    .foregroundColor(.red)
                    .padding()
            }
        }
        .frame(width: 300, height: 400)
        .padding()
        .onReceive(timer) { _ in
            if vpnManager.status.isConnected {
                currentTime = Date()
                Task {
                    await vpnManager.refreshStats()
                }
            }
        }
    }

    // MARK: - Login View

    private var loginView: some View {
        VStack(spacing: 16) {
            TextField("Server (host:port)", text: $serverAddress)
                .textFieldStyle(.roundedBorder)

            TextField("Username", text: $username)
                .textFieldStyle(.roundedBorder)

            SecureField("Password", text: $password)
                .textFieldStyle(.roundedBorder)

            Button(action: connect) {
                HStack {
                    if isConnecting {
                        ProgressView()
                            .scaleEffect(0.7)
                    }
                    Text(isConnecting ? "Connecting..." : "Connect")
                }
                .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .disabled(username.isEmpty || password.isEmpty || isConnecting)
        }
        .padding()
    }

    // MARK: - Connected View

    private var connectedView: some View {
        VStack(spacing: 16) {
            VStack(alignment: .leading, spacing: 8) {
                InfoRow(label: "Server", value: serverAddress)
                InfoRow(label: "Username", value: username)
                if !vpnManager.assignedIP.isEmpty {
                    InfoRow(label: "Assigned IP", value: vpnManager.assignedIP)
                }
                if let time = vpnManager.connectedTime {
                    InfoRow(label: "Connected", value: formatDuration(from: time, now: currentTime))
                }
                Divider()
                InfoRow(label: "↓ Download", value: formatBytes(vpnManager.bytesIn))
                InfoRow(label: "↑ Upload", value: formatBytes(vpnManager.bytesOut))
            }
            .padding()
            .background(Color.green.opacity(0.1))
            .cornerRadius(8)

            Button("Disconnect") {
                vpnManager.disconnect()
            }
            .buttonStyle(.bordered)
            .tint(.red)
        }
        .padding()
    }

    // MARK: - Actions

    private func connect() {
        isConnecting = true
        vpnManager.serverAddress = serverAddress

        Task {
            do {
                try await vpnManager.connect(username: username, password: password)
            } catch {
                // Error is handled by VPNManager
            }
            isConnecting = false
        }
    }

    private func formatDuration(from date: Date, now: Date) -> String {
        let interval = now.timeIntervalSince(date)
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
}

// MARK: - Info Row

struct InfoRow: View {
    let label: String
    let value: String

    var body: some View {
        HStack {
            Text(label)
                .foregroundColor(.secondary)
            Spacer()
            Text(value)
                .fontWeight(.medium)
        }
        .font(.callout)
    }
}

#Preview {
    ContentView()
}
