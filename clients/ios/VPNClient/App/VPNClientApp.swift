//
//  VPNClientApp.swift
//  VPNClient
//
//  iOS VPN Client Application Entry Point
//

import SwiftUI
import NetworkExtension

@main
struct VPNClientApp: App {
    @StateObject private var viewModel = VPNViewModel()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(viewModel)
        }
    }
}

// MARK: - Content View (single "VPN Client" screen, matches macOS / Android)
struct ContentView: View {
    @EnvironmentObject var viewModel: VPNViewModel

    @State private var server = ""
    @State private var username = ""
    @State private var password = ""

    var body: some View {
        VStack(spacing: 20) {
            Spacer()

            // Header: lock.shield + title + status
            HStack {
                Image(systemName: viewModel.isConnected ? "lock.shield.fill" : "lock.shield")
                    .font(.system(size: 40))
                    .foregroundColor(viewModel.isConnected ? .green : .secondary)

                VStack(alignment: .leading) {
                    Text("VPN Client")
                        .font(.title2)
                        .fontWeight(.bold)
                    Text(statusText)
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }

            Divider()

            if viewModel.isConnected {
                connectedView
            } else {
                loginView
            }

            if let error = viewModel.authError ?? viewModel.connectionError {
                Text(error)
                    .font(.caption)
                    .foregroundColor(.red)
                    .multilineTextAlignment(.center)
            }

            Spacer()
        }
        .padding()
        .onAppear {
            // Pre-fill the form with previously saved info
            server = viewModel.savedServerHostPort().ifEmpty("vpn.cacheby.com:1194")
            username = viewModel.savedUsername()
            password = viewModel.savedPassword()
        }
    }

    // MARK: - Login (disconnected) view
    private var loginView: some View {
        VStack(spacing: 16) {
            TextField("Server (host:port)", text: $server)
                .textFieldStyle(.roundedBorder)
                .autocapitalization(.none)
                .disableAutocorrection(true)

            TextField("Username", text: $username)
                .textFieldStyle(.roundedBorder)
                .autocapitalization(.none)
                .disableAutocorrection(true)

            SecureField("Password", text: $password)
                .textFieldStyle(.roundedBorder)

            Button(action: connect) {
                HStack {
                    if isBusy {
                        ProgressView().scaleEffect(0.8)
                    }
                    Text(isBusy ? "Connecting..." : "Connect")
                        .fontWeight(.semibold)
                }
                .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .disabled(server.isEmpty || username.isEmpty || password.isEmpty || isBusy)
        }
    }

    // MARK: - Connected view
    private var connectedView: some View {
        VStack(spacing: 16) {
            VStack(alignment: .leading, spacing: 8) {
                VPNInfoRow(label: "Server", value: "\(viewModel.serverAddress):\(viewModel.serverPort)")
                VPNInfoRow(label: "Username", value: viewModel.username)
                if !viewModel.assignedIP.isEmpty {
                    VPNInfoRow(label: "Assigned IP", value: viewModel.assignedIP)
                }
                VPNInfoRow(label: "Connected", value: viewModel.connectionDuration)
                Divider()
                VPNInfoRow(label: "↓ Download", value: viewModel.formattedBytesReceived)
                VPNInfoRow(label: "↑ Upload", value: viewModel.formattedBytesSent)
            }
            .padding()
            .background(Color.green.opacity(0.1))
            .cornerRadius(8)

            Button("Disconnect") {
                viewModel.disconnect()
            }
            .buttonStyle(.bordered)
            .tint(.red)
        }
    }

    // MARK: - Helpers
    private var isBusy: Bool {
        viewModel.isAuthenticating || viewModel.isConnecting
    }

    private var statusText: String {
        if viewModel.isConnected { return "Connected" }
        if isBusy { return "Connecting..." }
        switch viewModel.connectionStatus {
        case .disconnecting: return "Disconnecting..."
        case .reasserting: return "Reconnecting..."
        default: return "Disconnected"
        }
    }

    private func connect() {
        let parts = server.split(separator: ":", maxSplits: 1)
        let host = parts.first.map(String.init) ?? server
        let port = parts.count > 1 ? (Int(parts[1]) ?? 1194) : 1194
        viewModel.loginAndConnect(
            username: username,
            password: password,
            serverAddress: host,
            serverPort: port
        )
    }
}

private extension String {
    /// Returns `fallback` when the string is empty, otherwise itself.
    func ifEmpty(_ fallback: String) -> String { isEmpty ? fallback : self }
}

// MARK: - Info Row
struct VPNInfoRow: View {
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

// MARK: - Preview Provider
#Preview {
    ContentView()
        .environmentObject(VPNViewModel())
}
