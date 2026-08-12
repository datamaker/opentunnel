//
//  SettingsView.swift
//  VPNClient
//
//  Settings screen, shared by the iOS, iPadOS and macOS clients (Form
//  sections: Server Configuration, Connection Options, Security, About,
//  Reset).
//

import SwiftUI

struct SettingsView: View {
    @EnvironmentObject var session: AppSession
    @Environment(\.dismiss) private var dismiss

    @StateObject private var vpnManager = VPNManager.shared

    @State private var serverAddress: String = ""
    @State private var serverPort: String = "1194"
    @State private var autoConnect: Bool = false
    @State private var connectOnWiFi: Bool = true
    @State private var killSwitch: Bool = false
    @State private var showingResetConfirmation: Bool = false

    var body: some View {
        NavigationStack {
            Form {
                serverSection
                connectionSection
                securitySection
                aboutSection
                resetSection
            }
            .formStyle(.grouped)
            .navigationTitle("Settings")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") {
                        dismiss()
                    }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") {
                        saveSettings()
                        dismiss()
                    }
                    .fontWeight(.semibold)
                }
            }
            .onAppear {
                loadSettings()
            }
            .alert("Reset Settings", isPresented: $showingResetConfirmation) {
                Button("Cancel", role: .cancel) { }
                Button("Reset", role: .destructive) {
                    resetSettings()
                }
            } message: {
                Text("This will reset all settings to their default values. Your saved credentials will be removed.")
            }
        }
        .modifier(SettingsSheetSizing())
    }

    // MARK: - Server Section
    private var serverSection: some View {
        Section {
            HStack {
                Text("Server Address")
                Spacer()
                TextField("vpn.example.com", text: $serverAddress)
                    .multilineTextAlignment(.trailing)
                    .foregroundColor(.secondary)
                    .textFieldStyle(.plain)
                    .textFieldKind(.host)
            }

            HStack {
                Text("Port")
                Spacer()
                TextField("1194", text: $serverPort)
                    .multilineTextAlignment(.trailing)
                    .foregroundColor(.secondary)
                    .textFieldStyle(.plain)
                    .textFieldKind(.port)
                    .frame(width: 80)
            }
        } header: {
            Text("Server Configuration")
        } footer: {
            Text("The VPN server address and port to connect to.")
        }
    }

    // MARK: - Connection Section
    private var connectionSection: some View {
        Section {
            Toggle("Auto-connect on launch", isOn: $autoConnect)
            Toggle("Connect on Wi-Fi", isOn: $connectOnWiFi)
        } header: {
            Text("Connection Options")
        } footer: {
            Text("Configure when the VPN should automatically connect.")
        }
    }

    // MARK: - Security Section
    private var securitySection: some View {
        Section {
            Toggle("Kill Switch", isOn: $killSwitch)

            NavigationLink {
                certificateInfoView
            } label: {
                HStack {
                    Text("Certificate Info")
                    Spacer()
                    Text("View")
                        .foregroundColor(.secondary)
                }
            }
        } header: {
            Text("Security")
        } footer: {
            Text("Kill Switch blocks all internet traffic when VPN connection drops unexpectedly.")
        }
    }

    // MARK: - About Section
    private var aboutSection: some View {
        Section {
            HStack {
                Text("Version")
                Spacer()
                Text(appVersion)
                    .foregroundColor(.secondary)
            }

            HStack {
                Text("Protocol")
                Spacer()
                Text("TLS 1.3")
                    .foregroundColor(.secondary)
            }

            HStack {
                Text("Platform")
                Spacer()
                Text(RuntimePlatform.displayName)
                    .foregroundColor(.secondary)
            }

            NavigationLink {
                licensesView
            } label: {
                Text("Open Source Licenses")
            }
        } header: {
            Text("About")
        }
    }

    // MARK: - Reset Section
    private var resetSection: some View {
        Section {
            Button(role: .destructive) {
                showingResetConfirmation = true
            } label: {
                HStack {
                    Spacer()
                    Text("Reset All Settings")
                    Spacer()
                }
            }
        }
    }

    // MARK: - Certificate Info View
    private var certificateInfoView: some View {
        List {
            Section("Connection Security") {
                InfoRow(title: "Protocol", value: "TLS 1.3")
                InfoRow(title: "Cipher Suite", value: "TLS_AES_256_GCM_SHA384")
                InfoRow(title: "Key Exchange", value: "X25519")
            }

            Section("Server Certificate") {
                if vpnManager.status.isConnected {
                    InfoRow(title: "Server", value: vpnManager.serverAddress)
                    InfoRow(title: "Assigned IP", value: vpnManager.assignedIP.isEmpty ? "—" : vpnManager.assignedIP)
                } else {
                    Text("Connect to VPN to view certificate details")
                        .foregroundColor(.secondary)
                        .italic()
                }
            }
        }
        .navigationTitle("Certificate Info")
    }

    // MARK: - Licenses View
    private var licensesView: some View {
        List {
            Section {
                Text("This application uses the following open source components:")
                    .foregroundColor(.secondary)
            }

            Section("NetworkExtension Framework") {
                Text("Apple NetworkExtension Framework for VPN tunnel implementation.")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }

            Section("Network Framework") {
                Text("Apple Network Framework with TLS 1.3 support for secure connections.")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
        }
        .navigationTitle("Licenses")
    }

    // MARK: - Computed Properties
    private var appVersion: String {
        let version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "1.0"
        let build = Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "1"
        return "\(version) (\(build))"
    }

    // MARK: - Methods
    private func loadSettings() {
        let defaults = UserDefaults.standard

        serverAddress = defaults.string(forKey: "vpn_server_address") ?? session.serverHost
        serverPort = defaults.string(forKey: "vpn_server_port") ?? session.serverPort
        autoConnect = defaults.bool(forKey: "vpn_auto_connect")
        killSwitch = defaults.bool(forKey: "vpn_kill_switch")

        if defaults.object(forKey: "vpn_connect_wifi") == nil {
            connectOnWiFi = true
        } else {
            connectOnWiFi = defaults.bool(forKey: "vpn_connect_wifi")
        }
    }

    private func saveSettings() {
        let defaults = UserDefaults.standard

        defaults.set(serverAddress, forKey: "vpn_server_address")
        defaults.set(serverPort, forKey: "vpn_server_port")
        defaults.set(autoConnect, forKey: "vpn_auto_connect")
        defaults.set(connectOnWiFi, forKey: "vpn_connect_wifi")
        defaults.set(killSwitch, forKey: "vpn_kill_switch")

        // Reflect the edited server details back into the live session so the
        // next Connect uses them.
        session.serverHost = serverAddress
        session.serverPort = serverPort
    }

    private func resetSettings() {
        let defaults = UserDefaults.standard
        if let domain = Bundle.main.bundleIdentifier {
            defaults.removePersistentDomain(forName: domain)
        }

        serverAddress = ""
        serverPort = "1194"
        autoConnect = false
        connectOnWiFi = true
        killSwitch = false
    }
}

/// The settings sheet needs a minimum size on macOS, where a sheet is sized by
/// its content. On iOS the sheet is already the width of the device, and a
/// 420 pt minimum is wider than an iPhone SE/13 mini (320–375 pt), which pushes
/// the form off the right edge — so touch platforms take the sheet as-is.
private struct SettingsSheetSizing: ViewModifier {
    func body(content: Content) -> some View {
        #if os(macOS)
        content.frame(minWidth: 420, minHeight: 520)
        #else
        content
        #endif
    }
}

// MARK: - Preview
#Preview {
    SettingsView()
        .environmentObject(AppSession())
}
