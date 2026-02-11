//
//  SettingsView.swift
//  VPNClient
//
//  Settings screen for VPN configuration
//

import SwiftUI

struct SettingsView: View {
    @EnvironmentObject var viewModel: VPNViewModel
    @Environment(\.dismiss) private var dismiss

    @State private var serverAddress: String = ""
    @State private var serverPort: String = "443"
    @State private var autoConnect: Bool = false
    @State private var connectOnWiFi: Bool = true
    @State private var connectOnCellular: Bool = false
    @State private var killSwitch: Bool = false
    @State private var showingResetConfirmation: Bool = false

    var body: some View {
        NavigationStack {
            Form {
                // Server configuration section
                serverSection

                // Connection options section
                connectionSection

                // Security section
                securitySection

                // About section
                aboutSection

                // Reset section
                resetSection
            }
            .navigationTitle("Settings")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("Cancel") {
                        dismiss()
                    }
                }

                ToolbarItem(placement: .navigationBarTrailing) {
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
                    .autocapitalization(.none)
                    .disableAutocorrection(true)
            }

            HStack {
                Text("Port")
                Spacer()
                TextField("443", text: $serverPort)
                    .multilineTextAlignment(.trailing)
                    .foregroundColor(.secondary)
                    .keyboardType(.numberPad)
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

            Toggle("Connect on Cellular", isOn: $connectOnCellular)
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
                Text("iOS")
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
                if viewModel.isConnected {
                    InfoRow(title: "Issuer", value: viewModel.certificateIssuer)
                    InfoRow(title: "Valid Until", value: viewModel.certificateExpiry)
                    InfoRow(title: "Fingerprint", value: viewModel.certificateFingerprint)
                } else {
                    Text("Connect to VPN to view certificate details")
                        .foregroundColor(.secondary)
                        .italic()
                }
            }
        }
        .navigationTitle("Certificate Info")
        .navigationBarTitleDisplayMode(.inline)
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
        .navigationBarTitleDisplayMode(.inline)
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

        serverAddress = defaults.string(forKey: "vpn_server_address") ?? ""
        serverPort = defaults.string(forKey: "vpn_server_port") ?? "443"
        autoConnect = defaults.bool(forKey: "vpn_auto_connect")
        connectOnWiFi = defaults.bool(forKey: "vpn_connect_wifi")
        connectOnCellular = defaults.bool(forKey: "vpn_connect_cellular")
        killSwitch = defaults.bool(forKey: "vpn_kill_switch")

        // Set defaults for toggles if not previously set
        if defaults.object(forKey: "vpn_connect_wifi") == nil {
            connectOnWiFi = true
        }
    }

    private func saveSettings() {
        let defaults = UserDefaults.standard

        defaults.set(serverAddress, forKey: "vpn_server_address")
        defaults.set(serverPort, forKey: "vpn_server_port")
        defaults.set(autoConnect, forKey: "vpn_auto_connect")
        defaults.set(connectOnWiFi, forKey: "vpn_connect_wifi")
        defaults.set(connectOnCellular, forKey: "vpn_connect_cellular")
        defaults.set(killSwitch, forKey: "vpn_kill_switch")

        // Notify view model of settings change
        viewModel.updateSettings(
            serverAddress: serverAddress,
            serverPort: Int(serverPort) ?? 443,
            killSwitch: killSwitch
        )
    }

    private func resetSettings() {
        let defaults = UserDefaults.standard
        let domain = Bundle.main.bundleIdentifier!
        defaults.removePersistentDomain(forName: domain)
        defaults.synchronize()

        // Reset local state
        serverAddress = ""
        serverPort = "443"
        autoConnect = false
        connectOnWiFi = true
        connectOnCellular = false
        killSwitch = false

        // Clear credentials from keychain
        viewModel.clearSavedCredentials()
    }
}

// MARK: - Preview
#Preview {
    SettingsView()
        .environmentObject(VPNViewModel())
}
