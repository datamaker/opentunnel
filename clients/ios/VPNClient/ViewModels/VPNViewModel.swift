//
//  VPNViewModel.swift
//  VPNClient
//
//  ViewModel for VPN state management
//

import Foundation
import SwiftUI
import NetworkExtension
import Combine
import Security

@MainActor
class VPNViewModel: ObservableObject {
    // MARK: - Published Properties

    // Authentication state
    @Published var isAuthenticated = false
    @Published var isAuthenticating = false
    @Published var authError: String?
    @Published var username = ""
    @Published var sessionToken = ""

    // Connection state
    @Published var connectionStatus: NEVPNStatus = .disconnected
    @Published var isConnecting = false
    @Published var isDisconnecting = false
    @Published var connectionError: String?

    // Connection info
    @Published var serverAddress = ""
    @Published var serverPort = 443
    @Published var assignedIP = ""
    @Published var subnetMask = ""
    @Published var gateway = ""
    @Published var dnsServers: [String] = []
    @Published var mtu = 1400

    // Statistics
    @Published var bytesReceived: UInt64 = 0
    @Published var bytesSent: UInt64 = 0
    @Published var connectionStartTime: Date?

    // Certificate info
    @Published var certificateIssuer = ""
    @Published var certificateExpiry = ""
    @Published var certificateFingerprint = ""

    // Kill switch
    @Published var killSwitchEnabled = false

    // MARK: - Private Properties
    private var vpnManager: VPNManager?
    private var cancellables = Set<AnyCancellable>()
    private var statisticsTimer: Timer?

    // MARK: - Computed Properties
    var isConnected: Bool {
        connectionStatus == .connected
    }

    var formattedBytesReceived: String {
        formatBytes(bytesReceived)
    }

    var formattedBytesSent: String {
        formatBytes(bytesSent)
    }

    var connectionDuration: String {
        guard let startTime = connectionStartTime else {
            return "00:00:00"
        }

        let duration = Date().timeIntervalSince(startTime)
        let hours = Int(duration) / 3600
        let minutes = (Int(duration) % 3600) / 60
        let seconds = Int(duration) % 60

        return String(format: "%02d:%02d:%02d", hours, minutes, seconds)
    }

    // MARK: - Initialization
    init() {
        setupVPNManager()
    }

    // MARK: - Setup
    private func setupVPNManager() {
        vpnManager = VPNManager.shared

        // Observe VPN status changes
        vpnManager?.statusPublisher
            .receive(on: DispatchQueue.main)
            .sink { [weak self] status in
                self?.handleStatusChange(status)
            }
            .store(in: &cancellables)

        // Observe configuration changes
        vpnManager?.configurationPublisher
            .receive(on: DispatchQueue.main)
            .sink { [weak self] config in
                self?.handleConfigurationChange(config)
            }
            .store(in: &cancellables)
    }

    // MARK: - Authentication Methods
    func login(
        username: String,
        password: String,
        serverAddress: String,
        serverPort: Int,
        rememberCredentials: Bool
    ) {
        isAuthenticating = true
        authError = nil

        self.username = username
        self.serverAddress = serverAddress
        self.serverPort = serverPort

        Task {
            do {
                // Save server settings
                let defaults = UserDefaults.standard
                defaults.set(serverAddress, forKey: "vpn_server_address")
                defaults.set(String(serverPort), forKey: "vpn_server_port")
                defaults.set(rememberCredentials, forKey: "vpn_remember_credentials")

                if rememberCredentials {
                    defaults.set(username, forKey: "vpn_username")
                    savePasswordToKeychain(password: password, username: username)
                }

                // Configure VPN with credentials
                try await vpnManager?.configureVPN(
                    serverAddress: serverAddress,
                    serverPort: serverPort,
                    username: username,
                    password: password
                )

                isAuthenticated = true
                isAuthenticating = false

            } catch {
                authError = error.localizedDescription
                isAuthenticating = false
            }
        }
    }

    func logout() {
        // Disconnect if connected
        if isConnected {
            disconnect()
        }

        // Clear authentication state
        isAuthenticated = false
        username = ""
        sessionToken = ""

        // Clear connection info
        assignedIP = ""
        subnetMask = ""
        gateway = ""
        dnsServers = []
    }

    func loadSavedCredentials() {
        let defaults = UserDefaults.standard

        guard defaults.bool(forKey: "vpn_remember_credentials"),
              let savedUsername = defaults.string(forKey: "vpn_username"),
              let savedServer = defaults.string(forKey: "vpn_server_address"),
              let savedPort = defaults.string(forKey: "vpn_server_port"),
              let password = loadPasswordFromKeychain(username: savedUsername)
        else {
            return
        }

        // Auto-login with saved credentials
        login(
            username: savedUsername,
            password: password,
            serverAddress: savedServer,
            serverPort: Int(savedPort) ?? 443,
            rememberCredentials: true
        )
    }

    func clearSavedCredentials() {
        let defaults = UserDefaults.standard

        if let username = defaults.string(forKey: "vpn_username") {
            deletePasswordFromKeychain(username: username)
        }

        defaults.removeObject(forKey: "vpn_username")
        defaults.removeObject(forKey: "vpn_remember_credentials")
    }

    // MARK: - Connection Methods
    func connect() {
        guard !isConnecting else { return }

        isConnecting = true
        connectionError = nil

        Task {
            do {
                try await vpnManager?.connect()
            } catch {
                connectionError = error.localizedDescription
                isConnecting = false
            }
        }
    }

    func disconnect() {
        guard !isDisconnecting else { return }

        isDisconnecting = true

        Task {
            await vpnManager?.disconnect()
        }
    }

    // MARK: - Settings Methods
    func updateSettings(serverAddress: String, serverPort: Int, killSwitch: Bool) {
        self.serverAddress = serverAddress
        self.serverPort = serverPort
        self.killSwitchEnabled = killSwitch

        // Update VPN configuration if needed
        Task {
            if isAuthenticated {
                // Reconfigure VPN with new settings
                // This would require re-authentication in a real implementation
            }
        }
    }

    // MARK: - Status Handling
    private func handleStatusChange(_ status: NEVPNStatus) {
        connectionStatus = status

        switch status {
        case .connected:
            isConnecting = false
            isDisconnecting = false
            connectionStartTime = Date()
            startStatisticsTimer()

        case .disconnected:
            isConnecting = false
            isDisconnecting = false
            connectionStartTime = nil
            stopStatisticsTimer()
            resetStatistics()

        case .connecting:
            isConnecting = true
            isDisconnecting = false

        case .disconnecting:
            isConnecting = false
            isDisconnecting = true

        case .reasserting:
            isConnecting = false
            isDisconnecting = false

        case .invalid:
            isConnecting = false
            isDisconnecting = false

        @unknown default:
            break
        }
    }

    private func handleConfigurationChange(_ config: VPNConfiguration?) {
        guard let config = config else { return }

        assignedIP = config.assignedIP
        subnetMask = config.subnetMask
        gateway = config.gateway
        dnsServers = config.dns
        mtu = config.mtu
    }

    // MARK: - Statistics
    private func startStatisticsTimer() {
        statisticsTimer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { [weak self] _ in
            Task { @MainActor in
                self?.updateStatistics()
            }
        }
    }

    private func stopStatisticsTimer() {
        statisticsTimer?.invalidate()
        statisticsTimer = nil
    }

    private func updateStatistics() {
        // In a real implementation, these would come from the tunnel provider
        // via app group shared data or IPC
        if let stats = vpnManager?.getStatistics() {
            bytesReceived = stats.bytesReceived
            bytesSent = stats.bytesSent
        }

        // Update the view to refresh connection duration
        objectWillChange.send()
    }

    private func resetStatistics() {
        bytesReceived = 0
        bytesSent = 0
    }

    private func formatBytes(_ bytes: UInt64) -> String {
        let formatter = ByteCountFormatter()
        formatter.countStyle = .binary
        formatter.allowedUnits = [.useKB, .useMB, .useGB]
        return formatter.string(fromByteCount: Int64(bytes))
    }

    // MARK: - Keychain Methods
    private func savePasswordToKeychain(password: String, username: String) {
        let passwordData = password.data(using: .utf8)!

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: username,
            kSecAttrService as String: "com.vpnclient.ios",
            kSecValueData as String: passwordData
        ]

        // Delete existing item first
        SecItemDelete(query as CFDictionary)

        // Add new item
        SecItemAdd(query as CFDictionary, nil)
    }

    private func loadPasswordFromKeychain(username: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: username,
            kSecAttrService as String: "com.vpnclient.ios",
            kSecReturnData as String: true
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        guard status == errSecSuccess,
              let data = result as? Data,
              let password = String(data: data, encoding: .utf8)
        else {
            return nil
        }

        return password
    }

    private func deletePasswordFromKeychain(username: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: username,
            kSecAttrService as String: "com.vpnclient.ios"
        ]

        SecItemDelete(query as CFDictionary)
    }
}

// MARK: - VPN Configuration Model
struct VPNConfiguration {
    let assignedIP: String
    let subnetMask: String
    let gateway: String
    let dns: [String]
    let mtu: Int
}

// MARK: - VPN Statistics Model
struct VPNStatistics {
    let bytesReceived: UInt64
    let bytesSent: UInt64
}
