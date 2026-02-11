//
//  VPNManager.swift
//  VPNClient
//
//  VPN connection management using NetworkExtension
//

import Foundation
import NetworkExtension
import Combine

/// Errors that can occur during VPN operations
enum VPNError: LocalizedError {
    case configurationFailed(String)
    case connectionFailed(String)
    case authenticationFailed(String)
    case tunnelNotConfigured
    case permissionDenied
    case invalidConfiguration

    var errorDescription: String? {
        switch self {
        case .configurationFailed(let message):
            return "Configuration failed: \(message)"
        case .connectionFailed(let message):
            return "Connection failed: \(message)"
        case .authenticationFailed(let message):
            return "Authentication failed: \(message)"
        case .tunnelNotConfigured:
            return "VPN tunnel is not configured"
        case .permissionDenied:
            return "VPN permission denied"
        case .invalidConfiguration:
            return "Invalid VPN configuration"
        }
    }
}

/// Manages VPN tunnel configuration and connection
class VPNManager {
    // MARK: - Singleton
    static let shared = VPNManager()

    // MARK: - Properties
    private var tunnelProviderManager: NETunnelProviderManager?
    private var statusObserver: Any?

    // Publishers for reactive state updates
    private let statusSubject = CurrentValueSubject<NEVPNStatus, Never>(.invalid)
    private let configurationSubject = CurrentValueSubject<VPNConfiguration?, Never>(nil)

    var statusPublisher: AnyPublisher<NEVPNStatus, Never> {
        statusSubject.eraseToAnyPublisher()
    }

    var configurationPublisher: AnyPublisher<VPNConfiguration?, Never> {
        configurationSubject.eraseToAnyPublisher()
    }

    var currentStatus: NEVPNStatus {
        tunnelProviderManager?.connection.status ?? .invalid
    }

    // App Group identifier for sharing data with extension
    private let appGroupIdentifier = "group.com.vpnclient.ios"

    // MARK: - Initialization
    private init() {
        loadTunnelProviderManager()
    }

    deinit {
        if let observer = statusObserver {
            NotificationCenter.default.removeObserver(observer)
        }
    }

    // MARK: - Configuration
    /// Load existing tunnel provider manager or create new one
    private func loadTunnelProviderManager() {
        NETunnelProviderManager.loadAllFromPreferences { [weak self] managers, error in
            guard let self = self else { return }

            if let error = error {
                print("Failed to load tunnel provider managers: \(error.localizedDescription)")
                return
            }

            // Use existing manager or create new one
            self.tunnelProviderManager = managers?.first ?? NETunnelProviderManager()
            self.setupStatusObserver()
            self.statusSubject.send(self.currentStatus)
        }
    }

    /// Configure VPN with server and credentials
    func configureVPN(
        serverAddress: String,
        serverPort: Int,
        username: String,
        password: String
    ) async throws {
        // Ensure we have a tunnel provider manager
        if tunnelProviderManager == nil {
            tunnelProviderManager = NETunnelProviderManager()
        }

        guard let manager = tunnelProviderManager else {
            throw VPNError.configurationFailed("Unable to create tunnel provider manager")
        }

        // Create protocol configuration
        let protocolConfiguration = NETunnelProviderProtocol()
        protocolConfiguration.providerBundleIdentifier = "com.vpnclient.ios.PacketTunnelExtension"
        protocolConfiguration.serverAddress = serverAddress

        // Store configuration in provider configuration
        protocolConfiguration.providerConfiguration = [
            "serverAddress": serverAddress,
            "serverPort": serverPort,
            "username": username,
            "password": password,
            "clientVersion": Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "1.0",
            "platform": "ios"
        ]

        // Configure on-demand rules (optional)
        let connectRule = NEOnDemandRuleConnect()
        connectRule.interfaceTypeMatch = .any

        let disconnectRule = NEOnDemandRuleDisconnect()
        disconnectRule.interfaceTypeMatch = .any

        // Apply configuration
        manager.protocolConfiguration = protocolConfiguration
        manager.localizedDescription = "VPN Client"
        manager.isEnabled = true
        manager.isOnDemandEnabled = false  // Can be enabled for always-on VPN
        manager.onDemandRules = [connectRule]

        // Save configuration
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            manager.saveToPreferences { error in
                if let error = error {
                    continuation.resume(throwing: VPNError.configurationFailed(error.localizedDescription))
                } else {
                    continuation.resume()
                }
            }
        }

        // Reload from preferences to ensure we have the latest state
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            manager.loadFromPreferences { error in
                if let error = error {
                    continuation.resume(throwing: VPNError.configurationFailed(error.localizedDescription))
                } else {
                    continuation.resume()
                }
            }
        }

        setupStatusObserver()
    }

    // MARK: - Connection Control
    /// Start VPN connection
    func connect() async throws {
        guard let manager = tunnelProviderManager else {
            throw VPNError.tunnelNotConfigured
        }

        // Ensure enabled
        if !manager.isEnabled {
            manager.isEnabled = true
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                manager.saveToPreferences { error in
                    if let error = error {
                        continuation.resume(throwing: VPNError.configurationFailed(error.localizedDescription))
                    } else {
                        continuation.resume()
                    }
                }
            }
        }

        // Start the tunnel
        do {
            try manager.connection.startVPNTunnel()
        } catch {
            throw VPNError.connectionFailed(error.localizedDescription)
        }
    }

    /// Stop VPN connection
    func disconnect() async {
        tunnelProviderManager?.connection.stopVPNTunnel()
    }

    // MARK: - Status Observer
    private func setupStatusObserver() {
        // Remove existing observer
        if let observer = statusObserver {
            NotificationCenter.default.removeObserver(observer)
        }

        guard let manager = tunnelProviderManager else { return }

        // Observe status changes
        statusObserver = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object: manager.connection,
            queue: .main
        ) { [weak self] _ in
            guard let self = self else { return }
            let status = manager.connection.status
            self.statusSubject.send(status)
            self.handleStatusChange(status)
        }
    }

    private func handleStatusChange(_ status: NEVPNStatus) {
        switch status {
        case .connected:
            loadConfigurationFromExtension()
        case .disconnected:
            configurationSubject.send(nil)
        default:
            break
        }
    }

    // MARK: - Configuration from Extension
    private func loadConfigurationFromExtension() {
        // Load configuration from shared app group
        guard let sharedDefaults = UserDefaults(suiteName: appGroupIdentifier) else {
            return
        }

        guard let configData = sharedDefaults.data(forKey: "vpn_configuration"),
              let configDict = try? JSONSerialization.jsonObject(with: configData) as? [String: Any]
        else {
            return
        }

        let config = VPNConfiguration(
            assignedIP: configDict["assignedIP"] as? String ?? "",
            subnetMask: configDict["subnetMask"] as? String ?? "",
            gateway: configDict["gateway"] as? String ?? "",
            dns: configDict["dns"] as? [String] ?? [],
            mtu: configDict["mtu"] as? Int ?? 1400
        )

        configurationSubject.send(config)
    }

    // MARK: - Statistics
    func getStatistics() -> VPNStatistics? {
        guard let sharedDefaults = UserDefaults(suiteName: appGroupIdentifier) else {
            return nil
        }

        let bytesReceived = sharedDefaults.object(forKey: "vpn_bytes_received") as? UInt64 ?? 0
        let bytesSent = sharedDefaults.object(forKey: "vpn_bytes_sent") as? UInt64 ?? 0

        return VPNStatistics(bytesReceived: bytesReceived, bytesSent: bytesSent)
    }

    // MARK: - IPC with Extension
    /// Send message to tunnel provider extension
    func sendMessageToExtension(_ message: [String: Any]) async throws -> [String: Any]? {
        guard let session = tunnelProviderManager?.connection as? NETunnelProviderSession else {
            throw VPNError.tunnelNotConfigured
        }

        let messageData = try JSONSerialization.data(withJSONObject: message)

        return try await withCheckedThrowingContinuation { continuation in
            do {
                try session.sendProviderMessage(messageData) { responseData in
                    if let data = responseData,
                       let response = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                        continuation.resume(returning: response)
                    } else {
                        continuation.resume(returning: nil)
                    }
                }
            } catch {
                continuation.resume(throwing: error)
            }
        }
    }

    /// Request statistics from extension
    func requestStatisticsFromExtension() async {
        do {
            let message: [String: Any] = ["command": "getStatistics"]
            let _ = try await sendMessageToExtension(message)
        } catch {
            print("Failed to request statistics: \(error.localizedDescription)")
        }
    }
}
