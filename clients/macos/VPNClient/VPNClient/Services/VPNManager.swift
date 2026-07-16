//
//  VPNManager.swift
//  VPNClient
//
//  Manages VPN connection using NetworkExtension framework
//

import Foundation
import NetworkExtension
import Combine

// MARK: - VPN Status

enum VPNStatus: String {
    case disconnected = "Disconnected"
    case connecting = "Connecting..."
    case connected = "Connected"
    case disconnecting = "Disconnecting..."
    case invalid = "Invalid"
    case reasserting = "Reasserting..."

    var isConnected: Bool {
        return self == .connected
    }
}

// MARK: - VPN Manager

@MainActor
class VPNManager: ObservableObject {

    // MARK: - Published Properties

    @Published var status: VPNStatus = .disconnected
    @Published var assignedIP: String = ""
    @Published var connectedTime: Date?
    @Published var errorMessage: String?
    @Published var bytesIn: UInt64 = 0
    @Published var bytesOut: UInt64 = 0
    @Published var gateway: String = ""
    @Published var dnsServers: [String] = []
    @Published var mtu: Int = 0

    // MARK: - Configuration

    var serverAddress: String = "localhost:1194"

    // MARK: - Private Properties

    private var manager: NETunnelProviderManager?
    private var statusObserver: NSObjectProtocol?

    // MARK: - Singleton

    static let shared = VPNManager()

    private init() {
        Task {
            await loadManager()
        }
    }

    deinit {
        if let observer = statusObserver {
            NotificationCenter.default.removeObserver(observer)
        }
    }

    // MARK: - Manager Setup

    private func loadManager() async {
        print("🔵 Loading VPN manager...")
        do {
            let managers = try await NETunnelProviderManager.loadAllFromPreferences()
            print("🔵 Found \(managers.count) existing managers")

            if let existingManager = managers.first {
                self.manager = existingManager
                print("✅ Using existing manager")
            } else {
                self.manager = NETunnelProviderManager()
                print("✅ Created new manager")
            }

            setupStatusObserver()
            updateStatus()
            print("✅ Manager ready, status: \(status.rawValue)")
        } catch {
            print("❌ Failed to load VPN manager: \(error)")
            errorMessage = error.localizedDescription
        }
    }

    private func setupStatusObserver() {
        statusObserver = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object: manager?.connection,
            queue: .main
        ) { [weak self] _ in
            guard let self = self else { return }
            Task { @MainActor [weak self] in
                self?.updateStatus()
            }
        }
    }

    private func updateStatus() {
        guard let connection = manager?.connection else {
            status = .invalid
            return
        }

        switch connection.status {
        case .invalid:
            status = .invalid
        case .disconnected:
            status = .disconnected
            assignedIP = ""
            connectedTime = nil
            bytesIn = 0
            bytesOut = 0
            gateway = ""
            dnsServers = []
            mtu = 0
        case .connecting:
            status = .connecting
        case .connected:
            status = .connected
            if connectedTime == nil {
                connectedTime = Date()
            }
        case .reasserting:
            status = .reasserting
        case .disconnecting:
            status = .disconnecting
        @unknown default:
            status = .invalid
        }
    }

    // MARK: - Connection Methods

    func connect(username: String, password: String) async throws {
        print("🔵 Connect called")

        guard let manager = manager else {
            print("❌ Manager is nil!")
            throw VPNError.configurationFailed("VPN manager not initialized")
        }

        errorMessage = nil

        // Configure the VPN
        let bundleId = Bundle.main.bundleIdentifier! + ".PacketTunnel"
        print("🔵 Extension Bundle ID: \(bundleId)")

        let tunnelProtocol = NETunnelProviderProtocol()
        tunnelProtocol.providerBundleIdentifier = bundleId
        tunnelProtocol.serverAddress = serverAddress
        tunnelProtocol.providerConfiguration = [
            "serverAddress": serverAddress,
            "username": username,
            "password": password
        ]

        manager.protocolConfiguration = tunnelProtocol
        manager.localizedDescription = "VPN Client"
        manager.isEnabled = true

        // Save configuration
        print("🔵 Saving to preferences...")
        do {
            try await manager.saveToPreferences()
            print("✅ Saved!")
        } catch {
            print("❌ Save failed: \(error)")
            errorMessage = error.localizedDescription
            throw error
        }

        print("🔵 Loading from preferences...")
        do {
            try await manager.loadFromPreferences()
            print("✅ Loaded!")
        } catch {
            print("❌ Load failed: \(error)")
            errorMessage = error.localizedDescription
            throw error
        }

        // Start the tunnel
        print("🔵 Starting VPN tunnel...")
        do {
            try manager.connection.startVPNTunnel()
            print("✅ startVPNTunnel called!")
        } catch {
            print("❌ Start failed: \(error)")
            errorMessage = error.localizedDescription
            throw error
        }
    }

    func disconnect() {
        manager?.connection.stopVPNTunnel()
    }

    // MARK: - Status Query

    func queryStatus() async -> [String: Any]? {
        guard let session = manager?.connection as? NETunnelProviderSession else {
            return nil
        }

        return await withCheckedContinuation { continuation in
            do {
                try session.sendProviderMessage("stats".data(using: .utf8)!) { response in
                    if let data = response,
                       let stats = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                        continuation.resume(returning: stats)
                    } else {
                        continuation.resume(returning: nil)
                    }
                }
            } catch {
                continuation.resume(returning: nil)
            }
        }
    }

    func refreshStats() async {
        guard status.isConnected else { return }

        if let stats = await queryStatus() {
            if let inBytes = stats["bytesIn"] as? UInt64 {
                bytesIn = inBytes
            } else if let inBytes = stats["bytesIn"] as? Int {
                bytesIn = UInt64(inBytes)
            }
            if let outBytes = stats["bytesOut"] as? UInt64 {
                bytesOut = outBytes
            } else if let outBytes = stats["bytesOut"] as? Int {
                bytesOut = UInt64(outBytes)
            }
            if let ip = stats["assignedIP"] as? String, !ip.isEmpty {
                assignedIP = ip
            }
            if let gw = stats["gateway"] as? String {
                gateway = gw
            }
            if let dns = stats["dns"] as? [String] {
                dnsServers = dns
            }
            if let m = stats["mtu"] as? Int {
                mtu = m
            }
        }
    }
}
