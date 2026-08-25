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
    /// App-driven auto-reconnect after an unexpected drop (backoff retries).
    /// Distinct from `.reasserting`, which is the system's own transient state.
    case reconnecting = "Reconnecting..."

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

    // MARK: - Disconnect / Auto-reconnect State

    /// Set (in UserDefaults) right before a user-requested stop so the
    /// .disconnected observation can tell an intentional disconnect from an
    /// unexpected drop. Consumed (removed) when .disconnected is observed.
    private static let userInitiatedDisconnectKey = "vpn_user_initiated_disconnect"
    /// Settings toggle: auto-reconnect after an unexpected drop (default ON).
    static let autoReconnectKey = "vpn_auto_reconnect"

    static var isAutoReconnectEnabled: Bool {
        let defaults = UserDefaults.standard
        if defaults.object(forKey: autoReconnectKey) == nil { return true }
        return defaults.bool(forKey: autoReconnectKey)
    }

    /// True once a session has reached .connected; an observed .disconnected is
    /// only "unexpected" when a live connection actually dropped (NE may pass
    /// through .disconnecting on the way down, so the previous status alone
    /// cannot be trusted).
    private var hadActiveConnection = false
    /// The running backoff-retry loop, if an auto-reconnect is in progress.
    private var reconnectTask: Task<Void, Never>?
    /// Backoff schedule: 2, 4, 8, 16 s, then every 30 s — 10 attempts total.
    private static let reconnectDelays: [TimeInterval] = [2, 4, 8, 16, 30, 30, 30, 30, 30, 30]

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
            assignedIP = ""
            connectedTime = nil
            bytesIn = 0
            bytesOut = 0
            gateway = ""
            dnsServers = []
            mtu = 0
            // If the server rejected our SSO session token, clear it so the
            // user is sent back through the SSO flow.
            AppSession.shared.handleSSOSessionRejectionIfNeeded()
            handleDisconnected()
        case .connecting:
            // While our backoff loop is driving retries, surface the whole
            // sequence as "Reconnecting" instead of flip-flopping states.
            status = (reconnectTask != nil) ? .reconnecting : .connecting
        case .connected:
            status = .connected
            hadActiveConnection = true
            // A stale "user initiated" flag (e.g. from a disconnect that fired
            // no status event) must not misclassify the next real drop.
            UserDefaults.standard.removeObject(forKey: Self.userInitiatedDisconnectKey)
            if connectedTime == nil {
                connectedTime = Date()
            }
            // First SSO connect: the extension leaves the server-issued session
            // token in the App Group — move it into the Keychain.
            AppSession.shared.adoptPendingSSOSessionToken()
            if reconnectTask != nil {
                reconnectTask?.cancel()
                reconnectTask = nil
                NotificationService.shared.postIfEnabled(
                    title: "VPN Reconnected",
                    body: "The VPN connection has been restored."
                )
            }
        case .reasserting:
            status = .reasserting
        case .disconnecting:
            status = .disconnecting
        @unknown default:
            status = .invalid
        }
    }

    /// Classifies an observed .disconnected: intentional (user pressed
    /// Disconnect / logged out), a failed auto-reconnect attempt, or an
    /// unexpected drop — and notifies / starts the reconnect loop accordingly.
    private func handleDisconnected() {
        let defaults = UserDefaults.standard
        let userInitiated = defaults.bool(forKey: Self.userInitiatedDisconnectKey)
        defaults.removeObject(forKey: Self.userInitiatedDisconnectKey)

        if reconnectTask != nil {
            // A reconnect attempt just failed — the loop keeps retrying.
            status = .reconnecting
            hadActiveConnection = false
            return
        }

        status = .disconnected

        let wasConnected = hadActiveConnection
        hadActiveConnection = false
        guard wasConnected, !userInitiated else { return }

        // Unexpected drop of a live connection.
        NotificationService.shared.postIfEnabled(
            title: "VPN Disconnected",
            body: "The VPN connection was lost unexpectedly."
        )
        if Self.isAutoReconnectEnabled {
            startAutoReconnect()
        }
    }

    // MARK: - Connection Methods

    func connect(username: String, password: String) async throws {
        try await connect(providerConfiguration: [
            "serverAddress": serverAddress,
            "username": username,
            "password": password
        ])
    }

    /// SSO connect: authType "sso" with the IdP id_token (first connect) or
    /// "session" with the server-issued 30-day session token.
    func connect(authType: String, token: String) async throws {
        try await connect(providerConfiguration: [
            "serverAddress": serverAddress,
            "authType": authType,
            "token": token
        ])
    }

    /// Connects using the credentials of the current AppSession — the single
    /// connect entry point shared by MainView, the menu-bar item and the
    /// auto-reconnect loop. SSO sessions send the server-issued 30-day session
    /// token (authType "session") when one is stored, otherwise the fresh
    /// id_token ("sso"); password sessions send username/password.
    /// Throws `VPNError.authenticationFailed` when no usable credential exists
    /// (e.g. the session token was rejected and cleared) and
    /// `VPNError.configurationFailed` when there is no signed-in session.
    func connectUsingCurrentSession() async throws {
        let session = AppSession.shared
        guard session.isLoggedIn, !session.serverHost.isEmpty else {
            throw VPNError.configurationFailed("Not signed in")
        }
        serverAddress = "\(session.serverHost):\(session.serverPort)"

        if session.authMethod == .sso {
            guard let credential = session.ssoCredential() else {
                throw VPNError.authenticationFailed("No SSO credential — sign in again")
            }
            try await connect(authType: credential.authType, token: credential.token)
        } else {
            guard !session.username.isEmpty, !session.password.isEmpty else {
                throw VPNError.authenticationFailed("No stored credentials")
            }
            try await connect(username: session.username, password: session.password)
        }
    }

    private func connect(providerConfiguration: [String: Any]) async throws {
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
        tunnelProtocol.providerConfiguration = providerConfiguration

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
        // Mark this stop as user-requested so the .disconnected observation
        // does not treat it as an unexpected drop (no notification, no
        // auto-reconnect). Consumed in handleDisconnected().
        UserDefaults.standard.set(true, forKey: Self.userInitiatedDisconnectKey)

        // A disconnect during auto-reconnect cancels the retry loop.
        if reconnectTask != nil {
            reconnectTask?.cancel()
            reconnectTask = nil
            updateStatus()
        }

        manager?.connection.stopVPNTunnel()
    }

    // MARK: - Auto-reconnect

    private func startAutoReconnect() {
        guard reconnectTask == nil else { return }
        status = .reconnecting
        reconnectTask = Task { [weak self] in
            await self?.runReconnectLoop()
        }
    }

    private func runReconnectLoop() async {
        for delay in Self.reconnectDelays {
            do {
                try await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
            } catch {
                return // cancelled (user disconnected, or we got connected)
            }
            if Task.isCancelled { return }

            guard let attempted = await attemptReconnectOnce() else {
                break // unrecoverable (no credentials / logged out) — stop early
            }
            if attempted { return } // connected — the .connected observer cleans up
            if Task.isCancelled { return }
        }

        // All attempts exhausted (or credentials gone).
        guard reconnectTask != nil else { return }
        reconnectTask = nil
        updateStatus()
        NotificationService.shared.postIfEnabled(
            title: "VPN Reconnect Failed",
            body: "Could not restore the VPN connection. Connect manually to retry."
        )
    }

    /// Runs one reconnect attempt through the regular connect path (reusing the
    /// stored SSO session token / remembered credentials) and waits for the
    /// tunnel to settle. Returns true when connected, false when the attempt
    /// failed, and nil when reconnecting is impossible (no credentials).
    private func attemptReconnectOnce() async -> Bool? {
        do {
            try await connectUsingCurrentSession()
        } catch let error as VPNError {
            switch error {
            case .configurationFailed, .authenticationFailed:
                return nil // logged out / credentials gone — retrying is pointless
            default:
                return false
            }
        } catch {
            return false
        }

        // Wait (up to 30 s) for the tunnel to reach a terminal state.
        for _ in 0..<60 {
            try? await Task.sleep(nanoseconds: 500_000_000)
            if Task.isCancelled {
                return manager?.connection.status == .connected
            }
            switch manager?.connection.status {
            case .connected:
                return true
            case .disconnected, .invalid, .none:
                return false
            default:
                continue // still connecting
            }
        }
        return false
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
