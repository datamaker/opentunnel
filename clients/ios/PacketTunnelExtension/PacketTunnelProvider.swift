//
//  PacketTunnelProvider.swift
//  PacketTunnelExtension
//
//  VPN Packet Tunnel Provider Implementation
//

import NetworkExtension
import Foundation

class PacketTunnelProvider: NEPacketTunnelProvider {
    // MARK: - Properties
    private var tlsConnection: TLSConnection?
    private var serverAddress: String = ""
    private var serverPort: Int = 443
    private var username: String = ""
    private var password: String = ""
    private var sessionToken: String = ""

    // Connection state
    private var isConnected = false
    private var pendingStartCompletion: ((Error?) -> Void)?

    // Keep alive timer
    private var keepAliveTimer: DispatchSourceTimer?
    private let keepAliveInterval: TimeInterval = 30.0
    private var lastKeepAliveResponse: Date?

    // Statistics
    private var bytesReceived: UInt64 = 0
    private var bytesSent: UInt64 = 0

    // Configuration received from server
    private var assignedIP: String = ""
    private var subnetMask: String = ""
    private var gateway: String = ""
    private var dnsServers: [String] = []
    private var mtu: Int = 1400

    // Split tunneling (destination-based routing)
    private var splitTunnel: Bool = false
    private var includedRoutes: [String] = []
    private var includedDomains: [String] = []
    private var domainMatcher: DomainMatcher?
    private var dynamicRoutes: Set<String> = []

    // App group for sharing data with main app
    private let appGroupIdentifier = "group.com.vpnclient.ios"

    // Stream buffer for incoming data
    private var streamBuffer = StreamBuffer()

    // MARK: - Tunnel Lifecycle
    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        NSLog("[PacketTunnel] Starting tunnel...")

        pendingStartCompletion = completionHandler

        // Extract configuration from provider configuration
        guard let providerConfig = protocolConfiguration as? NETunnelProviderProtocol,
              let config = providerConfig.providerConfiguration else {
            completionHandler(PacketTunnelError.invalidConfiguration)
            return
        }

        // Parse configuration
        guard let serverAddress = config["serverAddress"] as? String,
              let serverPort = config["serverPort"] as? Int,
              let username = config["username"] as? String,
              let password = config["password"] as? String else {
            completionHandler(PacketTunnelError.invalidConfiguration)
            return
        }

        self.serverAddress = serverAddress
        self.serverPort = serverPort
        self.username = username
        self.password = password

        NSLog("[PacketTunnel] Connecting to \(serverAddress):\(serverPort)")

        // Create TLS connection
        tlsConnection = TLSConnection(host: serverAddress, port: serverPort)
        tlsConnection?.delegate = self

        // Start connection
        tlsConnection?.connect { [weak self] result in
            switch result {
            case .success:
                NSLog("[PacketTunnel] TLS connection established")
                self?.performAuthentication()

            case .failure(let error):
                NSLog("[PacketTunnel] Connection failed: \(error.localizedDescription)")
                completionHandler(error)
            }
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        NSLog("[PacketTunnel] Stopping tunnel with reason: \(reason.rawValue)")

        // Stop keep alive timer
        stopKeepAliveTimer()

        // Send disconnect message
        sendDisconnectMessage()

        // Close connection
        tlsConnection?.disconnect()
        tlsConnection = nil

        isConnected = false

        // Clear statistics
        saveStatistics()

        completionHandler()
    }

    // MARK: - Authentication
    private func performAuthentication() {
        NSLog("[PacketTunnel] Performing authentication...")

        let clientVersion = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "1.0"
        let authRequest = AuthRequest(
            username: username,
            password: password,
            clientVersion: clientVersion,
            platform: "ios"
        )

        do {
            let data = try VPNMessageSerializer.serialize(authRequest)
            tlsConnection?.send(data: data) { [weak self] error in
                if let error = error {
                    NSLog("[PacketTunnel] Failed to send auth request: \(error.localizedDescription)")
                    self?.pendingStartCompletion?(error)
                    self?.pendingStartCompletion = nil
                }
            }
        } catch {
            NSLog("[PacketTunnel] Failed to serialize auth request: \(error.localizedDescription)")
            pendingStartCompletion?(error)
            pendingStartCompletion = nil
        }
    }

    // MARK: - Tunnel Configuration
    private func configureTunnel() {
        NSLog("[PacketTunnel] Configuring tunnel...")
        NSLog("[PacketTunnel] Assigned IP: \(assignedIP)")
        NSLog("[PacketTunnel] Gateway: \(gateway)")
        NSLog("[PacketTunnel] DNS: \(dnsServers)")
        NSLog("[PacketTunnel] MTU: \(mtu)")

        // Apply settings
        setTunnelNetworkSettings(makeTunnelSettings()) { [weak self] error in
            if let error = error {
                NSLog("[PacketTunnel] Failed to set tunnel settings: \(error.localizedDescription)")
                self?.pendingStartCompletion?(error)
                self?.pendingStartCompletion = nil
                return
            }

            NSLog("[PacketTunnel] Tunnel configured successfully")

            self?.isConnected = true
            self?.startKeepAliveTimer()
            self?.startReadingPackets()
            self?.saveConfiguration()

            // Complete tunnel start
            self?.pendingStartCompletion?(nil)
            self?.pendingStartCompletion = nil
        }
    }

    /// Build the tunnel settings, honoring split-tunnel policy.
    private func makeTunnelSettings() -> NEPacketTunnelNetworkSettings {
        // tunnelRemoteAddress must be a valid IP (a hostname like "vpn.cacheby.com"
        // is rejected as "Invalid NETunnelNetworkSettings tunnelRemoteAddress").
        // Use the VPN gateway IP, matching the macOS client.
        let tunnelSettings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: gateway)
        let ipv4Settings = NEIPv4Settings(addresses: [assignedIP], subnetMasks: [subnetMask])

        if splitTunnel {
            // Route only the included destinations through the tunnel.
            ipv4Settings.includedRoutes = buildSplitRoutes()
        } else {
            let defaultRoute = NEIPv4Route.default()
            defaultRoute.gatewayAddress = gateway
            ipv4Settings.includedRoutes = [defaultRoute]
            // Keep the VPN server itself off the tunnel to avoid loops. NEIPv4Route
            // needs an IP, so only add this when serverAddress is an IP (not a
            // hostname). In split mode the server isn't routed in, so it's moot.
            if CidrUtils.parse(serverAddress) != nil {
                ipv4Settings.excludedRoutes = [
                    NEIPv4Route(destinationAddress: serverAddress, subnetMask: "255.255.255.255")
                ]
            }
        }
        tunnelSettings.ipv4Settings = ipv4Settings

        // Route DNS through the tunnel resolver so answers are observable for
        // domain-based rules (needed for CDN hostname matching).
        let dnsSettings = NEDNSSettings(servers: dnsServers)
        dnsSettings.matchDomains = [""]
        tunnelSettings.dnsSettings = dnsSettings
        tunnelSettings.mtu = NSNumber(value: mtu)
        return tunnelSettings
    }

    private func buildSplitRoutes() -> [NEIPv4Route] {
        var routes: [NEIPv4Route] = []
        for cidr in includedRoutes {
            if let c = CidrUtils.parse(cidr) {
                routes.append(NEIPv4Route(destinationAddress: c.address,
                                          subnetMask: CidrUtils.mask(forPrefix: c.prefix)))
            }
        }
        if let matcher = domainMatcher, !matcher.isEmpty {
            for dns in dnsServers where CidrUtils.parse(dns) != nil {
                routes.append(NEIPv4Route(destinationAddress: dns, subnetMask: "255.255.255.255"))
            }
            for ip in dynamicRoutes {
                routes.append(NEIPv4Route(destinationAddress: ip, subnetMask: "255.255.255.255"))
            }
        }
        NSLog("[PacketTunnel] Split tunnel: \(routes.count) route(s), \(includedDomains.count) domain rule(s)")
        return routes
    }

    /// Re-apply tunnel settings after learning new split routes (no timer/reader restart).
    private func reapplyTunnelSettings() {
        setTunnelNetworkSettings(makeTunnelSettings()) { error in
            if let error = error {
                NSLog("[PacketTunnel] Failed to re-apply split routes: \(error.localizedDescription)")
            }
        }
    }

    // MARK: - Packet Handling
    private func startReadingPackets() {
        // Read packets from the virtual interface and send to server
        packetFlow.readPackets { [weak self] packets, protocols in
            self?.handleOutgoingPackets(packets, protocols: protocols)
            self?.startReadingPackets()  // Continue reading
        }
    }

    private func handleOutgoingPackets(_ packets: [Data], protocols: [NSNumber]) {
        for (index, packet) in packets.enumerated() {
            let proto = protocols[index]

            // Only handle IPv4 packets (protocol family 2)
            guard proto.intValue == AF_INET else {
                continue
            }

            // Serialize and send packet
            let serializedData = DataPacketSerializer.serialize(packet)

            tlsConnection?.send(data: serializedData) { [weak self] error in
                if let error = error {
                    NSLog("[PacketTunnel] Failed to send packet: \(error.localizedDescription)")
                } else {
                    self?.bytesSent += UInt64(packet.count)
                }
            }
        }
    }

    private func handleIncomingPacket(_ packet: Data) {
        // Write packet to the virtual interface
        packetFlow.writePackets([packet], withProtocols: [NSNumber(value: AF_INET)])
        bytesReceived += UInt64(packet.count)
        maybeLearnRoute(packet)
    }

    /// Split tunneling: snoop DNS answers for matched domains and route the exact
    /// IPs the client resolved (handles CDN domains by hostname).
    private func maybeLearnRoute(_ packet: Data) {
        guard splitTunnel, let matcher = domainMatcher, !matcher.isEmpty else { return }
        guard let dns = DnsSniffer.parse(packet), matcher.matches(dns.qname) else { return }
        let added = dns.addresses.filter { dynamicRoutes.insert($0).inserted }
        if !added.isEmpty {
            NSLog("[PacketTunnel] Split tunnel: learned \(added.count) route(s) for \(dns.qname)")
            reapplyTunnelSettings()
        }
    }

    // MARK: - Message Handling
    private func handleMessage(_ message: any VPNMessageProtocol) {
        switch message {
        case let authResponse as AuthResponse:
            handleAuthResponse(authResponse)

        case let configPush as ConfigPush:
            handleConfigPush(configPush)

        case _ as KeepAliveAck:
            handleKeepAliveAck()

        case let disconnect as DisconnectMessage:
            handleDisconnect(disconnect)

        case let dataPacket as DataPacket:
            handleIncomingPacket(dataPacket.payload)

        default:
            NSLog("[PacketTunnel] Received unknown message type")
        }
    }

    private func handleAuthResponse(_ response: AuthResponse) {
        if response.success {
            NSLog("[PacketTunnel] Authentication successful")
            sessionToken = response.sessionToken ?? ""
            // Wait for CONFIG_PUSH from server
        } else {
            NSLog("[PacketTunnel] Authentication failed: \(response.errorMessage ?? "Unknown error")")
            let error = PacketTunnelError.authenticationFailed(response.errorMessage ?? "Unknown error")
            pendingStartCompletion?(error)
            pendingStartCompletion = nil
        }
    }

    private func handleConfigPush(_ config: ConfigPush) {
        NSLog("[PacketTunnel] Received configuration from server")

        assignedIP = config.assignedIP
        subnetMask = config.subnetMask
        gateway = config.gateway
        dnsServers = config.dns
        mtu = config.mtu

        splitTunnel = config.splitTunnel ?? false
        includedRoutes = config.includedRoutes ?? []
        includedDomains = config.includedDomains ?? []
        domainMatcher = (splitTunnel && !includedDomains.isEmpty) ? DomainMatcher(includedDomains) : nil
        dynamicRoutes = []

        configureTunnel()
    }

    private func handleKeepAliveAck() {
        lastKeepAliveResponse = Date()
        NSLog("[PacketTunnel] Received keep alive ack")
    }

    private func handleDisconnect(_ message: DisconnectMessage) {
        NSLog("[PacketTunnel] Received disconnect from server: \(message.reason)")

        // Cancel pending connection
        if pendingStartCompletion != nil {
            pendingStartCompletion?(PacketTunnelError.connectionClosed)
            pendingStartCompletion = nil
        }

        // Stop the tunnel
        cancelTunnelWithError(PacketTunnelError.serverDisconnected)
    }

    // MARK: - Keep Alive
    private func startKeepAliveTimer() {
        let timer = DispatchSource.makeTimerSource(queue: DispatchQueue.global())
        timer.schedule(deadline: .now() + keepAliveInterval, repeating: keepAliveInterval)
        timer.setEventHandler { [weak self] in
            self?.sendKeepAlive()
        }
        timer.resume()
        keepAliveTimer = timer
    }

    private func stopKeepAliveTimer() {
        keepAliveTimer?.cancel()
        keepAliveTimer = nil
    }

    private func sendKeepAlive() {
        guard isConnected else { return }

        let keepAlive = KeepAlive()

        do {
            let data = try VPNMessageSerializer.serialize(keepAlive)
            tlsConnection?.send(data: data) { error in
                if let error = error {
                    NSLog("[PacketTunnel] Failed to send keep alive: \(error.localizedDescription)")
                }
            }
        } catch {
            NSLog("[PacketTunnel] Failed to serialize keep alive: \(error.localizedDescription)")
        }
    }

    private func sendDisconnectMessage() {
        guard isConnected else { return }

        let disconnect = DisconnectMessage(reason: .userRequested)

        do {
            let data = try VPNMessageSerializer.serialize(disconnect)
            tlsConnection?.send(data: data) { _ in }
        } catch {
            NSLog("[PacketTunnel] Failed to serialize disconnect: \(error.localizedDescription)")
        }
    }

    // MARK: - Data Persistence
    private func saveConfiguration() {
        guard let sharedDefaults = UserDefaults(suiteName: appGroupIdentifier) else {
            return
        }

        let config: [String: Any] = [
            "assignedIP": assignedIP,
            "subnetMask": subnetMask,
            "gateway": gateway,
            "dns": dnsServers,
            "mtu": mtu
        ]

        if let data = try? JSONSerialization.data(withJSONObject: config) {
            sharedDefaults.set(data, forKey: "vpn_configuration")
        }
    }

    private func saveStatistics() {
        guard let sharedDefaults = UserDefaults(suiteName: appGroupIdentifier) else {
            return
        }

        sharedDefaults.set(bytesReceived, forKey: "vpn_bytes_received")
        sharedDefaults.set(bytesSent, forKey: "vpn_bytes_sent")
    }

    // MARK: - IPC from App
    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        guard let message = try? JSONSerialization.jsonObject(with: messageData) as? [String: Any],
              let command = message["command"] as? String else {
            completionHandler?(nil)
            return
        }

        switch command {
        case "getStatistics":
            let stats: [String: Any] = [
                "bytesReceived": bytesReceived,
                "bytesSent": bytesSent,
                "isConnected": isConnected
            ]
            let responseData = try? JSONSerialization.data(withJSONObject: stats)
            completionHandler?(responseData)

        case "getConfiguration":
            let config: [String: Any] = [
                "assignedIP": assignedIP,
                "subnetMask": subnetMask,
                "gateway": gateway,
                "dns": dnsServers,
                "mtu": mtu
            ]
            let responseData = try? JSONSerialization.data(withJSONObject: config)
            completionHandler?(responseData)

        default:
            completionHandler?(nil)
        }
    }

    override func sleep(completionHandler: @escaping () -> Void) {
        // Handle sleep - pause keep alive
        stopKeepAliveTimer()
        completionHandler()
    }

    override func wake() {
        // Handle wake - resume keep alive
        if isConnected {
            startKeepAliveTimer()
        }
    }
}

// MARK: - TLSConnectionDelegate
extension PacketTunnelProvider: TLSConnectionDelegate {
    func tlsConnection(_ connection: TLSConnection, didReceive data: Data) {
        do {
            try streamBuffer.append(data)

            let messages = try streamBuffer.extractMessages()
            for message in messages {
                handleMessage(message)
            }
        } catch {
            NSLog("[PacketTunnel] Error processing received data: \(error.localizedDescription)")
        }
    }

    func tlsConnection(_ connection: TLSConnection, didDisconnectWithError error: Error?) {
        if let error = error {
            NSLog("[PacketTunnel] Connection disconnected with error: \(error.localizedDescription)")
        } else {
            NSLog("[PacketTunnel] Connection disconnected")
        }

        isConnected = false

        // Complete pending start if any
        if pendingStartCompletion != nil {
            pendingStartCompletion?(error ?? PacketTunnelError.connectionClosed)
            pendingStartCompletion = nil
        }

        // Cancel the tunnel
        cancelTunnelWithError(error)
    }
}

// MARK: - Errors
enum PacketTunnelError: LocalizedError {
    case invalidConfiguration
    case authenticationFailed(String)
    case connectionFailed(String)
    case connectionClosed
    case serverDisconnected

    var errorDescription: String? {
        switch self {
        case .invalidConfiguration:
            return "Invalid tunnel configuration"
        case .authenticationFailed(let message):
            return "Authentication failed: \(message)"
        case .connectionFailed(let message):
            return "Connection failed: \(message)"
        case .connectionClosed:
            return "Connection was closed"
        case .serverDisconnected:
            return "Server requested disconnect"
        }
    }
}
