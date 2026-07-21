//
//  PacketTunnelProvider.swift
//  PacketTunnel
//

import NetworkExtension
import Network
import os.log

class PacketTunnelProvider: NEPacketTunnelProvider {

    // MARK: - Properties

    private var connection: NWConnection?
    private var pendingCompletion: ((Error?) -> Void)?
    private var messageBuffer = VPNMessageBuffer()
    private var sessionToken: String?
    private var isRunning = false
    private var bytesIn: UInt64 = 0
    private var bytesOut: UInt64 = 0
    private var serverHost: String = ""

    // Split-tunnel state (populated from the server's ConfigPush).
    private var tunnelConfig: ConfigPush?
    private var domainMatcher: DomainMatcher?
    private var dynamicRoutes: Set<String> = []

    // Keepalive / liveness. Without a periodic keepalive the server drops an
    // idle connection after ~120s; this also gives dead-peer detection. Matches
    // the Android/Windows clients' behavior.
    private var keepaliveTimer: DispatchSourceTimer?
    private var lastActivity = Date()
    private let keepaliveInterval: TimeInterval = 20
    private let idleTimeout: TimeInterval = 90

    private let logger = Logger(subsystem: "com.vpnclient.tunnel", category: "Provider")

    // MARK: - Tunnel Lifecycle

    override func startTunnel(options: [String : NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        logger.info("Starting tunnel...")
        pendingCompletion = completionHandler

        guard let config = protocolConfiguration as? NETunnelProviderProtocol,
              let providerConfig = config.providerConfiguration,
              let serverAddress = providerConfig["serverAddress"] as? String,
              let username = providerConfig["username"] as? String,
              let password = providerConfig["password"] as? String else {
            completionHandler(VPNError.configurationFailed("Invalid configuration"))
            return
        }

        // Parse server address
        let parts = serverAddress.split(separator: ":")
        guard parts.count == 2, let port = UInt16(parts[1]) else {
            completionHandler(VPNError.configurationFailed("Invalid server address"))
            return
        }

        let host = String(parts[0])
        serverHost = host
        logger.info("Connecting to \(host):\(port)")

        // Store credentials
        UserDefaults.standard.set(username, forKey: "vpn_username")
        UserDefaults.standard.set(password, forKey: "vpn_password")

        // Create TLS connection
        connectToServer(host: host, port: port)
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        logger.info("Stopping tunnel: \(String(describing: reason))")
        isRunning = false
        stopKeepalive()
        // Best-effort: tell the server we're leaving so it releases the session
        // promptly (parity with the Android/Windows clients).
        sendMessage(Disconnect())
        connection?.cancel()
        connection = nil
        completionHandler()
    }

    // MARK: - Keepalive

    private func startKeepalive() {
        stopKeepalive()
        let timer = DispatchSource.makeTimerSource(queue: .global())
        timer.schedule(deadline: .now() + keepaliveInterval, repeating: keepaliveInterval)
        timer.setEventHandler { [weak self] in
            guard let self = self, self.isRunning else { return }
            if Date().timeIntervalSince(self.lastActivity) > self.idleTimeout {
                self.logger.error("Keepalive timeout — no activity, stopping tunnel")
                self.cancelTunnelWithError(NSError(
                    domain: "VPN", code: -1,
                    userInfo: [NSLocalizedDescriptionKey: "Keepalive timeout"]))
                return
            }
            self.sendMessage(KeepAlive())
        }
        timer.resume()
        keepaliveTimer = timer
    }

    private func stopKeepalive() {
        keepaliveTimer?.cancel()
        keepaliveTimer = nil
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        if let command = String(data: messageData, encoding: .utf8) {
            switch command {
            case "status":
                let status = isRunning ? "connected" : "disconnected"
                completionHandler?(status.data(using: .utf8))
            case "stats":
                var stats: [String: Any] = [
                    "bytesIn": bytesIn,
                    "bytesOut": bytesOut,
                    "isRunning": isRunning
                ]
                // Surface the pushed network config so the app can display it.
                if let cfg = tunnelConfig {
                    stats["assignedIP"] = cfg.assignedIP
                    stats["gateway"] = cfg.gateway
                    stats["dns"] = cfg.dns
                    stats["mtu"] = Int(cfg.mtu)
                }
                if let data = try? JSONSerialization.data(withJSONObject: stats) {
                    completionHandler?(data)
                } else {
                    completionHandler?(nil)
                }
            default:
                completionHandler?(nil)
            }
        } else {
            completionHandler?(nil)
        }
    }

    // MARK: - Connection

    private func connectToServer(host: String, port: UInt16) {
        let tlsOptions = NWProtocolTLS.Options()

        // Accept self-signed certificates (development)
        sec_protocol_options_set_verify_block(tlsOptions.securityProtocolOptions, { _, _, complete in
            complete(true)
        }, .main)

        let params = NWParameters(tls: tlsOptions, tcp: NWProtocolTCP.Options())
        connection = NWConnection(host: NWEndpoint.Host(host), port: NWEndpoint.Port(rawValue: port)!, using: params)

        connection?.stateUpdateHandler = { [weak self] state in
            self?.handleConnectionState(state)
        }

        connection?.start(queue: .main)
    }

    private func handleConnectionState(_ state: NWConnection.State) {
        logger.info("Connection state changed: \(String(describing: state))")

        switch state {
        case .setup:
            logger.info("Connection setup")
        case .waiting(let error):
            logger.info("Connection waiting: \(error)")
        case .preparing:
            logger.info("Connection preparing")
        case .ready:
            logger.info("TLS connected")
            authenticate()
        case .failed(let error):
            logger.error("Connection failed: \(error)")
            if pendingCompletion != nil {
                pendingCompletion?(VPNError.connectionFailed(error.localizedDescription))
                pendingCompletion = nil
            } else {
                // Connection failed after tunnel was established
                logger.error("Connection lost after tunnel setup!")
            }
        case .cancelled:
            logger.info("Connection cancelled")
        @unknown default:
            logger.info("Unknown connection state")
        }
    }

    // MARK: - Authentication

    private func authenticate() {
        guard let username = UserDefaults.standard.string(forKey: "vpn_username"),
              let password = UserDefaults.standard.string(forKey: "vpn_password") else {
            pendingCompletion?(VPNError.authenticationFailed("No credentials"))
            return
        }

        // Clear stored credentials
        UserDefaults.standard.removeObject(forKey: "vpn_username")
        UserDefaults.standard.removeObject(forKey: "vpn_password")

        logger.info("Authenticating: \(username)")

        let request = AuthRequest(username: username, password: password)
        sendMessage(request) { [weak self] error in
            if let error = error {
                self?.pendingCompletion?(error)
                self?.pendingCompletion = nil
            } else {
                self?.startReceiving()
            }
        }
    }

    // MARK: - Messaging

    private func sendMessage(_ message: VPNMessage, completion: ((Error?) -> Void)? = nil) {
        guard let conn = connection else {
            completion?(VPNError.disconnected("Not connected"))
            return
        }

        do {
            let data = try VPNMessageSerializer.serialize(message)
            conn.send(content: data, completion: .contentProcessed { error in
                if let error = error {
                    completion?(VPNError.connectionFailed(error.localizedDescription))
                } else {
                    completion?(nil)
                }
            })
        } catch {
            completion?(error)
        }
    }

    private func startReceiving() {
        let currentIsRunning = self.isRunning
        let hasPending = self.pendingCompletion != nil
        logger.info("Starting receive... isRunning=\(currentIsRunning), hasPendingCompletion=\(hasPending)")

        connection?.receive(minimumIncompleteLength: 5, maximumLength: 65536) { [weak self] data, _, isComplete, error in
            guard let self = self else { return }

            if let error = error {
                self.logger.error("Receive error: \(error), isComplete=\(isComplete)")
                // Don't just return - we need to handle the error properly
                if self.pendingCompletion != nil {
                    self.pendingCompletion?(VPNError.connectionFailed("Receive error: \(error)"))
                    self.pendingCompletion = nil
                }
                return
            }

            if let data = data {
                self.logger.info("Received \(data.count) bytes")
                self.messageBuffer.append(data)
                self.processMessages()
            }

            if isComplete {
                self.logger.info("Connection completed (EOF)")
                return
            }

            if self.isRunning || self.pendingCompletion != nil {
                self.startReceiving()
            } else {
                self.logger.warning("Stopping receive loop: isRunning=\(self.isRunning), pendingCompletion=\(self.pendingCompletion != nil)")
            }
        }
    }

    private func processMessages() {
        do {
            while let message = try messageBuffer.extractMessage() {
                handleMessage(message)
            }
        } catch {
            logger.error("Message parse error: \(error)")
        }
    }

    private func handleMessage(_ message: VPNMessage) {
        logger.info("Handling message type: \(type(of: message))")

        switch message {
        case let response as AuthResponse:
            if response.success {
                logger.info("Auth successful, token: \(response.sessionToken ?? "nil")")
                sessionToken = response.sessionToken
            } else {
                logger.error("Auth failed: \(response.errorMessage ?? "")")
                pendingCompletion?(VPNError.authenticationFailed(response.errorMessage ?? "Failed"))
                pendingCompletion = nil
            }

        case let config as ConfigPush:
            logger.info("Config received - IP: \(config.assignedIP), Gateway: \(config.gateway), DNS: \(config.dns)")
            configureTunnel(config: config)

        case let packet as DataPacket:
            lastActivity = Date()
            handleInboundPacket(packet.payload)

        case is KeepAlive:
            lastActivity = Date()
            sendMessage(KeepAliveAck())

        case is KeepAliveAck:
            lastActivity = Date()

        default:
            break
        }
    }

    // MARK: - Tunnel Configuration

    private func configureTunnel(config: ConfigPush) {
        tunnelConfig = config

        // Set up split-tunnel policy from the server's push (if enabled).
        let splitOn = config.splitTunnel ?? false
        let domains = config.includedDomains ?? []
        domainMatcher = (splitOn && !domains.isEmpty) ? DomainMatcher(domains) : nil
        dynamicRoutes = []

        let settings = makeNetworkSettings(for: config)

        logger.info("Calling setTunnelNetworkSettings... (splitTunnel=\(splitOn))")

        setTunnelNetworkSettings(settings) { [weak self] error in
            guard let self = self else { return }

            if let error = error {
                self.logger.error("Tunnel setup failed: \(error)")
                self.pendingCompletion?(VPNError.tunnelSetupFailed(error.localizedDescription))
            } else {
                self.logger.info("Tunnel configured successfully!")
                self.logger.info("Setting isRunning = true")
                self.isRunning = true
                self.lastActivity = Date()
                self.startKeepalive()
                self.logger.info("Starting packet reading...")
                self.startReadingPackets()
                self.logger.info("Calling pendingCompletion(nil)...")
                self.pendingCompletion?(nil)
                self.logger.info("Tunnel setup complete!")
            }
            self.pendingCompletion = nil
        }
    }

    /// Build tunnel settings, honoring the split-tunnel policy.
    private func makeNetworkSettings(for config: ConfigPush) -> NEPacketTunnelNetworkSettings {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: config.gateway)
        let ipv4 = NEIPv4Settings(addresses: [config.assignedIP], subnetMasks: [config.subnetMask])

        if config.splitTunnel ?? false {
            // Split tunnel: only the policy's routes go through the VPN.
            ipv4.includedRoutes = buildSplitRoutes(config)
        } else {
            // Full tunnel: everything through the VPN, minus the server itself
            // so the control connection keeps working.
            ipv4.includedRoutes = [NEIPv4Route.default()]
            // Exclude the server's own address only when it's a literal IPv4 —
            // an NEIPv4Route built from a hostname is invalid and would be ignored.
            if CidrUtils.parse(serverHost) != nil {
                ipv4.excludedRoutes = [NEIPv4Route(destinationAddress: serverHost, subnetMask: "255.255.255.255")]
            }
        }

        settings.ipv4Settings = ipv4

        // Route DNS through the tunnel so answers are observable for domain learning.
        settings.dnsSettings = NEDNSSettings(servers: config.dns)
        settings.dnsSettings?.matchDomains = [""]
        settings.mtu = NSNumber(value: config.mtu)
        return settings
    }

    private func buildSplitRoutes(_ config: ConfigPush) -> [NEIPv4Route] {
        var routes: [NEIPv4Route] = []
        // Static CIDRs + server-resolved (concrete) domain IPs.
        for cidr in config.includedRoutes ?? [] {
            if let c = CidrUtils.parse(cidr) {
                routes.append(NEIPv4Route(destinationAddress: c.address,
                                          subnetMask: CidrUtils.mask(forPrefix: c.prefix)))
            }
        }
        // Wildcard/CDN domains: route the DNS servers (so lookups are seen) plus
        // the exact IPs we have learned by snooping DNS answers.
        if let matcher = domainMatcher, !matcher.isEmpty {
            for dns in config.dns where CidrUtils.parse(dns) != nil {
                routes.append(NEIPv4Route(destinationAddress: dns, subnetMask: "255.255.255.255"))
            }
            for ip in dynamicRoutes {
                routes.append(NEIPv4Route(destinationAddress: ip, subnetMask: "255.255.255.255"))
            }
        }
        logger.info("Split tunnel: \(routes.count) route(s), \((config.includedDomains ?? []).count) domain rule(s)")
        return routes
    }

    /// Re-apply settings after learning new split routes (no reader restart).
    /// `completion` fires once the new settings are active.
    private func reapplyRoutes(completion: (() -> Void)? = nil) {
        guard let config = tunnelConfig else { completion?(); return }
        setTunnelNetworkSettings(makeNetworkSettings(for: config)) { [weak self] error in
            if let error = error {
                self?.logger.error("Failed to re-apply split routes: \(error.localizedDescription)")
            }
            completion?()
        }
    }

    /// Snoop a DNS answer for a matched (CDN/wildcard) domain. If it carries IPs
    /// we have not routed yet, install the routes and deliver the answer to the
    /// app only *after* they are active, then return true (the caller must not
    /// deliver the packet itself). Returns false for any packet that is not a
    /// gated DNS answer, which the caller should deliver normally.
    ///
    /// Gating closes a race: the DNS answer reaches the app and the snooper at
    /// the same instant, so without it the app opens its connection to the
    /// freshly resolved IP before the route exists — the first request leaks
    /// outside the tunnel and the WAF rejects the client's real IP (403).
    private func maybeLearnRoute(_ packet: Data, proto: NSNumber) -> Bool {
        guard let matcher = domainMatcher, !matcher.isEmpty else { return false }
        guard let dns = DnsSniffer.parse(packet), matcher.matches(dns.qname) else { return false }
        let added = dns.addresses.filter { dynamicRoutes.insert($0).inserted }
        if added.isEmpty { return false }
        logger.info("Split tunnel: learned \(added.count) route(s) for \(dns.qname)")
        reapplyRoutes { [weak self] in
            self?.packetFlow.writePackets([packet], withProtocols: [proto])
        }
        return true
    }

    // MARK: - Packet Handling

    private func startReadingPackets() {
        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self = self, self.isRunning else { return }

            for packet in packets {
                self.bytesOut += UInt64(packet.count)
                self.sendMessage(DataPacket(payload: packet))
            }

            self.startReadingPackets()
        }
    }

    private func handleInboundPacket(_ data: Data) {
        guard isRunning, data.count >= 1 else { return }

        bytesIn += UInt64(data.count)

        let version = (data[0] >> 4) & 0x0F
        let proto: NSNumber = version == 6 ? NSNumber(value: AF_INET6) : NSNumber(value: AF_INET)

        // Under split tunnel, gate DNS answers for matched CDN/wildcard domains:
        // install the learned route before the answer reaches the app. When
        // gated, maybeLearnRoute delivers the packet once the route is active.
        if version == 4, maybeLearnRoute(data, proto: proto) {
            return
        }

        packetFlow.writePackets([data], withProtocols: [proto])
    }
}
