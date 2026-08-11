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

    // SSO handoff. The extension talks to the server; the app owns the Keychain.
    // The shared App Group container (see the .entitlements files) carries the
    // server-issued session token back to the app, and a rejection flag when a
    // session token is refused so the app can clear it and require SSO again.
    private static let appGroupId = "group.kr.co.datasee.VPNClient"
    private static let ssoSessionTokenKey = "vpn_sso_session_token"
    private static let ssoSessionRejectedKey = "vpn_sso_session_rejected"
    private var authType: String?

    // MARK: - Tunnel Lifecycle

    override func startTunnel(options: [String : NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        logger.info("Starting tunnel...")
        pendingCompletion = completionHandler

        guard let config = protocolConfiguration as? NETunnelProviderProtocol,
              let providerConfig = config.providerConfiguration,
              let serverAddress = providerConfig["serverAddress"] as? String else {
            completionHandler(VPNError.configurationFailed("Invalid configuration"))
            return
        }

        // Credentials: either token auth (authType "sso"/"session" + token) or
        // classic username/password.
        let authType = providerConfig["authType"] as? String
        let token = providerConfig["token"] as? String
        let username = providerConfig["username"] as? String
        let password = providerConfig["password"] as? String
        guard (authType != nil && token != nil) || (username != nil && password != nil) else {
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
        if let authType = authType, let token = token {
            UserDefaults.standard.set(authType, forKey: "vpn_auth_type")
            UserDefaults.standard.set(token, forKey: "vpn_auth_token")
        } else {
            UserDefaults.standard.set(username, forKey: "vpn_username")
            UserDefaults.standard.set(password, forKey: "vpn_password")
        }

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
        let defaults = UserDefaults.standard
        let storedAuthType = defaults.string(forKey: "vpn_auth_type")
        let storedToken = defaults.string(forKey: "vpn_auth_token")
        let username = defaults.string(forKey: "vpn_username")
        let password = defaults.string(forKey: "vpn_password")

        // Clear stored credentials
        defaults.removeObject(forKey: "vpn_auth_type")
        defaults.removeObject(forKey: "vpn_auth_token")
        defaults.removeObject(forKey: "vpn_username")
        defaults.removeObject(forKey: "vpn_password")

        let request: AuthRequest
        if let storedAuthType = storedAuthType, let storedToken = storedToken {
            authType = storedAuthType
            logger.info("Authenticating via \(storedAuthType) token")
            request = AuthRequest(authType: storedAuthType, token: storedToken)
        } else if let username = username, let password = password {
            authType = nil
            logger.info("Authenticating: \(username)")
            request = AuthRequest(username: username, password: password)
        } else {
            pendingCompletion?(VPNError.authenticationFailed("No credentials"))
            return
        }

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
                logger.info("Auth successful, token: \(response.sessionToken != nil ? "issued" : "nil")")
                sessionToken = response.sessionToken
                // First SSO connect: the server issues a 30-day session token.
                // Hand it to the app (App Group), which moves it to the Keychain
                // and uses authType "session" for subsequent connects.
                if authType == "sso", let issued = response.sessionToken, !issued.isEmpty,
                   let shared = UserDefaults(suiteName: Self.appGroupId) {
                    shared.set(issued, forKey: Self.ssoSessionTokenKey)
                    shared.removeObject(forKey: Self.ssoSessionRejectedKey)
                }
            } else {
                logger.error("Auth failed: \(response.errorMessage ?? "")")
                // A rejected session token is stale — flag it so the app clears
                // the Keychain copy and requires SSO again.
                if authType == "session", let shared = UserDefaults(suiteName: Self.appGroupId) {
                    shared.set(true, forKey: Self.ssoSessionRejectedKey)
                }
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
                self.preResolveSplitDomains()
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

    /// Pre-resolve concrete (non-wildcard) split-tunnel domains by sending our
    /// own A queries straight through the tunnel. The OS may hold cached DNS
    /// answers — in which case no query the sniffer could learn from would ever
    /// be sent — so a cached (possibly geo-stale) IP would be used with no
    /// route installed. The responses come back through `handleInboundPacket`,
    /// where `maybeLearnRoute` seeds the routes before the app needs them.
    private func preResolveSplitDomains() {
        guard let config = tunnelConfig, let matcher = domainMatcher, !matcher.isEmpty else { return }
        guard let dns = config.dns.first(where: { CidrUtils.parse($0) != nil }) else { return }
        let concrete = (config.includedDomains ?? []).filter { !$0.contains("*") }
        guard !concrete.isEmpty else { return }
        logger.info("Split tunnel: pre-resolving \(concrete.count) domain(s) through the tunnel")
        for (i, domain) in concrete.enumerated() {
            if let query = DnsQueryBuilder.buildAQuery(domain: domain,
                                                       srcIP: config.assignedIP,
                                                       dstIP: dns,
                                                       srcPort: UInt16(49152 + (i % 8192)),
                                                       id: UInt16(truncatingIfNeeded: 0x5350 &+ i)) {
                sendMessage(DataPacket(payload: Data(query)))
            }
        }
        // One retry a few seconds in, in case the first burst raced the server
        // finishing session setup. Skipped once any route has been learned.
        DispatchQueue.global().asyncAfter(deadline: .now() + 3) { [weak self] in
            guard let self = self, self.isRunning, self.dynamicRoutes.isEmpty else { return }
            for (i, domain) in concrete.enumerated() {
                if let query = DnsQueryBuilder.buildAQuery(domain: domain,
                                                           srcIP: config.assignedIP,
                                                           dstIP: dns,
                                                           srcPort: UInt16(49152 + ((i + 1) % 8192)),
                                                           id: UInt16(truncatingIfNeeded: 0x5A50 &+ i)) {
                    self.sendMessage(DataPacket(payload: Data(query)))
                }
            }
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

        if version == 4, let matcher = domainMatcher, !matcher.isEmpty {
            // The tunnel is IPv4-only, so an AAAA (or HTTPS-record) answer for a
            // matched domain would send the OS over untunneled IPv6, straight
            // past the split routes. Blank those answers (NODATA) to force the
            // fallback to A records, which the route learning below handles.
            if let stripped = DnsSniffer.strippedIPv6Response([UInt8](data)),
               matcher.matches(stripped.qname) {
                logger.info("Split tunnel: blanked IPv6/HTTPS DNS answers for \(stripped.qname)")
                packetFlow.writePackets([Data(stripped.packet)], withProtocols: [proto])
                return
            }

            // Gate DNS answers for matched CDN/wildcard domains: install the
            // learned route before the answer reaches the app. When gated,
            // maybeLearnRoute delivers the packet once the route is active.
            if maybeLearnRoute(data, proto: proto) {
                return
            }
        }

        packetFlow.writePackets([data], withProtocols: [proto])
    }
}
