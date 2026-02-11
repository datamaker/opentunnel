//
//  PacketTunnelProvider.swift
//  PacketTunnelExtension
//
//  Core VPN tunnel implementation using NetworkExtension framework
//

import NetworkExtension
import Network
import os.log

class PacketTunnelProvider: NEPacketTunnelProvider {

    // MARK: - Properties

    private var tlsConnection: TLSConnection?
    private var keepAliveManager: KeepAliveManager?
    private var pendingStartCompletion: ((Error?) -> Void)?
    private var pendingStopCompletion: (() -> Void)?

    private var tunnelConfig: ConfigPush?
    private var sessionToken: String?

    private var isRunning = false
    private let packetQueue = DispatchQueue(label: "com.vpnclient.packetQueue", qos: .userInteractive)

    private let logger = Logger(subsystem: "com.vpnclient.tunnel", category: "PacketTunnelProvider")

    // MARK: - Tunnel Lifecycle

    override func startTunnel(options: [String : NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        logger.info("Starting tunnel...")

        // Store completion handler for async flow
        pendingStartCompletion = completionHandler

        // Get configuration from protocol configuration
        guard let protocolConfig = protocolConfiguration as? NETunnelProviderProtocol,
              let providerConfig = protocolConfig.providerConfiguration else {
            logger.error("Missing provider configuration")
            completionHandler(VPNError.configurationFailed("Missing provider configuration"))
            return
        }

        // Extract configuration
        guard let serverAddress = providerConfig["serverAddress"] as? String,
              let username = providerConfig["username"] as? String,
              let password = providerConfig["password"] as? String else {
            logger.error("Invalid configuration parameters")
            completionHandler(VPNError.configurationFailed("Invalid configuration parameters"))
            return
        }

        logger.info("Connecting to server: \(serverAddress)")

        // Parse server address
        let components = serverAddress.split(separator: ":")
        guard components.count == 2,
              let port = UInt16(components[1]) else {
            logger.error("Invalid server address format")
            completionHandler(VPNError.configurationFailed("Invalid server address format"))
            return
        }

        // Create TLS connection
        let connection = TLSConnection(host: String(components[0]), port: port, queue: packetQueue)
        connection.delegate = self
        tlsConnection = connection

        // Store credentials for authentication after connection
        // We'll use the options dictionary to pass them along
        let credentials = ["username": username, "password": password]
        UserDefaults.standard.set(credentials, forKey: "pendingCredentials")

        // Connect
        connection.connect()
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        logger.info("Stopping tunnel with reason: \(String(describing: reason))")

        pendingStopCompletion = completionHandler
        isRunning = false

        // Stop keep-alive
        keepAliveManager?.stop()
        keepAliveManager = nil

        // Send disconnect message
        tlsConnection?.sendDisconnect(reason: "User requested disconnect") { [weak self] _ in
            self?.tlsConnection?.disconnect()
            self?.tlsConnection = nil
            self?.pendingStopCompletion?()
            self?.pendingStopCompletion = nil
        }

        // Timeout for graceful disconnect
        DispatchQueue.main.asyncAfter(deadline: .now() + 2) { [weak self] in
            if self?.pendingStopCompletion != nil {
                self?.tlsConnection?.disconnect()
                self?.tlsConnection = nil
                self?.pendingStopCompletion?()
                self?.pendingStopCompletion = nil
            }
        }
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        // Handle messages from the main app
        logger.debug("Received app message of \(messageData.count) bytes")

        // Parse command
        if let command = String(data: messageData, encoding: .utf8) {
            switch command {
            case "status":
                let status = isRunning ? "connected" : "disconnected"
                completionHandler?(status.data(using: .utf8))

            case "stats":
                // Return connection statistics
                let stats: [String: Any] = [
                    "isRunning": isRunning,
                    "serverAddress": (protocolConfiguration as? NETunnelProviderProtocol)?.serverAddress ?? "",
                    "assignedIP": tunnelConfig?.assignedIP ?? ""
                ]
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

    override func sleep(completionHandler: @escaping () -> Void) {
        logger.info("System going to sleep")
        // Keep connection alive during sleep if possible
        completionHandler()
    }

    override func wake() {
        logger.info("System woke up")
        // Verify connection is still alive
        tlsConnection?.sendKeepAlive()
    }

    // MARK: - Tunnel Configuration

    private func configureTunnel(with config: ConfigPush) {
        logger.info("Configuring tunnel with IP: \(config.assignedIP)")

        let networkSettings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: config.gateway)

        // Configure IPv4
        let ipv4Settings = NEIPv4Settings(addresses: [config.assignedIP], subnetMasks: [config.subnetMask])

        // Include all routes (full tunnel)
        ipv4Settings.includedRoutes = [NEIPv4Route.default()]

        // Exclude local network routes
        let excludedRoutes: [NEIPv4Route] = [
            NEIPv4Route(destinationAddress: "10.0.0.0", subnetMask: "255.0.0.0"),
            NEIPv4Route(destinationAddress: "172.16.0.0", subnetMask: "255.240.0.0"),
            NEIPv4Route(destinationAddress: "192.168.0.0", subnetMask: "255.255.0.0"),
            NEIPv4Route(destinationAddress: "127.0.0.0", subnetMask: "255.0.0.0")
        ]
        ipv4Settings.excludedRoutes = excludedRoutes

        networkSettings.ipv4Settings = ipv4Settings

        // Configure DNS
        let dnsSettings = NEDNSSettings(servers: config.dns)
        dnsSettings.matchDomains = [""]  // Match all domains
        networkSettings.dnsSettings = dnsSettings

        // Configure MTU
        networkSettings.mtu = NSNumber(value: config.mtu)

        // Apply settings
        setTunnelNetworkSettings(networkSettings) { [weak self] error in
            guard let self = self else { return }

            if let error = error {
                self.logger.error("Failed to set tunnel settings: \(error.localizedDescription)")
                self.pendingStartCompletion?(VPNError.tunnelSetupFailed(error.localizedDescription))
                self.pendingStartCompletion = nil
                return
            }

            self.logger.info("Tunnel configured successfully")
            self.tunnelConfig = config
            self.isRunning = true

            // Start reading packets from the tunnel
            self.startReadingPackets()

            // Start keep-alive
            self.startKeepAlive()

            // Complete startup
            self.pendingStartCompletion?(nil)
            self.pendingStartCompletion = nil
        }
    }

    // MARK: - Packet Handling

    private func startReadingPackets() {
        logger.info("Starting to read packets from tunnel")

        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self = self, self.isRunning else { return }

            self.handleOutboundPackets(packets, protocols: protocols)

            // Continue reading
            self.startReadingPackets()
        }
    }

    private func handleOutboundPackets(_ packets: [Data], protocols: [NSNumber]) {
        guard isRunning else { return }

        for packet in packets {
            // Send packet to VPN server
            tlsConnection?.sendData(packet) { [weak self] error in
                if let error = error {
                    self?.logger.error("Failed to send packet: \(error.localizedDescription)")
                }
            }
        }
    }

    private func handleInboundPacket(_ data: Data) {
        guard isRunning else { return }

        // Determine IP version from packet
        guard data.count >= 1 else { return }

        let version = (data[0] >> 4) & 0x0F
        let protocolNumber: NSNumber

        switch version {
        case 4:
            protocolNumber = NSNumber(value: AF_INET)
        case 6:
            protocolNumber = NSNumber(value: AF_INET6)
        default:
            logger.warning("Unknown IP version: \(version)")
            return
        }

        // Write packet to tunnel
        packetFlow.writePackets([data], withProtocols: [protocolNumber])
    }

    // MARK: - Keep Alive

    private func startKeepAlive() {
        guard let connection = tlsConnection else { return }

        let manager = KeepAliveManager(connection: connection, interval: 30, timeout: 90, queue: packetQueue)
        manager.onTimeout = { [weak self] in
            self?.handleKeepAliveTimeout()
        }
        manager.start()
        keepAliveManager = manager
    }

    private func handleKeepAliveTimeout() {
        logger.warning("Keep-alive timeout, attempting reconnection")

        // Cancel existing tunnel and let the system reconnect
        cancelTunnelWithError(VPNError.timeout)
    }

    // MARK: - Authentication

    private func performAuthentication() {
        guard let credentials = UserDefaults.standard.dictionary(forKey: "pendingCredentials"),
              let username = credentials["username"] as? String,
              let password = credentials["password"] as? String else {
            logger.error("No credentials available")
            pendingStartCompletion?(VPNError.authenticationFailed("No credentials"))
            pendingStartCompletion = nil
            return
        }

        // Clear stored credentials
        UserDefaults.standard.removeObject(forKey: "pendingCredentials")

        logger.info("Authenticating user: \(username)")

        tlsConnection?.sendAuthRequest(username: username, password: password) { [weak self] error in
            if let error = error {
                self?.logger.error("Failed to send auth request: \(error.localizedDescription)")
                self?.pendingStartCompletion?(error)
                self?.pendingStartCompletion = nil
            }
        }
    }
}

// MARK: - TLS Connection Delegate

extension PacketTunnelProvider: TLSConnectionDelegate {

    func connectionDidConnect(_ connection: TLSConnection) {
        logger.info("TLS connection established")
        performAuthentication()
    }

    func connectionDidDisconnect(_ connection: TLSConnection, error: Error?) {
        logger.info("TLS connection disconnected")

        isRunning = false
        keepAliveManager?.stop()

        if let error = error {
            cancelTunnelWithError(error)
        }
    }

    func connection(_ connection: TLSConnection, didReceiveMessage message: VPNMessage) {
        logger.debug("Received message: \(message.type.description)")

        switch message.type {
        case .authResponse:
            handleAuthResponse(message as! AuthResponse)

        case .configPush:
            handleConfigPush(message as! ConfigPush)

        case .keepAlive:
            // Respond with ack
            connection.sendKeepAliveAck()

        case .keepAliveAck:
            // Update keep-alive manager
            keepAliveManager?.receivedResponse()

        case .disconnect:
            let disconnect = message as! Disconnect
            logger.info("Server disconnected: \(disconnect.reason ?? "No reason")")
            cancelTunnelWithError(VPNError.disconnected(disconnect.reason ?? "Server closed connection"))

        case .dataPacket:
            let packet = message as! DataPacket
            handleInboundPacket(packet.payload)

        default:
            logger.warning("Unhandled message type: \(message.type.description)")
        }
    }

    func connection(_ connection: TLSConnection, didFailWithError error: Error) {
        logger.error("Connection error: \(error.localizedDescription)")

        isRunning = false
        keepAliveManager?.stop()

        if pendingStartCompletion != nil {
            pendingStartCompletion?(error)
            pendingStartCompletion = nil
        } else {
            cancelTunnelWithError(error)
        }
    }

    // MARK: - Message Handlers

    private func handleAuthResponse(_ response: AuthResponse) {
        if response.success {
            logger.info("Authentication successful")
            sessionToken = response.sessionToken
            // Wait for config push
        } else {
            logger.error("Authentication failed: \(response.errorMessage ?? "Unknown error")")
            pendingStartCompletion?(VPNError.authenticationFailed(response.errorMessage ?? "Authentication failed"))
            pendingStartCompletion = nil
            tlsConnection?.disconnect()
        }
    }

    private func handleConfigPush(_ config: ConfigPush) {
        logger.info("Received configuration: IP=\(config.assignedIP), MTU=\(config.mtu)")
        configureTunnel(with: config)
    }
}
