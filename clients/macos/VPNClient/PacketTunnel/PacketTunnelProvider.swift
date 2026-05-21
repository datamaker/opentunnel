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
        connection?.cancel()
        connection = nil
        completionHandler()
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        if let command = String(data: messageData, encoding: .utf8) {
            switch command {
            case "status":
                let status = isRunning ? "connected" : "disconnected"
                completionHandler?(status.data(using: .utf8))
            case "stats":
                let stats: [String: Any] = [
                    "bytesIn": bytesIn,
                    "bytesOut": bytesOut,
                    "isRunning": isRunning
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
            handleInboundPacket(packet.payload)

        case is KeepAlive:
            sendMessage(KeepAliveAck())

        default:
            break
        }
    }

    // MARK: - Tunnel Configuration

    private func configureTunnel(config: ConfigPush) {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: config.gateway)

        // IPv4 - Full Tunnel: route all traffic through VPN
        let ipv4 = NEIPv4Settings(addresses: [config.assignedIP], subnetMasks: [config.subnetMask])

        // Route all traffic through VPN
        ipv4.includedRoutes = [NEIPv4Route.default()]

        // Exclude VPN server IP to keep control connection working
        let serverRoute = NEIPv4Route(destinationAddress: serverHost, subnetMask: "255.255.255.255")
        ipv4.excludedRoutes = [serverRoute]

        settings.ipv4Settings = ipv4

        // DNS
        settings.dnsSettings = NEDNSSettings(servers: config.dns)
        settings.dnsSettings?.matchDomains = [""]

        // MTU
        settings.mtu = NSNumber(value: config.mtu)

        logger.info("Calling setTunnelNetworkSettings...")

        setTunnelNetworkSettings(settings) { [weak self] error in
            guard let self = self else { return }

            if let error = error {
                self.logger.error("Tunnel setup failed: \(error)")
                self.pendingCompletion?(VPNError.tunnelSetupFailed(error.localizedDescription))
            } else {
                self.logger.info("Tunnel configured successfully!")
                self.logger.info("Setting isRunning = true")
                self.isRunning = true
                self.logger.info("Starting packet reading...")
                self.startReadingPackets()
                self.logger.info("Calling pendingCompletion(nil)...")
                self.pendingCompletion?(nil)
                self.logger.info("Tunnel setup complete!")
            }
            self.pendingCompletion = nil
        }
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

        packetFlow.writePackets([data], withProtocols: [proto])
    }
}
