//
//  TLSConnection.swift
//  PacketTunnelExtension
//
//  TLS 1.3 connection handler using Network.framework
//

import Foundation
import Network
import os.log

// MARK: - TLS Connection Delegate

protocol TLSConnectionDelegate: AnyObject {
    func connectionDidConnect(_ connection: TLSConnection)
    func connectionDidDisconnect(_ connection: TLSConnection, error: Error?)
    func connection(_ connection: TLSConnection, didReceiveMessage message: VPNMessage)
    func connection(_ connection: TLSConnection, didFailWithError error: Error)
}

// MARK: - TLS Connection

/// Manages TLS 1.3 connection to VPN server using NWConnection
final class TLSConnection {

    // MARK: - Properties

    private var connection: NWConnection?
    private let host: String
    private let port: UInt16
    private let queue: DispatchQueue
    private let messageBuffer = VPNMessageBuffer()

    private(set) var isConnected = false
    private var isReading = false

    weak var delegate: TLSConnectionDelegate?

    private let logger = Logger(subsystem: "com.vpnclient.tunnel", category: "TLSConnection")

    // MARK: - Initialization

    init(host: String, port: UInt16, queue: DispatchQueue = .global(qos: .userInitiated)) {
        self.host = host
        self.port = port
        self.queue = queue
    }

    // MARK: - Connection Management

    /// Connect to the VPN server with TLS 1.3
    func connect() {
        logger.info("Connecting to \(self.host):\(self.port)")

        // Create TLS parameters
        let tlsOptions = NWProtocolTLS.Options()

        // Configure TLS 1.3
        sec_protocol_options_set_min_tls_protocol_version(
            tlsOptions.securityProtocolOptions,
            .TLSv13
        )
        sec_protocol_options_set_max_tls_protocol_version(
            tlsOptions.securityProtocolOptions,
            .TLSv13
        )

        // Allow self-signed certificates for development (remove in production)
        sec_protocol_options_set_verify_block(
            tlsOptions.securityProtocolOptions,
            { _, trust, completionHandler in
                // In production, implement proper certificate validation
                // For development, we accept all certificates
                completionHandler(true)
            },
            queue
        )

        // Create TCP options
        let tcpOptions = NWProtocolTCP.Options()
        tcpOptions.enableKeepalive = true
        tcpOptions.keepaliveIdle = 30
        tcpOptions.keepaliveCount = 3
        tcpOptions.keepaliveInterval = 10
        tcpOptions.noDelay = true

        // Create connection parameters
        let parameters = NWParameters(tls: tlsOptions, tcp: tcpOptions)
        parameters.includePeerToPeer = false
        parameters.expiredDNSBehavior = .allow

        // Create endpoint
        let endpoint = NWEndpoint.hostPort(
            host: NWEndpoint.Host(host),
            port: NWEndpoint.Port(rawValue: port)!
        )

        // Create connection
        connection = NWConnection(to: endpoint, using: parameters)

        // Set state handler
        connection?.stateUpdateHandler = { [weak self] state in
            self?.handleStateChange(state)
        }

        // Start connection
        connection?.start(queue: queue)
    }

    /// Disconnect from the VPN server
    func disconnect() {
        logger.info("Disconnecting from server")

        isConnected = false
        isReading = false
        messageBuffer.clear()

        connection?.cancel()
        connection = nil
    }

    // MARK: - State Handling

    private func handleStateChange(_ state: NWConnection.State) {
        switch state {
        case .setup:
            logger.debug("Connection setup")

        case .preparing:
            logger.debug("Connection preparing")

        case .waiting(let error):
            logger.warning("Connection waiting: \(error.localizedDescription)")

        case .ready:
            logger.info("Connection ready")
            isConnected = true
            delegate?.connectionDidConnect(self)
            startReading()

        case .failed(let error):
            logger.error("Connection failed: \(error.localizedDescription)")
            isConnected = false
            delegate?.connection(self, didFailWithError: VPNError.connectionFailed(error.localizedDescription))

        case .cancelled:
            logger.info("Connection cancelled")
            isConnected = false
            delegate?.connectionDidDisconnect(self, error: nil)

        @unknown default:
            logger.warning("Unknown connection state")
        }
    }

    // MARK: - Sending Data

    /// Send a VPN message
    func send(_ message: VPNMessage, completion: ((Error?) -> Void)? = nil) {
        guard isConnected, let connection = connection else {
            completion?(VPNError.disconnected("Not connected"))
            return
        }

        do {
            let data = try VPNMessageSerializer.serialize(message)
            logger.debug("Sending message type: \(message.type.description), size: \(data.count) bytes")

            connection.send(content: data, completion: .contentProcessed { [weak self] error in
                if let error = error {
                    self?.logger.error("Send error: \(error.localizedDescription)")
                    completion?(VPNError.connectionFailed(error.localizedDescription))
                } else {
                    completion?(nil)
                }
            })
        } catch {
            logger.error("Serialization error: \(error.localizedDescription)")
            completion?(error)
        }
    }

    /// Send raw data (for data packets)
    func sendData(_ data: Data, completion: ((Error?) -> Void)? = nil) {
        let packet = DataPacket(payload: data)
        send(packet, completion: completion)
    }

    /// Send authentication request
    func sendAuthRequest(username: String, password: String, completion: ((Error?) -> Void)? = nil) {
        let request = AuthRequest(username: username, password: password)
        send(request, completion: completion)
    }

    /// Send keep alive
    func sendKeepAlive(completion: ((Error?) -> Void)? = nil) {
        let keepAlive = KeepAlive()
        send(keepAlive, completion: completion)
    }

    /// Send keep alive ack
    func sendKeepAliveAck(completion: ((Error?) -> Void)? = nil) {
        let ack = KeepAliveAck()
        send(ack, completion: completion)
    }

    /// Send disconnect
    func sendDisconnect(reason: String? = nil, completion: ((Error?) -> Void)? = nil) {
        let disconnect = Disconnect(reason: reason)
        send(disconnect, completion: completion)
    }

    // MARK: - Receiving Data

    private func startReading() {
        guard isConnected, !isReading else { return }
        isReading = true
        readNextMessage()
    }

    private func readNextMessage() {
        guard isConnected, let connection = connection else {
            isReading = false
            return
        }

        // Read header first
        connection.receive(minimumIncompleteLength: VPNMessageSerializer.headerSize, maximumLength: 65536) { [weak self] content, _, isComplete, error in
            guard let self = self else { return }

            if let error = error {
                self.logger.error("Read error: \(error.localizedDescription)")
                self.isReading = false
                self.delegate?.connection(self, didFailWithError: VPNError.connectionFailed(error.localizedDescription))
                return
            }

            if let data = content, !data.isEmpty {
                self.messageBuffer.append(data)
                self.processBufferedMessages()
            }

            if isComplete {
                self.logger.info("Connection closed by server")
                self.isReading = false
                self.isConnected = false
                self.delegate?.connectionDidDisconnect(self, error: nil)
                return
            }

            // Continue reading
            self.readNextMessage()
        }
    }

    private func processBufferedMessages() {
        do {
            while let message = try messageBuffer.extractMessage() {
                logger.debug("Received message type: \(message.type.description)")
                delegate?.connection(self, didReceiveMessage: message)
            }
        } catch {
            logger.error("Message processing error: \(error.localizedDescription)")
        }
    }
}

// MARK: - Connection Factory

extension TLSConnection {
    /// Create a connection with default settings
    static func create(host: String, port: UInt16) -> TLSConnection {
        return TLSConnection(host: host, port: port)
    }

    /// Create a connection for specific VPN server
    static func create(serverAddress: String) -> TLSConnection? {
        // Parse server address (host:port format)
        let components = serverAddress.split(separator: ":")
        guard components.count == 2,
              let port = UInt16(components[1]) else {
            return nil
        }

        return TLSConnection(host: String(components[0]), port: port)
    }
}

// MARK: - Keep Alive Manager

/// Manages keep-alive mechanism for TLS connection
final class KeepAliveManager {

    private weak var connection: TLSConnection?
    private var timer: DispatchSourceTimer?
    private let interval: TimeInterval
    private let queue: DispatchQueue
    private var lastResponseTime: Date = Date()
    private let timeout: TimeInterval

    private let logger = Logger(subsystem: "com.vpnclient.tunnel", category: "KeepAlive")

    var onTimeout: (() -> Void)?

    init(connection: TLSConnection, interval: TimeInterval = 30, timeout: TimeInterval = 90, queue: DispatchQueue = .global()) {
        self.connection = connection
        self.interval = interval
        self.timeout = timeout
        self.queue = queue
    }

    func start() {
        stop()

        logger.info("Starting keep-alive with interval: \(self.interval)s")

        timer = DispatchSource.makeTimerSource(queue: queue)
        timer?.schedule(deadline: .now() + interval, repeating: interval)
        timer?.setEventHandler { [weak self] in
            self?.sendKeepAlive()
        }
        timer?.resume()
    }

    func stop() {
        timer?.cancel()
        timer = nil
    }

    func receivedResponse() {
        lastResponseTime = Date()
    }

    private func sendKeepAlive() {
        // Check for timeout
        let elapsed = Date().timeIntervalSince(lastResponseTime)
        if elapsed > timeout {
            logger.warning("Keep-alive timeout after \(elapsed)s")
            stop()
            onTimeout?()
            return
        }

        logger.debug("Sending keep-alive")
        connection?.sendKeepAlive { [weak self] error in
            if let error = error {
                self?.logger.error("Keep-alive send error: \(error.localizedDescription)")
            }
        }
    }

    deinit {
        stop()
    }
}
