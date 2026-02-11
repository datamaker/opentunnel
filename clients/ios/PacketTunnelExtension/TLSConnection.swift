//
//  TLSConnection.swift
//  PacketTunnelExtension
//
//  TLS 1.3 Connection Handler using Network Framework
//

import Foundation
import Network

// MARK: - TLS Connection Delegate
protocol TLSConnectionDelegate: AnyObject {
    func tlsConnection(_ connection: TLSConnection, didReceive data: Data)
    func tlsConnection(_ connection: TLSConnection, didDisconnectWithError error: Error?)
}

// MARK: - TLS Connection Errors
enum TLSConnectionError: LocalizedError {
    case connectionFailed(String)
    case tlsHandshakeFailed(String)
    case sendFailed(String)
    case notConnected
    case invalidHost
    case timeout

    var errorDescription: String? {
        switch self {
        case .connectionFailed(let message):
            return "Connection failed: \(message)"
        case .tlsHandshakeFailed(let message):
            return "TLS handshake failed: \(message)"
        case .sendFailed(let message):
            return "Send failed: \(message)"
        case .notConnected:
            return "Not connected to server"
        case .invalidHost:
            return "Invalid host address"
        case .timeout:
            return "Connection timed out"
        }
    }
}

// MARK: - TLS Connection
/// Manages TLS 1.3 connection to VPN server using Network framework
class TLSConnection {
    // MARK: - Properties
    private let host: String
    private let port: Int
    private var connection: NWConnection?
    private let queue: DispatchQueue

    weak var delegate: TLSConnectionDelegate?

    private(set) var isConnected = false
    private var connectCompletion: ((Result<Void, Error>) -> Void)?

    // Connection timeout
    private let connectionTimeout: TimeInterval = 30.0
    private var timeoutTimer: DispatchSourceTimer?

    // MARK: - Initialization
    init(host: String, port: Int) {
        self.host = host
        self.port = port
        self.queue = DispatchQueue(label: "com.vpnclient.ios.tlsconnection", qos: .userInteractive)
    }

    deinit {
        disconnect()
    }

    // MARK: - Connection
    /// Connect to VPN server with TLS 1.3
    func connect(completion: @escaping (Result<Void, Error>) -> Void) {
        guard !isConnected else {
            completion(.success(()))
            return
        }

        connectCompletion = completion

        // Create TLS options with TLS 1.3
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

        // Configure certificate validation
        // In production, you should implement proper certificate pinning
        sec_protocol_options_set_verify_block(
            tlsOptions.securityProtocolOptions,
            { (sec_protocol_metadata, sec_trust, sec_protocol_verify_complete) in
                // Get the trust object
                let trust = sec_trust_copy_ref(sec_trust).takeRetainedValue()

                // Perform standard certificate validation
                var error: CFError?
                let isValid = SecTrustEvaluateWithError(trust, &error)

                if isValid {
                    sec_protocol_verify_complete(true)
                } else {
                    // For development/testing, you might want to accept self-signed certs
                    // WARNING: Remove this in production!
                    #if DEBUG
                    NSLog("[TLSConnection] Certificate validation failed, accepting for debug: \(error?.localizedDescription ?? "unknown")")
                    sec_protocol_verify_complete(true)
                    #else
                    NSLog("[TLSConnection] Certificate validation failed: \(error?.localizedDescription ?? "unknown")")
                    sec_protocol_verify_complete(false)
                    #endif
                }
            },
            queue
        )

        // Create TCP options with TLS
        let tcpOptions = NWProtocolTCP.Options()
        tcpOptions.enableKeepalive = true
        tcpOptions.keepaliveInterval = 30
        tcpOptions.keepaliveCount = 3
        tcpOptions.connectionTimeout = 30

        // Create parameters with TLS
        let parameters = NWParameters(tls: tlsOptions, tcp: tcpOptions)

        // Create endpoint
        let endpoint = NWEndpoint.hostPort(
            host: NWEndpoint.Host(host),
            port: NWEndpoint.Port(integerLiteral: UInt16(port))
        )

        // Create connection
        connection = NWConnection(to: endpoint, using: parameters)

        // Setup state handler
        connection?.stateUpdateHandler = { [weak self] state in
            self?.handleStateChange(state)
        }

        // Start connection
        connection?.start(queue: queue)

        // Start timeout timer
        startTimeoutTimer()
    }

    /// Disconnect from server
    func disconnect() {
        stopTimeoutTimer()

        isConnected = false
        connection?.cancel()
        connection = nil
    }

    // MARK: - State Handling
    private func handleStateChange(_ state: NWConnection.State) {
        switch state {
        case .ready:
            NSLog("[TLSConnection] Connection ready")
            stopTimeoutTimer()
            isConnected = true
            connectCompletion?(.success(()))
            connectCompletion = nil
            startReceiving()

        case .failed(let error):
            NSLog("[TLSConnection] Connection failed: \(error.localizedDescription)")
            stopTimeoutTimer()
            isConnected = false
            connectCompletion?(.failure(TLSConnectionError.connectionFailed(error.localizedDescription)))
            connectCompletion = nil
            delegate?.tlsConnection(self, didDisconnectWithError: error)

        case .cancelled:
            NSLog("[TLSConnection] Connection cancelled")
            stopTimeoutTimer()
            isConnected = false
            delegate?.tlsConnection(self, didDisconnectWithError: nil)

        case .waiting(let error):
            NSLog("[TLSConnection] Connection waiting: \(error.localizedDescription)")

        case .preparing:
            NSLog("[TLSConnection] Connection preparing")

        case .setup:
            NSLog("[TLSConnection] Connection setup")

        @unknown default:
            break
        }
    }

    // MARK: - Sending Data
    /// Send data over the TLS connection
    func send(data: Data, completion: @escaping (Error?) -> Void) {
        guard isConnected, let connection = connection else {
            completion(TLSConnectionError.notConnected)
            return
        }

        connection.send(
            content: data,
            completion: .contentProcessed { error in
                if let error = error {
                    NSLog("[TLSConnection] Send error: \(error.localizedDescription)")
                    completion(TLSConnectionError.sendFailed(error.localizedDescription))
                } else {
                    completion(nil)
                }
            }
        )
    }

    /// Send data asynchronously
    func send(data: Data) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            send(data: data) { error in
                if let error = error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume()
                }
            }
        }
    }

    // MARK: - Receiving Data
    private func startReceiving() {
        guard isConnected, let connection = connection else {
            return
        }

        connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] content, _, isComplete, error in
            guard let self = self else { return }

            if let error = error {
                NSLog("[TLSConnection] Receive error: \(error.localizedDescription)")
                self.delegate?.tlsConnection(self, didDisconnectWithError: error)
                return
            }

            if let data = content, !data.isEmpty {
                self.delegate?.tlsConnection(self, didReceive: data)
            }

            if isComplete {
                NSLog("[TLSConnection] Connection completed")
                self.delegate?.tlsConnection(self, didDisconnectWithError: nil)
                return
            }

            // Continue receiving
            self.startReceiving()
        }
    }

    // MARK: - Timeout
    private func startTimeoutTimer() {
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + connectionTimeout)
        timer.setEventHandler { [weak self] in
            guard let self = self else { return }

            NSLog("[TLSConnection] Connection timeout")
            self.stopTimeoutTimer()

            if !self.isConnected {
                self.connectCompletion?(.failure(TLSConnectionError.timeout))
                self.connectCompletion = nil
                self.disconnect()
            }
        }
        timer.resume()
        timeoutTimer = timer
    }

    private func stopTimeoutTimer() {
        timeoutTimer?.cancel()
        timeoutTimer = nil
    }

    // MARK: - Connection Info
    /// Get the current connection's remote endpoint
    var remoteEndpoint: NWEndpoint? {
        return connection?.currentPath?.remoteEndpoint
    }

    /// Get the current connection's local endpoint
    var localEndpoint: NWEndpoint? {
        return connection?.currentPath?.localEndpoint
    }

    /// Check if using cellular
    var isUsingCellular: Bool {
        return connection?.currentPath?.usesInterfaceType(.cellular) ?? false
    }

    /// Check if using WiFi
    var isUsingWiFi: Bool {
        return connection?.currentPath?.usesInterfaceType(.wifi) ?? false
    }
}

// MARK: - Connection Quality Monitoring
extension TLSConnection {
    /// Get current connection path status
    var pathStatus: NWPath.Status? {
        return connection?.currentPath?.status
    }

    /// Check if connection path is satisfied
    var isPathSatisfied: Bool {
        return connection?.currentPath?.status == .satisfied
    }

    /// Monitor path changes
    func monitorPath(handler: @escaping (NWPath) -> Void) {
        connection?.pathUpdateHandler = handler
    }
}

// MARK: - TLS Information
extension TLSConnection {
    /// Get TLS protocol version string
    var tlsProtocolVersion: String {
        guard let metadata = connection?.metadata(definition: NWProtocolTLS.definition) as? NWProtocolTLS.Metadata else {
            return "Unknown"
        }

        let secProtocol = metadata.securityProtocolMetadata

        if let version = sec_protocol_metadata_get_negotiated_tls_protocol_version(secProtocol) {
            switch version {
            case .TLSv10: return "TLS 1.0"
            case .TLSv11: return "TLS 1.1"
            case .TLSv12: return "TLS 1.2"
            case .TLSv13: return "TLS 1.3"
            case .DTLSv10: return "DTLS 1.0"
            case .DTLSv12: return "DTLS 1.2"
            @unknown default: return "Unknown"
            }
        }

        return "Unknown"
    }

    /// Get negotiated cipher suite
    var cipherSuite: String {
        guard let metadata = connection?.metadata(definition: NWProtocolTLS.definition) as? NWProtocolTLS.Metadata else {
            return "Unknown"
        }

        let secProtocol = metadata.securityProtocolMetadata

        if let ciphersuite = sec_protocol_metadata_get_negotiated_tls_ciphersuite(secProtocol) {
            return String(describing: ciphersuite)
        }

        return "Unknown"
    }
}
