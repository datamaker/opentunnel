import Foundation
import Network

// MARK: - VPN Protocol Types
enum MessageType: UInt8 {
    case authRequest = 0x01
    case authResponse = 0x02
    case configPush = 0x03
    case keepalive = 0x04
    case disconnect = 0x05
    case dataPacket = 0x10
}

struct AuthRequest: Codable {
    let username: String
    let password: String
    let platform: String
    let version: String
}

struct AuthResponse: Codable {
    let success: Bool
    let message: String?
    let token: String?
}

struct VPNConfig: Codable {
    let assignedIp: String
    let subnetMask: String
    let gateway: String
    let dns: [String]
    let mtu: Int
}

// MARK: - Message Serializer
func serializeMessage(type: MessageType, payload: Data) -> Data {
    var data = Data()
    data.append(type.rawValue)

    // Length as big-endian 4 bytes
    var length = UInt32(payload.count).bigEndian
    data.append(Data(bytes: &length, count: 4))
    data.append(payload)

    return data
}

func parseMessage(data: Data) -> (type: MessageType, payload: Data)? {
    guard data.count >= 5 else { return nil }

    guard let type = MessageType(rawValue: data[0]) else { return nil }

    let lengthBytes = data.subdata(in: 1..<5)
    let length = lengthBytes.withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }

    guard data.count >= 5 + Int(length) else { return nil }

    let payload = data.subdata(in: 5..<(5 + Int(length)))
    return (type, payload)
}

// MARK: - VPN Client
class VPNClient {
    private var connection: NWConnection?
    private let host: String
    private let port: UInt16
    private var receivedData = Data()

    init(host: String, port: UInt16) {
        self.host = host
        self.port = port
    }

    func connect(completion: @escaping (Bool, String) -> Void) {
        let tlsOptions = NWProtocolTLS.Options()

        // Trust self-signed certificates (development only)
        sec_protocol_options_set_verify_block(tlsOptions.securityProtocolOptions, { (_, trust, complete) in
            complete(true)  // Accept any certificate
        }, DispatchQueue.main)

        let tcpOptions = NWProtocolTCP.Options()
        let params = NWParameters(tls: tlsOptions, tcp: tcpOptions)

        connection = NWConnection(host: NWEndpoint.Host(host), port: NWEndpoint.Port(rawValue: port)!, using: params)

        connection?.stateUpdateHandler = { [weak self] state in
            switch state {
            case .ready:
                completion(true, "Connected to \(self?.host ?? ""):\(self?.port ?? 0)")
                self?.startReceiving()
            case .failed(let error):
                completion(false, "Connection failed: \(error)")
            case .cancelled:
                completion(false, "Connection cancelled")
            default:
                break
            }
        }

        connection?.start(queue: .main)
    }

    func authenticate(username: String, password: String, completion: @escaping (Bool, String, VPNConfig?) -> Void) {
        let authRequest = AuthRequest(
            username: username,
            password: password,
            platform: "macOS",
            version: "1.0.0"
        )

        guard let payload = try? JSONEncoder().encode(authRequest) else {
            completion(false, "Failed to encode auth request", nil)
            return
        }

        let message = serializeMessage(type: .authRequest, payload: payload)

        connection?.send(content: message, completion: .contentProcessed { [weak self] error in
            if let error = error {
                completion(false, "Send error: \(error)", nil)
                return
            }

            // Wait for response
            self?.waitForAuthResponse(completion: completion)
        })
    }

    private func waitForAuthResponse(completion: @escaping (Bool, String, VPNConfig?) -> Void) {
        connection?.receive(minimumIncompleteLength: 5, maximumLength: 65536) { [weak self] content, _, _, error in
            if let error = error {
                completion(false, "Receive error: \(error)", nil)
                return
            }

            guard let data = content else {
                completion(false, "No data received", nil)
                return
            }

            self?.receivedData.append(data)
            self?.processReceivedData(completion: completion)
        }
    }

    private func processReceivedData(completion: @escaping (Bool, String, VPNConfig?) -> Void) {
        while receivedData.count >= 5 {
            let lengthBytes = receivedData.subdata(in: 1..<5)
            let length = lengthBytes.withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }
            let totalLength = 5 + Int(length)

            guard receivedData.count >= totalLength else {
                // Need more data
                waitForAuthResponse(completion: completion)
                return
            }

            let messageData = receivedData.prefix(totalLength)
            receivedData.removeFirst(totalLength)

            guard let (type, payload) = parseMessage(data: Data(messageData)) else {
                continue
            }

            switch type {
            case .authResponse:
                handleAuthResponse(payload: payload, completion: completion)
                return
            case .configPush:
                handleConfigPush(payload: payload, completion: completion)
                return
            default:
                print("Received message type: \(type.rawValue)")
            }
        }
    }

    private func handleAuthResponse(payload: Data, completion: @escaping (Bool, String, VPNConfig?) -> Void) {
        guard let response = try? JSONDecoder().decode(AuthResponse.self, from: payload) else {
            completion(false, "Failed to decode auth response", nil)
            return
        }

        if response.success {
            print("✅ Authentication successful!")
            // Wait for config push
            waitForAuthResponse(completion: completion)
        } else {
            completion(false, response.message ?? "Authentication failed", nil)
        }
    }

    private func handleConfigPush(payload: Data, completion: @escaping (Bool, String, VPNConfig?) -> Void) {
        guard let config = try? JSONDecoder().decode(VPNConfig.self, from: payload) else {
            completion(false, "Failed to decode config", nil)
            return
        }

        completion(true, "Configuration received", config)
    }

    private func startReceiving() {
        connection?.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] content, _, isComplete, error in
            if let data = content, !data.isEmpty {
                self?.receivedData.append(data)
            }

            if !isComplete {
                self?.startReceiving()
            }
        }
    }

    func disconnect() {
        let message = serializeMessage(type: .disconnect, payload: Data())
        connection?.send(content: message, completion: .contentProcessed { _ in })
        connection?.cancel()
    }
}

// MARK: - Main
func main() {
    print("""
    ╔═══════════════════════════════════════╗
    ║       VPN Client Test Tool            ║
    ║       macOS CLI Version               ║
    ╚═══════════════════════════════════════╝
    """)

    // Configuration
    let host = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "localhost"
    let port: UInt16 = CommandLine.arguments.count > 2 ? UInt16(CommandLine.arguments[2]) ?? 1194 : 1194

    print("Connecting to \(host):\(port)...")

    let client = VPNClient(host: host, port: port)
    let semaphore = DispatchSemaphore(value: 0)

    client.connect { success, message in
        print(message)

        if success {
            print("\nEnter credentials:")
            print("Username: ", terminator: "")
            guard let username = readLine(), !username.isEmpty else {
                print("Invalid username")
                semaphore.signal()
                return
            }

            print("Password: ", terminator: "")
            guard let password = readLine(), !password.isEmpty else {
                print("Invalid password")
                semaphore.signal()
                return
            }

            print("\nAuthenticating...")

            client.authenticate(username: username, password: password) { success, message, config in
                if success, let config = config {
                    print("""

                    ✅ VPN Configuration Received:
                    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                    Assigned IP: \(config.assignedIp)
                    Subnet Mask: \(config.subnetMask)
                    Gateway:     \(config.gateway)
                    DNS:         \(config.dns.joined(separator: ", "))
                    MTU:         \(config.mtu)
                    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

                    Press Enter to disconnect...
                    """)

                    _ = readLine()
                    client.disconnect()
                    print("Disconnected.")
                } else {
                    print("❌ \(message)")
                }
                semaphore.signal()
            }
        } else {
            semaphore.signal()
        }
    }

    semaphore.wait()
}

main()
RunLoop.main.run(until: Date(timeIntervalSinceNow: 1))
