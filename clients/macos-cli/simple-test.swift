import Foundation
import Network

print("""
╔═══════════════════════════════════════╗
║     macOS VPN Client Test Tool        ║
╚═══════════════════════════════════════╝
""")

let tlsOptions = NWProtocolTLS.Options()
sec_protocol_options_set_verify_block(tlsOptions.securityProtocolOptions, { (_, _, complete) in
    complete(true)
}, DispatchQueue.main)

let params = NWParameters(tls: tlsOptions, tcp: NWProtocolTCP.Options())
let connection = NWConnection(host: "localhost", port: 1194, using: params)

var done = false
var messageCount = 0

func receiveMessages() {
    connection.receive(minimumIncompleteLength: 5, maximumLength: 8192) { data, _, _, error in
        if let error = error {
            print("Receive error: \(error)")
            done = true
            return
        }

        guard let data = data, data.count >= 5 else {
            done = true
            return
        }

        var offset = 0
        while offset + 5 <= data.count {
            let type = data[offset]
            let lenBytes = data.subdata(in: (offset + 1)..<(offset + 5))
            let payloadLen = Int(lenBytes.withUnsafeBytes { $0.load(as: UInt32.self).bigEndian })

            guard offset + 5 + payloadLen <= data.count else { break }

            let payload = data.subdata(in: (offset + 5)..<(offset + 5 + payloadLen))
            offset += 5 + payloadLen
            messageCount += 1

            switch type {
            case 0x02: // AUTH_RESPONSE
                print("\n📨 [\(messageCount)] AUTH_RESPONSE")
                if let json = try? JSONSerialization.jsonObject(with: payload) as? [String: Any] {
                    if json["success"] as? Int == 1 {
                        print("   ✅ 인증 성공!")
                        if let token = json["sessionToken"] as? String {
                            print("   Token: \(token.prefix(50))...")
                        }
                    } else {
                        print("   ❌ 인증 실패: \(json["errorMessage"] ?? "unknown")")
                        done = true
                        return
                    }
                }

            case 0x03: // CONFIG_PUSH
                print("\n📨 [\(messageCount)] CONFIG_PUSH")
                if let json = try? JSONSerialization.jsonObject(with: payload) as? [String: Any] {
                    print("   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
                    print("   할당 IP:    \(json["assignedIp"] ?? "-")")
                    print("   서브넷:     \(json["subnetMask"] ?? "-")")
                    print("   게이트웨이: \(json["gateway"] ?? "-")")
                    if let dns = json["dns"] as? [String] {
                        print("   DNS:        \(dns.joined(separator: ", "))")
                    }
                    print("   MTU:        \(json["mtu"] ?? "-")")
                    print("   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
                }
                print("\n✅ VPN 연결 설정 완료!")
                done = true
                return

            case 0x04: // KEEPALIVE
                print("   💓 Keepalive")

            default:
                print("   Unknown message type: 0x\(String(format: "%02X", type))")
            }
        }

        // Continue receiving
        if !done {
            receiveMessages()
        }
    }
}

connection.stateUpdateHandler = { state in
    switch state {
    case .preparing:
        print("🔄 연결 준비 중...")
    case .ready:
        print("✅ TLS 연결 성공!")
        print("\n📤 인증 요청 전송 중...")

        let auth = ["username": "testuser", "password": "test1234", "platform": "macOS", "version": "1.0"]
        guard let json = try? JSONSerialization.data(withJSONObject: auth) else {
            print("Failed to encode")
            done = true
            return
        }

        var msg = Data([0x01])
        var len = UInt32(json.count).bigEndian
        msg.append(Data(bytes: &len, count: 4))
        msg.append(json)

        connection.send(content: msg, completion: .contentProcessed { error in
            if let error = error {
                print("Send error: \(error)")
                done = true
                return
            }
            receiveMessages()
        })

    case .failed(let error):
        print("❌ 연결 실패: \(error)")
        done = true
    case .cancelled:
        print("연결 취소됨")
        done = true
    default:
        break
    }
}

connection.start(queue: .main)

while !done {
    RunLoop.main.run(until: Date(timeIntervalSinceNow: 0.1))
}

connection.cancel()
print("\n프로그램 종료")
