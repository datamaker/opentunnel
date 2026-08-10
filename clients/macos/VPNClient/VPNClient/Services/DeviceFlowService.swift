//
//  DeviceFlowService.swift
//  VPNClient
//
//  OAuth 2.0 Device Authorization Grant (RFC 8628) against the Datasee IdP
//  (auth.datasee.co.kr). The IdP is public, so SSO works before the VPN is up:
//  start the flow, open the system browser for approval, then poll the token
//  endpoint until the user approves (or the request expires).
//

import Foundation
#if os(macOS)
import AppKit
#else
import UIKit
#endif

// MARK: - Errors

enum DeviceFlowError: LocalizedError {
    case invalidResponse
    case accessDenied
    case expired
    case server(String)

    var errorDescription: String? {
        switch self {
        case .invalidResponse: return "로그인 서버 응답을 해석할 수 없습니다"
        case .accessDenied: return "로그인이 거부되었습니다"
        case .expired: return "로그인 요청이 만료되었습니다. 다시 시도해 주세요"
        case .server(let msg): return "로그인 실패: \(msg)"
        }
    }
}

// MARK: - Wire Types

/// Response of POST /oidc/device/auth.
struct DeviceAuthorization: Decodable {
    let deviceCode: String
    let userCode: String
    let verificationUri: String
    let verificationUriComplete: String?
    let expiresIn: Int
    let interval: Int?

    enum CodingKeys: String, CodingKey {
        case deviceCode = "device_code"
        case userCode = "user_code"
        case verificationUri = "verification_uri"
        case verificationUriComplete = "verification_uri_complete"
        case expiresIn = "expires_in"
        case interval
    }
}

/// Successful response of the token endpoint.
struct DeviceFlowTokens {
    let idToken: String
    let accessToken: String?
}

// MARK: - Service

/// Runs the device flow with plain URLSession + async/await (no dependencies).
final class DeviceFlowService {
    static let issuer = "https://auth.datasee.co.kr"
    static let clientId = "opentunnel"
    static let scope = "openid email profile"

    private let session: URLSession

    init(session: URLSession = .shared) {
        self.session = session
    }

    /// Step 1: request a device/user code pair from the IdP.
    func startAuthorization() async throws -> DeviceAuthorization {
        let (data, response) = try await post(path: "/oidc/device/auth", parameters: [
            "client_id": Self.clientId,
            "scope": Self.scope
        ])
        guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
            throw DeviceFlowError.server(Self.errorCode(from: data) ?? "device auth failed")
        }
        guard let authorization = try? JSONDecoder().decode(DeviceAuthorization.self, from: data) else {
            throw DeviceFlowError.invalidResponse
        }
        return authorization
    }

    /// Step 3: poll the token endpoint until the user approves in the browser.
    /// Respects the server's `interval` (plus `slow_down` back-off) and gives up
    /// once `expires_in` elapses. Cancel the surrounding Task to abort.
    func pollForTokens(_ authorization: DeviceAuthorization) async throws -> DeviceFlowTokens {
        var interval = TimeInterval(max(authorization.interval ?? 5, 1))
        let deadline = Date().addingTimeInterval(TimeInterval(authorization.expiresIn))

        while Date() < deadline {
            try await Task.sleep(nanoseconds: UInt64(interval * 1_000_000_000))
            try Task.checkCancellation()

            let (data, response) = try await post(path: "/oidc/token", parameters: [
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": authorization.deviceCode,
                "client_id": Self.clientId
            ])
            guard let http = response as? HTTPURLResponse else {
                throw DeviceFlowError.invalidResponse
            }

            if (200..<300).contains(http.statusCode) {
                guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                      let idToken = json["id_token"] as? String, !idToken.isEmpty else {
                    throw DeviceFlowError.invalidResponse
                }
                return DeviceFlowTokens(idToken: idToken, accessToken: json["access_token"] as? String)
            }

            switch Self.errorCode(from: data) {
            case "authorization_pending":
                continue // user has not approved yet — keep polling
            case "slow_down":
                interval += 5
            case "expired_token":
                throw DeviceFlowError.expired
            case "access_denied":
                throw DeviceFlowError.accessDenied
            case let code:
                throw DeviceFlowError.server(code ?? "HTTP \(http.statusCode)")
            }
        }
        throw DeviceFlowError.expired
    }

    /// Step 2: open the system browser at the verification page. The UI keeps
    /// showing user_code + verification_uri as a manual fallback.
    static func openVerificationPage(_ authorization: DeviceAuthorization) {
        guard let url = URL(string: authorization.verificationUriComplete ?? authorization.verificationUri) else {
            return
        }
        #if os(macOS)
        NSWorkspace.shared.open(url)
        #else
        Task { @MainActor in
            UIApplication.shared.open(url)
        }
        #endif
    }

    /// Best-effort read of the `email` claim from an id_token (JWT), for display.
    static func email(fromIdToken idToken: String) -> String? {
        let parts = idToken.split(separator: ".")
        guard parts.count >= 2 else { return nil }
        var payload = String(parts[1])
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        while payload.count % 4 != 0 { payload += "=" }
        guard let data = Data(base64Encoded: payload),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return nil
        }
        return json["email"] as? String
    }

    // MARK: - Helpers

    private func post(path: String, parameters: [String: String]) async throws -> (Data, URLResponse) {
        guard let url = URL(string: Self.issuer + path) else {
            throw DeviceFlowError.invalidResponse
        }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        var components = URLComponents()
        components.queryItems = parameters.map { URLQueryItem(name: $0.key, value: $0.value) }
        request.httpBody = components.percentEncodedQuery?.data(using: .utf8)
        return try await session.data(for: request)
    }

    private static func errorCode(from data: Data) -> String? {
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return nil
        }
        return json["error"] as? String
    }
}
