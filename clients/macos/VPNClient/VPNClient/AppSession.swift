//
//  AppSession.swift
//  VPNClient
//
//  Lightweight app-level session/auth state for the macOS client.
//  macOS has no separate auth step, so "Sign In" simply validates and
//  stores the connection details, then flips `isLoggedIn`.
//

import SwiftUI
import Foundation
import Combine
import Security

// MARK: - Keychain (secure credential storage)
/// Minimal Keychain wrapper for the "Remember credentials" password. Storing the
/// password in UserDefaults would put it on disk in plaintext, so it lives here.
enum CredentialStore {
    private static let service = "com.vpnclient.macos.credentials"

    static func savePassword(_ password: String, account: String) {
        guard !account.isEmpty else { return }
        let base: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        SecItemDelete(base as CFDictionary)
        var add = base
        add[kSecValueData as String] = Data(password.utf8)
        SecItemAdd(add as CFDictionary, nil)
    }

    static func password(account: String) -> String? {
        guard !account.isEmpty else { return nil }
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var result: AnyObject?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    static func deletePassword(account: String) {
        guard !account.isEmpty else { return }
        let base: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        SecItemDelete(base as CFDictionary)
    }
}

@MainActor
final class AppSession: ObservableObject {
    @Published var isLoggedIn: Bool = false

    // Stored connection details (not published — read on demand).
    var serverHost: String = ""
    var serverPort: String = "443"
    var username: String = ""
    var password: String = ""

    private let defaults = UserDefaults.standard

    /// Validates + stores credentials and marks the session as logged in.
    func signIn(host: String, port: String, username: String, password: String, remember: Bool) {
        self.serverHost = host
        self.serverPort = port
        self.username = username
        self.password = password

        defaults.set(remember, forKey: "vpn_remember_credentials")
        if remember {
            defaults.set(host, forKey: "vpn_server_address")
            defaults.set(port, forKey: "vpn_server_port")
            defaults.set(username, forKey: "vpn_username")
            CredentialStore.savePassword(password, account: username)
        } else {
            defaults.removeObject(forKey: "vpn_username")
            CredentialStore.deletePassword(account: username)
        }

        isLoggedIn = true
    }

    /// Disconnects the VPN (if active) and returns to the login screen.
    /// Remembered credentials are kept so the login screen can pre-fill them.
    func logout() {
        VPNManager.shared.disconnect()
        password = ""
        isLoggedIn = false
    }
}

// MARK: - macOS color helpers
// iOS uses Color(.systemGroupedBackground)/Color(.systemBackground); these
// are the AppKit equivalents so the shared card look survives on macOS.
extension Color {
    static var groupedBackground: Color { Color(nsColor: .windowBackgroundColor) }
    static var cardBackground: Color { Color(nsColor: .controlBackgroundColor) }
}
