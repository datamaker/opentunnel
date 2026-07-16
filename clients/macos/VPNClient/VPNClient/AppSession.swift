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
    var serverPort: String = "1194"
    var username: String = ""
    var password: String = ""

    private let defaults = UserDefaults.standard

    init() {
        // Restore a previous session so the user stays logged in across app
        // restarts. Requires "Remember credentials" (the password lives in the
        // Keychain and is needed to connect from the main screen).
        guard defaults.bool(forKey: "vpn_logged_in"),
              defaults.bool(forKey: "vpn_remember_credentials"),
              let host = defaults.string(forKey: "vpn_server_address"),
              let user = defaults.string(forKey: "vpn_username"),
              let pw = CredentialStore.password(account: user)
        else { return }
        serverHost = host
        serverPort = defaults.string(forKey: "vpn_server_port") ?? "1194"
        username = user
        password = pw
        isLoggedIn = true
    }

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
        // Persist the logged-in state so the session survives an app quit (only
        // when credentials are remembered — restoring needs the saved password).
        defaults.set(remember, forKey: "vpn_logged_in")

        isLoggedIn = true
    }

    /// Disconnects the VPN (if active) and returns to the login screen.
    /// Remembered credentials are kept so the login screen can pre-fill them.
    func logout() {
        VPNManager.shared.disconnect()
        defaults.set(false, forKey: "vpn_logged_in")
        password = ""
        isLoggedIn = false
    }
}

// MARK: - Cross-platform color helpers
// This project is archived for iOS, macOS (and formerly visionOS) via Xcode
// Cloud, so the card colors must resolve on every platform, not just AppKit.
#if os(macOS)
import AppKit
extension Color {
    static var groupedBackground: Color { Color(nsColor: .windowBackgroundColor) }
    static var cardBackground: Color { Color(nsColor: .controlBackgroundColor) }
}
#else
import UIKit
extension Color {
    static var groupedBackground: Color { Color(uiColor: .systemGroupedBackground) }
    static var cardBackground: Color { Color(uiColor: .secondarySystemGroupedBackground) }
}
#endif
