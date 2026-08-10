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

    // MARK: SSO session token (server-issued 30-day credential)
    /// Stored under a fixed account so it survives independently of usernames.
    private static let ssoSessionAccount = "datasee.sso.session-token"

    static func saveSSOSessionToken(_ token: String) {
        savePassword(token, account: ssoSessionAccount)
    }

    static func ssoSessionToken() -> String? {
        password(account: ssoSessionAccount)
    }

    static func deleteSSOSessionToken() {
        deletePassword(account: ssoSessionAccount)
    }
}

@MainActor
final class AppSession: ObservableObject {
    /// Shared instance so the AppKit menu-bar status item and the SwiftUI scene
    /// observe the same session state.
    static let shared = AppSession()

    /// How the current session authenticates against the VPN server.
    enum AuthMethod: String {
        case password
        case sso
    }

    /// App Group shared with the PacketTunnel extension — carries the
    /// server-issued SSO session token back from the extension to the app.
    static let appGroupId = "group.kr.co.datasee.VPNClient"
    private static let ssoSessionTokenKey = "vpn_sso_session_token"
    private static let ssoSessionRejectedKey = "vpn_sso_session_rejected"

    @Published var isLoggedIn: Bool = false

    // Stored connection details (not published — read on demand).
    var serverHost: String = ""
    var serverPort: String = "1194"
    var username: String = ""
    var password: String = ""

    // SSO state. The id_token is transient (first connect only); the
    // server-issued 30-day session token lives in the Keychain.
    var authMethod: AuthMethod = .password
    var ssoIdToken: String?
    var ssoSessionToken: String?

    private let defaults = UserDefaults.standard

    init() {
        // Restore a previous session so the user stays logged in across app
        // restarts.
        guard defaults.bool(forKey: "vpn_logged_in"),
              let host = defaults.string(forKey: "vpn_server_address")
        else { return }

        if defaults.string(forKey: "vpn_auth_method") == AuthMethod.sso.rawValue {
            // SSO restore needs the server-issued session token (the extension
            // may have handed a fresh one over via the App Group while the app
            // was gone). Without one the user must sign in with SSO again.
            adoptPendingSSOSessionToken()
            guard let token = CredentialStore.ssoSessionToken() else { return }
            serverHost = host
            serverPort = defaults.string(forKey: "vpn_server_port") ?? "1194"
            username = defaults.string(forKey: "vpn_username") ?? ""
            authMethod = .sso
            ssoSessionToken = token
            isLoggedIn = true
            return
        }

        // Password restore requires "Remember credentials" (the password lives
        // in the Keychain and is needed to connect from the main screen).
        guard defaults.bool(forKey: "vpn_remember_credentials"),
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
        clearSSOState()

        defaults.set(AuthMethod.password.rawValue, forKey: "vpn_auth_method")
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

    /// Marks the session as logged in via Datasee SSO (device flow). The
    /// id_token authenticates the first connect; the server then issues a
    /// 30-day session token which replaces it (see adoptPendingSSOSessionToken).
    func signInWithSSO(host: String, port: String, idToken: String) {
        serverHost = host
        serverPort = port
        username = DeviceFlowService.email(fromIdToken: idToken) ?? "Datasee SSO"
        password = ""
        authMethod = .sso
        ssoIdToken = idToken
        // A fresh SSO login invalidates any previous session token (it may
        // belong to a different account).
        ssoSessionToken = nil
        CredentialStore.deleteSSOSessionToken()

        defaults.set(AuthMethod.sso.rawValue, forKey: "vpn_auth_method")
        defaults.set(host, forKey: "vpn_server_address")
        defaults.set(port, forKey: "vpn_server_port")
        defaults.set(username, forKey: "vpn_username")
        defaults.set(true, forKey: "vpn_logged_in")

        isLoggedIn = true
    }

    /// The credential VPNManager should send in SSO mode: the stored session
    /// token when we have one ("session"), otherwise the fresh id_token ("sso").
    func ssoCredential() -> (authType: String, token: String)? {
        if let token = ssoSessionToken, !token.isEmpty {
            return ("session", token)
        }
        if let token = ssoIdToken, !token.isEmpty {
            return ("sso", token)
        }
        return nil
    }

    /// Moves a session token the extension left in the App Group container
    /// into the Keychain. Called after a successful connect (and on restore).
    func adoptPendingSSOSessionToken() {
        guard let shared = UserDefaults(suiteName: Self.appGroupId),
              let token = shared.string(forKey: Self.ssoSessionTokenKey), !token.isEmpty
        else { return }
        shared.removeObject(forKey: Self.ssoSessionTokenKey)
        CredentialStore.saveSSOSessionToken(token)
        ssoSessionToken = token
    }

    /// If the extension flagged that the server rejected our session token,
    /// clear it and drop back to the login screen so the user re-runs SSO.
    func handleSSOSessionRejectionIfNeeded() {
        guard let shared = UserDefaults(suiteName: Self.appGroupId),
              shared.bool(forKey: Self.ssoSessionRejectedKey)
        else { return }
        shared.removeObject(forKey: Self.ssoSessionRejectedKey)
        guard authMethod == .sso else { return }
        ssoSessionToken = nil
        CredentialStore.deleteSSOSessionToken()
        if ssoIdToken == nil {
            defaults.set(false, forKey: "vpn_logged_in")
            isLoggedIn = false
        }
    }

    /// Disconnects the VPN (if active) and returns to the login screen.
    /// Remembered credentials are kept so the login screen can pre-fill them.
    /// SSO tokens are cleared — logging out ends the SSO session.
    func logout() {
        VPNManager.shared.disconnect()
        defaults.set(false, forKey: "vpn_logged_in")
        password = ""
        clearSSOState()
        isLoggedIn = false
    }

    private func clearSSOState() {
        authMethod = .password
        ssoIdToken = nil
        ssoSessionToken = nil
        CredentialStore.deleteSSOSessionToken()
        if let shared = UserDefaults(suiteName: Self.appGroupId) {
            shared.removeObject(forKey: Self.ssoSessionTokenKey)
            shared.removeObject(forKey: Self.ssoSessionRejectedKey)
        }
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
