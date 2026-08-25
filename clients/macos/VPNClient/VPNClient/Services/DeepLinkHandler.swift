//
//  DeepLinkHandler.swift
//  VPNClient
//
//  Parses the custom `opentunnel://` URL scheme the CLI uses to hand the GUI a
//  server-issued SSO session token, so the app reflects the CLI's logged-in /
//  connected state.
//
//  Contract (agreed with the CLI):
//    opentunnel://session?token=<urlencoded session JWT>&server=<host>&port=<port>&connect=1
//      token   — the VPN server's 30-day SSO session JWT (authType "session"). Required.
//      server  — optional VPN host  (default vpn.datasee.co.kr)
//      port    — optional VPN port  (default 1194)
//      connect — "1" to connect immediately after storing.
//
//  `parse(_:)` is a pure function (no side effects) so it can be exercised by
//  unit tests / previews without a running app. Applying a parsed link — moving
//  the token into the Keychain, flipping the session to logged-in, and kicking
//  off the connection — lives in AppSession.handleDeepLink(_:).
//

import Foundation

enum DeepLinkHandler {

    /// A validated `opentunnel://session` link. `token` is guaranteed non-empty.
    struct SessionLink: Equatable {
        var token: String
        var server: String
        var port: String
        var connect: Bool
    }

    static let scheme = "opentunnel"
    static let sessionAction = "session"
    static let defaultServer = "vpn.datasee.co.kr"
    static let defaultPort = "1194"

    /// Pure parser. Returns nil for anything that is not a well-formed
    /// `opentunnel://session` link carrying a non-empty `token`.
    static func parse(_ url: URL) -> SessionLink? {
        guard url.scheme?.lowercased() == scheme else { return nil }

        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false) else {
            return nil
        }

        // Accept the action as the URL host (opentunnel://session?…). Some URL
        // forms (opentunnel:session?… / opentunnel:///session) surface it as the
        // first path segment instead, so fall back to that.
        let host = components.host?.lowercased()
        let firstPathSegment = components.path
            .split(separator: "/").first.map { $0.lowercased() }
        let action = host ?? firstPathSegment
        guard action == sessionAction else { return nil }

        // URLComponents percent-decodes query values for us.
        let items = components.queryItems ?? []
        func value(_ name: String) -> String? {
            guard let raw = items.first(where: { $0.name == name })?.value else { return nil }
            let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            return trimmed.isEmpty ? nil : trimmed
        }

        guard let token = value("token") else { return nil }

        return SessionLink(
            token: token,
            server: value("server") ?? defaultServer,
            port: value("port") ?? defaultPort,
            connect: value("connect") == "1"
        )
    }
}
