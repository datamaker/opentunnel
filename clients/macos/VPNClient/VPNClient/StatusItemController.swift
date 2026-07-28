//
//  StatusItemController.swift
//  VPNClient
//
//  AppKit-based menu-bar status item (parity with the Windows system-tray icon).
//  We use NSStatusItem instead of SwiftUI's MenuBarExtra because MenuBarExtra
//  ignores custom icon sizing — it normalizes the label image to a fixed size,
//  so .font()/.frame() have no visible effect. With NSStatusItem we set the icon
//  from an SF Symbol at an explicit point size so it matches the neighboring
//  menu-bar icons.
//

import AppKit
import Combine

@MainActor
final class StatusItemController: NSObject {

    /// Point size of the menu-bar glyph. Bump this to enlarge the icon.
    private static let iconPointSize: CGFloat = 18

    private let statusItem: NSStatusItem
    private let vpn = VPNManager.shared
    private let session = AppSession.shared
    private var cancellables = Set<AnyCancellable>()

    private let statusHeaderItem = NSMenuItem(title: "OpenTunnel", action: nil, keyEquivalent: "")
    private let connectItem = NSMenuItem(title: "Connect", action: #selector(connectTapped), keyEquivalent: "")
    private let disconnectItem = NSMenuItem(title: "Disconnect", action: #selector(disconnectTapped), keyEquivalent: "")

    override init() {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        super.init()

        buildMenu()

        // Update icon + menu on VPN status and session (login) changes. Hop to
        // the main actor inside the sink (matches VPNManager's callback pattern).
        vpn.$status
            .sink { [weak self] _ in
                Task { @MainActor [weak self] in self?.refresh() }
            }
            .store(in: &cancellables)
        session.$isLoggedIn
            .sink { [weak self] _ in
                Task { @MainActor [weak self] in self?.refresh() }
            }
            .store(in: &cancellables)

        refresh()
    }

    // MARK: - Menu

    private func buildMenu() {
        let menu = NSMenu()
        menu.autoenablesItems = false

        statusHeaderItem.isEnabled = false
        menu.addItem(statusHeaderItem)
        menu.addItem(.separator())

        connectItem.target = self
        disconnectItem.target = self
        menu.addItem(connectItem)
        menu.addItem(disconnectItem)
        menu.addItem(.separator())

        let openItem = NSMenuItem(title: "Open OpenTunnel", action: #selector(openWindowTapped), keyEquivalent: "")
        openItem.target = self
        menu.addItem(openItem)

        let quitItem = NSMenuItem(title: "Quit OpenTunnel", action: #selector(quitTapped), keyEquivalent: "q")
        quitItem.target = self
        menu.addItem(quitItem)

        statusItem.menu = menu
    }

    // MARK: - Refresh (icon + menu state)

    private func refresh() {
        let connected = vpn.status.isConnected

        // One shape, two variants: filled shield-lock when connected, outline otherwise.
        let symbolName = connected ? "lock.shield.fill" : "lock.shield"
        let config = NSImage.SymbolConfiguration(pointSize: Self.iconPointSize, weight: .regular)
        let image = NSImage(systemSymbolName: symbolName, accessibilityDescription: "OpenTunnel: \(vpn.status.rawValue)")?
            .withSymbolConfiguration(config)
        image?.isTemplate = true   // adopt the menu-bar's light/dark tint
        statusItem.button?.image = image

        statusHeaderItem.title = "OpenTunnel — \(vpn.status.rawValue)"

        let transient = (vpn.status == .connecting || vpn.status == .reasserting || vpn.status == .disconnecting)
        connectItem.isEnabled = session.isLoggedIn && !connected && !transient
        disconnectItem.isEnabled = connected || transient
    }

    // MARK: - Actions

    @objc private func connectTapped() {
        guard session.isLoggedIn else { return }
        vpn.serverAddress = "\(session.serverHost):\(session.serverPort)"
        Task { try? await vpn.connect(username: session.username, password: session.password) }
    }

    @objc private func disconnectTapped() {
        vpn.disconnect()
    }

    @objc private func openWindowTapped() {
        NSApplication.shared.activate(ignoringOtherApps: true)
        NSApplication.shared.windows
            .first { $0.canBecomeMain }?
            .makeKeyAndOrderFront(nil)
    }

    @objc private func quitTapped() {
        NSApplication.shared.terminate(nil)
    }
}
