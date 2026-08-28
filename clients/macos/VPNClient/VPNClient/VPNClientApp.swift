//
//  VPNClientApp.swift
//  VPNClient
//
//  Created by 권정빈 on 2/11/26.
//

import SwiftUI

@main
struct VPNClientApp: App {
    // The macOS menu-bar status item is built in AppKit (NSStatusItem) rather
    // than SwiftUI's MenuBarExtra, because MenuBarExtra ignores custom icon
    // sizing — it normalizes the label image to a fixed size. NSStatusItem lets
    // us size the SF Symbol to match the neighboring menu-bar icons.
    // See StatusItemController. iOS has no menu bar (it shows its own system
    // VPN indicator), so this is macOS-only.
    #if os(macOS)
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    #endif

    @StateObject private var session = AppSession.shared

    var body: some Scene {
        #if os(macOS)
        // A single `Window`, not a `WindowGroup`: a WindowGroup opens a new
        // window whenever the app is activated by an incoming opentunnel:// URL,
        // so a CLI-driven connect spawned a second window. A single-instance
        // Window scene can't duplicate; deep links are routed through the
        // AppDelegate (see below), which reuses this window.
        Window("OpenTunnel", id: "main") {
            RootView()
                .environmentObject(session)
        }
        .windowResizability(.contentSize)
        // Always present the window on a fresh launch. Without this, state
        // restoration replays the "window closed" state from the previous run
        // (the app now keeps running in the menu bar after X), so launching
        // the app appeared to do nothing.
        .defaultLaunchBehavior(.presented)
        #else
        WindowGroup {
            RootView()
                .environmentObject(session)
        }
        .windowResizability(.contentSize)
        #endif
    }
}

#if os(macOS)
/// Owns the menu-bar status item for the app's lifetime.
final class AppDelegate: NSObject, NSApplicationDelegate {
    private var statusController: StatusItemController?

    func applicationDidFinishLaunching(_ notification: Notification) {
        statusController = StatusItemController()
        // Install the notification-center delegate so disconnect/reconnect
        // banners are shown even while the app is frontmost.
        NotificationService.shared.activate()
    }

    /// Closing the window (X / Cmd+W) keeps the app alive in the menu bar —
    /// parity with the Windows tray client. Quitting is explicit: Cmd+Q or the
    /// menu-bar "Quit OpenTunnel".
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        false
    }

    /// Quitting must not leave the NE tunnel running headless (the extension
    /// is a separate process, so it survives the app otherwise). Stop the
    /// tunnel first, then finish terminating once it reports disconnected
    /// (bounded at 5 s so a stuck teardown can never block Quit).
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        let vpn = VPNManager.shared
        switch vpn.status {
        case .disconnected, .invalid:
            return .terminateNow
        default:
            break
        }
        vpn.disconnect()
        Task { @MainActor in
            for _ in 0..<50 where VPNManager.shared.status != .disconnected {
                try? await Task.sleep(nanoseconds: 100_000_000)
            }
            sender.reply(toApplicationShouldTerminate: true)
        }
        return .terminateLater
    }

    /// CLI -> GUI handoff on macOS. We route deep links through the AppDelegate
    /// rather than SwiftUI's `.onOpenURL`, because with a `WindowGroup` every
    /// incoming URL spawns a *new* window (scene) — opening opentunnel:// twice
    /// left two OpenTunnel windows. This delegate method is also called on cold
    /// start (app launched by the URL), so it covers that case too. We reuse the
    /// existing window instead of creating one.
    func application(_ application: NSApplication, open urls: [URL]) {
        Task { @MainActor in
            for url in urls {
                AppSession.shared.handleDeepLink(url)
            }
            MainWindowOpener.show()
        }
    }
}

/// Re-shows the main window from AppKit contexts (the menu-bar item, deep
/// links) — needed because the window can now be closed while the app keeps
/// running. Prefers the still-alive NSWindow; falls back to SwiftUI's
/// `openWindow` action (captured by RootView) if the scene tore it down.
@MainActor
enum MainWindowOpener {
    /// Set by RootView's bridge on first appearance; opens the "main" Window.
    static var openWindowAction: (() -> Void)?

    static func show() {
        NSApp.activate(ignoringOtherApps: true)
        if let window = NSApp.windows.first(where: { $0.canBecomeMain }) {
            window.makeKeyAndOrderFront(nil)
        } else {
            openWindowAction?()
        }
    }
}
#endif
