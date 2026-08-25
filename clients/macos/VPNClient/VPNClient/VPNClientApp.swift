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
        WindowGroup {
            RootView()
                .environmentObject(session)
        }
        .windowResizability(.contentSize)
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
            // Bring the existing window forward instead of opening a new one.
            NSApp.activate(ignoringOtherApps: true)
            NSApp.windows.first { $0.canBecomeMain }?.makeKeyAndOrderFront(nil)
        }
    }
}
#endif
