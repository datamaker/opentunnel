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
    }
}
#endif
