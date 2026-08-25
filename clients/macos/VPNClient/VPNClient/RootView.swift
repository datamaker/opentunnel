//
//  RootView.swift
//  VPNClient
//
//  Switches between Login and Main based on the session state.
//

import SwiftUI

struct RootView: View {
    @EnvironmentObject var session: AppSession

    var body: some View {
        Group {
            if session.isLoggedIn {
                MainView()
            } else {
                LoginView()
            }
        }
        .modifier(RootSizing())
        // CLI -> GUI handoff. iOS uses SwiftUI's `.onOpenURL` (a single-scene
        // WindowGroup, so no new-window problem). macOS routes deep links
        // through the AppDelegate instead (see VPNClientApp) — with a
        // WindowGroup, `.onOpenURL` spawns a new window per URL. Both paths call
        // the same AppSession.handleDeepLink, whose 2s de-dupe keeps them safe.
        #if !os(macOS)
        .onOpenURL { url in
            session.handleDeepLink(url)
        }
        #endif
        // If a session was already restored at launch, honor the
        // "Auto-connect at app launch" setting. A just-completed login connects
        // via AppSession instead, so this only covers app restart.
        .task {
            VPNManager.shared.autoConnectOnLaunchIfEnabled()
        }
    }
}

/// macOS gets a fixed phone-sized window (matching the mobile clients; iPhone
/// 12 Pro is 390×844 pt) — windowResizability(.contentSize) makes the window
/// adopt this size and stay non-resizable.
///
/// The same frame on iOS/iPadOS would pin the UI to 390×820 pt regardless of
/// the device: clipped on an iPhone SE (375×667 pt), a letterboxed card on a
/// Pro Max, and a small floating panel on an iPad. Touch platforms therefore
/// fill the screen and let the layout adapt.
private struct RootSizing: ViewModifier {
    func body(content: Content) -> some View {
        #if os(macOS)
        content.frame(width: 390, height: 820)
        #else
        content.frame(maxWidth: .infinity, maxHeight: .infinity)
        #endif
    }
}

#Preview {
    RootView()
        .environmentObject(AppSession())
}
