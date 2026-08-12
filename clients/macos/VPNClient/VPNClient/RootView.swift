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
