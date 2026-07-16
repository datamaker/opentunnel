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
        // Fixed phone-sized window (matches the mobile clients; iPhone 12 Pro is
        // 390×844 pt). windowResizability(.contentSize) makes the window adopt this
        // size and stay non-resizable.
        .frame(width: 390, height: 820)
    }
}

#Preview {
    RootView()
        .environmentObject(AppSession())
}
