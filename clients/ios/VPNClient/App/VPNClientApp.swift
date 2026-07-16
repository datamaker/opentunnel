//
//  VPNClientApp.swift
//  VPNClient
//
//  iOS VPN Client Application Entry Point
//

import SwiftUI
import NetworkExtension

@main
struct VPNClientApp: App {
    @StateObject private var viewModel = VPNViewModel()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(viewModel)
        }
    }
}

// MARK: - Content View (Navigation Root)
struct ContentView: View {
    @EnvironmentObject var viewModel: VPNViewModel

    var body: some View {
        NavigationStack {
            if viewModel.isAuthenticated {
                MainView()
            } else {
                LoginView()
            }
        }
        // No silent auto-login: the login screen pre-fills remembered
        // credentials (incl. password from Keychain) and the user taps Sign In —
        // consistent with the macOS client.
    }
}

// MARK: - Preview Provider
#Preview {
    ContentView()
        .environmentObject(VPNViewModel())
}
