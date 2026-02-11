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
        .onAppear {
            viewModel.loadSavedCredentials()
        }
    }
}

// MARK: - Preview Provider
#Preview {
    ContentView()
        .environmentObject(VPNViewModel())
}
