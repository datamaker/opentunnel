//
//  LoginView.swift
//  VPNClient
//
//  Login screen for the macOS OpenTunnel client.
//  Visual design matches the iOS LoginView (shield.checkered gradient logo,
//  card-style fields, gradient Sign In button).
//

import SwiftUI

struct LoginView: View {
    @EnvironmentObject var session: AppSession

    @State private var username = ""
    @State private var password = ""
    @State private var serverAddress = ""
    @State private var serverPort = "1194"
    @State private var rememberCredentials = true
    @State private var showingPassword = false

    var body: some View {
        ScrollView {
            VStack(spacing: 32) {
                headerSection
                formSection
                loginButton
                Spacer()
            }
            .padding()
        }
        .background(Color.groupedBackground)
        .onAppear {
            loadSavedSettings()
        }
    }

    // MARK: - Header Section
    private var headerSection: some View {
        VStack(spacing: 16) {
            Image(systemName: "shield.checkered")
                .font(.system(size: 72))
                .foregroundStyle(
                    LinearGradient(
                        colors: [.blue, .cyan],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    )
                )

            VStack(spacing: 8) {
                Text("OpenTunnel")
                    .font(.largeTitle)
                    .fontWeight(.bold)

                Text("Secure your connection")
                    .font(.subheadline)
                    .foregroundColor(.secondary)
            }
        }
        .padding(.top, 40)
    }

    // MARK: - Form Section
    private var formSection: some View {
        VStack(spacing: 20) {
            // Server settings
            VStack(alignment: .leading, spacing: 8) {
                Text("Server")
                    .font(.headline)
                    .foregroundColor(.secondary)

                HStack(spacing: 12) {
                    // Server address field
                    HStack {
                        Image(systemName: "server.rack")
                            .foregroundColor(.gray)
                        TextField("Server Address", text: $serverAddress)
                            .textFieldStyle(.plain)
                    }
                    .padding()
                    .background(Color.cardBackground)
                    .cornerRadius(12)

                    // Port field
                    HStack {
                        TextField("Port", text: $serverPort)
                            .textFieldStyle(.plain)
                            .multilineTextAlignment(.center)
                    }
                    .padding()
                    .frame(width: 80)
                    .background(Color.cardBackground)
                    .cornerRadius(12)
                }
            }

            // Credentials
            VStack(alignment: .leading, spacing: 8) {
                Text("Credentials")
                    .font(.headline)
                    .foregroundColor(.secondary)

                // Username field
                HStack {
                    Image(systemName: "person.fill")
                        .foregroundColor(.gray)
                    TextField("Username", text: $username)
                        .textFieldStyle(.plain)
                }
                .padding()
                .background(Color.cardBackground)
                .cornerRadius(12)

                // Password field
                HStack {
                    Image(systemName: "lock.fill")
                        .foregroundColor(.gray)

                    if showingPassword {
                        TextField("Password", text: $password)
                            .textFieldStyle(.plain)
                    } else {
                        SecureField("Password", text: $password)
                            .textFieldStyle(.plain)
                    }

                    Button {
                        showingPassword.toggle()
                    } label: {
                        Image(systemName: showingPassword ? "eye.slash.fill" : "eye.fill")
                            .foregroundColor(.gray)
                    }
                    .buttonStyle(.plain)
                }
                .padding()
                .background(Color.cardBackground)
                .cornerRadius(12)
            }

            // Remember credentials toggle
            Toggle(isOn: $rememberCredentials) {
                HStack {
                    Image(systemName: "key.fill")
                        .foregroundColor(.gray)
                    Text("Remember credentials")
                }
            }
            .toggleStyle(.switch)
            .padding()
            .background(Color.cardBackground)
            .cornerRadius(12)
        }
    }

    // MARK: - Login Button
    private var loginButton: some View {
        Button {
            login()
        } label: {
            HStack(spacing: 12) {
                Image(systemName: "arrow.right.circle.fill")
                Text("Sign In")
                    .fontWeight(.semibold)
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 16)
            .background(
                LinearGradient(
                    colors: isFormValid ? [.blue, .cyan] : [.gray],
                    startPoint: .leading,
                    endPoint: .trailing
                )
            )
            .foregroundColor(.white)
            .cornerRadius(12)
        }
        .buttonStyle(.plain)
        .disabled(!isFormValid)
    }

    // MARK: - Computed Properties
    private var isFormValid: Bool {
        !username.isEmpty &&
        !password.isEmpty &&
        !serverAddress.isEmpty &&
        !serverPort.isEmpty &&
        Int(serverPort) != nil
    }

    // MARK: - Methods
    private func login() {
        session.signIn(
            host: serverAddress,
            port: serverPort,
            username: username,
            password: password,
            remember: rememberCredentials
        )
    }

    private func loadSavedSettings() {
        let defaults = UserDefaults.standard

        if let savedServer = defaults.string(forKey: "vpn_server_address") {
            serverAddress = savedServer
        }
        if let savedPort = defaults.string(forKey: "vpn_server_port") {
            serverPort = savedPort
        }
        if let savedUsername = defaults.string(forKey: "vpn_username") {
            username = savedUsername
        }
        if defaults.object(forKey: "vpn_remember_credentials") != nil {
            rememberCredentials = defaults.bool(forKey: "vpn_remember_credentials")
        }
        // Restore the remembered password from the Keychain.
        if rememberCredentials, !username.isEmpty,
           let savedPassword = CredentialStore.password(account: username) {
            password = savedPassword
        }
    }
}

// MARK: - Preview
#Preview {
    LoginView()
        .environmentObject(AppSession())
        .frame(width: 400, height: 640)
}
