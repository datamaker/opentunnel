//
//  LoginView.swift
//  VPNClient
//
//  Login screen for VPN authentication
//

import SwiftUI

struct LoginView: View {
    @EnvironmentObject var viewModel: VPNViewModel
    @State private var username = ""
    @State private var password = ""
    @State private var serverAddress = ""
    @State private var serverPort = "443"
    @State private var rememberCredentials = true
    @State private var showingPassword = false
    @FocusState private var focusedField: Field?

    enum Field {
        case username, password, serverAddress, serverPort
    }

    var body: some View {
        ScrollView {
            VStack(spacing: 32) {
                // Logo and title
                headerSection

                // Login form
                formSection

                // Login button
                loginButton

                // Error message
                if let error = viewModel.authError {
                    errorMessage(error)
                }

                Spacer()
            }
            .padding()
        }
        .background(Color(.systemGroupedBackground))
        .navigationBarHidden(true)
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
                Text("VPN Client")
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
                    VStack(alignment: .leading, spacing: 4) {
                        HStack {
                            Image(systemName: "server.rack")
                                .foregroundColor(.gray)
                            TextField("Server Address", text: $serverAddress)
                                .textContentType(.URL)
                                .autocapitalization(.none)
                                .disableAutocorrection(true)
                                .focused($focusedField, equals: .serverAddress)
                        }
                        .padding()
                        .background(Color(.systemBackground))
                        .cornerRadius(12)
                    }

                    // Port field
                    VStack(alignment: .leading, spacing: 4) {
                        HStack {
                            TextField("Port", text: $serverPort)
                                .keyboardType(.numberPad)
                                .multilineTextAlignment(.center)
                                .focused($focusedField, equals: .serverPort)
                        }
                        .padding()
                        .frame(width: 80)
                        .background(Color(.systemBackground))
                        .cornerRadius(12)
                    }
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
                        .textContentType(.username)
                        .autocapitalization(.none)
                        .disableAutocorrection(true)
                        .focused($focusedField, equals: .username)
                }
                .padding()
                .background(Color(.systemBackground))
                .cornerRadius(12)

                // Password field
                HStack {
                    Image(systemName: "lock.fill")
                        .foregroundColor(.gray)

                    if showingPassword {
                        TextField("Password", text: $password)
                            .textContentType(.password)
                            .autocapitalization(.none)
                            .disableAutocorrection(true)
                            .focused($focusedField, equals: .password)
                    } else {
                        SecureField("Password", text: $password)
                            .textContentType(.password)
                            .focused($focusedField, equals: .password)
                    }

                    Button {
                        showingPassword.toggle()
                    } label: {
                        Image(systemName: showingPassword ? "eye.slash.fill" : "eye.fill")
                            .foregroundColor(.gray)
                    }
                }
                .padding()
                .background(Color(.systemBackground))
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
            .padding()
            .background(Color(.systemBackground))
            .cornerRadius(12)
        }
    }

    // MARK: - Login Button
    private var loginButton: some View {
        Button {
            login()
        } label: {
            HStack(spacing: 12) {
                if viewModel.isAuthenticating {
                    ProgressView()
                        .progressViewStyle(CircularProgressViewStyle(tint: .white))
                } else {
                    Image(systemName: "arrow.right.circle.fill")
                }

                Text(viewModel.isAuthenticating ? "Signing in..." : "Sign In")
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
        .disabled(!isFormValid || viewModel.isAuthenticating)
    }

    // MARK: - Error Message
    private func errorMessage(_ message: String) -> some View {
        HStack {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundColor(.red)
            Text(message)
                .font(.subheadline)
                .foregroundColor(.red)
        }
        .padding()
        .frame(maxWidth: .infinity)
        .background(Color.red.opacity(0.1))
        .cornerRadius(12)
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
        focusedField = nil

        let port = Int(serverPort) ?? 443

        viewModel.login(
            username: username,
            password: password,
            serverAddress: serverAddress,
            serverPort: port,
            rememberCredentials: rememberCredentials
        )
    }

    private func loadSavedSettings() {
        // Load saved server settings from UserDefaults
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

        rememberCredentials = defaults.bool(forKey: "vpn_remember_credentials")
    }
}

// MARK: - Preview
#Preview {
    NavigationStack {
        LoginView()
    }
    .environmentObject(VPNViewModel())
}
