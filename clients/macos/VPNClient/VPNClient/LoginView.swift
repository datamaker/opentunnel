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

    // Datasee SSO (OAuth device flow) state.
    private enum SSOState {
        case idle
        case starting
        case waiting(DeviceAuthorization)
        case failed(String)
    }
    @State private var ssoState: SSOState = .idle
    @State private var ssoTask: Task<Void, Never>?

    var body: some View {
        ScrollView {
            VStack(spacing: 32) {
                headerSection
                formSection
                loginButton
                ssoSection
                Spacer()
            }
            .padding()
        }
        .background(Color.groupedBackground)
        .onAppear {
            loadSavedSettings()
        }
        .onDisappear {
            ssoTask?.cancel()
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

    // MARK: - SSO Section
    private var ssoSection: some View {
        VStack(spacing: 16) {
            // Divider: "또는"
            HStack {
                Rectangle()
                    .fill(Color.secondary.opacity(0.3))
                    .frame(height: 1)
                Text("또는")
                    .font(.caption)
                    .foregroundColor(.secondary)
                Rectangle()
                    .fill(Color.secondary.opacity(0.3))
                    .frame(height: 1)
            }

            switch ssoState {
            case .idle, .failed:
                ssoLoginButton
                if case .failed(let message) = ssoState {
                    Text(message)
                        .font(.caption)
                        .foregroundColor(.red)
                        .multilineTextAlignment(.center)
                }
            case .starting:
                ProgressView()
                    .padding(.vertical, 8)
            case .waiting(let authorization):
                ssoWaitingCard(authorization)
            }
        }
    }

    private var ssoLoginButton: some View {
        Button {
            startSSOLogin()
        } label: {
            HStack(spacing: 12) {
                Image(systemName: "person.badge.key.fill")
                Text("Google로 로그인 (Datasee SSO)")
                    .fontWeight(.semibold)
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 16)
            .background(Color.cardBackground)
            .foregroundColor(isServerValid ? .primary : .secondary)
            .cornerRadius(12)
            .overlay(
                RoundedRectangle(cornerRadius: 12)
                    .stroke(Color.secondary.opacity(0.3), lineWidth: 1)
            )
        }
        .buttonStyle(.plain)
        .disabled(!isServerValid)
    }

    /// Shown while waiting for the user to approve in the browser: the code as
    /// a manual fallback, the verification URL, and a cancel button.
    private func ssoWaitingCard(_ authorization: DeviceAuthorization) -> some View {
        VStack(spacing: 12) {
            ProgressView()

            Text("브라우저에서 승인해 주세요")
                .font(.headline)

            Text(authorization.userCode)
                .font(.system(.title, design: .monospaced))
                .fontWeight(.bold)
                .textSelection(.enabled)

            Text("브라우저가 열리지 않으면 \(authorization.verificationUri) 에서 위 코드를 입력하세요")
                .font(.caption)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)

            Button("취소") {
                cancelSSOLogin()
            }
            .buttonStyle(.plain)
            .foregroundColor(.red)
            .padding(.top, 4)
        }
        .frame(maxWidth: .infinity)
        .padding()
        .background(Color.cardBackground)
        .cornerRadius(12)
    }

    // MARK: - Computed Properties
    private var isServerValid: Bool {
        !serverAddress.isEmpty &&
        !serverPort.isEmpty &&
        Int(serverPort) != nil
    }

    private var isFormValid: Bool {
        !username.isEmpty &&
        !password.isEmpty &&
        !serverAddress.isEmpty &&
        !serverPort.isEmpty &&
        Int(serverPort) != nil
    }

    // MARK: - Methods
    private func login() {
        ssoTask?.cancel()
        session.signIn(
            host: serverAddress,
            port: serverPort,
            username: username,
            password: password,
            remember: rememberCredentials
        )
    }

    /// Runs the OAuth device flow: get a code, open the browser, poll for the
    /// id_token, then hand it to the session. Host/port still come from the
    /// form — SSO only replaces username/password.
    private func startSSOLogin() {
        ssoTask?.cancel()
        ssoState = .starting
        // Persist host/port like the password path does, so they pre-fill.
        UserDefaults.standard.set(serverAddress, forKey: "vpn_server_address")
        UserDefaults.standard.set(serverPort, forKey: "vpn_server_port")

        let host = serverAddress
        let port = serverPort
        ssoTask = Task {
            do {
                let service = DeviceFlowService()
                let authorization = try await service.startAuthorization()
                ssoState = .waiting(authorization)
                DeviceFlowService.openVerificationPage(authorization)
                let tokens = try await service.pollForTokens(authorization)
                ssoState = .idle
                session.signInWithSSO(host: host, port: port, idToken: tokens.idToken)
            } catch is CancellationError {
                ssoState = .idle
            } catch {
                ssoState = .failed(error.localizedDescription)
            }
        }
    }

    private func cancelSSOLogin() {
        ssoTask?.cancel()
        ssoTask = nil
        ssoState = .idle
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
