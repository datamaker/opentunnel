using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using VPNClient.Network;
using VPNClient.Protocol;
using VPNClient.Services;
using VPNClient.ViewModels;

namespace VPNClient.Views;

/// <summary>
/// Interaction logic for LoginView.xaml
/// </summary>
public partial class LoginView : UserControl
{
    private readonly ILogger<LoginView> _logger;
    private readonly TlsConnection _tlsConnection;
    private readonly MainViewModel _viewModel;
    private readonly DeviceFlowService _deviceFlow = new();

    private bool _passwordVisible;
    private CancellationTokenSource? _ssoCts;

    public event EventHandler<LoginEventArgs>? LoginSuccessful;

    public LoginView()
    {
        InitializeComponent();

        _logger = App.ServiceProvider.GetRequiredService<ILogger<LoginView>>();
        _tlsConnection = App.ServiceProvider.GetRequiredService<TlsConnection>();
        _viewModel = App.ServiceProvider.GetRequiredService<MainViewModel>();

        // Prefill the server fields from the last-used values held by the VM.
        ServerAddressTextBox.Text = string.IsNullOrWhiteSpace(_viewModel.ServerAddress)
            ? "vpn.example.com"
            : _viewModel.ServerAddress;
        PortTextBox.Text = _viewModel.ServerPort.ToString();

        // Load saved credentials if remember me was checked
        LoadSavedCredentials();
    }

    private void LoadSavedCredentials()
    {
        try
        {
            var savedUsername = Properties.Settings.Default.SavedUsername;
            var savedRememberMe = Properties.Settings.Default.RememberMe;

            if (savedRememberMe && !string.IsNullOrEmpty(savedUsername))
            {
                UsernameTextBox.Text = savedUsername;
                RememberMeCheckBox.IsChecked = true;
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to load saved credentials");
        }
    }

    private void SaveCredentials(string username, string password, string server, int port)
    {
        try
        {
            if (RememberMeCheckBox.IsChecked == true)
            {
                // Persist username + DPAPI-encrypted password + server so the app
                // stays signed in across restarts (parity with the other clients).
                CredentialStore.Save(username, password, server, port);
            }
            else
            {
                CredentialStore.Clear();
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to save credentials");
        }
    }

    private void TogglePasswordButton_Click(object sender, RoutedEventArgs e)
    {
        _passwordVisible = !_passwordVisible;

        if (_passwordVisible)
        {
            PasswordTextBox.Text = PasswordBox.Password;
            PasswordTextBox.Visibility = Visibility.Visible;
            PasswordBox.Visibility = Visibility.Collapsed;
            TogglePasswordText.Text = "Hide";
        }
        else
        {
            PasswordBox.Password = PasswordTextBox.Text;
            PasswordBox.Visibility = Visibility.Visible;
            PasswordTextBox.Visibility = Visibility.Collapsed;
            TogglePasswordText.Text = "Show";
        }
    }

    private string CurrentPassword => _passwordVisible ? PasswordTextBox.Text : PasswordBox.Password;

    private async void LoginButton_Click(object sender, RoutedEventArgs e)
    {
        // Validate input
        var username = UsernameTextBox.Text.Trim();
        var password = CurrentPassword;

        if (string.IsNullOrEmpty(username))
        {
            ShowError("Please enter your username.");
            return;
        }

        if (string.IsNullOrEmpty(password))
        {
            ShowError("Please enter your password.");
            return;
        }

        var serverAddress = GetServerAddress();
        if (string.IsNullOrEmpty(serverAddress))
        {
            ShowError("Please enter a server address.");
            return;
        }

        if (!TryGetServerPort(out int port))
        {
            ShowError("Please enter a valid port number (1-65535).");
            return;
        }

        // Show loading state
        SetLoadingState(true);
        HideError();

        try
        {
            _logger.LogInformation("Attempting authentication for user: {Username}", username);

            // Connect and authenticate
            await _tlsConnection.ConnectAsync(serverAddress, port);

            var authRequest = new AuthRequest
            {
                Username = username,
                Password = password,
                ClientVersion = "1.0.0",
                Platform = "windows"
            };

            var response = await _tlsConnection.AuthenticateAsync(authRequest);

            if (response.Success)
            {
                _logger.LogInformation("Authentication successful for user: {Username}", username);

                // Save credentials if remember me is checked
                SaveCredentials(username, password, serverAddress, port);

                // Publish the authenticated session + server details to the shared VM
                // so the Main screen can connect with them. The real password is kept
                // in the VM because the server re-verifies it on the tunnel connection.
                _viewModel.ServerAddress = serverAddress;
                _viewModel.ServerPort = port;
                _viewModel.Username = username;
                _viewModel.Password = password;
                _viewModel.SessionToken = response.SessionToken ?? string.Empty;
                _viewModel.AuthMode = CredentialStore.AuthModePassword;
                _viewModel.IsAuthenticated = true;

                // Disconnect the temporary connection (will reconnect through VpnTunnel)
                await _tlsConnection.DisconnectAsync();

                // Raise the login successful event
                LoginSuccessful?.Invoke(this, new LoginEventArgs(username, response.SessionToken ?? string.Empty));
            }
            else
            {
                ShowError(response.ErrorMessage ?? "Authentication failed. Please check your credentials.");
                await _tlsConnection.DisconnectAsync();
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Authentication failed");
            ShowError($"Connection failed: {ex.Message}");

            try
            {
                await _tlsConnection.DisconnectAsync();
            }
            catch
            {
                // Ignore cleanup errors
            }
        }
        finally
        {
            SetLoadingState(false);
        }
    }

    /// <summary>
    /// "Google로 로그인 (Datasee SSO)": OAuth 2.0 device flow against the public
    /// Datasee IdP (reachable without the VPN). The default browser opens the
    /// verification page; we show the user code + URL as a fallback and poll
    /// the token endpoint until an id_token is issued. The VPN server then
    /// exchanges it for a 30-day session token ({authType:"sso"}), which is
    /// persisted DPAPI-encrypted for reconnects ({authType:"session"}).
    /// </summary>
    private async void SsoLoginButton_Click(object sender, RoutedEventArgs e)
    {
        var serverAddress = GetServerAddress();
        if (string.IsNullOrEmpty(serverAddress))
        {
            ShowError("Please enter a server address.");
            return;
        }

        if (!TryGetServerPort(out int port))
        {
            ShowError("Please enter a valid port number (1-65535).");
            return;
        }

        HideError();
        _ssoCts = new CancellationTokenSource();
        SetSsoFlowState(true);

        try
        {
            // Step 1: request a device/user code pair from the IdP.
            SsoStatusText.Text = "Datasee SSO에 연결하는 중...";
            SsoUserCodeText.Text = string.Empty;
            SsoVerificationUriText.Text = string.Empty;

            var auth = await _deviceFlow.StartAsync(_ssoCts.Token);

            // Step 2: open the default browser; show code + URL as fallback.
            SsoStatusText.Text = "브라우저에서 Google 로그인을 완료해 주세요.";
            SsoUserCodeText.Text = auth.UserCode;
            SsoVerificationUriText.Text =
                $"브라우저가 열리지 않으면 {auth.VerificationUri} 에 접속해 위 코드를 입력해 주세요.";

            var browserUrl = string.IsNullOrEmpty(auth.VerificationUriComplete)
                ? auth.VerificationUri
                : auth.VerificationUriComplete;
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = browserUrl,
                    UseShellExecute = true
                });
            }
            catch (Exception ex)
            {
                // Not fatal — the user can follow the on-screen code + URL.
                _logger.LogWarning(ex, "Failed to open the default browser for SSO");
            }

            // Step 3: poll until the browser login completes.
            var idToken = await _deviceFlow.PollForIdTokenAsync(auth, _ssoCts.Token);

            // Step 4: exchange the id_token for a VPN session ({authType:"sso"}).
            SsoStatusText.Text = "VPN 서버에 인증하는 중...";
            _logger.LogInformation("SSO id_token acquired; authenticating with VPN server");

            await _tlsConnection.ConnectAsync(serverAddress, port);

            var username = DeviceFlowService.TryGetEmail(idToken) ?? "Datasee SSO";
            var authRequest = new AuthRequest
            {
                Username = username,
                AuthType = AuthTypes.Sso,
                Token = idToken,
                ClientVersion = "1.0.0",
                Platform = "windows"
            };

            var response = await _tlsConnection.AuthenticateAsync(authRequest);

            if (response.Success)
            {
                _logger.LogInformation("SSO authentication successful for {Username}", username);

                var sessionToken = response.SessionToken ?? string.Empty;

                // Persist the 30-day session token (DPAPI) so restarts and
                // reconnects skip the browser flow ({authType:"session"}).
                if (!string.IsNullOrEmpty(sessionToken))
                {
                    CredentialStore.SaveSsoSession(username, sessionToken, serverAddress, port);
                }

                _viewModel.ServerAddress = serverAddress;
                _viewModel.ServerPort = port;
                _viewModel.Username = username;
                _viewModel.Password = null;
                _viewModel.SessionToken = sessionToken;
                _viewModel.AuthMode = CredentialStore.AuthModeSso;
                _viewModel.IsAuthenticated = true;

                // Disconnect the temporary connection (will reconnect through VpnTunnel)
                await _tlsConnection.DisconnectAsync();

                LoginSuccessful?.Invoke(this, new LoginEventArgs(username, sessionToken));
            }
            else
            {
                ShowError(response.ErrorMessage ?? "SSO 인증에 실패했습니다. 관리자에게 문의해 주세요.");
                await _tlsConnection.DisconnectAsync();
            }
        }
        catch (OperationCanceledException)
        {
            // User pressed 취소 — quietly return to the idle login screen.
            _logger.LogInformation("SSO login cancelled by user");
        }
        catch (DeviceFlowException ex)
        {
            ShowError(ex.Message);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "SSO login failed");
            ShowError($"SSO 로그인에 실패했습니다: {ex.Message}");

            try
            {
                await _tlsConnection.DisconnectAsync();
            }
            catch
            {
                // Ignore cleanup errors
            }
        }
        finally
        {
            SetSsoFlowState(false);
            _ssoCts?.Dispose();
            _ssoCts = null;
        }
    }

    private void SsoCancelButton_Click(object sender, RoutedEventArgs e)
    {
        _ssoCts?.Cancel();
    }

    private void SetSsoFlowState(bool inProgress)
    {
        SsoPanel.Visibility = inProgress ? Visibility.Visible : Visibility.Collapsed;
        SsoLoginButton.IsEnabled = !inProgress;
        LoginButton.IsEnabled = !inProgress;
        ServerAddressTextBox.IsEnabled = !inProgress;
        PortTextBox.IsEnabled = !inProgress;
        UsernameTextBox.IsEnabled = !inProgress;
        PasswordBox.IsEnabled = !inProgress;
        PasswordTextBox.IsEnabled = !inProgress;
        TogglePasswordButton.IsEnabled = !inProgress;
        RememberMeCheckBox.IsEnabled = !inProgress;
    }

    private string GetServerAddress() => ServerAddressTextBox.Text.Trim();

    private bool TryGetServerPort(out int port)
    {
        if (int.TryParse(PortTextBox.Text.Trim(), out port) && port > 0 && port <= 65535)
        {
            return true;
        }

        port = 0;
        return false;
    }

    private void SetLoadingState(bool isLoading)
    {
        LoginButton.IsEnabled = !isLoading;
        SsoLoginButton.IsEnabled = !isLoading;
        ServerAddressTextBox.IsEnabled = !isLoading;
        PortTextBox.IsEnabled = !isLoading;
        UsernameTextBox.IsEnabled = !isLoading;
        PasswordBox.IsEnabled = !isLoading;
        PasswordTextBox.IsEnabled = !isLoading;
        TogglePasswordButton.IsEnabled = !isLoading;
        RememberMeCheckBox.IsEnabled = !isLoading;
        LoadingPanel.Visibility = isLoading ? Visibility.Visible : Visibility.Collapsed;
    }

    private void ShowError(string message)
    {
        ErrorMessage.Text = message;
        ErrorMessage.Visibility = Visibility.Visible;
    }

    private void HideError()
    {
        ErrorMessage.Text = string.Empty;
        ErrorMessage.Visibility = Visibility.Collapsed;
    }
}

// Re-export LoginEventArgs for convenience
public class LoginEventArgs : EventArgs
{
    public string Username { get; }
    public string SessionToken { get; }

    public LoginEventArgs(string username, string sessionToken)
    {
        Username = username;
        SessionToken = sessionToken;
    }
}
