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

    private bool _passwordVisible;

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
