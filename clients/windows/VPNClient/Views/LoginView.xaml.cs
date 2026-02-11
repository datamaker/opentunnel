using System.Windows;
using System.Windows.Controls;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using VPNClient.Network;
using VPNClient.Protocol;

namespace VPNClient.Views;

/// <summary>
/// Interaction logic for LoginView.xaml
/// </summary>
public partial class LoginView : UserControl
{
    private readonly ILogger<LoginView> _logger;
    private readonly TlsConnection _tlsConnection;

    public event EventHandler<LoginEventArgs>? LoginSuccessful;

    public LoginView()
    {
        InitializeComponent();

        _logger = App.ServiceProvider.GetRequiredService<ILogger<LoginView>>();
        _tlsConnection = App.ServiceProvider.GetRequiredService<TlsConnection>();

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

    private void SaveCredentials()
    {
        try
        {
            if (RememberMeCheckBox.IsChecked == true)
            {
                Properties.Settings.Default.SavedUsername = UsernameTextBox.Text;
                Properties.Settings.Default.RememberMe = true;
            }
            else
            {
                Properties.Settings.Default.SavedUsername = string.Empty;
                Properties.Settings.Default.RememberMe = false;
            }
            Properties.Settings.Default.Save();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to save credentials");
        }
    }

    private async void LoginButton_Click(object sender, RoutedEventArgs e)
    {
        // Validate input
        var username = UsernameTextBox.Text.Trim();
        var password = PasswordBox.Password;

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

        // Show loading state
        SetLoadingState(true);
        HideError();

        try
        {
            // For now, we'll create a temporary connection for authentication
            // In a real scenario, this would authenticate against the server
            var serverAddress = GetServerAddress();
            var port = GetServerPort();

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
                SaveCredentials();

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

    private string GetServerAddress()
    {
        // Get server address from parent window
        if (Window.GetWindow(this) is MainWindow mainWindow)
        {
            var serverTextBox = mainWindow.FindName("ServerAddressTextBox") as TextBox;
            return serverTextBox?.Text.Trim() ?? "localhost";
        }
        return "localhost";
    }

    private int GetServerPort()
    {
        // Get server port from parent window
        if (Window.GetWindow(this) is MainWindow mainWindow)
        {
            var portTextBox = mainWindow.FindName("PortTextBox") as TextBox;
            if (int.TryParse(portTextBox?.Text.Trim(), out int port))
            {
                return port;
            }
        }
        return 443;
    }

    private void SetLoadingState(bool isLoading)
    {
        LoginButton.IsEnabled = !isLoading;
        UsernameTextBox.IsEnabled = !isLoading;
        PasswordBox.IsEnabled = !isLoading;
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
