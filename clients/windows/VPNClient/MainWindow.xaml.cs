using System.Windows;
using System.Windows.Media;
using System.Windows.Threading;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using VPNClient.Services;
using VPNClient.ViewModels;
using VPNClient.Views;

namespace VPNClient;

/// <summary>
/// Interaction logic for MainWindow.xaml
/// </summary>
public partial class MainWindow : Window
{
    private readonly ILogger<MainWindow> _logger;
    private readonly VpnTunnel _vpnTunnel;
    private readonly MainViewModel _viewModel;
    private readonly DispatcherTimer _connectionTimer;
    private readonly DispatcherTimer _statsTimer;
    private DateTime _connectionStartTime;
    private bool _isConnected;
    private bool _isConnecting;

    public MainWindow()
    {
        InitializeComponent();

        _logger = App.ServiceProvider.GetRequiredService<ILogger<MainWindow>>();
        _vpnTunnel = App.ServiceProvider.GetRequiredService<VpnTunnel>();
        _viewModel = App.ServiceProvider.GetRequiredService<MainViewModel>();

        DataContext = _viewModel;

        // Set up connection timer
        _connectionTimer = new DispatcherTimer
        {
            Interval = TimeSpan.FromSeconds(1)
        };
        _connectionTimer.Tick += ConnectionTimer_Tick;

        // Set up stats timer
        _statsTimer = new DispatcherTimer
        {
            Interval = TimeSpan.FromMilliseconds(500)
        };
        _statsTimer.Tick += StatsTimer_Tick;

        // Subscribe to VPN events
        _vpnTunnel.ConnectionStateChanged += VpnTunnel_ConnectionStateChanged;
        _vpnTunnel.ErrorOccurred += VpnTunnel_ErrorOccurred;

        // Subscribe to login events
        LoginView.LoginSuccessful += LoginView_LoginSuccessful;

        _logger.LogInformation("MainWindow initialized");
    }

    private void LoginView_LoginSuccessful(object? sender, LoginEventArgs e)
    {
        _viewModel.Username = e.Username;
        _viewModel.SessionToken = e.SessionToken;
        _viewModel.IsAuthenticated = true;

        LoginCard.Visibility = Visibility.Collapsed;
        UpdateStatus("Authenticated successfully", false);
    }

    private void VpnTunnel_ConnectionStateChanged(object? sender, ConnectionStateEventArgs e)
    {
        Dispatcher.Invoke(() =>
        {
            switch (e.State)
            {
                case ConnectionState.Connected:
                    _isConnected = true;
                    _isConnecting = false;
                    _connectionStartTime = DateTime.Now;
                    _connectionTimer.Start();
                    _statsTimer.Start();

                    StatusIndicator.Fill = FindResource("SuccessBrush") as SolidColorBrush;
                    StatusText.Text = "Connected";
                    ConnectButtonText.Text = "Disconnect";
                    ConnectionInfoPanel.Visibility = Visibility.Visible;
                    IpAddressText.Text = e.AssignedIP ?? "--";
                    LoadingOverlay.Visibility = Visibility.Collapsed;
                    UpdateStatus($"Connected to VPN server", false);
                    break;

                case ConnectionState.Disconnected:
                    _isConnected = false;
                    _isConnecting = false;
                    _connectionTimer.Stop();
                    _statsTimer.Stop();

                    StatusIndicator.Fill = FindResource("ErrorBrush") as SolidColorBrush;
                    StatusText.Text = "Disconnected";
                    ConnectButtonText.Text = "Connect";
                    ConnectionInfoPanel.Visibility = Visibility.Collapsed;
                    LoadingOverlay.Visibility = Visibility.Collapsed;
                    UpdateStatus("Disconnected from VPN", false);
                    break;

                case ConnectionState.Connecting:
                    _isConnecting = true;
                    StatusIndicator.Fill = FindResource("WarningBrush") as SolidColorBrush;
                    StatusText.Text = "Connecting...";
                    LoadingOverlay.Visibility = Visibility.Visible;
                    LoadingText.Text = "Connecting to server...";
                    UpdateStatus("Establishing connection...", false);
                    break;

                case ConnectionState.Authenticating:
                    LoadingText.Text = "Authenticating...";
                    UpdateStatus("Authenticating...", false);
                    break;

                case ConnectionState.ConfiguringInterface:
                    LoadingText.Text = "Configuring network interface...";
                    UpdateStatus("Configuring network interface...", false);
                    break;
            }
        });
    }

    private void VpnTunnel_ErrorOccurred(object? sender, VpnErrorEventArgs e)
    {
        Dispatcher.Invoke(() =>
        {
            _isConnecting = false;
            LoadingOverlay.Visibility = Visibility.Collapsed;
            StatusIndicator.Fill = FindResource("ErrorBrush") as SolidColorBrush;
            StatusText.Text = "Error";
            UpdateStatus($"Error: {e.Message}", true);

            MessageBox.Show(e.Message, "VPN Error", MessageBoxButton.OK, MessageBoxImage.Error);

            _logger.LogError(e.Exception, "VPN Error: {Message}", e.Message);
        });
    }

    private void ConnectionTimer_Tick(object? sender, EventArgs e)
    {
        var elapsed = DateTime.Now - _connectionStartTime;
        ConnectionTimeText.Text = elapsed.ToString(@"hh\:mm\:ss");
    }

    private void StatsTimer_Tick(object? sender, EventArgs e)
    {
        var stats = _vpnTunnel.GetStats();
        DownloadText.Text = FormatBytes(stats.BytesReceived) + "/s";
        UploadText.Text = FormatBytes(stats.BytesSent) + "/s";
    }

    private async void ConnectButton_Click(object sender, RoutedEventArgs e)
    {
        if (_isConnecting)
            return;

        if (_isConnected)
        {
            // Disconnect
            await DisconnectAsync();
        }
        else
        {
            // Connect
            await ConnectAsync();
        }
    }

    private async Task ConnectAsync()
    {
        if (!_viewModel.IsAuthenticated)
        {
            MessageBox.Show("Please log in first.", "Authentication Required",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var serverAddress = ServerAddressTextBox.Text.Trim();
        if (string.IsNullOrEmpty(serverAddress))
        {
            MessageBox.Show("Please enter a server address.", "Validation Error",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (!int.TryParse(PortTextBox.Text.Trim(), out int port) || port <= 0 || port > 65535)
        {
            MessageBox.Show("Please enter a valid port number (1-65535).", "Validation Error",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        _isConnecting = true;
        ConnectButton.IsEnabled = false;

        try
        {
            await _vpnTunnel.ConnectAsync(
                serverAddress,
                port,
                _viewModel.Username!,
                _viewModel.SessionToken!);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to connect to VPN");
            MessageBox.Show($"Failed to connect: {ex.Message}", "Connection Error",
                MessageBoxButton.OK, MessageBoxImage.Error);
            _isConnecting = false;
        }
        finally
        {
            ConnectButton.IsEnabled = true;
        }
    }

    private async Task DisconnectAsync()
    {
        try
        {
            await _vpnTunnel.DisconnectAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to disconnect from VPN");
            MessageBox.Show($"Failed to disconnect: {ex.Message}", "Disconnection Error",
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void SettingsButton_Click(object sender, RoutedEventArgs e)
    {
        SettingsOverlay.Visibility = Visibility.Visible;
    }

    private void SettingsView_CloseRequested(object? sender, EventArgs e)
    {
        SettingsOverlay.Visibility = Visibility.Collapsed;
    }

    private void UpdateStatus(string message, bool isError)
    {
        StatusBarText.Text = message;
        StatusBarText.Foreground = isError
            ? FindResource("ErrorBrush") as SolidColorBrush
            : FindResource("TextSecondaryBrush") as SolidColorBrush;
    }

    private static string FormatBytes(long bytes)
    {
        string[] sizes = { "B", "KB", "MB", "GB" };
        int order = 0;
        double size = bytes;
        while (size >= 1024 && order < sizes.Length - 1)
        {
            order++;
            size /= 1024;
        }
        return $"{size:0.##} {sizes[order]}";
    }

    protected override void OnClosed(EventArgs e)
    {
        _connectionTimer.Stop();
        _statsTimer.Stop();
        _vpnTunnel.ConnectionStateChanged -= VpnTunnel_ConnectionStateChanged;
        _vpnTunnel.ErrorOccurred -= VpnTunnel_ErrorOccurred;

        if (_isConnected)
        {
            _ = _vpnTunnel.DisconnectAsync();
        }

        base.OnClosed(e);
    }
}
