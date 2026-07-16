using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using VPNClient.Services;
using VPNClient.ViewModels;

namespace VPNClient.Views;

/// <summary>
/// Interaction logic for MainView.xaml
///
/// Owns the live VPN connection flow that previously lived in MainWindow:
/// connect/disconnect, connection timer, statistics polling and status
/// presentation. Networking calls (VpnTunnel) are used unchanged.
/// </summary>
public partial class MainView : UserControl
{
    private readonly ILogger<MainView> _logger;
    private readonly VpnTunnel _vpnTunnel;
    private readonly MainViewModel _viewModel;
    private readonly DispatcherTimer _connectionTimer;
    private readonly DispatcherTimer _statsTimer;
    private DateTime _connectionStartTime;
    private bool _isConnected;
    private bool _isConnecting;

    /// <summary>Raised when the user taps the settings (gear) button.</summary>
    public event EventHandler? SettingsRequested;

    /// <summary>Raised after the user confirms logout.</summary>
    public event EventHandler? LogoutRequested;

    public MainView()
    {
        InitializeComponent();

        _logger = App.ServiceProvider.GetRequiredService<ILogger<MainView>>();
        _vpnTunnel = App.ServiceProvider.GetRequiredService<VpnTunnel>();
        _viewModel = App.ServiceProvider.GetRequiredService<MainViewModel>();

        // DataContext is inherited from MainWindow (the shared MainViewModel),
        // which drives the {Binding Username} in the header.

        _connectionTimer = new DispatcherTimer
        {
            Interval = TimeSpan.FromSeconds(1)
        };
        _connectionTimer.Tick += ConnectionTimer_Tick;

        _statsTimer = new DispatcherTimer
        {
            Interval = TimeSpan.FromMilliseconds(500)
        };
        _statsTimer.Tick += StatsTimer_Tick;

        _vpnTunnel.ConnectionStateChanged += VpnTunnel_ConnectionStateChanged;
        _vpnTunnel.ErrorOccurred += VpnTunnel_ErrorOccurred;

        // Reflect whatever state the tunnel is currently in.
        if (_vpnTunnel.IsConnected)
        {
            _isConnected = true;
            ShowConnectedState(_viewModel.AssignedIpAddress);
        }
        else
        {
            ShowDisconnectedState();
        }

        _logger.LogInformation("MainView initialized");
    }

    // MARK: - VPN tunnel events

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
                    ShowConnectedState(e.AssignedIP);
                    break;

                case ConnectionState.Disconnected:
                    _isConnected = false;
                    _isConnecting = false;
                    _connectionTimer.Stop();
                    _statsTimer.Stop();
                    ShowDisconnectedState();
                    break;

                case ConnectionState.Connecting:
                    _isConnecting = true;
                    ApplyStatusColor("WarningColor");
                    StatusIcon.Text = "⋯"; // ellipsis
                    StatusTitle.Text = "Connecting...";
                    StatusDescription.Text = "Establishing secure tunnel...";
                    break;

                case ConnectionState.Authenticating:
                    _isConnecting = true;
                    ApplyStatusColor("WarningColor");
                    StatusIcon.Text = "⋯";
                    StatusTitle.Text = "Authenticating...";
                    StatusDescription.Text = "Verifying your credentials...";
                    break;

                case ConnectionState.ConfiguringInterface:
                    _isConnecting = true;
                    ApplyStatusColor("WarningColor");
                    StatusIcon.Text = "⋯";
                    StatusTitle.Text = "Configuring...";
                    StatusDescription.Text = "Configuring network interface...";
                    break;
            }
        });
    }

    private void VpnTunnel_ErrorOccurred(object? sender, VpnErrorEventArgs e)
    {
        Dispatcher.Invoke(() =>
        {
            _isConnecting = false;
            ApplyStatusColor("ErrorColor");
            StatusIcon.Text = "✕"; // x mark
            StatusTitle.Text = "Error";
            StatusDescription.Text = e.Message;

            MessageBox.Show(e.Message, "VPN Error", MessageBoxButton.OK, MessageBoxImage.Error);

            _logger.LogError(e.Exception, "VPN Error: {Message}", e.Message);
        });
    }

    // MARK: - Timers

    private void ConnectionTimer_Tick(object? sender, EventArgs e)
    {
        var elapsed = DateTime.Now - _connectionStartTime;
        DurationText.Text = elapsed.ToString(@"hh\:mm\:ss");
    }

    private void StatsTimer_Tick(object? sender, EventArgs e)
    {
        var stats = _vpnTunnel.GetStats();
        DownloadText.Text = FormatBytes(stats.BytesReceived) + "/s";
        UploadText.Text = FormatBytes(stats.BytesSent) + "/s";
    }

    // MARK: - Actions

    private async void ConnectButton_Click(object sender, RoutedEventArgs e)
    {
        if (_isConnecting)
            return;

        if (_isConnected)
        {
            await DisconnectAsync();
        }
        else
        {
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

        var serverAddress = _viewModel.ServerAddress?.Trim();
        if (string.IsNullOrEmpty(serverAddress))
        {
            MessageBox.Show("Please enter a server address.", "Validation Error",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var port = _viewModel.ServerPort;
        if (port <= 0 || port > 65535)
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
                _viewModel.Password!);
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
        SettingsRequested?.Invoke(this, EventArgs.Empty);
    }

    private void LogoutButton_Click(object sender, RoutedEventArgs e)
    {
        var result = MessageBox.Show(
            "Are you sure you want to logout? This will disconnect the VPN if active.",
            "Logout",
            MessageBoxButton.YesNo,
            MessageBoxImage.Question);

        if (result != MessageBoxResult.Yes)
            return;

        _viewModel.LogoutCommand.Execute(null);
        LogoutRequested?.Invoke(this, EventArgs.Empty);
    }

    // MARK: - Presentation helpers

    private void ShowConnectedState(string? assignedIp)
    {
        ApplyStatusColor("SuccessColor");
        StatusIcon.Text = "✓"; // check mark
        StatusTitle.Text = "Connected";
        StatusDescription.Text = "Your connection is secure";

        ConnectButtonText.Text = "Disconnect";
        ConnectButton.Style = (Style)FindResource("DangerButtonStyle");

        ServerValueText.Text = $"{_viewModel.ServerAddress}:{_viewModel.ServerPort}";
        AssignedIpText.Text = string.IsNullOrEmpty(assignedIp) ? "--" : assignedIp;

        ConnectionDetailsCard.Visibility = Visibility.Visible;
        StatisticsCard.Visibility = Visibility.Visible;
    }

    private void ShowDisconnectedState()
    {
        ApplyStatusColor("TextSecondaryColor");
        StatusIcon.Text = "✕"; // x mark
        StatusTitle.Text = "Disconnected";
        StatusDescription.Text = "Tap Connect to secure your connection";

        ConnectButtonText.Text = "Connect";
        ConnectButton.Style = (Style)FindResource("ModernButtonStyle");

        ConnectionDetailsCard.Visibility = Visibility.Collapsed;
        StatisticsCard.Visibility = Visibility.Collapsed;
        DurationText.Text = "00:00:00";
        DownloadText.Text = "0 B/s";
        UploadText.Text = "0 B/s";
    }

    private void ApplyStatusColor(string colorKey)
    {
        var color = (Color)FindResource(colorKey);
        StatusOuter.Fill = new SolidColorBrush(color) { Opacity = 0.2 };
        StatusMid.Fill = new SolidColorBrush(color) { Opacity = 0.4 };
        StatusInner.Fill = new SolidColorBrush(color);
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

    /// <summary>
    /// Stops timers, unsubscribes from tunnel events and disconnects if needed.
    /// Called by the host window when it closes.
    /// </summary>
    public void Cleanup()
    {
        _connectionTimer.Stop();
        _statsTimer.Stop();
        _vpnTunnel.ConnectionStateChanged -= VpnTunnel_ConnectionStateChanged;
        _vpnTunnel.ErrorOccurred -= VpnTunnel_ErrorOccurred;

        if (_isConnected)
        {
            _ = _vpnTunnel.DisconnectAsync();
        }
    }
}
