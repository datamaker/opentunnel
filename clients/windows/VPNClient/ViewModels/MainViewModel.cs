using System.ComponentModel;
using System.Runtime.CompilerServices;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using VPNClient.Services;

namespace VPNClient.ViewModels;

/// <summary>
/// Main ViewModel for the VPN client application
/// </summary>
public partial class MainViewModel : ObservableObject
{
    private readonly ILogger<MainViewModel> _logger;
    private readonly VpnTunnel _vpnTunnel;

    [ObservableProperty]
    private bool _isAuthenticated;

    [ObservableProperty]
    private string? _username;

    [ObservableProperty]
    private string? _sessionToken;

    [ObservableProperty]
    private bool _isConnected;

    [ObservableProperty]
    private bool _isConnecting;

    [ObservableProperty]
    private string _connectionStatus = "Disconnected";

    [ObservableProperty]
    private string? _assignedIpAddress;

    [ObservableProperty]
    private string? _serverAddress;

    [ObservableProperty]
    private int _serverPort = 443;

    [ObservableProperty]
    private TimeSpan _connectionDuration;

    [ObservableProperty]
    private long _bytesReceived;

    [ObservableProperty]
    private long _bytesSent;

    [ObservableProperty]
    private string? _errorMessage;

    public MainViewModel(ILogger<MainViewModel> logger, VpnTunnel vpnTunnel)
    {
        _logger = logger;
        _vpnTunnel = vpnTunnel;

        // Subscribe to VPN tunnel events
        _vpnTunnel.ConnectionStateChanged += OnConnectionStateChanged;
        _vpnTunnel.ErrorOccurred += OnErrorOccurred;

        // Load saved settings
        LoadSavedSettings();

        _logger.LogDebug("MainViewModel initialized");
    }

    private void LoadSavedSettings()
    {
        try
        {
            var settings = Properties.Settings.Default;
            ServerAddress = settings.LastServerAddress;
            ServerPort = settings.LastServerPort;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to load saved settings");
            ServerAddress = "vpn.example.com";
            ServerPort = 443;
        }
    }

    private void SaveSettings()
    {
        try
        {
            var settings = Properties.Settings.Default;
            settings.LastServerAddress = ServerAddress ?? "vpn.example.com";
            settings.LastServerPort = ServerPort;
            settings.Save();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to save settings");
        }
    }

    private void OnConnectionStateChanged(object? sender, ConnectionStateEventArgs e)
    {
        switch (e.State)
        {
            case ConnectionState.Disconnected:
                IsConnected = false;
                IsConnecting = false;
                ConnectionStatus = "Disconnected";
                AssignedIpAddress = null;
                break;

            case ConnectionState.Connecting:
                IsConnecting = true;
                ConnectionStatus = "Connecting...";
                break;

            case ConnectionState.Authenticating:
                ConnectionStatus = "Authenticating...";
                break;

            case ConnectionState.ConfiguringInterface:
                ConnectionStatus = "Configuring interface...";
                break;

            case ConnectionState.Connected:
                IsConnected = true;
                IsConnecting = false;
                ConnectionStatus = "Connected";
                AssignedIpAddress = e.AssignedIP;
                SaveSettings();
                break;
        }
    }

    private void OnErrorOccurred(object? sender, VpnErrorEventArgs e)
    {
        ErrorMessage = e.Message;
        IsConnecting = false;
        _logger.LogError(e.Exception, "VPN Error: {Message}", e.Message);
    }

    [RelayCommand]
    private async Task ConnectAsync()
    {
        if (IsConnecting || IsConnected)
            return;

        if (!IsAuthenticated)
        {
            ErrorMessage = "Please log in first.";
            return;
        }

        if (string.IsNullOrWhiteSpace(ServerAddress))
        {
            ErrorMessage = "Please enter a server address.";
            return;
        }

        ErrorMessage = null;

        try
        {
            await _vpnTunnel.ConnectAsync(ServerAddress, ServerPort, Username!, SessionToken!);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to connect");
            ErrorMessage = $"Connection failed: {ex.Message}";
        }
    }

    [RelayCommand]
    private async Task DisconnectAsync()
    {
        if (!IsConnected && !IsConnecting)
            return;

        try
        {
            await _vpnTunnel.DisconnectAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to disconnect");
            ErrorMessage = $"Disconnection failed: {ex.Message}";
        }
    }

    [RelayCommand]
    private void Logout()
    {
        if (IsConnected)
        {
            _ = DisconnectAsync();
        }

        IsAuthenticated = false;
        Username = null;
        SessionToken = null;
        _logger.LogInformation("User logged out");
    }

    public void UpdateStats(VpnStats stats)
    {
        BytesReceived = stats.BytesReceived;
        BytesSent = stats.BytesSent;
    }
}

/// <summary>
/// VPN connection statistics
/// </summary>
public class VpnStats
{
    public long BytesReceived { get; set; }
    public long BytesSent { get; set; }
    public long PacketsReceived { get; set; }
    public long PacketsSent { get; set; }
}
