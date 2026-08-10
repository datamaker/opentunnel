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

    /// <summary>
    /// How this session authenticates on (re)connect:
    /// <see cref="CredentialStore.AuthModePassword"/> re-sends the account
    /// password, <see cref="CredentialStore.AuthModeSso"/> re-sends the
    /// server-issued session token with {authType:"session"}.
    /// </summary>
    [ObservableProperty]
    private string _authMode = CredentialStore.AuthModePassword;

    /// <summary>
    /// The account password, kept for the lifetime of the session so the tunnel
    /// can re-authenticate on (re)connect (password mode only — SSO sessions
    /// have no password and reconnect with the session token instead).
    /// </summary>
    [ObservableProperty]
    private string? _password;

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
    private int _serverPort = 1194;

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
        _vpnTunnel.SessionTokenRefreshed += OnSessionTokenRefreshed;

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
            ServerPort = 1194;
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

    private void OnSessionTokenRefreshed(object? sender, string newToken)
    {
        // The tunnel already persisted the rotated token; keep our copy in sync
        // so the next reconnect sends the fresh one.
        SessionToken = newToken;
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
            if (AuthMode == CredentialStore.AuthModeSso)
            {
                if (string.IsNullOrEmpty(SessionToken))
                {
                    ErrorMessage = "SSO 재로그인 필요: 저장된 세션이 없습니다. 다시 로그인해 주세요.";
                    IsAuthenticated = false;
                    return;
                }

                await _vpnTunnel.ConnectWithSessionTokenAsync(
                    ServerAddress, ServerPort, Username ?? string.Empty, SessionToken);
            }
            else
            {
                await _vpnTunnel.ConnectAsync(ServerAddress, ServerPort, Username!, Password!);
            }
        }
        catch (VpnSessionExpiredException ex)
        {
            // Token already cleared from the store by the tunnel; drop the
            // in-memory session so the user is sent back to the login screen.
            _logger.LogWarning("SSO session token rejected by server");
            SessionToken = null;
            IsAuthenticated = false;
            ErrorMessage = ex.Message;
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
        Password = null;
        AuthMode = CredentialStore.AuthModePassword;
        CredentialStore.Clear();
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
