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

    /// <summary>
    /// True while the automatic reconnect loop is active (waiting between
    /// attempts or attempting). The tray icon shows the "connecting" state and
    /// keeps Disconnect enabled so the user can abort the retries.
    /// </summary>
    [ObservableProperty]
    private bool _isReconnecting;

    /// <summary>
    /// Set when the user explicitly asked to disconnect (Disconnect button /
    /// tray menu / Logout), so <see cref="OnConnectionStateChanged"/> can tell
    /// an intentional disconnect from an unexpected drop. Cleared on Connect.
    /// </summary>
    private bool _userRequestedDisconnect;

    /// <summary>Cancels the auto-reconnect retry loop. Non-null only while a
    /// loop is running.</summary>
    private CancellationTokenSource? _reconnectCts;

    private const int MaxReconnectAttempts = 10;

    /// <summary>Backoff before each retry; the last value repeats (2, 4, 8,
    /// 16, then every 30 seconds up to 10 attempts).</summary>
    private static readonly int[] ReconnectDelaysSeconds = { 2, 4, 8, 16, 30 };

    /// <summary>
    /// Raised when the tray icon should show a balloon notification (connection
    /// dropped / reconnected / reconnect failed). Already gated by the
    /// DisconnectNotify setting. May fire on a background thread.
    /// </summary>
    public event EventHandler<TrayNotificationEventArgs>? TrayNotificationRequested;

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
                var wasConnected = IsConnected;
                IsConnected = false;
                IsConnecting = false;
                ConnectionStatus = "Disconnected";
                AssignedIpAddress = null;

                if (wasConnected && !_userRequestedDisconnect)
                {
                    OnUnexpectedDisconnect();
                }
                break;

            case ConnectionState.Connecting:
                IsConnecting = true;
                ConnectionStatus = "Connecting...";
                break;

            case ConnectionState.Reconnecting:
                IsConnecting = true;
                ConnectionStatus = "Reconnecting...";
                break;

            case ConnectionState.Authenticating:
                ConnectionStatus = "Authenticating...";
                break;

            case ConnectionState.ConfiguringInterface:
                ConnectionStatus = "Configuring interface...";
                break;

            case ConnectionState.Connected:
                var wasReconnecting = IsReconnecting;
                IsConnected = true;
                IsConnecting = false;
                IsReconnecting = false;
                ConnectionStatus = "Connected";
                AssignedIpAddress = e.AssignedIP;
                SaveSettings();

                if (wasReconnecting)
                {
                    RequestTrayNotification("VPN 재연결됨",
                        $"{ServerAddress} 서버에 다시 연결되었습니다.");
                }
                break;
        }
    }

    /// <summary>
    /// The tunnel dropped without the user asking (server closed the stream,
    /// socket error, dead-peer timeout). Notify via the tray balloon and,
    /// if enabled and credentials are on hand, start the auto-reconnect loop.
    /// </summary>
    private void OnUnexpectedDisconnect()
    {
        _logger.LogWarning("VPN connection dropped unexpectedly");

        var reason = ErrorMessage ?? "연결이 예기치 않게 끊어졌습니다.";

        if (IsAutoReconnectEnabled() && IsAuthenticated && HasReconnectCredentials())
        {
            RequestTrayNotification("VPN 연결 끊김",
                $"{reason}\n자동으로 재연결을 시도합니다.", isError: true);
            StartReconnect();
        }
        else
        {
            RequestTrayNotification("VPN 연결 끊김", reason, isError: true);
        }
    }

    /// <summary>
    /// Whether the session holds everything a silent reconnect needs: SSO mode
    /// re-sends the 30-day session token ({authType:"session"}), password mode
    /// re-sends the account password kept for the session's lifetime.
    /// </summary>
    private bool HasReconnectCredentials()
    {
        if (string.IsNullOrWhiteSpace(ServerAddress))
        {
            return false;
        }

        return AuthMode == CredentialStore.AuthModeSso
            ? !string.IsNullOrEmpty(SessionToken)
            : !string.IsNullOrEmpty(Username) && !string.IsNullOrEmpty(Password);
    }

    /// <summary>
    /// Mark the upcoming disconnect as user-intended (so it triggers neither
    /// the drop notification nor auto-reconnect) and stop any retry loop.
    /// Called by views that drive the tunnel directly (MainView's button)
    /// as well as by this view-model's own Disconnect/Logout commands.
    /// </summary>
    public void NotifyUserRequestedDisconnect()
    {
        _userRequestedDisconnect = true;
        CancelReconnect();
    }

    /// <summary>
    /// A user-initiated connect supersedes any pending auto-retry and re-arms
    /// unexpected-drop detection for the new session.
    /// </summary>
    public void NotifyUserInitiatedConnect()
    {
        _userRequestedDisconnect = false;
        CancelReconnect();
    }

    private void StartReconnect()
    {
        if (_reconnectCts != null)
        {
            return; // a retry loop is already running
        }

        var cts = new CancellationTokenSource();
        _reconnectCts = cts;
        IsReconnecting = true;
        _ = Task.Run(() => RunReconnectLoopAsync(cts));
    }

    /// <summary>
    /// Stop the auto-reconnect loop (user pressed Disconnect, logged out, or
    /// started a manual connect that supersedes the retries).
    /// </summary>
    private void CancelReconnect()
    {
        var cts = _reconnectCts;
        _reconnectCts = null;

        if (cts != null)
        {
            try
            {
                cts.Cancel();
            }
            catch (ObjectDisposedException)
            {
                // Already torn down by the loop's finally block.
            }
        }

        IsReconnecting = false;
    }

    /// <summary>
    /// Retry loop after an unexpected drop: backoff of 2, 4, 8, 16, then 30s
    /// between attempts, at most <see cref="MaxReconnectAttempts"/> attempts.
    /// Reuses the session's own credentials (SSO session token or password).
    /// </summary>
    private async Task RunReconnectLoopAsync(CancellationTokenSource cts)
    {
        var ct = cts.Token;

        try
        {
            for (var attempt = 1; attempt <= MaxReconnectAttempts; attempt++)
            {
                var delaySeconds = ReconnectDelaysSeconds[
                    Math.Min(attempt - 1, ReconnectDelaysSeconds.Length - 1)];
                ConnectionStatus = $"재연결 중 ({attempt}/{MaxReconnectAttempts})";

                try
                {
                    await Task.Delay(TimeSpan.FromSeconds(delaySeconds), ct);
                }
                catch (OperationCanceledException)
                {
                    return; // user cancelled
                }

                if (ct.IsCancellationRequested || IsConnected || IsConnecting)
                {
                    return;
                }

                try
                {
                    await ConnectTunnelAsync();
                    // Success: OnConnectionStateChanged(Connected) clears
                    // IsReconnecting and shows the "VPN 재연결됨" balloon.
                    return;
                }
                catch (VpnSessionExpiredException)
                {
                    // The 30-day SSO session died mid-retry — no attempt can
                    // ever succeed. Send the user back to the login screen.
                    _logger.LogWarning("SSO session expired during reconnect");
                    SessionToken = null;
                    IsAuthenticated = false;
                    ErrorMessage = "SSO 재로그인 필요: 세션이 만료되었습니다. Google로 다시 로그인해 주세요.";
                    break;
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Reconnect attempt {Attempt}/{Max} failed",
                        attempt, MaxReconnectAttempts);
                }
            }

            // All attempts exhausted (or the session expired).
            ConnectionStatus = "Disconnected";
            RequestTrayNotification("재연결 실패",
                "VPN 재연결에 실패했습니다. 수동으로 다시 연결해 주세요.", isError: true);
        }
        finally
        {
            if (ReferenceEquals(_reconnectCts, cts))
            {
                _reconnectCts = null;
                IsReconnecting = false;
            }

            cts.Dispose();
        }
    }

    /// <summary>
    /// Connect the tunnel with whatever credentials the current session holds.
    /// Shared by the Connect command and the auto-reconnect loop; throws on
    /// failure (including <see cref="VpnSessionExpiredException"/>).
    /// </summary>
    private Task ConnectTunnelAsync()
    {
        if (AuthMode == CredentialStore.AuthModeSso)
        {
            if (string.IsNullOrEmpty(SessionToken))
            {
                throw new VpnSessionExpiredException(
                    "SSO 재로그인 필요: 저장된 세션이 없습니다. 다시 로그인해 주세요.");
            }

            return _vpnTunnel.ConnectWithSessionTokenAsync(
                ServerAddress!, ServerPort, Username ?? string.Empty, SessionToken);
        }

        return _vpnTunnel.ConnectAsync(ServerAddress!, ServerPort, Username!, Password!);
    }

    private void RequestTrayNotification(string title, string message, bool isError = false)
    {
        if (!IsDisconnectNotifyEnabled())
        {
            return;
        }

        TrayNotificationRequested?.Invoke(this, new TrayNotificationEventArgs(title, message, isError));
    }

    private static bool IsDisconnectNotifyEnabled()
    {
        try
        {
            return Properties.Settings.Default.DisconnectNotify;
        }
        catch
        {
            return true;
        }
    }

    private static bool IsAutoReconnectEnabled()
    {
        try
        {
            return Properties.Settings.Default.AutoReconnect;
        }
        catch
        {
            return true;
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

        NotifyUserInitiatedConnect();

        ErrorMessage = null;

        try
        {
            await ConnectTunnelAsync();
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
        NotifyUserRequestedDisconnect();

        if (!IsConnected && !IsConnecting)
        {
            // Nothing to tear down (e.g. cancelled while waiting between
            // reconnect attempts) — just settle the status text.
            ConnectionStatus = "Disconnected";
            return;
        }

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
        NotifyUserRequestedDisconnect();

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

/// <summary>
/// A balloon notification for the tray icon (connection dropped, reconnected,
/// reconnect failed). Consumed by <see cref="Services.TrayIconManager"/>.
/// </summary>
public class TrayNotificationEventArgs : EventArgs
{
    public string Title { get; }
    public string Message { get; }
    public bool IsError { get; }

    public TrayNotificationEventArgs(string title, string message, bool isError = false)
    {
        Title = title;
        Message = message;
        IsError = isError;
    }
}
