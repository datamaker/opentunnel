using System.Net;
using Microsoft.Extensions.Logging;
using VPNClient.Network;
using VPNClient.Protocol;
using VPNClient.ViewModels;

namespace VPNClient.Services;

/// <summary>
/// Core VPN tunnel implementation that coordinates TLS connection and WinTun adapter
/// </summary>
public class VpnTunnel : IDisposable
{
    private readonly ILogger<VpnTunnel> _logger;
    private readonly TlsConnection _tlsConnection;
    private readonly WintunAdapter _wintunAdapter;

    private CancellationTokenSource? _cancellationTokenSource;
    private Task? _receiveTask;
    private Task? _sendTask;
    private Task? _keepaliveTask;

    private VpnConfig? _config;
    private string? _sessionToken;
    private bool _isDisposed;
    private readonly object _stateLock = new();

    private long _bytesReceived;
    private long _bytesSent;
    private long _packetsReceived;
    private long _packetsSent;
    private DateTime _lastStatsReset = DateTime.Now;

    public event EventHandler<ConnectionStateEventArgs>? ConnectionStateChanged;
    public event EventHandler<VpnErrorEventArgs>? ErrorOccurred;

    public bool IsConnected { get; private set; }

    public VpnTunnel(ILogger<VpnTunnel> logger, TlsConnection tlsConnection, WintunAdapter wintunAdapter)
    {
        _logger = logger;
        _tlsConnection = tlsConnection;
        _wintunAdapter = wintunAdapter;
    }

    /// <summary>
    /// Connect to VPN server with given credentials
    /// </summary>
    public async Task ConnectAsync(string serverAddress, int port, string username, string sessionToken)
    {
        if (IsConnected)
        {
            throw new InvalidOperationException("Already connected to VPN");
        }

        _cancellationTokenSource = new CancellationTokenSource();
        var cancellationToken = _cancellationTokenSource.Token;

        try
        {
            // Step 1: Connect to server via TLS
            RaiseConnectionStateChanged(ConnectionState.Connecting, null);
            _logger.LogInformation("Connecting to VPN server at {Server}:{Port}", serverAddress, port);

            await _tlsConnection.ConnectAsync(serverAddress, port);

            // Step 2: Authenticate
            RaiseConnectionStateChanged(ConnectionState.Authenticating, null);
            _logger.LogInformation("Authenticating user {Username}", username);

            var authRequest = new AuthRequest
            {
                Username = username,
                Password = sessionToken, // Using session token as password for re-auth
                ClientVersion = "1.0.0",
                Platform = "windows"
            };

            var authResponse = await _tlsConnection.AuthenticateAsync(authRequest);

            if (!authResponse.Success)
            {
                throw new VpnException($"Authentication failed: {authResponse.ErrorMessage}");
            }

            _sessionToken = authResponse.SessionToken;
            _logger.LogInformation("Authentication successful");

            // Step 3: Receive configuration from server
            _logger.LogInformation("Waiting for configuration from server");
            _config = await _tlsConnection.ReceiveConfigAsync(cancellationToken);

            if (_config == null)
            {
                throw new VpnException("Failed to receive VPN configuration from server");
            }

            _logger.LogInformation("Received VPN configuration: IP={IP}, Gateway={Gateway}, DNS={DNS}",
                _config.AssignedIP, _config.Gateway, string.Join(", ", _config.Dns ?? Array.Empty<string>()));

            // Step 4: Configure WinTun interface
            RaiseConnectionStateChanged(ConnectionState.ConfiguringInterface, _config.AssignedIP);
            _logger.LogInformation("Configuring network interface");

            await _wintunAdapter.InitializeAsync(
                _config.AssignedIP!,
                _config.SubnetMask ?? "255.255.255.0",
                _config.Gateway!,
                _config.Dns ?? new[] { "8.8.8.8", "8.8.4.4" },
                _config.Mtu);

            // Step 5: Start packet forwarding
            _logger.LogInformation("Starting packet forwarding");
            StartPacketForwarding(cancellationToken);

            IsConnected = true;
            RaiseConnectionStateChanged(ConnectionState.Connected, _config.AssignedIP);
            _logger.LogInformation("VPN connection established successfully");
        }
        catch (OperationCanceledException)
        {
            _logger.LogInformation("Connection cancelled");
            await CleanupAsync();
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to establish VPN connection");
            await CleanupAsync();
            RaiseError("Connection failed", ex);
            throw;
        }
    }

    /// <summary>
    /// Disconnect from VPN server
    /// </summary>
    public async Task DisconnectAsync()
    {
        if (!IsConnected && _cancellationTokenSource == null)
        {
            return;
        }

        _logger.LogInformation("Disconnecting from VPN");

        try
        {
            // Send disconnect message to server
            await _tlsConnection.SendMessageAsync(new VpnMessage
            {
                Type = MessageType.Disconnect,
                Payload = Array.Empty<byte>()
            });
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to send disconnect message");
        }

        await CleanupAsync();
        RaiseConnectionStateChanged(ConnectionState.Disconnected, null);
        _logger.LogInformation("Disconnected from VPN");
    }

    private async Task CleanupAsync()
    {
        _cancellationTokenSource?.Cancel();

        // Wait for tasks to complete
        var tasks = new List<Task>();
        if (_receiveTask != null) tasks.Add(_receiveTask);
        if (_sendTask != null) tasks.Add(_sendTask);
        if (_keepaliveTask != null) tasks.Add(_keepaliveTask);

        if (tasks.Count > 0)
        {
            try
            {
                await Task.WhenAll(tasks).WaitAsync(TimeSpan.FromSeconds(5));
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error waiting for tasks to complete");
            }
        }

        // Cleanup resources
        try
        {
            await _wintunAdapter.ShutdownAsync();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error shutting down WinTun adapter");
        }

        try
        {
            await _tlsConnection.DisconnectAsync();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error disconnecting TLS connection");
        }

        _cancellationTokenSource?.Dispose();
        _cancellationTokenSource = null;
        _receiveTask = null;
        _sendTask = null;
        _keepaliveTask = null;
        IsConnected = false;
    }

    private void StartPacketForwarding(CancellationToken cancellationToken)
    {
        // Task to receive packets from TLS and send to TUN
        _receiveTask = Task.Run(async () =>
        {
            try
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    var message = await _tlsConnection.ReceiveMessageAsync(cancellationToken);

                    if (message == null)
                    {
                        _logger.LogWarning("Received null message, connection may be closed");
                        break;
                    }

                    switch (message.Type)
                    {
                        case MessageType.DataPacket:
                            // Forward IP packet to TUN interface
                            await _wintunAdapter.WritePacketAsync(message.Payload);
                            Interlocked.Add(ref _bytesReceived, message.Payload.Length);
                            Interlocked.Increment(ref _packetsReceived);
                            break;

                        case MessageType.KeepaliveAck:
                            _logger.LogDebug("Received keepalive ACK");
                            break;

                        case MessageType.Disconnect:
                            _logger.LogInformation("Server requested disconnect");
                            _ = DisconnectAsync();
                            return;

                        default:
                            _logger.LogWarning("Received unexpected message type: {Type}", message.Type);
                            break;
                    }
                }
            }
            catch (OperationCanceledException)
            {
                _logger.LogDebug("Receive task cancelled");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in receive task");
                RaiseError("Error receiving data from server", ex);
            }
        }, cancellationToken);

        // Task to receive packets from TUN and send to TLS
        _sendTask = Task.Run(async () =>
        {
            try
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    var packet = await _wintunAdapter.ReadPacketAsync(cancellationToken);

                    if (packet == null || packet.Length == 0)
                    {
                        continue;
                    }

                    var message = new VpnMessage
                    {
                        Type = MessageType.DataPacket,
                        Payload = packet
                    };

                    await _tlsConnection.SendMessageAsync(message);
                    Interlocked.Add(ref _bytesSent, packet.Length);
                    Interlocked.Increment(ref _packetsSent);
                }
            }
            catch (OperationCanceledException)
            {
                _logger.LogDebug("Send task cancelled");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in send task");
                RaiseError("Error sending data to server", ex);
            }
        }, cancellationToken);

        // Keepalive task
        _keepaliveTask = Task.Run(async () =>
        {
            var keepaliveInterval = TimeSpan.FromSeconds(30);

            try
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    await Task.Delay(keepaliveInterval, cancellationToken);

                    var message = new VpnMessage
                    {
                        Type = MessageType.Keepalive,
                        Payload = Array.Empty<byte>()
                    };

                    await _tlsConnection.SendMessageAsync(message);
                    _logger.LogDebug("Sent keepalive");
                }
            }
            catch (OperationCanceledException)
            {
                _logger.LogDebug("Keepalive task cancelled");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in keepalive task");
            }
        }, cancellationToken);
    }

    /// <summary>
    /// Get current connection statistics
    /// </summary>
    public VpnStats GetStats()
    {
        var now = DateTime.Now;
        var elapsed = (now - _lastStatsReset).TotalSeconds;

        var stats = new VpnStats
        {
            BytesReceived = elapsed > 0 ? (long)(_bytesReceived / elapsed) : 0,
            BytesSent = elapsed > 0 ? (long)(_bytesSent / elapsed) : 0,
            PacketsReceived = _packetsReceived,
            PacketsSent = _packetsSent
        };

        // Reset counters
        Interlocked.Exchange(ref _bytesReceived, 0);
        Interlocked.Exchange(ref _bytesSent, 0);
        _lastStatsReset = now;

        return stats;
    }

    private void RaiseConnectionStateChanged(ConnectionState state, string? assignedIP)
    {
        ConnectionStateChanged?.Invoke(this, new ConnectionStateEventArgs(state, assignedIP));
    }

    private void RaiseError(string message, Exception? exception = null)
    {
        ErrorOccurred?.Invoke(this, new VpnErrorEventArgs(message, exception));
    }

    public void Dispose()
    {
        if (_isDisposed) return;

        _isDisposed = true;
        _ = DisconnectAsync();
    }
}

/// <summary>
/// VPN connection states
/// </summary>
public enum ConnectionState
{
    Disconnected,
    Connecting,
    Authenticating,
    ConfiguringInterface,
    Connected
}

/// <summary>
/// Event arguments for connection state changes
/// </summary>
public class ConnectionStateEventArgs : EventArgs
{
    public ConnectionState State { get; }
    public string? AssignedIP { get; }

    public ConnectionStateEventArgs(ConnectionState state, string? assignedIP)
    {
        State = state;
        AssignedIP = assignedIP;
    }
}

/// <summary>
/// Event arguments for VPN errors
/// </summary>
public class VpnErrorEventArgs : EventArgs
{
    public string Message { get; }
    public Exception? Exception { get; }

    public VpnErrorEventArgs(string message, Exception? exception = null)
    {
        Message = message;
        Exception = exception;
    }
}

/// <summary>
/// VPN configuration received from server
/// </summary>
public class VpnConfig
{
    public string? AssignedIP { get; set; }
    public string? SubnetMask { get; set; }
    public string? Gateway { get; set; }
    public string[]? Dns { get; set; }
    public int Mtu { get; set; } = 1400;
}

/// <summary>
/// Exception for VPN-specific errors
/// </summary>
public class VpnException : Exception
{
    public VpnException(string message) : base(message) { }
    public VpnException(string message, Exception innerException) : base(message, innerException) { }
}
