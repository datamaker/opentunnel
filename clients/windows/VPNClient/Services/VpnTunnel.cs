using System.Net;
using Microsoft.Extensions.Logging;
using VPNClient.Network;
using VPNClient.Protocol;
using VPNClient.Split;
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

    // Split tunneling: hostname matcher for domain rules and IPs learned via DNS.
    private DomainMatcher? _domainMatcher;
    private readonly HashSet<string> _dynamicRoutes = new();

    private long _bytesReceived;
    private long _bytesSent;
    private long _packetsReceived;
    private long _packetsSent;

    public event EventHandler<ConnectionStateEventArgs>? ConnectionStateChanged;
    public event EventHandler<VpnErrorEventArgs>? ErrorOccurred;

    /// <summary>
    /// Raised when a session-token authentication succeeded and the server
    /// issued a (possibly rotated) session token. The new token is already
    /// persisted; subscribers should refresh their in-memory copy.
    /// </summary>
    public event EventHandler<string>? SessionTokenRefreshed;

    public bool IsConnected { get; private set; }

    // Details from the server's ConfigPush, surfaced for the Connection Details
    // card (parity with the macOS/iOS clients).
    public string? Gateway => _config?.Gateway;
    public IReadOnlyList<string> DnsServers => _config?.Dns ?? Array.Empty<string>();
    public int Mtu => _config?.Mtu ?? 0;
    public bool SplitTunnel => _config?.SplitTunnel ?? false;

    public VpnTunnel(ILogger<VpnTunnel> logger, TlsConnection tlsConnection, WintunAdapter wintunAdapter)
    {
        _logger = logger;
        _tlsConnection = tlsConnection;
        _wintunAdapter = wintunAdapter;
    }

    /// <summary>
    /// Connect to VPN server with username/password credentials
    /// </summary>
    public Task ConnectAsync(string serverAddress, int port, string username, string password)
    {
        return ConnectCoreAsync(serverAddress, port, new AuthRequest
        {
            Username = username,
            Password = password,
            ClientVersion = "1.0.0",
            Platform = "windows"
        });
    }

    /// <summary>
    /// Connect to VPN server with the persisted SSO session token
    /// ({authType:"session"}). Used on every (re)connect after a
    /// "Google로 로그인 (Datasee SSO)" login — no password is available then.
    /// </summary>
    public Task ConnectWithSessionTokenAsync(string serverAddress, int port, string username, string sessionToken)
    {
        return ConnectCoreAsync(serverAddress, port, new AuthRequest
        {
            Username = username,
            AuthType = AuthTypes.Session,
            Token = sessionToken,
            ClientVersion = "1.0.0",
            Platform = "windows"
        });
    }

    private async Task ConnectCoreAsync(string serverAddress, int port, AuthRequest authRequest)
    {
        if (IsConnected)
        {
            throw new InvalidOperationException("Already connected to VPN");
        }

        _cancellationTokenSource = new CancellationTokenSource();
        var cancellationToken = _cancellationTokenSource.Token;

        // Reset per-session cumulative counters.
        Interlocked.Exchange(ref _bytesReceived, 0);
        Interlocked.Exchange(ref _bytesSent, 0);
        Interlocked.Exchange(ref _packetsReceived, 0);
        Interlocked.Exchange(ref _packetsSent, 0);

        try
        {
            // Step 1: Connect to server via TLS
            RaiseConnectionStateChanged(ConnectionState.Connecting, null);
            _logger.LogInformation("Connecting to VPN server at {Server}:{Port}", serverAddress, port);

            await _tlsConnection.ConnectAsync(serverAddress, port);

            // Step 2: Authenticate. Password logins re-send the account password
            // (bcrypt-verified by the server); SSO logins re-send the 30-day
            // session token with {authType:"session"} instead.
            RaiseConnectionStateChanged(ConnectionState.Authenticating, null);
            _logger.LogInformation("Authenticating user {Username} (authType={AuthType})",
                authRequest.Username, authRequest.AuthType ?? AuthTypes.Password);

            var authResponse = await _tlsConnection.AuthenticateAsync(authRequest);

            if (!authResponse.Success)
            {
                if (authRequest.AuthType == AuthTypes.Session)
                {
                    // The session token was rejected (expired/revoked): drop it
                    // so the next launch goes back to the login screen, and
                    // surface a re-login prompt instead of a generic failure.
                    CredentialStore.ClearSessionToken();
                    throw new VpnSessionExpiredException(
                        "SSO 재로그인 필요: 세션이 만료되었습니다. Google로 다시 로그인해 주세요.");
                }

                throw new VpnException($"Authentication failed: {authResponse.ErrorMessage}");
            }

            _sessionToken = authResponse.SessionToken;
            _logger.LogInformation("Authentication successful");

            // Session-token auth: the server may rotate the 30-day token on each
            // re-auth. Persist the fresh one and let the view-model update its copy.
            if (authRequest.AuthType == AuthTypes.Session
                && !string.IsNullOrEmpty(authResponse.SessionToken))
            {
                CredentialStore.UpdateSessionToken(authResponse.SessionToken);
                SessionTokenRefreshed?.Invoke(this, authResponse.SessionToken);
            }

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
                _config.Mtu,
                _config.SplitTunnel);

            // Split tunneling: install routes only for the included destinations.
            if (_config.SplitTunnel)
            {
                await ConfigureSplitRoutesAsync();
            }

            // Step 5: Start packet forwarding
            _logger.LogInformation("Starting packet forwarding");
            StartPacketForwarding(cancellationToken);

            // Seed learned routes for concrete split domains, bypassing any
            // stale OS DNS cache (see PreResolveSplitDomainsAsync).
            if (_config.SplitTunnel)
            {
                await PreResolveSplitDomainsAsync();
            }

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

    /// <summary>
    /// Install split-tunnel routes: the server-provided include list plus DNS
    /// servers (so their answers are observable for domain-based rules).
    /// </summary>
    private async Task ConfigureSplitRoutesAsync()
    {
        if (_config == null) return;

        var domains = _config.IncludedDomains ?? Array.Empty<string>();
        _domainMatcher = domains.Length > 0 ? new DomainMatcher(domains) : null;
        lock (_dynamicRoutes) _dynamicRoutes.Clear();

        var count = 0;
        foreach (var cidr in _config.IncludedRoutes ?? Array.Empty<string>())
        {
            var c = CidrUtils.Parse(cidr);
            if (c != null)
            {
                await _wintunAdapter.AddRouteAsync(c.Address, c.Prefix);
                count++;
            }
        }

        if (_domainMatcher != null && !_domainMatcher.IsEmpty)
        {
            foreach (var dns in _config.Dns ?? Array.Empty<string>())
            {
                if (CidrUtils.Parse(dns) != null)
                {
                    await _wintunAdapter.AddRouteAsync(dns, 32);
                }
            }
        }

        _logger.LogInformation("Split tunnel: {Count} route(s), {Domains} domain rule(s)",
            count, domains.Length);
    }

    /// <summary>
    /// If the packet is a DNS answer to an AAAA/HTTPS query for a matched
    /// split-tunnel domain, return a rewritten no-answer (NODATA) packet;
    /// otherwise null. See <see cref="DnsSniffer.StripIPv6Response"/>.
    /// </summary>
    private byte[]? StripIPv6AnswersIfMatched(byte[] packet)
    {
        var matcher = _domainMatcher;
        if (matcher == null || matcher.IsEmpty) return null;
        var stripped = DnsSniffer.StripIPv6Response(packet);
        if (stripped == null || !matcher.Matches(stripped.QName)) return null;
        _logger.LogInformation("Split tunnel: blanked IPv6/HTTPS DNS answers for {Domain}", stripped.QName);
        return stripped.Packet;
    }

    /// <summary>
    /// Pre-resolve concrete (non-wildcard) split-tunnel domains by sending our
    /// own A queries straight through the tunnel. The OS may hold cached DNS
    /// answers — in which case no query the sniffer could learn from would ever
    /// be sent — so a cached (possibly geo-stale) IP would be used with no
    /// route installed. The responses come back through the receive loop, where
    /// <see cref="MaybeLearnRouteAsync"/> seeds the routes before they're needed.
    /// </summary>
    private async Task PreResolveSplitDomainsAsync()
    {
        var matcher = _domainMatcher;
        if (_config == null || matcher == null || matcher.IsEmpty) return;
        var dns = (_config.Dns ?? Array.Empty<string>()).FirstOrDefault(d => CidrUtils.Parse(d) != null);
        if (dns == null || _config.AssignedIP == null) return;
        var concrete = (_config.IncludedDomains ?? Array.Empty<string>())
            .Where(d => !d.Contains('*')).ToArray();
        if (concrete.Length == 0) return;

        _logger.LogInformation("Split tunnel: pre-resolving {Count} domain(s) through the tunnel", concrete.Length);
        for (var i = 0; i < concrete.Length; i++)
        {
            var query = DnsQueryBuilder.BuildAQuery(concrete[i], _config.AssignedIP, dns,
                (ushort)(49152 + (i % 8192)), (ushort)(0x5350 + i));
            if (query != null)
            {
                await _tlsConnection.SendMessageAsync(new VpnMessage
                {
                    Type = MessageType.DataPacket,
                    Payload = query
                });
            }
        }
    }

    /// <summary>
    /// Snoop a DNS answer for a matched (CDN/wildcard) domain. If it carries IPs
    /// we have not routed yet, install the routes and only return once they are
    /// in place. The caller awaits this before delivering the DNS answer to the
    /// app, which closes a race: the answer reaches the app and the snooper at
    /// the same instant, so without gating the app opens its connection to the
    /// freshly resolved IP before the route exists — the first request leaks
    /// outside the tunnel and the WAF rejects the client's real IP (403).
    /// </summary>
    private async Task MaybeLearnRouteAsync(byte[] packet)
    {
        var matcher = _domainMatcher;
        if (matcher == null || matcher.IsEmpty) return;

        var dns = DnsSniffer.Parse(packet);
        if (dns == null || !matcher.Matches(dns.QName)) return;

        var added = new List<string>();
        lock (_dynamicRoutes)
        {
            foreach (var ip in dns.Addresses)
            {
                if (_dynamicRoutes.Add(ip)) added.Add(ip);
            }
        }

        if (added.Count > 0)
        {
            _logger.LogInformation("Split tunnel: learned {Count} route(s) for {Domain}",
                added.Count, dns.QName);
            foreach (var ip in added)
            {
                await _wintunAdapter.AddRouteAsync(ip, 32);
            }
        }
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
                            var payload = message.Payload;
                            var stripped = StripIPv6AnswersIfMatched(payload);
                            if (stripped != null)
                            {
                                // IPv4-only tunnel: a AAAA/HTTPS answer for a
                                // matched split domain would send Windows over
                                // untunneled IPv6, past the split routes —
                                // deliver a blanked (NODATA) answer instead.
                                payload = stripped;
                            }
                            else
                            {
                                // Gate: install any newly-learned split route
                                // BEFORE delivering the DNS answer, so the app's
                                // first connection to the freshly-resolved IP
                                // uses the tunnel instead of leaking (WAF 403).
                                await MaybeLearnRouteAsync(payload);
                            }
                            // Forward IP packet to TUN interface
                            await _wintunAdapter.WritePacketAsync(payload);
                            Interlocked.Add(ref _bytesReceived, message.Payload.Length);
                            Interlocked.Increment(ref _packetsReceived);
                            break;

                        case MessageType.Keepalive:
                            // Server-originated keepalive — answer so it doesn't
                            // consider us idle (parity with Android/macOS).
                            await _tlsConnection.SendMessageAsync(new VpnMessage
                            {
                                Type = MessageType.KeepaliveAck,
                                Payload = Array.Empty<byte>()
                            });
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
        // Cumulative totals for the current session (consistent with the other
        // platform clients). Counters are reset in ConnectAsync, not here.
        return new VpnStats
        {
            BytesReceived = Interlocked.Read(ref _bytesReceived),
            BytesSent = Interlocked.Read(ref _bytesSent),
            PacketsReceived = Interlocked.Read(ref _packetsReceived),
            PacketsSent = Interlocked.Read(ref _packetsSent)
        };
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
    public bool SplitTunnel { get; set; } = false;
    public string[]? IncludedRoutes { get; set; }
    public string[]? IncludedDomains { get; set; }
}

/// <summary>
/// Exception for VPN-specific errors
/// </summary>
public class VpnException : Exception
{
    public VpnException(string message) : base(message) { }
    public VpnException(string message, Exception innerException) : base(message, innerException) { }
}

/// <summary>
/// The persisted SSO session token was rejected by the server (expired or
/// revoked). The token has already been cleared from the credential store;
/// the user must sign in with "Google로 로그인 (Datasee SSO)" again.
/// </summary>
public class VpnSessionExpiredException : VpnException
{
    public VpnSessionExpiredException(string message) : base(message) { }
}
