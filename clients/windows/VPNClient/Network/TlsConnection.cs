using System.Buffers.Binary;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using VPNClient.Protocol;
using VPNClient.Services;

namespace VPNClient.Network;

/// <summary>
/// TLS 1.3 connection handler for secure communication with the VPN server
/// </summary>
public class TlsConnection : IDisposable
{
    private readonly ILogger<TlsConnection> _logger;

    private TcpClient? _tcpClient;
    private SslStream? _sslStream;
    private readonly SemaphoreSlim _sendLock = new(1, 1);
    private readonly SemaphoreSlim _receiveLock = new(1, 1);
    private bool _isConnected;
    private bool _isDisposed;

    private const int DEFAULT_TIMEOUT_MS = 30000;
    private const int HEADER_SIZE = 5; // 1 byte type + 4 bytes length

    public bool IsConnected => _isConnected;

    public TlsConnection(ILogger<TlsConnection> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Connect to the VPN server using TLS 1.3
    /// </summary>
    public async Task ConnectAsync(string serverAddress, int port, int timeoutMs = DEFAULT_TIMEOUT_MS)
    {
        if (_isConnected)
        {
            throw new InvalidOperationException("Already connected");
        }

        _logger.LogInformation("Connecting to {Server}:{Port}", serverAddress, port);

        try
        {
            // Create TCP connection
            _tcpClient = new TcpClient
            {
                SendTimeout = timeoutMs,
                ReceiveTimeout = timeoutMs,
                NoDelay = true
            };

            using var cts = new CancellationTokenSource(timeoutMs);
            await _tcpClient.ConnectAsync(serverAddress, port, cts.Token);

            _logger.LogDebug("TCP connection established");

            // Establish TLS connection
            var networkStream = _tcpClient.GetStream();
            _sslStream = new SslStream(
                networkStream,
                leaveInnerStreamOpen: false,
                userCertificateValidationCallback: ValidateServerCertificate,
                userCertificateSelectionCallback: null);

            var sslOptions = new SslClientAuthenticationOptions
            {
                TargetHost = serverAddress,
                EnabledSslProtocols = SslProtocols.Tls13 | SslProtocols.Tls12, // Prefer TLS 1.3, fallback to 1.2
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck, // Can be changed for production
                ApplicationProtocols = new List<SslApplicationProtocol>
                {
                    new SslApplicationProtocol("vpn")
                }
            };

            await _sslStream.AuthenticateAsClientAsync(sslOptions, cts.Token);

            _isConnected = true;

            _logger.LogInformation("TLS connection established. Protocol: {Protocol}, Cipher: {Cipher}",
                _sslStream.SslProtocol,
                _sslStream.CipherAlgorithm);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to establish TLS connection");
            Cleanup();
            throw new TlsConnectionException("Failed to establish TLS connection", ex);
        }
    }

    /// <summary>
    /// Authenticate with the VPN server
    /// </summary>
    public async Task<AuthResponse> AuthenticateAsync(AuthRequest request)
    {
        if (!_isConnected)
        {
            throw new InvalidOperationException("Not connected to server");
        }

        _logger.LogDebug("Sending authentication request for user: {Username}", request.Username);

        var payload = VpnSerializer.SerializeAuthRequest(request);
        var message = new VpnMessage
        {
            Type = MessageType.AuthRequest,
            Payload = payload
        };

        await SendMessageAsync(message);

        // Wait for response
        using var cts = new CancellationTokenSource(DEFAULT_TIMEOUT_MS);
        var response = await ReceiveMessageAsync(cts.Token);

        if (response == null || response.Type != MessageType.AuthResponse)
        {
            throw new TlsConnectionException("Invalid authentication response from server");
        }

        return VpnSerializer.DeserializeAuthResponse(response.Payload);
    }

    /// <summary>
    /// Receive VPN configuration from server
    /// </summary>
    public async Task<VpnConfig?> ReceiveConfigAsync(CancellationToken cancellationToken)
    {
        var message = await ReceiveMessageAsync(cancellationToken);

        if (message == null)
        {
            return null;
        }

        if (message.Type != MessageType.ConfigPush)
        {
            _logger.LogWarning("Expected CONFIG_PUSH message but received: {Type}", message.Type);
            return null;
        }

        return VpnSerializer.DeserializeConfig(message.Payload);
    }

    /// <summary>
    /// Send a VPN message to the server
    /// </summary>
    public async Task SendMessageAsync(VpnMessage message)
    {
        if (!_isConnected || _sslStream == null)
        {
            throw new InvalidOperationException("Not connected to server");
        }

        await _sendLock.WaitAsync();
        try
        {
            var data = VpnSerializer.SerializeMessage(message);
            await _sslStream.WriteAsync(data);
            await _sslStream.FlushAsync();

            _logger.LogTrace("Sent message: Type={Type}, Length={Length}",
                message.Type, message.Payload.Length);
        }
        finally
        {
            _sendLock.Release();
        }
    }

    /// <summary>
    /// Receive a VPN message from the server
    /// </summary>
    public async Task<VpnMessage?> ReceiveMessageAsync(CancellationToken cancellationToken)
    {
        if (!_isConnected || _sslStream == null)
        {
            throw new InvalidOperationException("Not connected to server");
        }

        await _receiveLock.WaitAsync(cancellationToken);
        try
        {
            // Read header
            var header = new byte[HEADER_SIZE];
            var bytesRead = await ReadExactAsync(header, HEADER_SIZE, cancellationToken);

            if (bytesRead < HEADER_SIZE)
            {
                _logger.LogWarning("Connection closed while reading header");
                return null;
            }

            var messageType = (MessageType)header[0];
            var payloadLength = BinaryPrimitives.ReadInt32BigEndian(header.AsSpan(1));

            if (payloadLength < 0 || payloadLength > 65535)
            {
                throw new TlsConnectionException($"Invalid payload length: {payloadLength}");
            }

            // Read payload
            byte[] payload;
            if (payloadLength > 0)
            {
                payload = new byte[payloadLength];
                bytesRead = await ReadExactAsync(payload, payloadLength, cancellationToken);

                if (bytesRead < payloadLength)
                {
                    _logger.LogWarning("Connection closed while reading payload");
                    return null;
                }
            }
            else
            {
                payload = Array.Empty<byte>();
            }

            _logger.LogTrace("Received message: Type={Type}, Length={Length}",
                messageType, payloadLength);

            return new VpnMessage
            {
                Type = messageType,
                Payload = payload
            };
        }
        finally
        {
            _receiveLock.Release();
        }
    }

    private async Task<int> ReadExactAsync(byte[] buffer, int count, CancellationToken cancellationToken)
    {
        int totalRead = 0;
        while (totalRead < count)
        {
            var bytesRead = await _sslStream!.ReadAsync(
                buffer.AsMemory(totalRead, count - totalRead),
                cancellationToken);

            if (bytesRead == 0)
                break;

            totalRead += bytesRead;
        }
        return totalRead;
    }

    private bool ValidateServerCertificate(
        object sender,
        X509Certificate? certificate,
        X509Chain? chain,
        SslPolicyErrors sslPolicyErrors)
    {
        // In production, implement proper certificate validation
        // For development, we'll accept any certificate

        if (sslPolicyErrors == SslPolicyErrors.None)
        {
            return true;
        }

        _logger.LogWarning("Certificate validation warning: {Errors}", sslPolicyErrors);

        // For development purposes, accept self-signed certificates
        // TODO: In production, implement proper certificate pinning
        if (sslPolicyErrors == SslPolicyErrors.RemoteCertificateChainErrors ||
            sslPolicyErrors == SslPolicyErrors.RemoteCertificateNameMismatch)
        {
            _logger.LogWarning("Accepting certificate with errors for development");
            return true;
        }

        return false;
    }

    /// <summary>
    /// Disconnect from the server
    /// </summary>
    public async Task DisconnectAsync()
    {
        if (!_isConnected)
            return;

        _logger.LogInformation("Disconnecting TLS connection");

        try
        {
            if (_sslStream != null)
            {
                await _sslStream.ShutdownAsync();
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error during TLS shutdown");
        }

        Cleanup();
    }

    private void Cleanup()
    {
        _isConnected = false;

        _sslStream?.Dispose();
        _sslStream = null;

        _tcpClient?.Close();
        _tcpClient?.Dispose();
        _tcpClient = null;
    }

    public void Dispose()
    {
        if (_isDisposed) return;
        _isDisposed = true;

        Cleanup();
        _sendLock.Dispose();
        _receiveLock.Dispose();
    }
}

/// <summary>
/// Exception for TLS connection errors
/// </summary>
public class TlsConnectionException : Exception
{
    public TlsConnectionException(string message) : base(message) { }
    public TlsConnectionException(string message, Exception innerException) : base(message, innerException) { }
}
