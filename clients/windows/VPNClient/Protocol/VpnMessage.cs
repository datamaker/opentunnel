namespace VPNClient.Protocol;

/// <summary>
/// VPN protocol message types
/// </summary>
public enum MessageType : byte
{
    /// <summary>
    /// Authentication request from client
    /// Payload: JSON {"username":"","password":"","clientVersion":"","platform":"windows"}
    /// </summary>
    AuthRequest = 0x01,

    /// <summary>
    /// Authentication response from server
    /// Payload: JSON {"success":true,"sessionToken":"","errorMessage":""}
    /// </summary>
    AuthResponse = 0x02,

    /// <summary>
    /// Configuration push from server after successful authentication
    /// Payload: JSON {"assignedIP":"","subnetMask":"","gateway":"","dns":[],"mtu":1400}
    /// </summary>
    ConfigPush = 0x03,

    /// <summary>
    /// Keepalive message sent periodically
    /// Payload: empty
    /// </summary>
    Keepalive = 0x04,

    /// <summary>
    /// Keepalive acknowledgment
    /// Payload: empty
    /// </summary>
    KeepaliveAck = 0x05,

    /// <summary>
    /// Disconnect request
    /// Payload: empty
    /// </summary>
    Disconnect = 0x06,

    /// <summary>
    /// Data packet containing raw IP packet
    /// Payload: raw IP packet bytes
    /// </summary>
    DataPacket = 0x10
}

/// <summary>
/// VPN protocol message structure
/// Header format: [type:1byte][length:4bytes BE][payload]
/// </summary>
public class VpnMessage
{
    /// <summary>
    /// Message type identifier
    /// </summary>
    public MessageType Type { get; set; }

    /// <summary>
    /// Message payload (raw bytes)
    /// </summary>
    public byte[] Payload { get; set; } = Array.Empty<byte>();

    /// <summary>
    /// Total message length including header
    /// </summary>
    public int TotalLength => 5 + Payload.Length; // 1 byte type + 4 bytes length + payload
}

/// <summary>
/// Authentication request payload structure
/// </summary>
public class AuthRequest
{
    /// <summary>
    /// Username for authentication
    /// </summary>
    public string Username { get; set; } = string.Empty;

    /// <summary>
    /// Password for authentication
    /// </summary>
    public string Password { get; set; } = string.Empty;

    /// <summary>
    /// Client version string
    /// </summary>
    public string ClientVersion { get; set; } = "1.0.0";

    /// <summary>
    /// Platform identifier (always "windows" for this client)
    /// </summary>
    public string Platform { get; set; } = "windows";
}

/// <summary>
/// Authentication response payload structure
/// </summary>
public class AuthResponse
{
    /// <summary>
    /// Whether authentication was successful
    /// </summary>
    public bool Success { get; set; }

    /// <summary>
    /// Session token for authenticated session
    /// </summary>
    public string? SessionToken { get; set; }

    /// <summary>
    /// Error message if authentication failed
    /// </summary>
    public string? ErrorMessage { get; set; }
}

/// <summary>
/// Configuration push payload structure
/// </summary>
public class ConfigPush
{
    /// <summary>
    /// Assigned IP address for the VPN interface
    /// </summary>
    public string? AssignedIP { get; set; }

    /// <summary>
    /// Subnet mask for the VPN interface
    /// </summary>
    public string? SubnetMask { get; set; }

    /// <summary>
    /// Gateway IP address
    /// </summary>
    public string? Gateway { get; set; }

    /// <summary>
    /// DNS server addresses
    /// </summary>
    public string[]? Dns { get; set; }

    /// <summary>
    /// Maximum transmission unit size
    /// </summary>
    public int Mtu { get; set; } = 1400;
}
