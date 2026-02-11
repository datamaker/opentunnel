using System.Buffers.Binary;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using VPNClient.Services;

namespace VPNClient.Protocol;

/// <summary>
/// Serializer/Deserializer for VPN protocol messages
/// </summary>
public static class VpnSerializer
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    /// <summary>
    /// Serialize a VPN message to bytes
    /// Format: [type:1byte][length:4bytes BE][payload]
    /// </summary>
    public static byte[] SerializeMessage(VpnMessage message)
    {
        var payloadLength = message.Payload.Length;
        var result = new byte[5 + payloadLength]; // Header (5 bytes) + payload

        // Type (1 byte)
        result[0] = (byte)message.Type;

        // Length (4 bytes, big-endian)
        BinaryPrimitives.WriteInt32BigEndian(result.AsSpan(1), payloadLength);

        // Payload
        if (payloadLength > 0)
        {
            Buffer.BlockCopy(message.Payload, 0, result, 5, payloadLength);
        }

        return result;
    }

    /// <summary>
    /// Deserialize a VPN message from bytes (header + payload)
    /// </summary>
    public static VpnMessage DeserializeMessage(byte[] data)
    {
        if (data.Length < 5)
        {
            throw new ArgumentException("Data too short for VPN message header");
        }

        var type = (MessageType)data[0];
        var length = BinaryPrimitives.ReadInt32BigEndian(data.AsSpan(1));

        if (data.Length < 5 + length)
        {
            throw new ArgumentException("Data too short for declared payload length");
        }

        var payload = new byte[length];
        if (length > 0)
        {
            Buffer.BlockCopy(data, 5, payload, 0, length);
        }

        return new VpnMessage
        {
            Type = type,
            Payload = payload
        };
    }

    /// <summary>
    /// Parse message header and return payload length
    /// </summary>
    public static (MessageType Type, int PayloadLength) ParseHeader(byte[] header)
    {
        if (header.Length < 5)
        {
            throw new ArgumentException("Header must be at least 5 bytes");
        }

        var type = (MessageType)header[0];
        var length = BinaryPrimitives.ReadInt32BigEndian(header.AsSpan(1));

        return (type, length);
    }

    /// <summary>
    /// Serialize authentication request to JSON bytes
    /// </summary>
    public static byte[] SerializeAuthRequest(AuthRequest request)
    {
        var json = JsonSerializer.Serialize(request, JsonOptions);
        return Encoding.UTF8.GetBytes(json);
    }

    /// <summary>
    /// Deserialize authentication request from JSON bytes
    /// </summary>
    public static AuthRequest DeserializeAuthRequest(byte[] data)
    {
        var json = Encoding.UTF8.GetString(data);
        return JsonSerializer.Deserialize<AuthRequest>(json, JsonOptions)
            ?? throw new JsonException("Failed to deserialize AuthRequest");
    }

    /// <summary>
    /// Serialize authentication response to JSON bytes
    /// </summary>
    public static byte[] SerializeAuthResponse(AuthResponse response)
    {
        var json = JsonSerializer.Serialize(response, JsonOptions);
        return Encoding.UTF8.GetBytes(json);
    }

    /// <summary>
    /// Deserialize authentication response from JSON bytes
    /// </summary>
    public static AuthResponse DeserializeAuthResponse(byte[] data)
    {
        var json = Encoding.UTF8.GetString(data);
        return JsonSerializer.Deserialize<AuthResponse>(json, JsonOptions)
            ?? throw new JsonException("Failed to deserialize AuthResponse");
    }

    /// <summary>
    /// Serialize config push to JSON bytes
    /// </summary>
    public static byte[] SerializeConfig(ConfigPush config)
    {
        var json = JsonSerializer.Serialize(config, JsonOptions);
        return Encoding.UTF8.GetBytes(json);
    }

    /// <summary>
    /// Deserialize config push from JSON bytes to VpnConfig
    /// </summary>
    public static VpnConfig DeserializeConfig(byte[] data)
    {
        var json = Encoding.UTF8.GetString(data);
        var configPush = JsonSerializer.Deserialize<ConfigPush>(json, JsonOptions)
            ?? throw new JsonException("Failed to deserialize ConfigPush");

        return new VpnConfig
        {
            AssignedIP = configPush.AssignedIP,
            SubnetMask = configPush.SubnetMask,
            Gateway = configPush.Gateway,
            Dns = configPush.Dns,
            Mtu = configPush.Mtu
        };
    }

    /// <summary>
    /// Create a keepalive message
    /// </summary>
    public static VpnMessage CreateKeepaliveMessage()
    {
        return new VpnMessage
        {
            Type = MessageType.Keepalive,
            Payload = Array.Empty<byte>()
        };
    }

    /// <summary>
    /// Create a keepalive acknowledgment message
    /// </summary>
    public static VpnMessage CreateKeepaliveAckMessage()
    {
        return new VpnMessage
        {
            Type = MessageType.KeepaliveAck,
            Payload = Array.Empty<byte>()
        };
    }

    /// <summary>
    /// Create a disconnect message
    /// </summary>
    public static VpnMessage CreateDisconnectMessage()
    {
        return new VpnMessage
        {
            Type = MessageType.Disconnect,
            Payload = Array.Empty<byte>()
        };
    }

    /// <summary>
    /// Create a data packet message with raw IP packet
    /// </summary>
    public static VpnMessage CreateDataPacketMessage(byte[] ipPacket)
    {
        return new VpnMessage
        {
            Type = MessageType.DataPacket,
            Payload = ipPacket
        };
    }

    /// <summary>
    /// Validate IP packet basic structure (IPv4 or IPv6)
    /// </summary>
    public static bool ValidateIpPacket(byte[] packet)
    {
        if (packet == null || packet.Length < 20)
            return false;

        // Check IP version (first 4 bits)
        var version = (packet[0] >> 4) & 0x0F;

        switch (version)
        {
            case 4: // IPv4
                // Minimum IPv4 header is 20 bytes
                if (packet.Length < 20)
                    return false;

                // Check header length
                var ihl = (packet[0] & 0x0F) * 4;
                if (ihl < 20 || packet.Length < ihl)
                    return false;

                // Check total length field
                var totalLength = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(2));
                return packet.Length >= totalLength;

            case 6: // IPv6
                // Minimum IPv6 header is 40 bytes
                if (packet.Length < 40)
                    return false;

                // Check payload length field
                var payloadLength = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(4));
                return packet.Length >= 40 + payloadLength;

            default:
                return false;
        }
    }

    /// <summary>
    /// Extract source and destination IP from packet for logging
    /// </summary>
    public static (string? Source, string? Destination) ExtractIpAddresses(byte[] packet)
    {
        if (packet == null || packet.Length < 20)
            return (null, null);

        var version = (packet[0] >> 4) & 0x0F;

        if (version == 4 && packet.Length >= 20)
        {
            // IPv4: source at offset 12, destination at offset 16
            var sourceBytes = new byte[4];
            var destBytes = new byte[4];
            Buffer.BlockCopy(packet, 12, sourceBytes, 0, 4);
            Buffer.BlockCopy(packet, 16, destBytes, 0, 4);

            return (
                $"{sourceBytes[0]}.{sourceBytes[1]}.{sourceBytes[2]}.{sourceBytes[3]}",
                $"{destBytes[0]}.{destBytes[1]}.{destBytes[2]}.{destBytes[3]}"
            );
        }
        else if (version == 6 && packet.Length >= 40)
        {
            // IPv6: source at offset 8, destination at offset 24 (16 bytes each)
            var sourceBytes = new byte[16];
            var destBytes = new byte[16];
            Buffer.BlockCopy(packet, 8, sourceBytes, 0, 16);
            Buffer.BlockCopy(packet, 24, destBytes, 0, 16);

            return (
                FormatIPv6(sourceBytes),
                FormatIPv6(destBytes)
            );
        }

        return (null, null);
    }

    private static string FormatIPv6(byte[] bytes)
    {
        var parts = new string[8];
        for (int i = 0; i < 8; i++)
        {
            var value = BinaryPrimitives.ReadUInt16BigEndian(bytes.AsSpan(i * 2));
            parts[i] = value.ToString("x");
        }
        return string.Join(":", parts);
    }
}
