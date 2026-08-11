namespace VPNClient.Split;

/// <summary>
/// Destination-based (split-tunnel) routing helpers.
///
/// Mirrors the Android <c>SplitRouting.kt</c> (whose logic is unit-tested on the
/// JVM) and the Swift <c>SplitRouting.swift</c>. The server pushes an "include"
/// policy (IP CIDRs + domains). Concrete domains are resolved to CIDRs
/// server-side, but CDN domains resolve to shared, rotating, geo-dependent IPs,
/// so those are matched by hostname on the client: we snoop DNS answers for
/// matched domains and route exactly the IPs the client actually resolved.
/// </summary>
public record Cidr(string Address, int Prefix);

public static class CidrUtils
{
    /// <summary>Parse an IPv4 CIDR (or bare IP, treated as /32). Returns null if invalid.</summary>
    public static Cidr? Parse(string cidr)
    {
        var trimmed = cidr.Trim();
        if (trimmed.Length == 0) return null;
        var slash = trimmed.IndexOf('/');
        var addr = slash >= 0 ? trimmed[..slash] : trimmed;
        int prefix;
        if (slash >= 0)
        {
            if (!int.TryParse(trimmed[(slash + 1)..], out prefix)) return null;
        }
        else
        {
            prefix = 32;
        }
        if (prefix is < 0 or > 32) return null;
        return IsIPv4(addr) ? new Cidr(addr, prefix) : null;
    }

    public static int PrefixFromMask(string mask)
    {
        var octets = mask.Split('.');
        if (octets.Length != 4) return 24;
        var bits = 0;
        foreach (var o in octets)
        {
            if (!int.TryParse(o, out var v)) return 24;
            bits += System.Numerics.BitOperations.PopCount((uint)(v & 0xff));
        }
        return bits;
    }

    private static bool IsIPv4(string s)
    {
        var parts = s.Split('.');
        if (parts.Length != 4) return false;
        foreach (var p in parts)
        {
            if (!int.TryParse(p, out var v) || v < 0 || v > 255) return false;
        }
        return true;
    }
}

/// <summary>
/// Matches hostnames against domain patterns. A pattern matches its apex and any
/// subdomain; a leading <c>*.</c> is accepted and ignored. So <c>cacheby.com</c>
/// and <c>*.cacheby.com</c> both match <c>cacheby.com</c> and
/// <c>img.cacheby.com</c>, but not <c>notcacheby.com</c>.
/// </summary>
public sealed class DomainMatcher
{
    private readonly List<string> _bases = new();

    public DomainMatcher(IEnumerable<string> patterns)
    {
        foreach (var p in patterns)
        {
            var n = Normalize(p);
            if (n != null && !_bases.Contains(n)) _bases.Add(n);
        }
    }

    public bool IsEmpty => _bases.Count == 0;

    public bool Matches(string host)
    {
        var h = host.Trim().TrimEnd('.').ToLowerInvariant();
        if (h.Length == 0) return false;
        foreach (var b in _bases)
        {
            if (h == b || h.EndsWith("." + b, StringComparison.Ordinal)) return true;
        }
        return false;
    }

    private static string? Normalize(string pattern)
    {
        var s = pattern.Trim().ToLowerInvariant().TrimEnd('.');
        if (s.StartsWith("*.", StringComparison.Ordinal)) s = s[2..];
        if (s.StartsWith(".", StringComparison.Ordinal)) s = s[1..];
        return string.IsNullOrEmpty(s) ? null : s;
    }
}

public record DnsResponse(string QName, IReadOnlyList<string> Addresses);

/// <summary>A DNS response rewritten to carry no answers (NODATA), plus its query name.</summary>
public record StrippedDnsResponse(string QName, byte[] Packet);

/// <summary>
/// Minimal DNS-over-UDP response sniffer. Given a raw IPv4 packet, returns the
/// query name and any A-record IPv4s if it is a DNS response (UDP src port 53),
/// else null. Handles DNS name compression pointers.
/// </summary>
public static class DnsSniffer
{
    public static DnsResponse? Parse(byte[] packet)
    {
        if (packet.Length < 20) return null;
        var version = (packet[0] >> 4) & 0x0f;
        if (version != 4) return null;
        var ihl = (packet[0] & 0x0f) * 4;
        if (ihl < 20 || packet.Length < ihl + 8) return null;
        if (packet[9] != 17) return null; // UDP
        var udpStart = ihl;
        var srcPort = (packet[udpStart] << 8) | packet[udpStart + 1];
        if (srcPort != 53) return null;
        return ParseDns(packet, udpStart + 8);
    }

    private static DnsResponse? ParseDns(byte[] p, int start)
    {
        if (p.Length < start + 12) return null;
        var flags = U16(p, start + 2);
        if (((flags >> 15) & 1) != 1) return null; // must be a response
        var qdCount = U16(p, start + 4);
        var anCount = U16(p, start + 6);
        if (qdCount < 1) return null;

        var off = start + 12;
        var name = ReadName(p, off, start);
        if (name == null) return null;
        var qname = name.Value.Name;
        off = name.Value.After + 4; // qtype + qclass
        for (var i = 1; i < qdCount; i++)
        {
            var skip = SkipName(p, off, start);
            if (skip == null) return null;
            off = skip.Value + 4;
        }

        var addresses = new List<string>();
        for (var i = 0; i < anCount; i++)
        {
            var skip = SkipName(p, off, start);
            if (skip == null) break;
            off = skip.Value;
            if (off + 10 > p.Length) break;
            var type = U16(p, off);
            var rdLength = U16(p, off + 8);
            off += 10;
            if (type == 1 && rdLength == 4 && off + 4 <= p.Length)
            {
                addresses.Add($"{p[off]}.{p[off + 1]}.{p[off + 2]}.{p[off + 3]}");
            }
            off += rdLength;
        }
        return new DnsResponse(qname, addresses);
    }

    /// <summary>
    /// If <paramref name="packet"/> is a DNS response to an AAAA (28) or
    /// HTTPS/SVCB (65) query, rebuild it with zero answer/authority/additional
    /// records (a NODATA response), preserving the header flags and question
    /// section. The caller decides whether the query name warrants it
    /// (split-tunnel domain match).
    ///
    /// Rationale: the tunnel is IPv4-only, so an AAAA answer for a matched
    /// domain sends the OS over untunneled IPv6, straight past the split
    /// routes. Blanking AAAA (and HTTPS, whose ipv6hint has the same effect)
    /// forces the fallback to A records, which the sniffer routes correctly.
    /// </summary>
    public static StrippedDnsResponse? StripIPv6Response(byte[] packet)
    {
        if (packet.Length < 20) return null;
        if (((packet[0] >> 4) & 0x0f) != 4) return null;
        var ihl = (packet[0] & 0x0f) * 4;
        if (ihl < 20 || packet.Length < ihl + 8) return null;
        if (packet[9] != 17) return null; // UDP
        if (((packet[ihl] << 8) | packet[ihl + 1]) != 53) return null; // src port
        var dnsStart = ihl + 8;
        if (packet.Length < dnsStart + 12) return null;
        var flags = U16(packet, dnsStart + 2);
        if (((flags >> 15) & 1) != 1) return null; // must be a response
        var qdCount = U16(packet, dnsStart + 4);
        var anCount = U16(packet, dnsStart + 6);
        var nsCount = U16(packet, dnsStart + 8);
        var arCount = U16(packet, dnsStart + 10);
        if (qdCount < 1) return null;
        if (anCount == 0 && nsCount == 0 && arCount == 0) return null; // already empty

        var name = ReadName(packet, dnsStart + 12, dnsStart);
        if (name == null) return null;
        var afterQname = name.Value.After;
        if (afterQname + 4 > packet.Length) return null;
        var qtype = U16(packet, afterQname);
        if (qtype != 28 && qtype != 65) return null; // AAAA / HTTPS only
        var qEnd = afterQname + 4;
        for (var i = 1; i < qdCount; i++)
        {
            var skip = SkipName(packet, qEnd, dnsStart);
            if (skip == null) return null;
            qEnd = skip.Value + 4;
        }
        if (qEnd > packet.Length) return null;

        // IP + UDP headers + DNS header + question section(s) only.
        var outPacket = new byte[qEnd];
        Array.Copy(packet, outPacket, qEnd);
        outPacket[dnsStart + 6] = 0; outPacket[dnsStart + 7] = 0;   // ANCOUNT
        outPacket[dnsStart + 8] = 0; outPacket[dnsStart + 9] = 0;   // NSCOUNT
        outPacket[dnsStart + 10] = 0; outPacket[dnsStart + 11] = 0; // ARCOUNT

        var udpLen = outPacket.Length - ihl;
        outPacket[ihl + 4] = (byte)((udpLen >> 8) & 0xff);
        outPacket[ihl + 5] = (byte)(udpLen & 0xff);
        outPacket[ihl + 6] = 0; // UDP checksum 0 = "not computed" (valid over IPv4)
        outPacket[ihl + 7] = 0;
        outPacket[2] = (byte)((outPacket.Length >> 8) & 0xff);
        outPacket[3] = (byte)(outPacket.Length & 0xff);
        outPacket[10] = 0; outPacket[11] = 0;
        var ck = PacketBytes.Ipv4HeaderChecksum(outPacket, ihl);
        outPacket[10] = (byte)((ck >> 8) & 0xff);
        outPacket[11] = (byte)(ck & 0xff);
        return new StrippedDnsResponse(name.Value.Name, outPacket);
    }

    private static (string Name, int After)? ReadName(byte[] p, int start, int msgStart)
    {
        var labels = new List<string>();
        var i = start;
        var afterField = -1;
        var jumps = 0;
        while (true)
        {
            if (i >= p.Length) return null;
            int len = p[i];
            if (len == 0)
            {
                if (afterField < 0) afterField = i + 1;
                break;
            }
            if ((len & 0xc0) == 0xc0)
            {
                if (i + 1 >= p.Length) return null;
                var pointer = ((len & 0x3f) << 8) | p[i + 1];
                if (afterField < 0) afterField = i + 2;
                i = msgStart + pointer;
                if (++jumps > 64) return null; // guard against pointer loops
            }
            else
            {
                if (i + 1 + len > p.Length) return null;
                labels.Add(System.Text.Encoding.ASCII.GetString(p, i + 1, len));
                i += 1 + len;
            }
        }
        return (string.Join(".", labels), afterField);
    }

    private static int? SkipName(byte[] p, int start, int msgStart) => ReadName(p, start, msgStart)?.After;

    private static int U16(byte[] p, int i) => (p[i] << 8) | p[i + 1];
}

internal static class PacketBytes
{
    /// <summary>RFC 1071 checksum over the IPv4 header (checksum field must be zeroed first).</summary>
    internal static int Ipv4HeaderChecksum(byte[] p, int headerLen)
    {
        var sum = 0;
        for (var i = 0; i + 1 < headerLen; i += 2)
        {
            sum += (p[i] << 8) | p[i + 1];
        }
        while (sum > 0xffff) sum = (sum & 0xffff) + (sum >> 16);
        return ~sum & 0xffff;
    }
}

/// <summary>
/// Builds raw IPv4/UDP DNS A-record queries. Used to pre-resolve split-tunnel
/// domains through the tunnel right after it comes up: the OS may be holding a
/// cached answer (so no query the sniffer could learn from would ever be sent),
/// and the first user connection would otherwise race ahead of route learning.
/// </summary>
public static class DnsQueryBuilder
{
    public static byte[]? BuildAQuery(string domain, string srcIP, string dstIP, ushort srcPort, ushort id)
    {
        var src = Ipv4Bytes(srcIP);
        var dst = Ipv4Bytes(dstIP);
        if (src == null || dst == null) return null;

        // DNS: header (RD set, one question) + QNAME + QTYPE=A, QCLASS=IN.
        var dns = new List<byte>
        {
            (byte)((id >> 8) & 0xff), (byte)(id & 0xff),
            0x01, 0x00,
            0, 1, 0, 0, 0, 0, 0, 0
        };
        foreach (var label in domain.Split('.'))
        {
            var bytes = System.Text.Encoding.ASCII.GetBytes(label);
            if (bytes.Length == 0 || bytes.Length > 63) return null;
            dns.Add((byte)bytes.Length);
            dns.AddRange(bytes);
        }
        dns.Add(0);
        dns.AddRange(new byte[] { 0, 1, 0, 1 });

        var udpLen = 8 + dns.Count;
        var udp = new byte[]
        {
            (byte)((srcPort >> 8) & 0xff), (byte)(srcPort & 0xff),
            0, 53,
            (byte)((udpLen >> 8) & 0xff), (byte)(udpLen & 0xff),
            0, 0 // checksum optional over IPv4
        };

        var totalLen = 20 + udpLen;
        var ip = new byte[20]
        {
            0x45, 0,
            (byte)((totalLen >> 8) & 0xff), (byte)(totalLen & 0xff),
            (byte)((id >> 8) & 0xff), (byte)(id & 0xff),
            0, 0,
            64, 17, 0, 0,
            src[0], src[1], src[2], src[3],
            dst[0], dst[1], dst[2], dst[3]
        };
        var ck = PacketBytes.Ipv4HeaderChecksum(ip, 20);
        ip[10] = (byte)((ck >> 8) & 0xff);
        ip[11] = (byte)(ck & 0xff);

        var packet = new byte[20 + udp.Length + dns.Count];
        ip.CopyTo(packet, 0);
        udp.CopyTo(packet, 20);
        dns.CopyTo(packet, 28);
        return packet;
    }

    private static byte[]? Ipv4Bytes(string s)
    {
        var parts = s.Split('.');
        if (parts.Length != 4) return null;
        var outBytes = new byte[4];
        for (var i = 0; i < 4; i++)
        {
            if (!int.TryParse(parts[i], out var v) || v < 0 || v > 255) return null;
            outBytes[i] = (byte)v;
        }
        return outBytes;
    }
}
