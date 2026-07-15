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
