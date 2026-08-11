//
//  SplitRouting.swift
//  Destination-based (split-tunnel) routing helpers.
//
//  Foundation-only logic shared by the iOS and macOS packet-tunnel providers.
//  Mirrors the Android `SplitRouting.kt` (whose logic is unit-tested on the JVM).
//
//  The server pushes an "include" policy (IP CIDRs + domains). Concrete domains
//  are resolved to CIDRs server-side, but CDN domains (CloudFront/Cloudflare)
//  resolve to shared, rotating, geo-dependent IPs, so those are matched by
//  hostname on the client: we snoop DNS answers for matched domains and route
//  exactly the IPs the client actually resolved. DomainMatcher + DnsSniffer
//  implement that path.
//

import Foundation

struct Cidr: Equatable {
    let address: String
    let prefix: Int
}

enum CidrUtils {
    /// Parse an IPv4 CIDR (or bare IP, treated as /32). Returns nil if invalid.
    static func parse(_ cidr: String) -> Cidr? {
        let trimmed = cidr.trimmingCharacters(in: .whitespaces)
        if trimmed.isEmpty { return nil }
        let parts = trimmed.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false)
        let addr = String(parts[0])
        let prefix: Int
        if parts.count > 1 {
            guard let p = Int(parts[1]) else { return nil }
            prefix = p
        } else {
            prefix = 32
        }
        if prefix < 0 || prefix > 32 { return nil }
        if !isIPv4(addr) { return nil }
        return Cidr(address: addr, prefix: prefix)
    }

    /// Dotted-decimal subnet mask for a prefix length (for NEIPv4Route).
    static func mask(forPrefix prefix: Int) -> String {
        let bits: UInt32 = prefix == 0 ? 0 : (0xffff_ffff << (32 - UInt32(min(prefix, 32))))
        return "\((bits >> 24) & 0xff).\((bits >> 16) & 0xff).\((bits >> 8) & 0xff).\(bits & 0xff)"
    }

    static func prefix(fromMask mask: String) -> Int {
        let octets = mask.split(separator: ".").compactMap { Int($0) }
        if octets.count != 4 { return 24 }
        return octets.reduce(0) { $0 + ($1 & 0xff).nonzeroBitCount }
    }

    private static func isIPv4(_ s: String) -> Bool {
        let parts = s.split(separator: ".", omittingEmptySubsequences: false)
        if parts.count != 4 { return false }
        return parts.allSatisfy { part in
            if let v = Int(part) { return v >= 0 && v <= 255 }
            return false
        }
    }
}

/// Matches hostnames against domain patterns. A pattern matches its apex and any
/// subdomain; a leading `*.` is accepted and ignored. So `cacheby.com` and
/// `*.cacheby.com` both match `cacheby.com` and `img.cacheby.com`, but not
/// `notcacheby.com`.
final class DomainMatcher {
    private let bases: [String]

    init(_ patterns: [String]) {
        var seen: [String] = []
        for p in patterns {
            if let n = DomainMatcher.normalize(p), !seen.contains(n) {
                seen.append(n)
            }
        }
        bases = seen
    }

    var isEmpty: Bool { bases.isEmpty }

    func matches(_ host: String) -> Bool {
        var h = host.trimmingCharacters(in: .whitespaces).lowercased()
        while h.hasSuffix(".") { h.removeLast() }
        if h.isEmpty { return false }
        return bases.contains { base in h == base || h.hasSuffix("." + base) }
    }

    private static func normalize(_ pattern: String) -> String? {
        var s = pattern.trimmingCharacters(in: .whitespaces).lowercased()
        while s.hasSuffix(".") { s.removeLast() }
        if s.hasPrefix("*.") { s = String(s.dropFirst(2)) }
        if s.hasPrefix(".") { s = String(s.dropFirst()) }
        return s.isEmpty ? nil : s
    }
}

struct DnsResponse {
    let qname: String
    let addresses: [String]
}

/// A DNS response rewritten to carry no answers (NODATA), plus its query name.
struct StrippedDnsResponse {
    let qname: String
    let packet: [UInt8]
}

/// Minimal DNS-over-UDP response sniffer. Given a raw IPv4 packet, returns the
/// query name and any A-record IPv4s if it is a DNS response (UDP src port 53),
/// else nil. Handles DNS name compression pointers.
enum DnsSniffer {
    static func parse(_ packet: [UInt8]) -> DnsResponse? {
        if packet.count < 20 { return nil }
        let version = (Int(packet[0]) >> 4) & 0x0f
        if version != 4 { return nil }
        let ihl = Int(packet[0] & 0x0f) * 4
        if ihl < 20 || packet.count < ihl + 8 { return nil }
        if Int(packet[9]) != 17 { return nil } // UDP
        let udpStart = ihl
        let srcPort = (Int(packet[udpStart]) << 8) | Int(packet[udpStart + 1])
        if srcPort != 53 { return nil }
        return parseDns(packet, udpStart + 8)
    }

    static func parse(_ data: Data) -> DnsResponse? {
        parse([UInt8](data))
    }

    /// If `packet` is a DNS response to an AAAA (28) or HTTPS/SVCB (65) query,
    /// rebuild it with zero answer/authority/additional records (a NODATA
    /// response), preserving the header flags and question section. The caller
    /// decides whether the query name warrants it (split-tunnel domain match).
    ///
    /// Rationale: the tunnel is IPv4-only, so an AAAA answer for a matched
    /// domain sends the OS over untunneled IPv6, straight past the split
    /// routes. Blanking AAAA (and HTTPS, whose ipv6hint has the same effect)
    /// forces the fallback to A records, which the sniffer routes correctly.
    static func strippedIPv6Response(_ packet: [UInt8]) -> StrippedDnsResponse? {
        if packet.count < 20 { return nil }
        if (Int(packet[0]) >> 4) & 0x0f != 4 { return nil }
        let ihl = Int(packet[0] & 0x0f) * 4
        if ihl < 20 || packet.count < ihl + 8 { return nil }
        if Int(packet[9]) != 17 { return nil } // UDP
        if (Int(packet[ihl]) << 8) | Int(packet[ihl + 1]) != 53 { return nil } // src port
        let dnsStart = ihl + 8
        if packet.count < dnsStart + 12 { return nil }
        let flags = u16(packet, dnsStart + 2)
        if (flags >> 15) & 1 != 1 { return nil } // must be a response
        let qdCount = u16(packet, dnsStart + 4)
        let anCount = u16(packet, dnsStart + 6)
        let nsCount = u16(packet, dnsStart + 8)
        let arCount = u16(packet, dnsStart + 10)
        if qdCount < 1 { return nil }
        if anCount == 0, nsCount == 0, arCount == 0 { return nil } // already empty

        guard let (qname, afterQname) = readName(packet, dnsStart + 12, dnsStart) else { return nil }
        if afterQname + 4 > packet.count { return nil }
        let qtype = u16(packet, afterQname)
        if qtype != 28, qtype != 65 { return nil } // AAAA / HTTPS only
        var qEnd = afterQname + 4
        if qdCount > 1 {
            for _ in 1 ..< qdCount {
                guard let next = skipName(packet, qEnd, dnsStart) else { return nil }
                qEnd = next + 4
            }
        }
        if qEnd > packet.count { return nil }

        // DNS header + question section(s) only, with record counts zeroed.
        var dns = Array(packet[dnsStart ..< qEnd])
        dns[6] = 0; dns[7] = 0    // ANCOUNT
        dns[8] = 0; dns[9] = 0    // NSCOUNT
        dns[10] = 0; dns[11] = 0  // ARCOUNT

        var out = Array(packet[0 ..< dnsStart])
        out.append(contentsOf: dns)
        let udpLen = 8 + dns.count
        out[ihl + 4] = UInt8((udpLen >> 8) & 0xff)
        out[ihl + 5] = UInt8(udpLen & 0xff)
        out[ihl + 6] = 0 // UDP checksum 0 = "not computed" (valid over IPv4)
        out[ihl + 7] = 0
        out[2] = UInt8((out.count >> 8) & 0xff)
        out[3] = UInt8(out.count & 0xff)
        out[10] = 0; out[11] = 0
        let ck = ipv4HeaderChecksum(out, headerLen: ihl)
        out[10] = UInt8((ck >> 8) & 0xff)
        out[11] = UInt8(ck & 0xff)
        return StrippedDnsResponse(qname: qname, packet: out)
    }

    private static func parseDns(_ p: [UInt8], _ start: Int) -> DnsResponse? {
        if p.count < start + 12 { return nil }
        let flags = u16(p, start + 2)
        if (flags >> 15) & 1 != 1 { return nil } // must be a response
        let qdCount = u16(p, start + 4)
        let anCount = u16(p, start + 6)
        if qdCount < 1 { return nil }

        var off = start + 12
        guard let (qname, afterQname) = readName(p, off, start) else { return nil }
        off = afterQname + 4 // qtype + qclass
        if qdCount > 1 {
            for _ in 1 ..< qdCount {
                guard let next = skipName(p, off, start) else { return nil }
                off = next + 4
            }
        }

        var addresses: [String] = []
        var ansLeft = anCount
        while ansLeft > 0 {
            ansLeft -= 1
            guard let next = skipName(p, off, start) else { break }
            off = next
            if off + 10 > p.count { break }
            let type = u16(p, off)
            let rdLength = u16(p, off + 8)
            off += 10
            if type == 1, rdLength == 4, off + 4 <= p.count {
                addresses.append("\(p[off]).\(p[off + 1]).\(p[off + 2]).\(p[off + 3])")
            }
            off += rdLength
        }
        return DnsResponse(qname: qname, addresses: addresses)
    }

    /// Read a (possibly compressed) name; returns (name, offset-after-name-field).
    private static func readName(_ p: [UInt8], _ start: Int, _ msgStart: Int) -> (String, Int)? {
        var labels: [String] = []
        var i = start
        var afterField = -1
        var jumps = 0
        while true {
            if i >= p.count { return nil }
            let len = Int(p[i])
            if len == 0 {
                if afterField < 0 { afterField = i + 1 }
                break
            } else if (len & 0xc0) == 0xc0 {
                if i + 1 >= p.count { return nil }
                let pointer = ((len & 0x3f) << 8) | Int(p[i + 1])
                if afterField < 0 { afterField = i + 2 }
                i = msgStart + pointer
                jumps += 1
                if jumps > 64 { return nil } // guard against pointer loops
            } else {
                if i + 1 + len > p.count { return nil }
                let bytes = Array(p[(i + 1) ..< (i + 1 + len)])
                labels.append(String(decoding: bytes, as: UTF8.self))
                i += 1 + len
            }
        }
        return (labels.joined(separator: "."), afterField)
    }

    private static func skipName(_ p: [UInt8], _ start: Int, _ msgStart: Int) -> Int? {
        readName(p, start, msgStart)?.1
    }

    private static func u16(_ p: [UInt8], _ i: Int) -> Int {
        (Int(p[i]) << 8) | Int(p[i + 1])
    }
}

/// RFC 1071 checksum over the IPv4 header (checksum field must be zeroed first).
func ipv4HeaderChecksum(_ p: [UInt8], headerLen: Int) -> Int {
    var sum = 0
    var i = 0
    while i + 1 < headerLen {
        sum += (Int(p[i]) << 8) | Int(p[i + 1])
        i += 2
    }
    while sum > 0xffff { sum = (sum & 0xffff) + (sum >> 16) }
    return ~sum & 0xffff
}

/// Builds raw IPv4/UDP DNS A-record queries. Used to pre-resolve split-tunnel
/// domains through the tunnel right after it comes up: the OS may be holding a
/// cached answer (so no query the sniffer could learn from would ever be sent),
/// and the first user connection would otherwise race ahead of route learning.
enum DnsQueryBuilder {
    static func buildAQuery(domain: String, srcIP: String, dstIP: String,
                            srcPort: UInt16, id: UInt16) -> [UInt8]? {
        guard let src = ipv4Bytes(srcIP), let dst = ipv4Bytes(dstIP) else { return nil }

        // DNS: header (RD set, one question) + QNAME + QTYPE=A, QCLASS=IN.
        var dns: [UInt8] = [UInt8((id >> 8) & 0xff), UInt8(id & 0xff),
                            0x01, 0x00,
                            0, 1, 0, 0, 0, 0, 0, 0]
        for label in domain.split(separator: ".") {
            let bytes = Array(label.utf8)
            if bytes.isEmpty || bytes.count > 63 { return nil }
            dns.append(UInt8(bytes.count))
            dns.append(contentsOf: bytes)
        }
        dns.append(0)
        dns.append(contentsOf: [0, 1, 0, 1])

        let udpLen = 8 + dns.count
        let udp: [UInt8] = [UInt8((srcPort >> 8) & 0xff), UInt8(srcPort & 0xff),
                            0, 53,
                            UInt8((udpLen >> 8) & 0xff), UInt8(udpLen & 0xff),
                            0, 0] // checksum optional over IPv4

        let totalLen = 20 + udpLen
        var ip: [UInt8] = [0x45, 0,
                           UInt8((totalLen >> 8) & 0xff), UInt8(totalLen & 0xff),
                           UInt8((id >> 8) & 0xff), UInt8(id & 0xff),
                           0, 0,
                           64, 17, 0, 0]
        ip.append(contentsOf: src)
        ip.append(contentsOf: dst)
        let ck = ipv4HeaderChecksum(ip, headerLen: 20)
        ip[10] = UInt8((ck >> 8) & 0xff)
        ip[11] = UInt8(ck & 0xff)
        return ip + udp + dns
    }

    private static func ipv4Bytes(_ s: String) -> [UInt8]? {
        let parts = s.split(separator: ".", omittingEmptySubsequences: false)
        if parts.count != 4 { return nil }
        var out: [UInt8] = []
        for part in parts {
            guard let v = Int(part), v >= 0, v <= 255 else { return nil }
            out.append(UInt8(v))
        }
        return out
    }
}
