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
