package com.vpn.client.split

/**
 * Destination-based (split-tunnel) routing helpers.
 *
 * These classes are intentionally free of Android dependencies (JDK only) so the
 * routing logic can be unit-tested on a plain JVM. The Android [VpnService]
 * integration lives in `MyVpnService`.
 *
 * The server pushes an "include" policy: a list of IP CIDRs and domains that
 * should go through the tunnel. Static/dedicated-IP domains are resolved to
 * CIDRs server-side, but CDN domains (CloudFront/Cloudflare) resolve to shared,
 * rotating, geo-dependent IPs — so those must be matched by *hostname* on the
 * client: we snoop DNS answers for matched domains and route exactly the IPs the
 * client actually resolved. [DomainMatcher] + [DnsSniffer] implement that path.
 */

/** A parsed IPv4 CIDR, e.g. `10.0.0.0/8`. */
data class Cidr(val address: String, val prefix: Int)

object CidrUtils {
    /** Parse an IPv4 CIDR (or bare IP, treated as /32). Returns null if invalid. */
    fun parse(cidr: String): Cidr? {
        val trimmed = cidr.trim()
        if (trimmed.isEmpty()) return null
        val slash = trimmed.indexOf('/')
        val addr = if (slash >= 0) trimmed.substring(0, slash) else trimmed
        val prefix = if (slash >= 0) {
            trimmed.substring(slash + 1).toIntOrNull() ?: return null
        } else {
            32
        }
        if (prefix !in 0..32) return null
        if (!isIpv4(addr)) return null
        return Cidr(addr, prefix)
    }

    /** Convert a dotted-decimal netmask (e.g. `255.255.255.0`) to a prefix length. */
    fun prefixFromMask(mask: String): Int {
        val octets = mask.split(".").mapNotNull { it.toIntOrNull() }
        if (octets.size != 4) return 24
        var bits = 0
        for (o in octets) bits += Integer.bitCount(o and 0xff)
        return bits
    }

    private fun isIpv4(s: String): Boolean {
        val parts = s.split(".")
        if (parts.size != 4) return false
        return parts.all { p -> p.toIntOrNull()?.let { it in 0..255 } == true }
    }
}

/**
 * Matches hostnames against a set of domain patterns.
 *
 * A pattern matches its apex and any subdomain, and a leading `*.` is accepted
 * and ignored (CDN convenience). So `cacheby.com` and `*.cacheby.com` both match
 * `cacheby.com`, `img.cacheby.com`, and `a.b.cacheby.com` — but not
 * `notcacheby.com`.
 */
class DomainMatcher(patterns: List<String>) {
    private val bases: List<String> = patterns.mapNotNull { normalize(it) }.distinct()

    fun isEmpty(): Boolean = bases.isEmpty()

    fun matches(host: String): Boolean {
        val h = host.trim().trimEnd('.').lowercase()
        if (h.isEmpty()) return false
        return bases.any { base -> h == base || h.endsWith(".$base") }
    }

    private fun normalize(pattern: String): String? {
        var s = pattern.trim().lowercase().trimEnd('.')
        if (s.startsWith("*.")) s = s.substring(2)
        if (s.startsWith(".")) s = s.substring(1)
        return s.ifEmpty { null }
    }
}

/** A DNS response worth acting on: the queried name and its A-record IPv4s. */
data class DnsResponse(val qname: String, val addresses: List<String>)

/**
 * Minimal DNS-over-UDP response sniffer.
 *
 * Given a raw IPv4 packet captured from the tunnel, returns the query name and
 * any A-record addresses if it is a DNS *response* (UDP source port 53), else
 * null. Handles DNS name compression pointers.
 */
object DnsSniffer {
    fun parse(packet: ByteArray): DnsResponse? {
        if (packet.size < 20) return null
        val version = (packet[0].toInt() ushr 4) and 0x0f
        if (version != 4) return null
        val ihl = (packet[0].toInt() and 0x0f) * 4
        if (ihl < 20 || packet.size < ihl + 8) return null
        val protocol = packet[9].toInt() and 0xff
        if (protocol != 17) return null // UDP
        val udpStart = ihl
        val srcPort = u16(packet, udpStart)
        if (srcPort != 53) return null // DNS response
        return parseDns(packet, udpStart + 8)
    }

    private fun parseDns(p: ByteArray, start: Int): DnsResponse? {
        if (p.size < start + 12) return null
        val flags = u16(p, start + 2)
        if ((flags ushr 15) and 1 != 1) return null // must be a response
        val qdCount = u16(p, start + 4)
        val anCount = u16(p, start + 6)
        if (qdCount < 1) return null

        var off = start + 12
        val (qname, afterQname) = readName(p, off, start) ?: return null
        off = afterQname + 4 // qtype + qclass
        // Skip any additional questions.
        for (i in 1 until qdCount) {
            off = skipName(p, off, start) ?: return null
            off += 4
        }

        val addresses = ArrayList<String>()
        for (i in 0 until anCount) {
            off = skipName(p, off, start) ?: break
            if (off + 10 > p.size) break
            val type = u16(p, off)
            val rdLength = u16(p, off + 8)
            off += 10
            if (type == 1 && rdLength == 4 && off + 4 <= p.size) {
                addresses.add(
                    "${p[off].toInt() and 0xff}.${p[off + 1].toInt() and 0xff}." +
                        "${p[off + 2].toInt() and 0xff}.${p[off + 3].toInt() and 0xff}"
                )
            }
            off += rdLength
        }
        return DnsResponse(qname, addresses)
    }

    /** Read a (possibly compressed) name; returns (name, offset-after-name-field). */
    private fun readName(p: ByteArray, start: Int, msgStart: Int): Pair<String, Int>? {
        val labels = ArrayList<String>()
        var i = start
        var afterField = -1
        var jumps = 0
        while (true) {
            if (i >= p.size) return null
            val len = p[i].toInt() and 0xff
            when {
                len == 0 -> {
                    if (afterField < 0) afterField = i + 1
                    break
                }
                (len and 0xc0) == 0xc0 -> {
                    if (i + 1 >= p.size) return null
                    val pointer = ((len and 0x3f) shl 8) or (p[i + 1].toInt() and 0xff)
                    if (afterField < 0) afterField = i + 2
                    i = msgStart + pointer
                    if (++jumps > 64) return null // guard against pointer loops
                }
                else -> {
                    if (i + 1 + len > p.size) return null
                    labels.add(String(p, i + 1, len, Charsets.US_ASCII))
                    i += 1 + len
                }
            }
        }
        return Pair(labels.joinToString("."), afterField)
    }

    private fun skipName(p: ByteArray, start: Int, msgStart: Int): Int? =
        readName(p, start, msgStart)?.second

    private fun u16(p: ByteArray, i: Int): Int =
        ((p[i].toInt() and 0xff) shl 8) or (p[i + 1].toInt() and 0xff)
}
