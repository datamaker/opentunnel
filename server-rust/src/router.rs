//! Packet router: pumps inbound TUN packets to the owning client session.
//!
//! Port of the internet -> client direction of `routing/packetRouter.ts`. The
//! client -> internet direction is handled inline in the connection loop, which
//! writes directly to the [`TunHandle`](crate::tun::TunHandle) after each
//! packet has passed the [`PacketFilter`].

use crate::session::SessionManager;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;

/// Spawn the routing loop that reads packets from the TUN device and dispatches
/// each to the session that owns its destination IP.
pub fn spawn(mut incoming: mpsc::Receiver<Vec<u8>>, sessions: Arc<SessionManager>) {
    tokio::spawn(async move {
        while let Some(packet) = incoming.recv().await {
            // Need at least a full IPv4 header to read the destination address,
            // and the version nibble must be 4 (the tunnel is IPv4-only, and the
            // destination is only at offset 16 for IPv4).
            if packet.len() < 20 || (packet[0] >> 4) != 4 {
                continue;
            }
            let dest = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
            if sessions.route_to_client(dest, &packet) {
                tracing::trace!("routed {} bytes to {}", packet.len(), dest);
            }
        }
        tracing::warn!("packet router stopped: TUN stream closed");
    });
}

/// Why a packet a client sent into the tunnel was not forwarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// Not a well-formed IPv4 packet (the tunnel is IPv4-only).
    Malformed,
    /// Source address is not the address assigned to the sending session.
    BadSource,
    /// Destination is another client's tunnel address and isolation is on.
    Isolated,
}

/// Checks applied to every packet a client sends into the tunnel
/// (client -> internet), before it is written to the TUN device.
///
/// Without the source check a client could send packets *as* any other
/// address — another client's tunnel IP, the gateway, or an internal host —
/// and the kernel would forward them. The isolation check keeps one client
/// from reaching another through the server; it lives here, in the server's
/// own forwarding path, so it does not depend on the host's iptables rules.
pub struct PacketFilter {
    subnet: u32,
    mask: u32,
    gateway: Ipv4Addr,
    isolate_clients: bool,
    malformed: AtomicU64,
    bad_source: AtomicU64,
    isolated: AtomicU64,
}

/// Totals since startup, for the periodic status line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DropStats {
    pub malformed: u64,
    pub bad_source: u64,
    pub isolated: u64,
}

impl PacketFilter {
    /// `subnet` is the tunnel network (e.g. `10.8.0.0`) with `prefix_bits`.
    pub fn new(subnet: Ipv4Addr, prefix_bits: u32, gateway: Ipv4Addr, isolate_clients: bool) -> Self {
        let mask = if prefix_bits == 0 {
            0
        } else {
            u32::MAX << (32 - prefix_bits.min(32))
        };
        PacketFilter {
            subnet: u32::from(subnet) & mask,
            mask,
            gateway,
            isolate_clients,
            malformed: AtomicU64::new(0),
            bad_source: AtomicU64::new(0),
            isolated: AtomicU64::new(0),
        }
    }

    /// Decide whether `packet`, sent by the session that owns `assigned`, may
    /// be forwarded. Refusals are counted.
    pub fn check(&self, packet: &[u8], assigned: Ipv4Addr) -> Result<(), Refusal> {
        let verdict = self.classify(packet, assigned);
        match verdict {
            Ok(()) => {}
            Err(Refusal::Malformed) => {
                self.malformed.fetch_add(1, Ordering::Relaxed);
            }
            Err(Refusal::BadSource) => {
                self.bad_source.fetch_add(1, Ordering::Relaxed);
            }
            Err(Refusal::Isolated) => {
                self.isolated.fetch_add(1, Ordering::Relaxed);
            }
        }
        verdict
    }

    fn classify(&self, packet: &[u8], assigned: Ipv4Addr) -> Result<(), Refusal> {
        if packet.len() < 20 || (packet[0] >> 4) != 4 {
            return Err(Refusal::Malformed);
        }
        let source = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
        if source != assigned {
            return Err(Refusal::BadSource);
        }
        if self.isolate_clients {
            let dest = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
            let in_tunnel = u32::from(dest) & self.mask == self.subnet;
            // The gateway is the server itself (DNS, the admin panel); the
            // client's own address is harmless. Anything else inside the
            // tunnel network is another client.
            if in_tunnel && dest != self.gateway && dest != assigned {
                return Err(Refusal::Isolated);
            }
        }
        Ok(())
    }

    pub fn stats(&self) -> DropStats {
        DropStats {
            malformed: self.malformed.load(Ordering::Relaxed),
            bad_source: self.bad_source.load(Ordering::Relaxed),
            isolated: self.isolated.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLIENT: Ipv4Addr = Ipv4Addr::new(10, 8, 0, 2);
    const OTHER_CLIENT: Ipv4Addr = Ipv4Addr::new(10, 8, 0, 3);
    const GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 8, 0, 1);

    fn filter(isolate: bool) -> PacketFilter {
        PacketFilter::new(Ipv4Addr::new(10, 8, 0, 0), 24, GATEWAY, isolate)
    }

    /// A minimal IPv4 header with the given addresses.
    pub(crate) fn ipv4(source: Ipv4Addr, dest: Ipv4Addr) -> Vec<u8> {
        let mut packet = vec![0u8; 28];
        packet[0] = 0x45;
        packet[12..16].copy_from_slice(&source.octets());
        packet[16..20].copy_from_slice(&dest.octets());
        packet
    }

    #[test]
    fn packet_from_the_assigned_address_is_forwarded() {
        let f = filter(true);
        assert_eq!(f.check(&ipv4(CLIENT, Ipv4Addr::new(11, 0, 1, 21)), CLIENT), Ok(()));
        assert_eq!(f.check(&ipv4(CLIENT, Ipv4Addr::new(8, 8, 8, 8)), CLIENT), Ok(()));
        assert_eq!(f.stats(), DropStats { malformed: 0, bad_source: 0, isolated: 0 });
    }

    #[test]
    fn spoofed_source_is_dropped_and_counted() {
        let f = filter(false);
        let internal = Ipv4Addr::new(11, 0, 1, 21);
        // Another client's address, the gateway, an internal host, anything.
        for forged in [OTHER_CLIENT, GATEWAY, internal, Ipv4Addr::new(1, 2, 3, 4)] {
            assert_eq!(f.check(&ipv4(forged, internal), CLIENT), Err(Refusal::BadSource));
        }
        assert_eq!(f.stats().bad_source, 4);
    }

    #[test]
    fn non_ipv4_and_truncated_packets_are_dropped() {
        let f = filter(true);
        let mut v6 = vec![0u8; 40];
        v6[0] = 0x60;
        assert_eq!(f.check(&v6, CLIENT), Err(Refusal::Malformed));
        assert_eq!(f.check(&ipv4(CLIENT, GATEWAY)[..19], CLIENT), Err(Refusal::Malformed));
        assert_eq!(f.check(&[], CLIENT), Err(Refusal::Malformed));
        assert_eq!(f.stats().malformed, 3);
    }

    #[test]
    fn isolation_blocks_other_clients_but_not_the_gateway() {
        let f = filter(true);
        assert_eq!(f.check(&ipv4(CLIENT, OTHER_CLIENT), CLIENT), Err(Refusal::Isolated));
        // An address in the tunnel network that is not assigned right now is
        // still "another client" as far as this check goes.
        assert_eq!(
            f.check(&ipv4(CLIENT, Ipv4Addr::new(10, 8, 0, 200)), CLIENT),
            Err(Refusal::Isolated)
        );
        assert_eq!(f.check(&ipv4(CLIENT, GATEWAY), CLIENT), Ok(()));
        assert_eq!(f.check(&ipv4(CLIENT, CLIENT), CLIENT), Ok(()));
        // Outside the tunnel network is not this check's business.
        assert_eq!(f.check(&ipv4(CLIENT, Ipv4Addr::new(10, 9, 0, 3)), CLIENT), Ok(()));
        assert_eq!(f.stats().isolated, 2);
    }

    #[test]
    fn isolation_can_be_switched_off() {
        let f = filter(false);
        assert_eq!(f.check(&ipv4(CLIENT, OTHER_CLIENT), CLIENT), Ok(()));
    }
}
