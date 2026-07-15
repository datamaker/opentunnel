//! Packet router: pumps inbound TUN packets to the owning client session.
//!
//! Port of the internet -> client direction of `routing/packetRouter.ts`. The
//! client -> internet direction is handled inline in the connection loop, which
//! writes directly to the [`TunHandle`](crate::tun::TunHandle).

use crate::session::SessionManager;
use std::net::Ipv4Addr;
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
