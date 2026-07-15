//! Registry of active sessions with routing by assigned IP.
//!
//! Port of `session/sessionManager.ts`.

use crate::protocol::serializer;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use uuid::Uuid;

/// Lightweight handle to a live session, held by the manager.
#[derive(Clone)]
pub struct SessionHandle {
    pub id: Uuid,
    pub assigned_ip: Ipv4Addr,
    /// Raw bytes to be written to the client socket.
    pub tx: mpsc::Sender<Vec<u8>>,
    pub bytes_sent: Arc<AtomicU64>,
    pub bytes_received: Arc<AtomicU64>,
}

/// Sessions are indexed by assigned IP for the routing hot path, and by id for
/// lifecycle operations. Both maps are guarded by plain mutexes; the routing
/// path takes a single, short lock and clones only the cheap `mpsc::Sender`.
#[derive(Default)]
pub struct SessionManager {
    by_ip: Mutex<HashMap<Ipv4Addr, SessionHandle>>,
    ids: Mutex<HashMap<Uuid, Ipv4Addr>>,
}

pub struct ManagerStats {
    pub active_sessions: usize,
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
}

impl SessionManager {
    pub fn new() -> Self {
        SessionManager::default()
    }

    pub fn register(&self, handle: SessionHandle) {
        self.ids.lock().unwrap().insert(handle.id, handle.assigned_ip);
        self.by_ip.lock().unwrap().insert(handle.assigned_ip, handle);
    }

    pub fn unregister(&self, id: Uuid) {
        if let Some(ip) = self.ids.lock().unwrap().remove(&id) {
            self.by_ip.lock().unwrap().remove(&ip);
        }
    }

    /// Forward an inbound IP packet to the session that owns `dest_ip`.
    /// Returns `true` if a matching session was found.
    ///
    /// The lock is held only long enough to clone the channel sender; framing
    /// and the non-blocking send happen outside the critical section.
    pub fn route_to_client(&self, dest_ip: Ipv4Addr, packet: &[u8]) -> bool {
        let tx = self.by_ip.lock().unwrap().get(&dest_ip).map(|h| h.tx.clone());
        match tx {
            // Non-blocking send; drop the packet if the client is backed up.
            // Bytes are counted by the session's writer task, not here.
            Some(tx) => tx.try_send(serializer::data_packet(packet)).is_ok(),
            None => false,
        }
    }

    pub fn active_count(&self) -> usize {
        self.ids.lock().unwrap().len()
    }

    pub fn stats(&self) -> ManagerStats {
        let by_ip = self.by_ip.lock().unwrap();
        let mut total_bytes_sent = 0;
        let mut total_bytes_received = 0;
        for handle in by_ip.values() {
            total_bytes_sent += handle.bytes_sent.load(Ordering::Relaxed);
            total_bytes_received += handle.bytes_received.load(Ordering::Relaxed);
        }
        ManagerStats {
            active_sessions: by_ip.len(),
            total_bytes_sent,
            total_bytes_received,
        }
    }

    pub fn close_all(&self) {
        // Dropping the senders closes each writer task, which shuts the socket.
        self.by_ip.lock().unwrap().clear();
        self.ids.lock().unwrap().clear();
    }
}
