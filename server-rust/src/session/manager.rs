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

#[derive(Default)]
pub struct SessionManager {
    sessions: Mutex<HashMap<Uuid, SessionHandle>>,
    by_ip: Mutex<HashMap<Ipv4Addr, Uuid>>,
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
        self.by_ip
            .lock()
            .unwrap()
            .insert(handle.assigned_ip, handle.id);
        self.sessions.lock().unwrap().insert(handle.id, handle);
    }

    pub fn unregister(&self, id: Uuid) {
        if let Some(handle) = self.sessions.lock().unwrap().remove(&id) {
            self.by_ip.lock().unwrap().remove(&handle.assigned_ip);
        }
    }

    /// Forward an inbound IP packet to the session that owns `dest_ip`.
    /// Returns `true` if a matching session was found.
    pub fn route_to_client(&self, dest_ip: Ipv4Addr, packet: &[u8]) -> bool {
        let handle = self.by_ip.lock().unwrap().get(&dest_ip).and_then(|id| {
            self.sessions.lock().unwrap().get(id).cloned()
        });

        if let Some(handle) = handle {
            let framed = serializer::data_packet(packet);
            handle.bytes_sent.fetch_add(framed.len() as u64, Ordering::Relaxed);
            // Non-blocking send; drop the packet if the client is backed up.
            handle.tx.try_send(framed).is_ok()
        } else {
            false
        }
    }

    pub fn active_count(&self) -> usize {
        self.sessions.lock().unwrap().len()
    }

    pub fn stats(&self) -> ManagerStats {
        let sessions = self.sessions.lock().unwrap();
        let mut total_bytes_sent = 0;
        let mut total_bytes_received = 0;
        for handle in sessions.values() {
            total_bytes_sent += handle.bytes_sent.load(Ordering::Relaxed);
            total_bytes_received += handle.bytes_received.load(Ordering::Relaxed);
        }
        ManagerStats {
            active_sessions: sessions.len(),
            total_bytes_sent,
            total_bytes_received,
        }
    }

    pub fn close_all(&self) {
        // Dropping the senders closes each writer task, which shuts the socket.
        self.sessions.lock().unwrap().clear();
        self.by_ip.lock().unwrap().clear();
    }
}
