//! Registry of active sessions with routing by assigned IP.
//!
//! Port of `session/sessionManager.ts`.

use crate::protocol::serializer;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::{mpsc, Notify};
use uuid::Uuid;

/// Who a live session belongs to and what it was authenticated with. This is
/// what revocation decisions are made on.
#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub user_id: Uuid,
    pub username: String,
    /// Row id in the `sessions` table (`None` if the insert failed).
    pub db_id: Option<Uuid>,
    /// True when the session descends from an SSO login.
    pub sso: bool,
    /// Email the SSO login was for (SSO sessions only).
    pub email: Option<String>,
    /// When the credential this session was opened with was issued by this
    /// server (unix milliseconds). Compared against `users.tokens_valid_after`.
    pub issued_at_ms: i64,
    /// When the user last really logged in (unix seconds): the SSO login the
    /// token chain started from, or the password login.
    pub auth_time: i64,
}

/// Lets the server end a session from outside its connection task.
#[derive(Default)]
pub struct KillSwitch {
    notify: Notify,
    reason: Mutex<Option<String>>,
}

impl KillSwitch {
    /// Ask the connection to close. The first reason given is kept.
    pub fn trigger(&self, reason: &str) {
        self.reason
            .lock()
            .unwrap()
            .get_or_insert_with(|| reason.to_string());
        // `notify_one` stores a permit, so a trigger that lands before the
        // connection task starts waiting is not lost.
        self.notify.notify_one();
    }

    /// Resolves once [`trigger`](Self::trigger) has been called.
    pub async fn triggered(&self) -> String {
        self.notify.notified().await;
        self.reason.lock().unwrap().clone().unwrap_or_default()
    }
}

/// Lightweight handle to a live session, held by the manager.
#[derive(Clone)]
pub struct SessionHandle {
    pub id: Uuid,
    pub assigned_ip: Ipv4Addr,
    /// Raw bytes to be written to the client socket.
    pub tx: mpsc::Sender<Vec<u8>>,
    pub bytes_sent: Arc<AtomicU64>,
    pub bytes_received: Arc<AtomicU64>,
    pub info: Arc<SessionInfo>,
    pub kill: Arc<KillSwitch>,
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

    /// Every live session, for the periodic revalidation pass.
    pub fn snapshot(&self) -> Vec<(Uuid, Arc<SessionInfo>)> {
        self.by_ip
            .lock()
            .unwrap()
            .values()
            .map(|h| (h.id, h.info.clone()))
            .collect()
    }

    /// Number of live tunnels per user.
    pub fn live_counts(&self) -> HashMap<Uuid, usize> {
        let mut counts = HashMap::new();
        for handle in self.by_ip.lock().unwrap().values() {
            *counts.entry(handle.info.user_id).or_insert(0) += 1;
        }
        counts
    }

    /// The live session persisted as `sessions.id = db_id`, if any.
    pub fn find_by_db_id(&self, db_id: Uuid) -> Option<Arc<SessionInfo>> {
        self.by_ip
            .lock()
            .unwrap()
            .values()
            .find(|h| h.info.db_id == Some(db_id))
            .map(|h| h.info.clone())
    }

    /// Close every live session matching `pred`. Each is removed from the
    /// routing tables right away (no further packets reach it) and its
    /// connection task is told to shut the socket; that task releases the
    /// tunnel IP and deletes the `sessions` row as part of its normal cleanup.
    /// The IP is deliberately *not* released here: doing it in two places could
    /// free an address that has already been handed to another client.
    fn kill_where(&self, reason: &str, pred: impl Fn(&SessionHandle) -> bool) -> Vec<Arc<SessionInfo>> {
        let victims: Vec<SessionHandle> = {
            let mut by_ip = self.by_ip.lock().unwrap();
            let ips: Vec<Ipv4Addr> = by_ip
                .values()
                .filter(|h| pred(h))
                .map(|h| h.assigned_ip)
                .collect();
            ips.iter().filter_map(|ip| by_ip.remove(ip)).collect()
        };
        let mut ids = self.ids.lock().unwrap();
        victims
            .into_iter()
            .map(|handle| {
                ids.remove(&handle.id);
                handle.kill.trigger(reason);
                handle.info
            })
            .collect()
    }

    /// Close one session by its connection id. Returns whether it was live.
    pub fn kill(&self, id: Uuid, reason: &str) -> bool {
        !self.kill_where(reason, |h| h.id == id).is_empty()
    }

    /// Close every live session of a user. Returns the sessions closed.
    pub fn kill_user(&self, user_id: Uuid, reason: &str) -> Vec<Arc<SessionInfo>> {
        self.kill_where(reason, |h| h.info.user_id == user_id)
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
