//! Per-connection state machine.
//!
//! Combines the responsibilities of `session/vpnSession.ts` and the connection
//! handling in `index.ts`: authentication, config push, keepalive and data
//! forwarding for a single client socket.

use crate::protocol::{serializer, AuthResponse, ConfigPush, MessageBuffer, MessageType};
use crate::state::SharedState;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::time::{Instant, MissedTickBehavior};
use uuid::Uuid;

use super::manager::SessionHandle;

const KEEPALIVE_TICK: Duration = Duration::from_secs(10);
const IDLE_KEEPALIVE: Duration = Duration::from_secs(30);
const IDLE_TIMEOUT: Duration = Duration::from_secs(120);

/// Handle a single accepted (TLS) connection to completion.
pub async fn handle<S>(stream: S, peer: IpAddr, state: Arc<SharedState>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut reader, mut writer) = tokio::io::split(stream);

    // Single writer task; everyone writes to the socket through this channel.
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(1024);
    let bytes_sent = Arc::new(AtomicU64::new(0));
    let bytes_received = Arc::new(AtomicU64::new(0));

    let writer_sent = bytes_sent.clone();
    let writer_task = tokio::spawn(async move {
        while let Some(data) = rx.recv().await {
            if writer.write_all(&data).await.is_err() {
                break;
            }
            writer_sent.fetch_add(data.len() as u64, Ordering::Relaxed);
        }
        let _ = writer.shutdown().await;
    });

    let mut conn = Connection {
        id: Uuid::new_v4(),
        peer,
        state: state.clone(),
        tx: tx.clone(),
        bytes_received: bytes_received.clone(),
        bytes_sent: bytes_sent.clone(),
        authenticated: false,
        assigned_ip: None,
        session_db_id: None,
        last_activity: Instant::now(),
    };

    tracing::info!("New connection {} from {}", conn.id, peer);

    let mut buffer = MessageBuffer::new();
    let mut chunk = [0u8; 65536];
    let mut ticker = tokio::time::interval(KEEPALIVE_TICK);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            read = reader.read(&mut chunk) => {
                match read {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        conn.bytes_received.fetch_add(n as u64, Ordering::Relaxed);
                        conn.last_activity = Instant::now();
                        buffer.append(&chunk[..n]);
                        if !conn.drain_buffer(&mut buffer).await {
                            break;
                        }
                    }
                }
            }
            _ = ticker.tick() => {
                let idle = conn.last_activity.elapsed();
                if idle > IDLE_TIMEOUT {
                    tracing::info!("Session {}: timeout, closing", conn.id);
                    break;
                }
                if idle > IDLE_KEEPALIVE {
                    let _ = conn.tx.send(serializer::keepalive()).await;
                }
            }
        }
    }

    conn.cleanup().await;
    drop(tx);
    let _ = writer_task.await;
    tracing::info!("Session {}: closed", conn.id);
}

struct Connection {
    id: Uuid,
    peer: IpAddr,
    state: Arc<SharedState>,
    tx: mpsc::Sender<Vec<u8>>,
    bytes_received: Arc<AtomicU64>,
    bytes_sent: Arc<AtomicU64>,
    authenticated: bool,
    assigned_ip: Option<Ipv4Addr>,
    session_db_id: Option<Uuid>,
    last_activity: Instant,
}

impl Connection {
    /// Process every fully-buffered frame. Returns `false` to close the socket.
    async fn drain_buffer(&mut self, buffer: &mut MessageBuffer) -> bool {
        loop {
            match buffer.extract() {
                Ok(Some(msg)) => {
                    if !self.dispatch(msg.msg_type, msg.payload).await {
                        return false;
                    }
                }
                Ok(None) => return true,
                Err(unknown) => {
                    tracing::warn!("Session {}: unknown message type {}", self.id, unknown);
                    return true;
                }
            }
        }
    }

    async fn dispatch(&mut self, msg_type: MessageType, payload: Vec<u8>) -> bool {
        match msg_type {
            MessageType::AuthRequest => self.handle_auth(payload).await,
            MessageType::Keepalive => {
                let _ = self.tx.send(serializer::keepalive_ack()).await;
                if let Some(id) = self.session_db_id {
                    self.state.auth.update_session_activity(id).await;
                }
                true
            }
            // Explicitly handled so it is not logged as "unknown" (PR #1 fix).
            MessageType::KeepaliveAck => true,
            MessageType::Disconnect => {
                tracing::info!("Session {}: client requested disconnect", self.id);
                false
            }
            MessageType::DataPacket => {
                if self.authenticated {
                    self.state.tun.write(payload).await;
                }
                true
            }
            _ => true,
        }
    }

    async fn handle_auth(&mut self, payload: Vec<u8>) -> bool {
        if self.authenticated {
            tracing::warn!("Session {}: duplicate auth request", self.id);
            return true;
        }

        let request = match serde_json::from_slice::<crate::protocol::AuthRequest>(&payload) {
            Ok(req) => req,
            Err(e) => {
                tracing::warn!("Session {}: bad auth request: {e}", self.id);
                return false;
            }
        };

        tracing::info!("Session {}: auth request from {}", self.id, request.username);

        let result = self
            .state
            .auth
            .authenticate(&request.username, &request.password, request.platform, self.peer)
            .await;

        let auth_ok = match result {
            Ok(ok) => ok,
            Err(message) => {
                self.send_auth_response(false, Some(message), None).await;
                return false;
            }
        };

        // Allocate a tunnel IP.
        let Some(ip) = self.state.ip_pool.allocate() else {
            self.send_auth_response(false, Some("No available IP addresses".into()), None)
                .await;
            return false;
        };
        self.assigned_ip = Some(ip);

        // Persist the session row.
        match self
            .state
            .auth
            .create_session(
                auth_ok.user_id,
                &ip.to_string(),
                request.platform,
                self.peer,
                &request.client_version,
            )
            .await
        {
            Ok(session_id) => self.session_db_id = Some(session_id),
            Err(e) => tracing::error!("Session {}: failed to persist session: {e}", self.id),
        }

        self.authenticated = true;

        // Auth success + config push.
        self.send_auth_response(true, None, Some(auth_ok.session_token))
            .await;
        self.send_config(ip).await;

        // Register for packet routing.
        self.state.sessions.register(SessionHandle {
            id: self.id,
            assigned_ip: ip,
            tx: self.tx.clone(),
            bytes_sent: self.bytes_sent.clone(),
            bytes_received: self.bytes_received.clone(),
        });

        tracing::info!(
            "Session {}: user {} authenticated, assigned IP {}",
            self.id,
            request.username,
            ip
        );
        true
    }

    async fn send_auth_response(
        &self,
        success: bool,
        error_message: Option<String>,
        session_token: Option<String>,
    ) {
        let response = AuthResponse {
            success,
            error_message,
            session_token,
        };
        let _ = self.tx.send(serializer::auth_response(&response)).await;
    }

    async fn send_config(&self, ip: Ipv4Addr) {
        let cfg = &self.state.config;
        let config = ConfigPush {
            assigned_ip: ip.to_string(),
            subnet_mask: self.state.ip_pool.subnet_mask(),
            gateway: self.state.ip_pool.gateway().to_string(),
            dns: cfg.vpn.dns.clone(),
            mtu: cfg.vpn.mtu,
            keepalive_interval: 10,
        };
        let _ = self.tx.send(serializer::config_push(&config)).await;
    }

    async fn cleanup(&mut self) {
        self.state.sessions.unregister(self.id);

        if let Some(ip) = self.assigned_ip.take() {
            self.state.ip_pool.release(ip);
        }

        if let Some(id) = self.session_db_id.take() {
            let sent = self.bytes_sent.load(Ordering::Relaxed) as i64;
            let received = self.bytes_received.load(Ordering::Relaxed) as i64;
            self.state.auth.update_session_stats(id, sent, received).await;
            self.state.auth.end_session(id).await;
        }
    }
}
