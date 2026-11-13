//! Per-connection state machine.
//!
//! Combines the responsibilities of `session/vpnSession.ts` and the connection
//! handling in `index.ts`: authentication, config push, keepalive and data
//! forwarding for a single client socket.

use crate::limits::ConnGuard;
use crate::protocol::{
    serializer, AuthRequest, AuthResponse, AuthType, ConfigPush, Frame, MessageBuffer, MessageType,
};
use crate::state::SharedState;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::time::{Instant, MissedTickBehavior};
use uuid::Uuid;

use super::manager::{KillSwitch, SessionHandle, SessionInfo};

const KEEPALIVE_TICK: Duration = Duration::from_secs(10);
const IDLE_KEEPALIVE: Duration = Duration::from_secs(30);
const IDLE_TIMEOUT: Duration = Duration::from_secs(120);
/// Socket read size. A TLS record carries at most 16 KiB of plaintext, so a
/// larger buffer would only cost memory on every (possibly hostile) connection.
const READ_CHUNK: usize = 16 * 1024;
/// How long to wait for queued output to flush when closing a connection.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(5);

/// Take a freshly-accepted TCP connection through the TLS handshake and then
/// run the session on it.
///
/// The authentication deadline starts here — at TCP accept, not after the
/// handshake — so the handshake cannot be used to buy extra time, and the
/// handshake itself is additionally bounded by its own (shorter) timeout.
pub async fn serve<S>(
    stream: S,
    peer: IpAddr,
    acceptor: tokio_rustls::TlsAcceptor,
    state: Arc<SharedState>,
    guard: ConnGuard,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let limits = &state.config.limits;
    let accepted = Instant::now();
    let auth_deadline = accepted + limits.auth_timeout;
    let handshake_deadline = (accepted + limits.tls_handshake_timeout).min(auth_deadline);

    match tokio::time::timeout_at(handshake_deadline, acceptor.accept(stream)).await {
        Ok(Ok(tls_stream)) => handle(tls_stream, peer, state, guard, auth_deadline).await,
        // NLB TCP health checks open a connection and close it without a
        // ClientHello every 10s, which surfaces here as an EOF. Logging that at
        // WARN once filled the disk when a probe burst hit; keep real handshake
        // failures at WARN.
        Ok(Err(e)) if e.to_string().contains("eof") => {
            tracing::debug!("TLS handshake failed from {peer}: {e}")
        }
        Ok(Err(e)) => {
            // Anyone on the internet can produce these at will (port scanners
            // do), so they are throttled like every other pre-auth log line.
            if let Some(suppressed) = state.limits.handshake_log.should_log_now() {
                tracing::warn!(
                    "TLS handshake failed from {peer}: {e} \
                     ({suppressed} similar failures not logged)"
                );
            }
        }
        // A peer that connects and then stays silent (or stalls mid-handshake).
        Err(_) => tracing::debug!("TLS handshake from {peer} timed out"),
    }
    // `guard` is dropped on every path above, releasing the connection's slots.
}

/// Handle a single accepted (TLS) connection to completion.
///
/// `guard` holds the connection's slots in the [`ConnLimiter`](crate::limits::ConnLimiter)
/// and is released when this returns. `auth_deadline` is the absolute instant
/// by which the peer must have authenticated; it is fixed at TCP accept and
/// nothing the peer sends can move it.
pub async fn handle<S>(
    stream: S,
    peer: IpAddr,
    state: Arc<SharedState>,
    guard: ConnGuard,
    auth_deadline: Instant,
) where
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
        guard,
        auth_deadline,
        kill: Arc::new(KillSwitch::default()),
        dropped_packets: 0,
    };

    tracing::info!("New connection {} from {}", conn.id, peer);

    // Run the session until the peer goes away, or until the server ends it
    // (admin disconnect, revocation). The kill switch is raced against the
    // whole loop rather than polled inside it, so a session is closed even
    // while it is blocked writing to a client that has stopped reading.
    let kill = conn.kill.clone();
    tokio::select! {
        _ = conn.run(&mut reader, auth_deadline) => {}
        reason = kill.triggered() => {
            tracing::info!("Session {}: closed by the server ({reason})", conn.id);
        }
    }

    conn.cleanup().await;

    // Close the socket. The writer task ends once *every* sender is gone, so
    // the connection's own clone has to be dropped too — holding on to it here
    // used to leave the writer (and with it the socket) open forever after the
    // read side had finished. Anything already queued (e.g. the auth-failure
    // response) is still flushed first.
    let id = conn.id;
    let guard = conn.into_guard();
    drop(tx);
    let mut writer_task = writer_task;
    if tokio::time::timeout(CLOSE_TIMEOUT, &mut writer_task).await.is_err() {
        // The peer is not reading; do not wait on it.
        writer_task.abort();
        let _ = writer_task.await;
    }
    // Only now is the socket closed, so only now give the slot back.
    drop(guard);
    tracing::info!("Session {id}: closed");
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
    guard: ConnGuard,
    auth_deadline: Instant,
    /// Lets the session manager close this connection from outside.
    kill: Arc<KillSwitch>,
    /// Packets from this client refused by the packet filter.
    dropped_packets: u64,
}

impl Connection {
    /// Read and process frames until the connection should close.
    async fn run<R>(&mut self, reader: &mut R, auth_deadline: Instant)
    where
        R: AsyncRead + Unpin,
    {
        let state = self.state.clone();
        // Until the peer authenticates, only an auth request has to fit in a frame.
        let mut buffer = MessageBuffer::new(state.config.limits.max_preauth_frame);
        let mut chunk = vec![0u8; READ_CHUNK];
        let mut ticker = tokio::time::interval(KEEPALIVE_TICK);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                read = reader.read(&mut chunk) => {
                    match read {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            self.bytes_received.fetch_add(n as u64, Ordering::Relaxed);
                            self.last_activity = Instant::now();
                            buffer.append(&chunk[..n]);
                            if !self.drain_buffer(&mut buffer).await {
                                break;
                            }
                        }
                    }
                }
                _ = ticker.tick() => {
                    let idle = self.last_activity.elapsed();
                    if idle > IDLE_TIMEOUT {
                        tracing::info!("Session {}: timeout, closing", self.id);
                        break;
                    }
                    if idle > IDLE_KEEPALIVE {
                        let _ = self.tx.send(serializer::keepalive()).await;
                    }
                }
                // Absolute authentication deadline. Unlike the idle timeout it is
                // not refreshed by reads, so trickling bytes (or keepalives) cannot
                // hold an unauthenticated connection open.
                _ = tokio::time::sleep_until(auth_deadline), if !self.authenticated => {
                    self.guard.record_auth_failure();
                    if let Some(suppressed) = state.limits.deadline_log.should_log_now() {
                        tracing::info!(
                            "Session {}: no authentication from {} before the deadline, closing \
                             ({suppressed} similar events not logged)",
                            self.id,
                            self.peer
                        );
                    }
                    break;
                }
            }
        }
    }

    /// Tear the connection state down, keeping only its limiter slots.
    fn into_guard(self) -> ConnGuard {
        self.guard
    }

    /// Process every fully-buffered frame. Returns `false` to close the socket.
    async fn drain_buffer(&mut self, buffer: &mut MessageBuffer) -> bool {
        loop {
            let frame = match buffer.extract() {
                Ok(Some(frame)) => frame,
                Ok(None) => return true,
                Err(e) => {
                    // The announced length is over the limit. Close without
                    // reading the body: the stream cannot be resynchronised,
                    // and no legitimate client sends such a frame.
                    if !self.authenticated {
                        self.guard.record_auth_failure();
                    }
                    if let Some(suppressed) = self.state.limits.frame_log.should_log_now() {
                        tracing::warn!(
                            "Session {}: frame type 0x{:02x} from {} announces {} bytes \
                             (limit {}, authenticated: {}), closing \
                             ({suppressed} similar events not logged)",
                            self.id,
                            e.type_byte,
                            self.peer,
                            e.length,
                            e.limit,
                            self.authenticated,
                        );
                    }
                    return false;
                }
            };

            let was_authenticated = self.authenticated;
            if !self.dispatch(frame).await {
                return false;
            }
            if self.authenticated && !was_authenticated {
                // Authenticated: data packets may now be as large as a
                // tunnelled IP packet, and the connection no longer counts
                // toward its source's unauthenticated budget.
                buffer.set_max_payload(self.state.config.limits.max_frame);
                self.guard.mark_authenticated();
            }
        }
    }

    async fn dispatch(&mut self, frame: Frame) -> bool {
        let Some(msg_type) = MessageType::from_u8(frame.type_byte) else {
            tracing::warn!("Session {}: unknown message type {}", self.id, frame.type_byte);
            return true;
        };

        match msg_type {
            MessageType::AuthRequest => self.handle_auth(frame.payload).await,
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
                // `assigned_ip` is set exactly when the session is authenticated.
                if let Some(assigned) = self.assigned_ip.filter(|_| self.authenticated) {
                    match self.state.filter.check(&frame.payload, assigned) {
                        Ok(()) => self.state.tun.write(frame.payload).await,
                        Err(refusal) => {
                            self.dropped_packets += 1;
                            if let Some(suppressed) =
                                self.state.limits.packet_drop_log.should_log_now()
                            {
                                tracing::warn!(
                                    "Session {}: dropped a packet from {} ({refusal:?}; \
                                     assigned {assigned}, {} dropped on this session, \
                                     {suppressed} similar events not logged)",
                                    self.id,
                                    self.peer,
                                    self.dropped_packets,
                                );
                            }
                        }
                    }
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
                self.guard.record_auth_failure();
                tracing::warn!("Session {}: bad auth request: {e}", self.id);
                return false;
            }
        };

        // Credential verification is the part a peer can make slow (bcrypt,
        // JWKS fetch), so it runs under the same absolute deadline.
        let verification = tokio::time::timeout_at(self.auth_deadline, self.verify(&request)).await;
        let result = match verification {
            Ok(result) => result,
            Err(_) => {
                tracing::warn!(
                    "Session {}: authentication from {} did not finish before the deadline",
                    self.id,
                    self.peer
                );
                Err("Authentication timed out".to_string())
            }
        };

        let auth_ok = match result {
            Ok(ok) => ok,
            Err(message) => {
                self.guard.record_auth_failure();
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
        self.send_auth_response(true, None, Some(auth_ok.session_token.clone()))
            .await;
        self.send_config(ip).await;

        // Register for packet routing — and for revocation: from here on the
        // session can be found by user and closed from outside.
        self.state.sessions.register(SessionHandle {
            id: self.id,
            assigned_ip: ip,
            tx: self.tx.clone(),
            bytes_sent: self.bytes_sent.clone(),
            bytes_received: self.bytes_received.clone(),
            info: Arc::new(SessionInfo {
                user_id: auth_ok.user_id,
                username: auth_ok.username.clone(),
                db_id: self.session_db_id,
                sso: auth_ok.sso,
                email: auth_ok.email.clone(),
                issued_at_ms: auth_ok.issued_at_ms,
                auth_time: auth_ok.auth_time,
            }),
            kill: self.kill.clone(),
        });

        tracing::info!(
            "Session {}: user {} authenticated, assigned IP {}",
            self.id,
            auth_ok.username,
            ip
        );
        true
    }

    /// Check the credentials carried by an auth request.
    async fn verify(&self, request: &AuthRequest) -> crate::auth::AuthResult {
        match request.auth_type {
            AuthType::Password => {
                tracing::info!(
                    "Session {}: password auth request from {}",
                    self.id,
                    request.username
                );
                self.state
                    .auth
                    .authenticate(&request.username, &request.password, request.platform, self.peer)
                    .await
            }
            AuthType::Sso => {
                tracing::info!("Session {}: SSO auth request", self.id);
                self.authenticate_sso(&request).await
            }
            AuthType::Session => {
                tracing::info!("Session {}: session-token auth request", self.id);
                match request.token.as_deref() {
                    Some(token) => {
                        self.state
                            .auth
                            .authenticate_session_token(token, request.platform, self.peer)
                            .await
                    }
                    None => {
                        self.state
                            .auth
                            .log_auth_failure(
                                request.platform,
                                self.peer,
                                "Session auth request missing token",
                            )
                            .await;
                        Err("Session token is required".to_string())
                    }
                }
            }
        }
    }

    /// Verify the OIDC id_token from an `authType: "sso"` request and log the
    /// user in (JIT-provisioning on first login). SSO must be enabled
    /// (`OIDC_ISSUER` set) and the request must carry a token.
    async fn authenticate_sso(&self, request: &AuthRequest) -> crate::auth::AuthResult {
        let Some(verifier) = self.state.sso.as_ref() else {
            self.state
                .auth
                .log_auth_failure(
                    request.platform,
                    self.peer,
                    "SSO auth attempted but OIDC_ISSUER is not configured (sso)",
                )
                .await;
            return Err("SSO is not enabled on this server".to_string());
        };
        let Some(token) = request.token.as_deref() else {
            self.state
                .auth
                .log_auth_failure(request.platform, self.peer, "SSO auth request missing token (sso)")
                .await;
            return Err("SSO token is required".to_string());
        };

        let identity = match verifier.verify_id_token(token).await {
            Ok(identity) => identity,
            Err(message) => {
                self.state
                    .auth
                    .log_auth_failure(
                        request.platform,
                        self.peer,
                        &format!("SSO id_token verification failed: {message} (sso)"),
                    )
                    .await;
                return Err(message);
            }
        };

        self.state
            .auth
            .authenticate_sso(
                &identity.email,
                identity.name.as_deref(),
                identity.issued_at,
                request.platform,
                self.peer,
            )
            .await
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
        let split = self.state.split.snapshot();
        let config = ConfigPush {
            assigned_ip: ip.to_string(),
            subnet_mask: self.state.ip_pool.subnet_mask(),
            gateway: self.state.ip_pool.gateway().to_string(),
            dns: cfg.vpn.dns.clone(),
            mtu: cfg.vpn.mtu,
            keepalive_interval: 10,
            split_tunnel: split.enabled,
            // Only advertise the include lists in split mode; a full tunnel
            // leaves them empty and the client installs a default route.
            included_routes: if split.enabled { split.routes } else { Vec::new() },
            included_domains: if split.enabled { split.domains } else { Vec::new() },
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
