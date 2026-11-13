//! Listener hardening tests: pre-auth frame limit, handshake timeout and the
//! absolute authentication deadline, exercised through the real connection
//! code (and, for the `tls_*` tests, a real TLS handshake over loopback TCP).
//!
//! None of these reach a database: users come from an in-memory store, and the
//! pool behind session rows and connection logs refuses every connection (the
//! server treats that like a database outage and carries on).

use super::connection::{handle, serve};
use crate::auth::testing::MemUserStore;
use crate::gatehouse::GatehouseStatus;
use crate::router::PacketFilter;
use crate::config::{Config, LimitsConfig};
use crate::ippool::IpPool;
use crate::limits::ConnLimiter;
use crate::protocol::{serializer, MessageType};
use crate::session::SessionManager;
use crate::split::SplitPolicy;
use crate::state::SharedState;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::Instant;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio_rustls::{TlsAcceptor, TlsConnector};

const PEER: &str = "203.0.113.50";

async fn test_state(limits: LimitsConfig) -> Arc<SharedState> {
    let mut config = Config::from_env();
    config.limits = limits;

    let (tun, _tun_rx) = crate::tun::start("test0", config.vpn.mtu, "10.8.0.1/24", true)
        .await
        .unwrap();

    let ip_pool = Arc::new(IpPool::new("10.8.0.0/24"));
    let sessions = Arc::new(SessionManager::new());
    // No database: the user store is in memory, and the pool behind session
    // rows and connection logs refuses every connection.
    let users = Arc::new(MemUserStore::default());
    let auth = Arc::new(crate::auth::testing::service(
        users.clone(),
        sessions.clone(),
        Arc::new(GatehouseStatus::disabled()),
        crate::auth::testing::settings(),
    ));
    USERS.with(|slot| *slot.borrow_mut() = Some(users));

    Arc::new(SharedState {
        auth,
        filter: PacketFilter::new("10.8.0.0".parse().unwrap(), 24, ip_pool.gateway(), true),
        ip_pool,
        sessions,
        split: Arc::new(SplitPolicy::new(&config.split)),
        sso: None,
        tun,
        limits: ConnLimiter::new(&config.limits),
        config,
    })
}

thread_local! {
    /// The user store behind the state most recently built on this thread
    /// (each test builds exactly one, on its own current-thread runtime).
    static USERS: std::cell::RefCell<Option<Arc<MemUserStore>>> = const { std::cell::RefCell::new(None) };
}

fn users() -> Arc<MemUserStore> {
    USERS.with(|slot| slot.borrow().clone().expect("test_state not called"))
}

/// Read until the peer closes (EOF or a transport error), returning everything
/// received and how long it took. Panics if the peer is still open at `limit`.
async fn read_until_closed<S: AsyncRead + Unpin>(stream: &mut S, limit: Duration) -> (Vec<u8>, Duration) {
    let started = Instant::now();
    let mut received = Vec::new();
    let mut chunk = [0u8; 4096];
    let outcome = tokio::time::timeout(limit, async {
        loop {
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(n) => received.extend_from_slice(&chunk[..n]),
            }
        }
    })
    .await;
    assert!(outcome.is_ok(), "connection still open after {limit:?}");
    (received, started.elapsed())
}

/// Run the plaintext session handler on one end of an in-memory pipe.
async fn spawn_session(state: &Arc<SharedState>) -> tokio::io::DuplexStream {
    let (client, server) = tokio::io::duplex(256 * 1024);
    let peer: IpAddr = PEER.parse().unwrap();
    let guard = state.limits.try_acquire(peer).unwrap();
    let deadline = Instant::now() + state.config.limits.auth_timeout;
    tokio::spawn(handle(server, peer, state.clone(), guard, deadline));
    client
}

async fn wait_for_release(state: &SharedState) {
    for _ in 0..200 {
        if state.limits.total() == 0 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("connection slot was not released");
}

#[tokio::test]
async fn huge_length_header_closes_the_connection_immediately() {
    let state = test_state(LimitsConfig {
        auth_timeout: Duration::from_secs(30),
        ..LimitsConfig::default()
    })
    .await;
    let mut client = spawn_session(&state).await;

    // Header only: an auth request claiming a 4 GiB body.
    client
        .write_all(&[MessageType::AuthRequest as u8, 0xff, 0xff, 0xff, 0xff])
        .await
        .unwrap();

    // Closed straight away — the server neither waits for the body nor for the
    // 30 s authentication deadline.
    let (received, elapsed) = read_until_closed(&mut client, Duration::from_secs(5)).await;
    assert!(received.is_empty());
    assert!(elapsed < Duration::from_secs(2), "took {elapsed:?}");

    // The body is never consumed: the server side of the pipe is gone.
    assert!(client.write_all(&vec![0u8; 1 << 20]).await.is_err());
    wait_for_release(&state).await;
}

#[tokio::test]
async fn frame_just_over_the_pre_auth_limit_is_refused() {
    let state = test_state(LimitsConfig {
        auth_timeout: Duration::from_secs(30),
        ..LimitsConfig::default()
    })
    .await;
    let limit = state.config.limits.max_preauth_frame;

    // At the limit the frame is accepted (and, being an unknown type, skipped):
    // the keepalive behind it is still answered.
    let mut client = spawn_session(&state).await;
    let mut ok = vec![0x7f];
    ok.extend_from_slice(&(limit as u32).to_be_bytes());
    ok.extend_from_slice(&vec![0u8; limit]);
    client.write_all(&ok).await.unwrap();
    client.write_all(&serializer::keepalive()).await.unwrap();
    let mut ack = [0u8; 5];
    tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut ack))
        .await
        .expect("no keepalive ack")
        .unwrap();
    assert_eq!(ack.to_vec(), serializer::keepalive_ack());
    drop(client);
    wait_for_release(&state).await;

    // One byte over, even as a data packet that fits the post-auth limit: this
    // connection has not authenticated, so it is closed.
    let mut client = spawn_session(&state).await;
    let mut header = vec![MessageType::DataPacket as u8];
    header.extend_from_slice(&((limit + 1) as u32).to_be_bytes());
    client.write_all(&header).await.unwrap();
    let (_, elapsed) = read_until_closed(&mut client, Duration::from_secs(5)).await;
    assert!(elapsed < Duration::from_secs(2), "took {elapsed:?}");
    wait_for_release(&state).await;
}

#[tokio::test]
async fn unauthenticated_connection_is_closed_at_the_deadline_despite_traffic() {
    let auth_timeout = Duration::from_millis(600);
    let state = test_state(LimitsConfig {
        auth_timeout,
        ..LimitsConfig::default()
    })
    .await;
    let client = spawn_session(&state).await;
    let (mut reader, mut writer) = tokio::io::split(client);

    // Keep the connection busy with valid frames: under the old idle-only
    // timeout this would hold it open indefinitely.
    let chatter = tokio::spawn(async move {
        while writer.write_all(&serializer::keepalive()).await.is_ok() {
            tokio::time::sleep(Duration::from_millis(40)).await;
        }
    });

    let (received, elapsed) = read_until_closed(&mut reader, Duration::from_secs(10)).await;
    chatter.abort();

    // The frames were processed (acks came back), yet the deadline held.
    assert!(received.len() >= 5 && received.len() % 5 == 0);
    assert_eq!(received[..5].to_vec(), serializer::keepalive_ack());
    assert!(elapsed >= auth_timeout - Duration::from_millis(100), "closed early: {elapsed:?}");
    assert!(elapsed < auth_timeout + Duration::from_secs(2), "closed late: {elapsed:?}");
    wait_for_release(&state).await;
}

#[tokio::test]
async fn server_side_is_torn_down_when_the_client_goes_away() {
    // Regression: the writer task used to outlive the session (the connection
    // kept a sender alive), so the socket and task of every finished
    // connection leaked.
    let state = test_state(LimitsConfig {
        auth_timeout: Duration::from_secs(30),
        ..LimitsConfig::default()
    })
    .await;
    let client = spawn_session(&state).await;
    assert_eq!(state.limits.total(), 1);
    drop(client);
    wait_for_release(&state).await;
}

// ---- Real TLS over loopback TCP -------------------------------------------

struct TlsFixture {
    addr: std::net::SocketAddr,
    connector: TlsConnector,
    state: Arc<SharedState>,
}

/// Start a one-listener server running the production `serve` path.
async fn tls_fixture(limits: LimitsConfig) -> TlsFixture {
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivateKeyDer::try_from(cert.key_pair.serialize_der()).unwrap();

    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    let mut roots = RootCertStore::empty();
    roots.add(cert_der).unwrap();
    let client_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_config));

    let state = test_state(limits).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let accept_state = state.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, peer)) = listener.accept().await else {
                break;
            };
            // Same admission step as the accept loop in `main`.
            let Ok(guard) = accept_state.limits.try_acquire(peer.ip()) else {
                continue;
            };
            tokio::spawn(serve(
                stream,
                peer.ip(),
                acceptor.clone(),
                accept_state.clone(),
                guard,
            ));
        }
    });

    TlsFixture {
        addr,
        connector,
        state,
    }
}

impl TlsFixture {
    async fn connect(&self) -> impl AsyncRead + AsyncWrite + Unpin {
        let tcp = TcpStream::connect(self.addr).await.unwrap();
        self.connector
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await
            .unwrap()
    }
}

#[tokio::test]
async fn tls_silent_tcp_peer_is_dropped_at_the_handshake_timeout() {
    let handshake = Duration::from_millis(400);
    let fx = tls_fixture(LimitsConfig {
        tls_handshake_timeout: handshake,
        auth_timeout: Duration::from_secs(30),
        ..LimitsConfig::default()
    })
    .await;

    // Connect and never send a ClientHello.
    let mut tcp = TcpStream::connect(fx.addr).await.unwrap();
    let (_, elapsed) = read_until_closed(&mut tcp, Duration::from_secs(10)).await;
    assert!(elapsed >= handshake - Duration::from_millis(100), "closed early: {elapsed:?}");
    assert!(elapsed < handshake + Duration::from_secs(2), "closed late: {elapsed:?}");
    wait_for_release(&fx.state).await;
}

#[tokio::test]
async fn tls_stalled_handshake_cannot_outlive_the_timeout() {
    let handshake = Duration::from_millis(400);
    let fx = tls_fixture(LimitsConfig {
        tls_handshake_timeout: handshake,
        auth_timeout: Duration::from_secs(30),
        ..LimitsConfig::default()
    })
    .await;

    // The first bytes of a TLS record, trickled one at a time: each byte is a
    // successful read for the server, but the handshake timeout is absolute.
    let mut tcp = TcpStream::connect(fx.addr).await.unwrap();
    let (mut reader, mut writer) = tcp.split();
    let trickle = async {
        for byte in [0x16u8, 0x03, 0x01, 0x40, 0x00].into_iter().chain(std::iter::repeat(0)) {
            if writer.write_all(&[byte]).await.is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    };
    let closed = read_until_closed(&mut reader, Duration::from_secs(10));
    tokio::pin!(trickle);
    let (_, elapsed) = tokio::select! {
        result = closed => result,
        _ = &mut trickle => panic!("server stopped accepting bytes without closing"),
    };
    assert!(elapsed < handshake + Duration::from_secs(2), "closed late: {elapsed:?}");
    wait_for_release(&fx.state).await;
}

#[tokio::test]
async fn tls_huge_length_header_closes_the_connection() {
    let fx = tls_fixture(LimitsConfig {
        auth_timeout: Duration::from_secs(30),
        ..LimitsConfig::default()
    })
    .await;

    let mut tls = fx.connect().await;
    tls.write_all(&[MessageType::AuthRequest as u8, 0xff, 0xff, 0xff, 0xff])
        .await
        .unwrap();
    tls.flush().await.unwrap();

    let (received, elapsed) = read_until_closed(&mut tls, Duration::from_secs(5)).await;
    assert!(received.is_empty());
    assert!(elapsed < Duration::from_secs(2), "took {elapsed:?}");
    wait_for_release(&fx.state).await;
}

#[tokio::test]
async fn tls_connection_that_never_authenticates_is_closed_at_the_deadline() {
    let auth_timeout = Duration::from_millis(700);
    let fx = tls_fixture(LimitsConfig {
        auth_timeout,
        ..LimitsConfig::default()
    })
    .await;

    // The clock starts at TCP accept, so it is measured from before the
    // handshake here.
    let started = Instant::now();
    let mut tls = fx.connect().await;
    tls.write_all(&serializer::keepalive()).await.unwrap();
    tls.flush().await.unwrap();

    let (received, _) = read_until_closed(&mut tls, Duration::from_secs(10)).await;
    let elapsed = started.elapsed();
    assert_eq!(received, serializer::keepalive_ack());
    assert!(elapsed >= auth_timeout - Duration::from_millis(100), "closed early: {elapsed:?}");
    assert!(elapsed < auth_timeout + Duration::from_secs(2), "closed late: {elapsed:?}");
    wait_for_release(&fx.state).await;
}

#[tokio::test]
async fn tls_listener_refuses_sources_over_their_unauthenticated_cap() {
    let fx = tls_fixture(LimitsConfig {
        max_unauth_per_ip: 2,
        auth_timeout: Duration::from_secs(30),
        ..LimitsConfig::default()
    })
    .await;

    // Two idle unauthenticated connections use up this source's budget...
    let _a = fx.connect().await;
    let _b = fx.connect().await;

    // ...so the third is closed before any TLS work is done for it.
    let mut tcp = TcpStream::connect(fx.addr).await.unwrap();
    let (_, elapsed) = read_until_closed(&mut tcp, Duration::from_secs(5)).await;
    assert!(elapsed < Duration::from_secs(2), "took {elapsed:?}");
    assert_eq!(fx.state.limits.total(), 2);
}

// ---- Authenticated sessions: disconnect, revocation, packet filter ---------

/// Read one frame: (type byte, payload).
async fn read_frame<S: AsyncRead + Unpin>(stream: &mut S) -> (u8, Vec<u8>) {
    let mut header = [0u8; 5];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut header))
        .await
        .expect("no frame from the server")
        .unwrap();
    let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).await.unwrap();
    (header[0], payload)
}

/// Authenticate over the wire. Returns the auth response and, on success,
/// the pushed config.
async fn authenticate<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut S,
    request: serde_json::Value,
) -> (serde_json::Value, Option<serde_json::Value>) {
    let body = serde_json::to_vec(&request).unwrap();
    client
        .write_all(&serializer::serialize(MessageType::AuthRequest, &body))
        .await
        .unwrap();
    let (kind, payload) = read_frame(client).await;
    assert_eq!(kind, MessageType::AuthResponse as u8);
    let response: serde_json::Value = serde_json::from_slice(&payload).unwrap();
    if response["success"] != true {
        return (response, None);
    }
    let (kind, payload) = read_frame(client).await;
    assert_eq!(kind, MessageType::ConfigPush as u8);
    (response, Some(serde_json::from_slice(&payload).unwrap()))
}

fn password_login(username: &str, password: &str) -> serde_json::Value {
    serde_json::json!({
        "username": username, "password": password,
        "platform": "macos", "clientVersion": "1.0.0",
    })
}

fn session_login(token: &str) -> serde_json::Value {
    serde_json::json!({
        "authType": "session", "token": token,
        "platform": "windows", "clientVersion": "1.0.0",
    })
}

async fn authenticated_state() -> Arc<SharedState> {
    test_state(LimitsConfig {
        auth_timeout: Duration::from_secs(30),
        ..LimitsConfig::default()
    })
    .await
}

#[tokio::test]
async fn existing_clients_authenticate_exactly_as_before() {
    // The wire format is untouched: a password login without `authType`, and a
    // reconnect with the returned session token, both yield a tunnel.
    let state = authenticated_state().await;
    users().add("alice", Some("correct horse"));

    let mut first = spawn_session(&state).await;
    let (response, config) = authenticate(&mut first, password_login("alice", "correct horse")).await;
    assert_eq!(response["success"], true);
    assert!(response.get("errorMessage").is_none());
    let token = response["sessionToken"].as_str().unwrap().to_string();
    assert_eq!(config.unwrap()["assignedIP"], "10.8.0.2");

    let mut second = spawn_session(&state).await;
    let (response, config) = authenticate(&mut second, session_login(&token)).await;
    assert_eq!(response["success"], true);
    assert!(response["sessionToken"].as_str().is_some());
    assert_eq!(config.unwrap()["assignedIP"], "10.8.0.3");
    assert_eq!(state.sessions.active_count(), 2);
}

#[tokio::test]
async fn killing_a_users_sessions_closes_the_sockets_and_frees_the_addresses() {
    let state = authenticated_state().await;
    let alice = users().add("alice", Some("correct horse"));
    users().add("bob", Some("battery staple"));

    let mut laptop = spawn_session(&state).await;
    let mut phone = spawn_session(&state).await;
    let mut bob = spawn_session(&state).await;
    authenticate(&mut laptop, password_login("alice", "correct horse")).await;
    authenticate(&mut phone, password_login("alice", "correct horse")).await;
    authenticate(&mut bob, password_login("bob", "battery staple")).await;
    assert_eq!(state.sessions.active_count(), 3);
    assert_eq!(state.ip_pool.stats().used, 4); // gateway + three clients
    assert_eq!(state.sessions.live_counts()[&alice.id], 2);

    // What the admin panel's disconnect / deactivate / delete all end in.
    let closed = state.sessions.kill_user(alice.id, "disconnected by an admin");
    assert_eq!(closed.len(), 2);
    // Out of the routing table at once...
    assert_eq!(state.sessions.active_count(), 1);
    assert!(!state.sessions.route_to_client("10.8.0.2".parse().unwrap(), &[0x45; 20]));

    // ...and the sockets really close, promptly, without the client's help.
    let (_, elapsed) = read_until_closed(&mut laptop, Duration::from_secs(5)).await;
    assert!(elapsed < Duration::from_secs(2), "took {elapsed:?}");
    read_until_closed(&mut phone, Duration::from_secs(5)).await;

    // Their addresses and connection slots are released; bob is untouched.
    for _ in 0..200 {
        if state.ip_pool.stats().used == 2 && state.limits.total() == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(state.ip_pool.stats().used, 2);
    assert_eq!(state.limits.total(), 1);
    bob.write_all(&serializer::keepalive()).await.unwrap();
    let (kind, _) = read_frame(&mut bob).await;
    assert_eq!(kind, MessageType::KeepaliveAck as u8);

    // The freed address is handed out again.
    let mut again = spawn_session(&state).await;
    let (_, config) = authenticate(&mut again, password_login("alice", "correct horse")).await;
    assert_eq!(config.unwrap()["assignedIP"], "10.8.0.2");
}

#[tokio::test]
async fn a_session_blocked_on_a_stalled_client_is_still_closed() {
    // The client authenticates and then stops reading while traffic for it
    // keeps arriving, until the server-side write is stuck. The kill must not
    // wait for that write.
    let state = authenticated_state().await;
    let alice = users().add("alice", Some("correct horse"));
    let (mut client, server) = tokio::io::duplex(1024);
    let peer: IpAddr = PEER.parse().unwrap();
    let guard = state.limits.try_acquire(peer).unwrap();
    let deadline = Instant::now() + state.config.limits.auth_timeout;
    tokio::spawn(handle(server, peer, state.clone(), guard, deadline));
    authenticate(&mut client, password_login("alice", "correct horse")).await;

    let ip = "10.8.0.2".parse().unwrap();
    for _ in 0..64 {
        state.sessions.route_to_client(ip, &[0x45; 1200]);
    }
    tokio::time::sleep(Duration::from_millis(50)).await;

    assert_eq!(state.sessions.kill_user(alice.id, "test").len(), 1);
    for _ in 0..200 {
        if state.ip_pool.stats().used == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    // The address is free again although the client never read a byte more.
    assert_eq!(state.ip_pool.stats().used, 1);
    assert_eq!(state.sessions.active_count(), 0);
}

#[tokio::test]
async fn revoked_user_is_disconnected_and_cannot_reconnect_with_the_old_token() {
    let state = authenticated_state().await;
    let user = users().add("kim@datasee.co.kr", None);
    let now_ms = chrono::Utc::now().timestamp_millis();
    let token = state.auth.token_for_test(&user, true, now_ms - 60_000, now_ms / 1000 - 3600);

    let mut client = spawn_session(&state).await;
    let (response, _) = authenticate(&mut client, session_login(&token)).await;
    assert_eq!(response["success"], true);
    let renewed = response["sessionToken"].as_str().unwrap().to_string();

    // "모든 기기에서 로그아웃".
    let closed = state.auth.revoke_user(user.id, "logged out everywhere by an admin").await;
    assert_eq!(closed.unwrap().len(), 1);
    read_until_closed(&mut client, Duration::from_secs(5)).await;

    // The client's automatic reconnect — with either token — is turned away,
    // which is what sends it back to the SSO sign-in screen.
    for stale in [&token, &renewed] {
        let mut retry = spawn_session(&state).await;
        let (response, config) = authenticate(&mut retry, session_login(stale)).await;
        assert_eq!(response["success"], false);
        assert_eq!(response["errorMessage"], "Invalid or expired session token");
        assert!(config.is_none());
        read_until_closed(&mut retry, Duration::from_secs(5)).await;
    }
    assert_eq!(state.sessions.active_count(), 0);
}

#[tokio::test]
async fn revalidation_closes_a_live_tunnel_whose_account_was_deactivated() {
    let state = authenticated_state().await;
    let user = users().add("alice", Some("correct horse"));
    let mut client = spawn_session(&state).await;
    authenticate(&mut client, password_login("alice", "correct horse")).await;

    assert_eq!(state.auth.revalidate_sessions().await, 0);
    users().update(user.id, |u| u.is_active = false);
    assert_eq!(state.auth.revalidate_sessions().await, 1);
    read_until_closed(&mut client, Duration::from_secs(5)).await;
    wait_for_release(&state).await;
}

#[tokio::test]
async fn password_login_failures_look_the_same_on_the_wire() {
    let state = authenticated_state().await;
    users().add("alice", Some("correct horse"));
    let bob = users().add("bob", Some("battery staple"));
    users().update(bob.id, |u| u.is_active = false);

    let mut answers = Vec::new();
    for (username, password) in [("alice", "wrong"), ("nobody", "wrong"), ("bob", "battery staple")] {
        let mut client = spawn_session(&state).await;
        let (response, _) = authenticate(&mut client, password_login(username, password)).await;
        read_until_closed(&mut client, Duration::from_secs(5)).await;
        answers.push(response.to_string());
    }
    assert_eq!(answers[0], r#"{"errorMessage":"Invalid credentials","success":false}"#);
    assert_eq!(answers[1], answers[0]);
    assert_eq!(answers[2], answers[0]);
}

#[tokio::test]
async fn packets_with_a_forged_source_or_for_another_client_are_dropped() {
    use crate::router::DropStats;
    use std::net::Ipv4Addr;

    fn packet(source: Ipv4Addr, dest: Ipv4Addr) -> Vec<u8> {
        let mut packet = vec![0u8; 40];
        packet[0] = 0x45;
        packet[12..16].copy_from_slice(&source.octets());
        packet[16..20].copy_from_slice(&dest.octets());
        serializer::data_packet(&packet)
    }
    let me = Ipv4Addr::new(10, 8, 0, 2);
    let other = Ipv4Addr::new(10, 8, 0, 3);
    let internal = Ipv4Addr::new(11, 0, 1, 21);

    let state = authenticated_state().await;
    users().add("alice", Some("correct horse"));
    let mut client = spawn_session(&state).await;

    // Before authentication nothing is forwarded or even inspected.
    client.write_all(&packet(other, internal)).await.unwrap();

    let (_, config) = authenticate(&mut client, password_login("alice", "correct horse")).await;
    assert_eq!(config.unwrap()["assignedIP"], me.to_string());

    client.write_all(&packet(me, internal)).await.unwrap(); // fine
    client.write_all(&packet(other, internal)).await.unwrap(); // forged source
    client.write_all(&packet(internal, me)).await.unwrap(); // forged source
    client.write_all(&packet(me, other)).await.unwrap(); // client-to-client
    client.write_all(&packet(me, Ipv4Addr::new(10, 8, 0, 1))).await.unwrap(); // gateway: fine
    client.write_all(&serializer::data_packet(&[0x60; 40])).await.unwrap(); // IPv6

    // Frames are handled in order, so once the keepalive is answered every
    // packet before it has been through the filter. The session stays up:
    // a bad packet is dropped, not punished.
    client.write_all(&serializer::keepalive()).await.unwrap();
    let (kind, _) = read_frame(&mut client).await;
    assert_eq!(kind, MessageType::KeepaliveAck as u8);

    assert_eq!(
        state.filter.stats(),
        DropStats { malformed: 1, bad_source: 2, isolated: 1 }
    );
}
