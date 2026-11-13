//! Listener hardening tests: pre-auth frame limit, handshake timeout and the
//! absolute authentication deadline, exercised through the real connection
//! code (and, for the `tls_*` tests, a real TLS handshake over loopback TCP).
//!
//! None of these reach the database: every connection here is closed before
//! it could authenticate, so the pool is never asked for a connection.

use super::connection::{handle, serve};
use crate::auth::AuthService;
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

    // A pool that is never connected: deadpool only dials on `get()`.
    let mut pg = deadpool_postgres::Config::new();
    pg.host = Some("127.0.0.1".into());
    pg.port = Some(1);
    pg.dbname = Some("unused".into());
    pg.user = Some("unused".into());
    let db = pg
        .create_pool(Some(deadpool_postgres::Runtime::Tokio1), tokio_postgres::NoTls)
        .unwrap();

    let (tun, _tun_rx) = crate::tun::start("test0", config.vpn.mtu, "10.8.0.1/24", true)
        .await
        .unwrap();

    Arc::new(SharedState {
        auth: Arc::new(AuthService::new(db, "test-secret".into(), 30, Vec::new(), 10)),
        ip_pool: Arc::new(IpPool::new("10.8.0.0/24")),
        sessions: Arc::new(SessionManager::new()),
        split: Arc::new(SplitPolicy::new(&config.split)),
        sso: None,
        tun,
        limits: ConnLimiter::new(&config.limits),
        config,
    })
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
