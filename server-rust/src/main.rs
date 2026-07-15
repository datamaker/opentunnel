//! OpenTunnel VPN Server (Rust).
//!
//! A port of the original Node.js/TypeScript server. It speaks the same wire
//! protocol over TLS, uses the same PostgreSQL schema, and exposes the same
//! admin HTTP API, so existing clients and deployments work unchanged.

mod admin;
mod auth;
mod config;
mod db;
mod ippool;
mod logging;
mod protocol;
mod router;
mod session;
mod state;
mod tls;
mod tun;

use anyhow::Context;
use auth::AuthService;
use config::Config;
use ippool::IpPool;
use session::SessionManager;
use state::SharedState;
use std::sync::Arc;
use std::time::Duration;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    logging::init();

    // Install the ring crypto provider for rustls.
    tokio_rustls::rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let config = Config::from_env();
    tracing::info!("Starting OpenTunnel VPN Server (Rust)");
    tracing::info!(
        "Environment: {}",
        if config.production { "production" } else { "development" }
    );

    // Database.
    let db = db::create_pool(&config.database)
        .await
        .context("database initialization failed")?;
    tracing::info!("Database connected");

    // Core services.
    let ip_pool = Arc::new(IpPool::new(&format!("{}/24", config.vpn.subnet)));
    let auth = Arc::new(AuthService::new(db.clone(), config.jwt_secret.clone()));
    let sessions = Arc::new(SessionManager::new());

    // TUN device + packet router. Use the mock device outside production.
    let gateway_cidr = format!("{}/24", ip_pool.gateway());
    let (tun_handle, tun_rx) = tun::start(
        "vpn0",
        config.vpn.mtu,
        &gateway_cidr,
        !config.production,
    )
    .await
    .context("failed to start TUN device")?;
    router::spawn(tun_rx, sessions.clone());
    tracing::info!("Packet router initialized");

    // TLS acceptor.
    let acceptor = tls::build_acceptor(&config.server).context("TLS setup failed")?;

    let shared = Arc::new(SharedState {
        config: config.clone(),
        auth: auth.clone(),
        ip_pool: ip_pool.clone(),
        sessions: sessions.clone(),
        tun: tun_handle,
    });

    // Admin panel.
    {
        let admin_cfg = config.admin.clone();
        let admin_db = db.clone();
        tokio::spawn(async move {
            if let Err(e) = admin::serve(admin_cfg, admin_db).await {
                tracing::error!("Admin server error: {e}");
            }
        });
    }

    // Periodic status log (every 60s): active sessions, pool usage, throughput.
    {
        let sessions = sessions.clone();
        let ip_pool = ip_pool.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            interval.tick().await;
            loop {
                interval.tick().await;
                let s = sessions.stats();
                let pool = ip_pool.stats();
                tracing::info!(
                    "status: {} active sessions, IP pool {}/{} ({} free), \
                     {} bytes sent / {} received",
                    s.active_sessions,
                    pool.used,
                    pool.total,
                    pool.available,
                    s.total_bytes_sent,
                    s.total_bytes_received,
                );
            }
        });
    }

    // Stale-session cleanup (every 5 minutes).
    {
        let auth = auth.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(5 * 60));
            interval.tick().await; // consume the immediate first tick
            loop {
                interval.tick().await;
                let cleaned = auth.cleanup_stale_sessions(5).await;
                if cleaned > 0 {
                    tracing::info!("Cleaned up {cleaned} stale sessions");
                }
            }
        });
    }

    // Bind the VPN listener.
    let addr = format!("{}:{}", config.server.host, config.server.port);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .with_context(|| format!("failed to bind {addr}"))?;
    tracing::info!("TLS Server listening on {addr}");

    print_status(&ip_pool, &sessions, &config);
    tracing::info!("VPN Server started successfully");

    // Accept loop, with graceful shutdown on Ctrl-C / SIGTERM.
    let accept_loop = async {
        loop {
            match listener.accept().await {
                Ok((stream, peer)) => {
                    let acceptor = acceptor.clone();
                    let shared = shared.clone();
                    tokio::spawn(async move {
                        match acceptor.accept(stream).await {
                            Ok(tls_stream) => {
                                session::handle(tls_stream, peer.ip(), shared).await;
                            }
                            Err(e) => tracing::warn!("TLS handshake failed from {peer}: {e}"),
                        }
                    });
                }
                Err(e) => tracing::error!("Accept error: {e}"),
            }
        }
    };

    tokio::select! {
        _ = accept_loop => {}
        _ = shutdown_signal() => {
            tracing::info!("Shutting down VPN Server...");
            sessions.close_all();
        }
    }

    Ok(())
}

fn print_status(ip_pool: &IpPool, sessions: &SessionManager, config: &Config) {
    let ip_stats = ip_pool.stats();
    tracing::info!("=== VPN Server Status ===");
    tracing::info!("  IP Pool: {}/{} used", ip_stats.used, ip_stats.total);
    tracing::info!("  Active Sessions: {}", sessions.active_count());
    tracing::info!("  Gateway: {}", ip_pool.gateway());
    tracing::info!("  DNS: {}", config.vpn.dns.join(", "));
    tracing::info!("========================");
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c().await.ok();
    };

    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sig) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            sig.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
}
