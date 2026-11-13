//! OpenTunnel VPN Server (Rust).
//!
//! A port of the original Node.js/TypeScript server. It speaks the same wire
//! protocol over TLS, uses the same PostgreSQL schema, and exposes the same
//! admin HTTP API, so existing clients and deployments work unchanged.

mod admin;
mod auth;
mod config;
mod db;
mod gatehouse;
mod ippool;
mod limits;
mod logging;
mod protocol;
mod router;
mod session;
mod settings;
mod split;
mod sso;
mod state;
mod tls;
mod tun;

use anyhow::Context;
use auth::AuthService;
use config::Config;
use ippool::IpPool;
use session::SessionManager;
use split::SplitPolicy;
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

    let mut config = Config::from_env();
    tracing::info!("Starting OpenTunnel VPN Server (Rust)");
    tracing::info!(
        "Environment: {}",
        if config.production { "production" } else { "development" }
    );

    // A predictable JWT secret lets anyone mint valid session tokens and
    // authenticate as any user. In production, replace the compiled-in default
    // with a random per-process secret: existing session tokens stop working
    // across restarts, but forgery becomes impossible.
    if config.production && config.jwt_secret == "change-this-in-production" {
        config.jwt_secret = format!(
            "{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        );
        tracing::warn!(
            "JWT_SECRET is unset/default in production — using a random per-process secret. \
             Session tokens will not survive restarts; set JWT_SECRET to fix this."
        );
    }

    // Database.
    let db = db::create_pool(&config.database)
        .await
        .context("database initialization failed")?;
    tracing::info!("Database connected");

    // Tunnel state lives in memory, so every sessions row predating this
    // process is stale. Clearing them keeps the fresh in-memory IP pool from
    // colliding with leftover assigned_ip rows after a restart.
    {
        let client = db.get().await.context("database initialization failed")?;
        let stale = client
            .execute("DELETE FROM sessions", &[])
            .await
            .context("failed to clear stale sessions")?;
        if stale > 0 {
            tracing::info!("Cleared {stale} stale session(s) from previous run");
        }
    }

    // Columns added since the database was created (see `auth::ensure_schema`
    // for why this is safe on a live database).
    auth::ensure_schema(&db)
        .await
        .context("failed to migrate the users table (tokens_valid_after)")?;

    // Settings the operator edits from the panel. These override the
    // environment per key, so anything never edited keeps its env value.
    // Loaded before the services below are built, since they capture config.
    let settings = Arc::new(settings::Store::new(db.clone()));
    settings
        .ensure_schema()
        .await
        .context("failed to create settings tables")?;
    let overrides = settings.load().await;
    if !overrides.is_empty() {
        let mut keys: Vec<&str> = overrides.keys().map(String::as_str).collect();
        keys.sort_unstable();
        tracing::info!("Settings loaded from database: {}", keys.join(", "));
        config.apply_overrides(&overrides);
    }

    // Core services.
    let ip_pool = Arc::new(IpPool::new(&format!("{}/24", config.vpn.subnet)));
    let sessions = Arc::new(SessionManager::new());

    // gatehouse account status: off unless both the URL and the secret are set.
    let gatehouse = Arc::new(gatehouse::GatehouseStatus::from_config(
        &config.gatehouse.status_url,
        &config.gatehouse.status_secret,
    ));
    if gatehouse.enabled() {
        tracing::info!(
            "gatehouse status checks enabled ({}), live sessions re-checked every {}s",
            config.gatehouse.status_url,
            config.gatehouse.recheck_secs
        );
    } else {
        tracing::info!(
            "gatehouse status checks disabled \
             (GATEHOUSE_STATUS_URL / GATEHOUSE_STATUS_SECRET not both set)"
        );
    }

    if !config.vpn.password_auth {
        tracing::info!("Password authentication disabled (VPN_PASSWORD_AUTH=false)");
    } else if config.production {
        tracing::warn!(
            "Password authentication is enabled. Once every user signs in through SSO, \
             set VPN_PASSWORD_AUTH=false: password accounts are not covered by SSO \
             offboarding and can simply log in again after being disconnected."
        );
    }

    let auth = Arc::new(AuthService::new(
        db.clone(),
        Arc::new(auth::PgUserStore::new(db.clone())),
        sessions.clone(),
        gatehouse.clone(),
        auth::AuthSettings {
            jwt_secret: config.jwt_secret.clone(),
            sso_session_ttl_days: config.sso.session_ttl_days,
            max_lifetime_days: config.sso.effective_max_lifetime_days(),
            sso_allowed: config.sso.allowed_domains.clone(),
            password_auth: config.vpn.password_auth,
            auth_fail_log_per_min: config.limits.auth_fail_log_per_min,
        },
    ));

    // OIDC SSO: enabled only when OIDC_ISSUER is set.
    let sso = if config.sso.issuer.is_empty() {
        tracing::info!("OIDC SSO disabled (OIDC_ISSUER not set)");
        None
    } else {
        tracing::info!(
            "OIDC SSO enabled: issuer {}, client_id {}",
            config.sso.issuer,
            config.sso.client_id
        );
        if config.sso.allowed_domains.is_empty() {
            tracing::warn!(
                "SSO_ALLOWED_DOMAINS is not set: ANY account verified by the IdP can log in \
                 and will be auto-provisioned. Set it (e.g. SSO_ALLOWED_DOMAINS=datasee.co.kr) \
                 to restrict VPN access."
            );
        }
        Some(Arc::new(sso::SsoVerifier::new(
            config.sso.issuer.clone(),
            config.sso.client_id.clone(),
            config.sso.id_token_max_age_secs,
        )))
    };

    // Admin-panel SSO uses its own audience (Google web client) when configured;
    // it shares the VPN verifier when the client ids match.
    let admin_sso: Option<Arc<sso::SsoVerifier>> = match &sso {
        None => None,
        Some(v) if config.sso.admin_client_id == config.sso.client_id => Some(v.clone()),
        Some(_) => Some(Arc::new(sso::SsoVerifier::new(
            config.sso.issuer.clone(),
            config.sso.admin_client_id.clone(),
            config.sso.id_token_max_age_secs,
        ))),
    };

    // Split-tunnel policy: resolve domains once up front, then refresh on a timer.
    let split = Arc::new(SplitPolicy::new(&config.split));
    if config.split.enabled {
        split.refresh_once().await;
        let snap = split.snapshot();
        tracing::info!(
            "Split tunnel ENABLED: {} route(s), {} domain(s)",
            snap.routes.len(),
            snap.domains.len()
        );
        split.clone().spawn_refresher();
    } else {
        tracing::info!("Split tunnel disabled (full tunnel)");
    }

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
        split: split.clone(),
        sso,
        tun: tun_handle,
        filter: router::PacketFilter::new(
            config.vpn.subnet.parse().unwrap_or(std::net::Ipv4Addr::new(10, 8, 0, 0)),
            24,
            ip_pool.gateway(),
            config.vpn.client_isolation,
        ),
        limits: limits::ConnLimiter::new(&config.limits),
    });
    tracing::info!(
        "Tunnel packet filter: source address enforced, client-to-client isolation {}",
        if config.vpn.client_isolation { "ON" } else { "OFF (VPN_CLIENT_ISOLATION=false)" }
    );
    tracing::info!(
        "Listener limits: {} connections, {} unauthenticated per source, \
         {} connects/min and {} failed auths/min per source, \
         frames {} bytes before auth / {} after, TLS handshake {}s, auth deadline {}s",
        config.limits.max_connections,
        config.limits.max_unauth_per_ip,
        config.limits.conn_rate_per_min,
        config.limits.auth_fail_per_min,
        config.limits.max_preauth_frame,
        config.limits.max_frame,
        config.limits.tls_handshake_timeout.as_secs(),
        config.limits.auth_timeout.as_secs(),
    );

    // Admin panel.
    {
        let admin_cfg = config.admin.clone();
        let admin_db = db.clone();
        let admin_split = split.clone();
        let admin_client_id = config.sso.admin_client_id.clone();
        let admin_settings = settings.clone();
        let admin_auth = auth.clone();
        let admin_sessions = sessions.clone();
        let production = config.production;
        tokio::spawn(async move {
            if let Err(e) = admin::serve(
                admin_cfg,
                admin_db,
                admin_split,
                admin_sso,
                admin_client_id,
                production,
                admin_settings,
                admin_auth,
                admin_sessions,
            )
            .await
            {
                tracing::error!("Admin server error: {e}");
            }
        });
    }

    // Periodic status log (every 60s): active sessions, pool usage, throughput.
    {
        let sessions = sessions.clone();
        let ip_pool = ip_pool.clone();
        let shared = shared.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            interval.tick().await;
            loop {
                interval.tick().await;
                let s = sessions.stats();
                let pool = ip_pool.stats();
                let drops = shared.filter.stats();
                tracing::info!(
                    "status: {} active sessions, IP pool {}/{} ({} free), \
                     {} bytes sent / {} received, client packets dropped since start: \
                     {} wrong source, {} client-to-client, {} malformed",
                    s.active_sessions,
                    pool.used,
                    pool.total,
                    pool.available,
                    s.total_bytes_sent,
                    s.total_bytes_received,
                    drops.bad_source,
                    drops.isolated,
                    drops.malformed,
                );
            }
        });
    }

    // Revalidation of live tunnels: local account state for everyone, and
    // gatehouse's account status for SSO users.
    {
        let auth = auth.clone();
        let every = Duration::from_secs(config.gatehouse.recheck_secs);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(every);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            interval.tick().await; // consume the immediate first tick
            loop {
                interval.tick().await;
                let closed = auth.revalidate_sessions().await;
                if closed > 0 {
                    tracing::info!("Revalidation closed {closed} session(s)");
                }
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

    // connection_logs retention (hourly; the first pass runs at startup).
    if config.limits.log_retention_days > 0 {
        let auth = auth.clone();
        let days = config.limits.log_retention_days;
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60 * 60));
            loop {
                interval.tick().await;
                let deleted = auth.cleanup_old_connection_logs(days).await;
                if deleted > 0 {
                    tracing::info!(
                        "Deleted {deleted} connection log rows older than {days} days"
                    );
                }
            }
        });
    } else {
        tracing::info!("connection_logs retention disabled (CONNECTION_LOG_RETENTION_DAYS=0)");
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
                    // Admission control happens before any TLS work, so a
                    // refused connection costs one accept() and one close().
                    // Dropping `stream` closes the socket.
                    let guard = match shared.limits.try_acquire(peer.ip()) {
                        Ok(guard) => guard,
                        Err(reason) => {
                            shared.limits.log_reject(reason, peer.ip());
                            continue;
                        }
                    };
                    tokio::spawn(session::serve(
                        stream,
                        peer.ip(),
                        acceptor.clone(),
                        shared.clone(),
                        guard,
                    ));
                }
                Err(e) => {
                    tracing::error!("Accept error: {e}");
                    // A persistent accept error (EMFILE fd exhaustion being the
                    // classic case) would otherwise spin this loop hot — pegging
                    // a core and writing error lines at tens of thousands per
                    // second, which is the leading suspect for the 35GB log that
                    // filled the disk on 2026-09-02. Back off before retrying.
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
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
