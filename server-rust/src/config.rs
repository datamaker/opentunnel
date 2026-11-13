//! Runtime configuration, loaded from environment variables.
//!
//! Mirrors the layout of the original TypeScript `config/config.ts` so that the
//! same `.env` files and Docker environment work unchanged.

use std::env;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub port: u16,
    pub host: String,
    pub tls_cert_path: String,
    pub tls_key_path: String,
    #[allow(dead_code)] // optional CA, loaded by clients; retained for config parity
    pub tls_ca_path: String,
}

#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    pub host: String,
    pub port: u16,
    pub database: String,
    pub user: String,
    pub password: String,
}

#[derive(Debug, Clone)]
pub struct VpnConfig {
    pub subnet: String,
    // netmask/gateway are derived from the IP pool at runtime, but kept here for
    // config parity with the original server and future overrides.
    #[allow(dead_code)]
    pub netmask: String,
    #[allow(dead_code)]
    pub gateway: String,
    pub dns: Vec<String>,
    pub mtu: u32,
    /// Drop packets one client addresses to another client's tunnel IP
    /// (`VPN_CLIENT_ISOLATION`, default on).
    pub client_isolation: bool,
    /// Accept `authType: "password"` logins (`VPN_PASSWORD_AUTH`, default on
    /// for backwards compatibility; production should turn it off once every
    /// user signs in through SSO).
    pub password_auth: bool,
}

#[derive(Debug, Clone)]
pub struct AdminConfig {
    pub port: u16,
    pub password: String,
    /// Emails (or `@domain` / bare-domain entries) allowed to log into the
    /// admin panel via SSO (`ADMIN_SSO_EMAILS`). Empty = admin SSO disabled —
    /// panel admin rights are too sensitive for an implicit allow-all.
    pub sso_emails: Vec<String>,
    /// CIDRs of reverse proxies whose authentication headers may be believed
    /// (`ADMIN_TRUSTED_PROXIES`). Empty = never believe them, which is the only
    /// safe default: the header is trivially forged by anyone who can reach the
    /// admin port directly.
    pub trusted_proxies: Vec<String>,
}

/// Split-tunnel (destination-based routing) policy.
///
/// When `enabled`, the server pushes an "include" list to the client: only the
/// listed IP CIDRs and domains should be routed through the tunnel; everything
/// else uses the client's normal connection. When disabled, the client does a
/// full tunnel (default route), preserving the original behavior.
#[derive(Debug, Clone)]
pub struct SplitConfig {
    pub enabled: bool,
    /// Static IP CIDRs to route through the tunnel (e.g. `10.0.0.0/8`).
    pub routes: Vec<String>,
    /// Domains to route through the tunnel; resolved to IPs server-side.
    pub domains: Vec<String>,
    /// How often to re-resolve `domains`, in seconds.
    pub refresh_secs: u64,
}

/// OIDC single sign-on settings.
///
/// SSO is enabled when `issuer` is non-empty: `authType: "sso"` auth requests
/// carry an id_token that is verified against the issuer's JWKS. When `issuer`
/// is empty, SSO auth is rejected (session-token reconnects still work — they
/// only need `JWT_SECRET`).
#[derive(Debug, Clone)]
pub struct SsoConfig {
    /// OIDC issuer URL (`OIDC_ISSUER`). Empty = SSO disabled.
    pub issuer: String,
    /// Expected `aud` claim of the id_token (`OIDC_CLIENT_ID`).
    pub client_id: String,
    /// Expected `aud` for admin-panel SSO logins (`OIDC_ADMIN_CLIENT_ID`).
    /// Google Identity Services on the web needs a Web-type OAuth client,
    /// which may differ from the device-flow client. Defaults to `client_id`.
    pub admin_client_id: String,
    /// Lifetime of session JWTs minted for SSO logins, in days
    /// (`SSO_SESSION_TTL_DAYS`).
    pub session_ttl_days: i64,
    /// Emails or domains allowed to authenticate via SSO
    /// (`SSO_ALLOWED_DOMAINS`, e.g. `datasee.co.kr,contractor@gmail.com`).
    /// Empty = any verified account accepted (a startup warning is logged) —
    /// kept for backwards compatibility with existing deployments.
    pub allowed_domains: Vec<String>,
    /// How long after a real login a session token may keep being renewed, in
    /// days (`SSO_SESSION_MAX_LIFETIME_DAYS`). `None` = same as
    /// `session_ttl_days`, i.e. a real SSO login at least that often.
    pub max_lifetime_days: Option<i64>,
    /// Oldest id_token accepted, by its `iat`, in seconds
    /// (`SSO_ID_TOKEN_MAX_AGE_SECS`).
    pub id_token_max_age_secs: i64,
}

impl SsoConfig {
    /// Absolute session lifetime since the last real login, in days.
    pub fn effective_max_lifetime_days(&self) -> i64 {
        self.max_lifetime_days.unwrap_or(self.session_ttl_days)
    }
}

/// gatehouse account-status lookups (revocation propagation). Disabled unless
/// both the URL and the secret are set.
#[derive(Debug, Clone)]
pub struct GatehouseConfig {
    /// Base URL (`GATEHOUSE_STATUS_URL`, e.g. `https://auth.datasee.co.kr`).
    pub status_url: String,
    /// Shared secret sent as `X-Gatehouse-Secret` (`GATEHOUSE_STATUS_SECRET`).
    pub status_secret: String,
    /// How often live sessions are re-checked, in seconds
    /// (`GATEHOUSE_RECHECK_SECS`). This pass also re-checks the local account
    /// state, so it runs even when gatehouse lookups are disabled.
    pub recheck_secs: u64,
}

/// Resource limits for the public VPN listener (see [`crate::limits`]).
///
/// Everything here bounds what a peer can make the server do *before* it has
/// authenticated. A count/rate of 0 disables that particular limit.
#[derive(Debug, Clone)]
pub struct LimitsConfig {
    /// Largest frame payload accepted before authentication
    /// (`VPN_MAX_PREAUTH_FRAME_BYTES`). Only has to fit an auth request.
    pub max_preauth_frame: usize,
    /// Largest frame payload accepted after authentication
    /// (`VPN_MAX_FRAME_BYTES`). Has to fit one tunnelled IP packet.
    pub max_frame: usize,
    /// Time allowed for the TLS handshake (`VPN_TLS_HANDSHAKE_TIMEOUT_SECS`).
    pub tls_handshake_timeout: Duration,
    /// Absolute time from TCP accept to successful authentication
    /// (`VPN_AUTH_TIMEOUT_SECS`). Not extended by anything the peer sends.
    pub auth_timeout: Duration,
    /// Concurrent connections, authenticated or not (`VPN_MAX_CONNECTIONS`).
    pub max_connections: usize,
    /// Concurrent unauthenticated connections per source address
    /// (`VPN_MAX_UNAUTH_PER_IP`).
    pub max_unauth_per_ip: u32,
    /// New connections per source per minute, with a burst of the same size
    /// (`VPN_CONN_RATE_PER_MIN`).
    pub conn_rate_per_min: u32,
    /// Failed authentications per source per minute, with a burst of the same
    /// size; while exhausted, new connections from the source are refused
    /// (`VPN_AUTH_FAIL_PER_MIN`).
    pub auth_fail_per_min: u32,
    /// `auth_fail` rows written to `connection_logs` per source per minute
    /// (`VPN_AUTH_FAIL_LOG_PER_MIN`); the rest are counted, not stored.
    pub auth_fail_log_per_min: u32,
    /// Sources exempt from the per-source limits (`VPN_LIMIT_EXEMPT_CIDRS`).
    /// They still count toward `max_connections`.
    pub exempt_cidrs: Vec<String>,
    /// Days of `connection_logs` to keep (`CONNECTION_LOG_RETENTION_DAYS`).
    /// 0 keeps everything.
    pub log_retention_days: u32,
}

/// Smallest frame limits that can still work: an auth request needs room for a
/// JWT, and the data phase needs room for one IP packet at the tunnel MTU.
const MIN_PREAUTH_FRAME: usize = 1024;
/// Largest IPv4 packet. Every client refuses to send or receive more than this
/// per frame, so nothing larger is ever legitimate.
pub const MAX_IP_PACKET: usize = 65_535;

impl Default for LimitsConfig {
    fn default() -> Self {
        LimitsConfig {
            max_preauth_frame: 16 * 1024,
            max_frame: MAX_IP_PACKET,
            tls_handshake_timeout: Duration::from_secs(10),
            auth_timeout: Duration::from_secs(15),
            max_connections: 256,
            max_unauth_per_ip: 32,
            conn_rate_per_min: 120,
            auth_fail_per_min: 30,
            auth_fail_log_per_min: 10,
            exempt_cidrs: Vec::new(),
            log_retention_days: 90,
        }
    }
}

impl LimitsConfig {
    fn from_env(mtu: u32) -> Self {
        let d = LimitsConfig::default();
        let mut limits = LimitsConfig {
            max_preauth_frame: env_parse("VPN_MAX_PREAUTH_FRAME_BYTES", d.max_preauth_frame),
            max_frame: env_parse("VPN_MAX_FRAME_BYTES", d.max_frame),
            tls_handshake_timeout: Duration::from_secs(env_parse(
                "VPN_TLS_HANDSHAKE_TIMEOUT_SECS",
                d.tls_handshake_timeout.as_secs(),
            )),
            auth_timeout: Duration::from_secs(env_parse(
                "VPN_AUTH_TIMEOUT_SECS",
                d.auth_timeout.as_secs(),
            )),
            max_connections: env_parse("VPN_MAX_CONNECTIONS", d.max_connections),
            max_unauth_per_ip: env_parse("VPN_MAX_UNAUTH_PER_IP", d.max_unauth_per_ip),
            conn_rate_per_min: env_parse("VPN_CONN_RATE_PER_MIN", d.conn_rate_per_min),
            auth_fail_per_min: env_parse("VPN_AUTH_FAIL_PER_MIN", d.auth_fail_per_min),
            auth_fail_log_per_min: env_parse(
                "VPN_AUTH_FAIL_LOG_PER_MIN",
                d.auth_fail_log_per_min,
            ),
            exempt_cidrs: env_csv("VPN_LIMIT_EXEMPT_CIDRS"),
            log_retention_days: env_parse("CONNECTION_LOG_RETENTION_DAYS", d.log_retention_days),
        };
        limits.sanitize(mtu);
        limits
    }

    /// Clamp values that would break the server outright. Unlike the counts and
    /// rates, the frame limits and timeouts cannot be switched off with 0: an
    /// unbounded frame or an endless handshake is the hole these exist to close.
    pub fn sanitize(&mut self, mtu: u32) {
        let d = LimitsConfig::default();
        if self.max_preauth_frame < MIN_PREAUTH_FRAME {
            tracing::warn!(
                "VPN_MAX_PREAUTH_FRAME_BYTES={} is too small for an auth request, using {}",
                self.max_preauth_frame,
                d.max_preauth_frame
            );
            self.max_preauth_frame = d.max_preauth_frame;
        }
        // The pre-auth limit never exceeds the IP maximum either: it exists to
        // be the *smaller* of the two.
        self.max_preauth_frame = self.max_preauth_frame.min(MAX_IP_PACKET);

        let min_frame = (mtu as usize).max(self.max_preauth_frame);
        if self.max_frame < min_frame {
            tracing::warn!(
                "VPN_MAX_FRAME_BYTES={} is below the tunnel MTU / pre-auth limit, using {}",
                self.max_frame,
                min_frame
            );
            self.max_frame = min_frame;
        }
        self.max_frame = self.max_frame.min(MAX_IP_PACKET);

        if self.tls_handshake_timeout.is_zero() {
            self.tls_handshake_timeout = d.tls_handshake_timeout;
        }
        if self.auth_timeout.is_zero() {
            self.auth_timeout = d.auth_timeout;
        }
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub vpn: VpnConfig,
    pub admin: AdminConfig,
    pub split: SplitConfig,
    pub sso: SsoConfig,
    pub gatehouse: GatehouseConfig,
    pub limits: LimitsConfig,
    pub jwt_secret: String,
    pub production: bool,
}

fn env_or(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
}

fn env_parse<T: std::str::FromStr>(key: &str, default: T) -> T {
    env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Parse a comma-separated env var into a trimmed, non-empty list.
fn env_csv(key: &str) -> Vec<String> {
    env::var(key)
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn env_bool(key: &str, default: bool) -> bool {
    match env::var(key) {
        Ok(v) => matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"),
        Err(_) => default,
    }
}

impl Config {
    /// Build a [`Config`] from the process environment, applying the same
    /// defaults as the original server.
    /// Overlay database-stored settings on top of the environment.
    ///
    /// Per key, not wholesale: anything the operator has never edited keeps its
    /// environment value, so an existing deployment behaves identically until
    /// someone changes something in the panel. Unparseable values are logged
    /// and skipped rather than taking the server down — the environment value
    /// is always a working fallback.
    pub fn apply_overrides(&mut self, overrides: &std::collections::HashMap<String, String>) {
        fn csv(raw: &str) -> Vec<String> {
            raw.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        }

        for (key, raw) in overrides {
            let value = raw.trim();
            match key.as_str() {
                "SPLIT_TUNNEL" => self.split.enabled = value == "true",
                "SPLIT_INCLUDE_ROUTES" => self.split.routes = csv(value),
                "SPLIT_INCLUDE_DOMAINS" => self.split.domains = csv(value),
                "SPLIT_DNS_REFRESH_SECS" => match value.parse() {
                    Ok(v) => self.split.refresh_secs = v,
                    Err(_) => tracing::warn!("settings: {key}={value:?} is not a number, keeping env"),
                },
                "VPN_DNS" => self.vpn.dns = csv(value),
                "VPN_MTU" => match value.parse() {
                    Ok(v) => {
                        self.vpn.mtu = v;
                        // Keep the data-phase frame limit at or above the MTU.
                        self.limits.sanitize(v);
                    }
                    Err(_) => tracing::warn!("settings: {key}={value:?} is not a number, keeping env"),
                },
                "SSO_ALLOWED_DOMAINS" => self.sso.allowed_domains = csv(value),
                "SSO_SESSION_TTL_DAYS" => match value.parse() {
                    Ok(v) => self.sso.session_ttl_days = v,
                    Err(_) => tracing::warn!("settings: {key}={value:?} is not a number, keeping env"),
                },
                "ADMIN_SSO_EMAILS" => self.admin.sso_emails = csv(value),
                other => tracing::warn!("settings: ignoring unknown key {other:?}"),
            }
        }
    }

    pub fn from_env() -> Self {
        let mtu: u32 = env_parse("VPN_MTU", 1400);
        Config {
            server: ServerConfig {
                // `PORT` is set by the Dockerfile; `VPN_PORT` by `.env.example`.
                port: env::var("VPN_PORT")
                    .or_else(|_| env::var("PORT"))
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(1194),
                host: env_or("VPN_HOST", "0.0.0.0"),
                tls_cert_path: env_or("TLS_CERT_PATH", "./certs/server.crt"),
                tls_key_path: env_or("TLS_KEY_PATH", "./certs/server.key"),
                tls_ca_path: env_or("TLS_CA_PATH", "./certs/ca.crt"),
            },
            database: DatabaseConfig {
                host: env_or("DB_HOST", "localhost"),
                port: env_parse("DB_PORT", 5432),
                database: env_or("DB_NAME", "vpn"),
                user: env_or("DB_USER", "vpn"),
                password: env_or("DB_PASSWORD", "vpn_password"),
            },
            vpn: VpnConfig {
                subnet: env_or("VPN_SUBNET", "10.8.0.0"),
                netmask: env_or("VPN_NETMASK", "255.255.255.0"),
                gateway: env_or("VPN_GATEWAY", "10.8.0.1"),
                dns: env::var("VPN_DNS")
                    .or_else(|_| env::var("DNS_SERVERS"))
                    .unwrap_or_else(|_| "8.8.8.8,8.8.4.4".to_string())
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect(),
                mtu,
                client_isolation: env_bool("VPN_CLIENT_ISOLATION", true),
                password_auth: env_bool("VPN_PASSWORD_AUTH", true),
            },
            admin: AdminConfig {
                port: env_parse("ADMIN_PORT", 8080),
                password: env_or("ADMIN_PASSWORD", "admin123"),
                sso_emails: env_csv("ADMIN_SSO_EMAILS"),
                trusted_proxies: env_csv("ADMIN_TRUSTED_PROXIES"),
            },
            split: SplitConfig {
                enabled: env_bool("SPLIT_TUNNEL", false),
                routes: env_csv("SPLIT_INCLUDE_ROUTES"),
                domains: env_csv("SPLIT_INCLUDE_DOMAINS"),
                refresh_secs: env_parse("SPLIT_DNS_REFRESH_SECS", 300),
            },
            sso: {
                let client_id = env_or("OIDC_CLIENT_ID", "opentunnel");
                SsoConfig {
                    issuer: env_or("OIDC_ISSUER", "")
                        .trim()
                        .trim_end_matches('/')
                        .to_string(),
                    admin_client_id: env_or("OIDC_ADMIN_CLIENT_ID", &client_id),
                    client_id,
                    session_ttl_days: env_parse("SSO_SESSION_TTL_DAYS", 30),
                    allowed_domains: env_csv("SSO_ALLOWED_DOMAINS"),
                    max_lifetime_days: env::var("SSO_SESSION_MAX_LIFETIME_DAYS")
                        .ok()
                        .and_then(|v| v.trim().parse::<i64>().ok())
                        .filter(|days| *days > 0),
                    id_token_max_age_secs: env_parse("SSO_ID_TOKEN_MAX_AGE_SECS", 600i64).max(1),
                }
            },
            gatehouse: GatehouseConfig {
                status_url: env_or("GATEHOUSE_STATUS_URL", "")
                    .trim()
                    .trim_end_matches('/')
                    .to_string(),
                status_secret: env_or("GATEHOUSE_STATUS_SECRET", "").trim().to_string(),
                recheck_secs: env_parse("GATEHOUSE_RECHECK_SECS", 300u64).max(10),
            },
            limits: LimitsConfig::from_env(mtu),
            jwt_secret: env_or("JWT_SECRET", "change-this-in-production"),
            production: env_or("NODE_ENV", "development") == "production",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_limits_are_clamped_to_workable_values() {
        let mut limits = LimitsConfig {
            max_preauth_frame: 10,
            max_frame: 100,
            tls_handshake_timeout: Duration::ZERO,
            auth_timeout: Duration::ZERO,
            ..LimitsConfig::default()
        };
        limits.sanitize(1400);
        let d = LimitsConfig::default();
        assert_eq!(limits.max_preauth_frame, d.max_preauth_frame);
        // Never below the pre-auth limit or the MTU.
        assert_eq!(limits.max_frame, d.max_preauth_frame);
        assert_eq!(limits.tls_handshake_timeout, d.tls_handshake_timeout);
        assert_eq!(limits.auth_timeout, d.auth_timeout);

        let mut jumbo = LimitsConfig {
            max_preauth_frame: 2048,
            max_frame: 4096,
            ..LimitsConfig::default()
        };
        jumbo.sanitize(9000);
        assert_eq!(jumbo.max_frame, 9000);

        // Nothing may exceed the largest IP packet.
        let mut huge = LimitsConfig {
            max_preauth_frame: usize::MAX,
            max_frame: usize::MAX,
            ..LimitsConfig::default()
        };
        huge.sanitize(1400);
        assert_eq!(huge.max_preauth_frame, MAX_IP_PACKET);
        assert_eq!(huge.max_frame, MAX_IP_PACKET);
    }

    #[test]
    fn defaults_survive_sanitize_unchanged() {
        let mut limits = LimitsConfig::default();
        limits.sanitize(1400);
        assert_eq!(limits.max_preauth_frame, 16 * 1024);
        assert_eq!(limits.max_frame, MAX_IP_PACKET);
    }
}
