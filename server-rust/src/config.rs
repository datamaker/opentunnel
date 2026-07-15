//! Runtime configuration, loaded from environment variables.
//!
//! Mirrors the layout of the original TypeScript `config/config.ts` so that the
//! same `.env` files and Docker environment work unchanged.

use std::env;

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
}

#[derive(Debug, Clone)]
pub struct AdminConfig {
    pub port: u16,
    pub password: String,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub vpn: VpnConfig,
    pub admin: AdminConfig,
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

impl Config {
    /// Build a [`Config`] from the process environment, applying the same
    /// defaults as the original server.
    pub fn from_env() -> Self {
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
                mtu: env_parse("VPN_MTU", 1400),
            },
            admin: AdminConfig {
                port: env_parse("ADMIN_PORT", 8080),
                password: env_or("ADMIN_PASSWORD", "admin123"),
            },
            jwt_secret: env_or("JWT_SECRET", "change-this-in-production"),
            production: env_or("NODE_ENV", "development") == "production",
        }
    }
}
