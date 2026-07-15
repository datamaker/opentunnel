//! Tracing/log setup. Honors the `LOG_LEVEL` environment variable (default `info`).

use tracing_subscriber::{fmt, EnvFilter};

pub fn init() {
    let level = std::env::var("LOG_LEVEL").unwrap_or_else(|_| "info".to_string());
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("opentunnel_server={level},warn")));

    fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();
}
