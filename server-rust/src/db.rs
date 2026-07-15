//! PostgreSQL connection pool built on `deadpool-postgres`.

use crate::config::DatabaseConfig;
use anyhow::Context;
use deadpool_postgres::{Config as PgConfig, ManagerConfig, Pool, RecyclingMethod, Runtime};
use tokio_postgres::NoTls;

pub type DbPool = Pool;

/// Create the connection pool and verify connectivity with a probe query.
pub async fn create_pool(cfg: &DatabaseConfig) -> anyhow::Result<DbPool> {
    let mut pg = PgConfig::new();
    pg.host = Some(cfg.host.clone());
    pg.port = Some(cfg.port);
    pg.dbname = Some(cfg.database.clone());
    pg.user = Some(cfg.user.clone());
    pg.password = Some(cfg.password.clone());
    pg.manager = Some(ManagerConfig {
        recycling_method: RecyclingMethod::Fast,
    });

    let pool = pg
        .create_pool(Some(Runtime::Tokio1), NoTls)
        .context("failed to build database pool")?;

    // Probe the connection so startup fails fast on misconfiguration.
    let client = pool.get().await.context("database connection failed")?;
    client
        .query_one("SELECT 1", &[])
        .await
        .context("database probe query failed")?;

    Ok(pool)
}
