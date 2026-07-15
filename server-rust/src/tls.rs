//! TLS acceptor construction from PEM certificate/key files.

use anyhow::Context;
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;

use crate::config::ServerConfig as AppServerConfig;

/// Build a [`TlsAcceptor`] from the certificate and key paths in the config.
pub fn build_acceptor(cfg: &AppServerConfig) -> anyhow::Result<TlsAcceptor> {
    let certs = load_certs(&cfg.tls_cert_path)
        .with_context(|| format!("loading certificate from {}", cfg.tls_cert_path))?;
    let key = load_key(&cfg.tls_key_path)
        .with_context(|| format!("loading private key from {}", cfg.tls_key_path))?;

    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("invalid certificate/key pair")?;

    Ok(TlsAcceptor::from(Arc::new(server_config)))
}

fn load_certs(path: &str) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let mut reader = BufReader::new(File::open(path)?);
    let certs = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?;
    anyhow::ensure!(!certs.is_empty(), "no certificates found");
    Ok(certs)
}

fn load_key(path: &str) -> anyhow::Result<PrivateKeyDer<'static>> {
    let mut reader = BufReader::new(File::open(path)?);
    rustls_pemfile::private_key(&mut reader)?.context("no private key found")
}
