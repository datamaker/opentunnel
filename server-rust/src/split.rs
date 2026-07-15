//! Split-tunnel (destination-based routing) policy.
//!
//! Holds the set of IP CIDRs and domains that should be routed through the
//! tunnel, resolves the domains to IPv4 addresses periodically, and exposes the
//! effective route list that gets pushed to clients in the config message.
//!
//! Note: the server does not itself decide which packets a client tunnels — the
//! client applies this policy to its own routing table. The server's job is to
//! define the policy, resolve domains to concrete routes, and push both.

use crate::config::SplitConfig;
use std::collections::BTreeSet;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

struct Inner {
    enabled: bool,
    routes: Vec<String>,
    domains: Vec<String>,
    /// `/32` CIDRs resolved from `domains`.
    resolved: Vec<String>,
}

pub struct SplitPolicy {
    inner: Mutex<Inner>,
    refresh: Duration,
}

/// A snapshot of the effective policy, for pushing to clients or the admin API.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SplitSnapshot {
    pub enabled: bool,
    pub domains: Vec<String>,
    /// Static routes plus resolved domain IPs, deduplicated and sorted.
    pub routes: Vec<String>,
}

impl SplitPolicy {
    pub fn new(cfg: &SplitConfig) -> Self {
        SplitPolicy {
            inner: Mutex::new(Inner {
                enabled: cfg.enabled,
                routes: cfg.routes.clone(),
                domains: cfg.domains.clone(),
                resolved: Vec::new(),
            }),
            refresh: Duration::from_secs(cfg.refresh_secs.max(10)),
        }
    }

    pub fn enabled(&self) -> bool {
        self.inner.lock().unwrap().enabled
    }

    /// The effective policy: static routes + resolved domain IPs, deduped.
    pub fn snapshot(&self) -> SplitSnapshot {
        let inner = self.inner.lock().unwrap();
        let mut set: BTreeSet<String> = BTreeSet::new();
        set.extend(inner.routes.iter().cloned());
        set.extend(inner.resolved.iter().cloned());
        SplitSnapshot {
            enabled: inner.enabled,
            domains: inner.domains.clone(),
            routes: set.into_iter().collect(),
        }
    }

    /// Replace the policy at runtime (admin API). Triggers a re-resolve.
    pub async fn update(&self, enabled: bool, routes: Vec<String>, domains: Vec<String>) {
        {
            let mut inner = self.inner.lock().unwrap();
            inner.enabled = enabled;
            inner.routes = routes;
            inner.domains = domains;
        }
        self.refresh_once().await;
    }

    /// Resolve every configured domain to its IPv4 addresses and store them as
    /// `/32` routes. The DNS lookups run without holding the lock.
    pub async fn refresh_once(&self) {
        let domains = self.inner.lock().unwrap().domains.clone();
        if domains.is_empty() {
            self.inner.lock().unwrap().resolved.clear();
            return;
        }

        let mut resolved: Vec<String> = Vec::new();
        for domain in &domains {
            match tokio::net::lookup_host((domain.as_str(), 0u16)).await {
                Ok(addrs) => {
                    for addr in addrs {
                        if let IpAddr::V4(v4) = addr.ip() {
                            resolved.push(format!("{v4}/32"));
                        }
                    }
                }
                Err(e) => tracing::warn!("split: failed to resolve {domain}: {e}"),
            }
        }
        resolved.sort();
        resolved.dedup();

        tracing::debug!("split: resolved {} domain IP(s)", resolved.len());
        self.inner.lock().unwrap().resolved = resolved;
    }

    /// Spawn the periodic domain re-resolution loop. No-op when disabled or when
    /// there are no domains to resolve.
    pub fn spawn_refresher(self: Arc<Self>) {
        if !self.enabled() || self.inner.lock().unwrap().domains.is_empty() {
            return;
        }
        let refresh = self.refresh;
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(refresh).await;
                self.refresh_once().await;
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(enabled: bool, routes: &[&str], domains: &[&str]) -> SplitConfig {
        SplitConfig {
            enabled,
            routes: routes.iter().map(|s| s.to_string()).collect(),
            domains: domains.iter().map(|s| s.to_string()).collect(),
            refresh_secs: 300,
        }
    }

    #[test]
    fn snapshot_dedupes_and_sorts_static_routes() {
        let policy = SplitPolicy::new(&cfg(true, &["10.0.0.0/8", "10.0.0.0/8", "1.2.3.4/32"], &[]));
        let snap = policy.snapshot();
        assert!(snap.enabled);
        // BTreeSet-backed: deduplicated and sorted.
        assert_eq!(snap.routes, vec!["1.2.3.4/32".to_string(), "10.0.0.0/8".to_string()]);
    }

    #[test]
    fn disabled_policy_reports_disabled() {
        let policy = SplitPolicy::new(&cfg(false, &["1.2.3.0/24"], &[]));
        assert!(!policy.enabled());
        assert!(!policy.snapshot().enabled);
    }

    #[tokio::test]
    async fn empty_domains_clears_resolved() {
        let policy = SplitPolicy::new(&cfg(true, &["1.2.3.0/24"], &[]));
        // No domains -> refresh is a no-op that leaves only the static route.
        policy.refresh_once().await;
        assert_eq!(policy.snapshot().routes, vec!["1.2.3.0/24".to_string()]);
    }
}
