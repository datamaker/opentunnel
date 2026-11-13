//! Pre-authentication abuse limits for the public VPN listener.
//!
//! The listener is reachable from the whole internet, so everything a peer can
//! make the server do before it has authenticated must be bounded:
//!
//! - a global cap on concurrent connections,
//! - a per-source cap on concurrent *unauthenticated* connections,
//! - a per-source token bucket on new connections,
//! - a per-source token bucket on failed authentications.
//!
//! All state is in memory. The per-source map is swept periodically and has a
//! hard entry cap, so it cannot grow without bound however many addresses an
//! attacker cycles through.
//!
//! Time is passed in explicitly (`*_at` methods) so the logic is unit-testable
//! without sleeping.

use crate::admin::IpNet;
use crate::config::LimitsConfig;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Hard cap on tracked sources. ~100 bytes per entry, so the map tops out at a
/// few MB. When it is full of *live* entries, unknown sources are refused.
const MAX_TRACKED_SOURCES: usize = 50_000;
/// How often the per-source map is swept for idle entries.
const SWEEP_INTERVAL: Duration = Duration::from_secs(60);
/// Minimum spacing between log lines of one throttled category.
const LOG_INTERVAL: Duration = Duration::from_secs(10);

/// Reduce a peer address to the key limits are tracked under.
///
/// IPv4 (and IPv4-mapped IPv6) is tracked per address. IPv6 is tracked per /64,
/// since a single host normally controls its whole /64 and could otherwise
/// rotate through addresses to dodge every per-source limit.
pub fn source_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let s = v6.segments();
                IpAddr::V6(Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
            }
        },
    }
}

/// Token bucket holding at most `capacity` tokens, refilled continuously at
/// `capacity` tokens per minute. A capacity of 0 disables the limit.
#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    updated: Instant,
}

impl Bucket {
    fn full(capacity: u32, now: Instant) -> Self {
        Bucket {
            tokens: capacity as f64,
            updated: now,
        }
    }

    fn refill(&mut self, capacity: u32, now: Instant) {
        let elapsed = now.saturating_duration_since(self.updated).as_secs_f64();
        self.tokens = (self.tokens + elapsed * capacity as f64 / 60.0).min(capacity as f64);
        self.updated = now;
    }

    /// Take one token; `false` if the bucket is empty.
    fn try_take(&mut self, capacity: u32, now: Instant) -> bool {
        if capacity == 0 {
            return true;
        }
        self.refill(capacity, now);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Take one token, allowing the balance to bottom out at zero.
    fn drain_one(&mut self, capacity: u32, now: Instant) {
        if capacity == 0 {
            return;
        }
        self.refill(capacity, now);
        self.tokens = (self.tokens - 1.0).max(0.0);
    }

    fn has_token(&mut self, capacity: u32, now: Instant) -> bool {
        if capacity == 0 {
            return true;
        }
        self.refill(capacity, now);
        self.tokens >= 1.0
    }

    fn is_full(&mut self, capacity: u32, now: Instant) -> bool {
        if capacity == 0 {
            return true;
        }
        self.refill(capacity, now);
        self.tokens >= capacity as f64
    }
}

#[derive(Debug)]
struct Source {
    /// Connections from this source that have not authenticated yet.
    unauthenticated: u32,
    connects: Bucket,
    auth_failures: Bucket,
}

/// Why a new connection was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reject {
    /// The server-wide connection cap is reached.
    GlobalCap,
    /// Too many unauthenticated connections from this source.
    SourceUnauthCap,
    /// This source is opening connections too fast.
    ConnectRate,
    /// This source has failed authentication too often recently.
    AuthFailureRate,
    /// The tracking table is full of live sources.
    TableFull,
}

impl Reject {
    fn index(self) -> usize {
        self as usize
    }

    fn describe(self) -> &'static str {
        match self {
            Reject::GlobalCap => "global connection cap reached",
            Reject::SourceUnauthCap => "too many unauthenticated connections from source",
            Reject::ConnectRate => "connection rate limit exceeded for source",
            Reject::AuthFailureRate => "failed-auth rate limit exceeded for source",
            Reject::TableFull => "source tracking table full",
        }
    }
}

struct Inner {
    total: usize,
    sources: HashMap<IpAddr, Source>,
    last_sweep: Instant,
}

/// Emits at most one line per [`LOG_INTERVAL`], carrying the number of events
/// swallowed since the previous line. A flood therefore costs a constant
/// amount of log output regardless of how many sources take part.
pub struct LogThrottle {
    state: Mutex<(Option<Instant>, u64)>,
}

impl LogThrottle {
    fn new() -> Self {
        LogThrottle {
            state: Mutex::new((None, 0)),
        }
    }

    /// `Some(suppressed)` if the caller should log now.
    pub fn should_log_now(&self) -> Option<u64> {
        self.should_log(Instant::now())
    }

    fn should_log(&self, now: Instant) -> Option<u64> {
        let mut state = self.state.lock().unwrap();
        match state.0 {
            Some(last) if now.saturating_duration_since(last) < LOG_INTERVAL => {
                state.1 += 1;
                None
            }
            _ => {
                let suppressed = state.1;
                *state = (Some(now), 0);
                Some(suppressed)
            }
        }
    }
}

pub struct ConnLimiter {
    max_connections: usize,
    max_unauth_per_source: u32,
    connects_per_min: u32,
    auth_failures_per_min: u32,
    max_sources: usize,
    exempt: Vec<IpNet>,
    inner: Mutex<Inner>,
    reject_logs: [LogThrottle; 5],
    /// Throttle for "oversized frame" log lines.
    pub frame_log: LogThrottle,
    /// Throttle for "authentication deadline passed" log lines.
    pub deadline_log: LogThrottle,
    /// Throttle for TLS handshake failure log lines.
    pub handshake_log: LogThrottle,
}

impl ConnLimiter {
    pub fn new(cfg: &LimitsConfig) -> Arc<Self> {
        Self::with_table_size(cfg, MAX_TRACKED_SOURCES)
    }

    fn with_table_size(cfg: &LimitsConfig, max_sources: usize) -> Arc<Self> {
        let exempt = cfg
            .exempt_cidrs
            .iter()
            .filter_map(|entry| {
                let net = IpNet::parse(entry);
                if net.is_none() {
                    tracing::warn!("VPN_LIMIT_EXEMPT_CIDRS: ignoring invalid entry {entry:?}");
                }
                net
            })
            .collect();
        Arc::new(ConnLimiter {
            max_connections: cfg.max_connections,
            max_unauth_per_source: cfg.max_unauth_per_ip,
            connects_per_min: cfg.conn_rate_per_min,
            auth_failures_per_min: cfg.auth_fail_per_min,
            max_sources,
            exempt,
            inner: Mutex::new(Inner {
                total: 0,
                sources: HashMap::new(),
                last_sweep: Instant::now(),
            }),
            reject_logs: std::array::from_fn(|_| LogThrottle::new()),
            frame_log: LogThrottle::new(),
            deadline_log: LogThrottle::new(),
            handshake_log: LogThrottle::new(),
        })
    }

    fn is_exempt(&self, ip: IpAddr) -> bool {
        self.exempt.iter().any(|net| net.contains(ip))
    }

    /// Admit or refuse a freshly-accepted connection.
    pub fn try_acquire(self: &Arc<Self>, ip: IpAddr) -> Result<ConnGuard, Reject> {
        self.try_acquire_at(ip, Instant::now())
    }

    pub fn try_acquire_at(self: &Arc<Self>, ip: IpAddr, now: Instant) -> Result<ConnGuard, Reject> {
        // Exempt sources (e.g. load-balancer health checks) skip the per-source
        // limits but still count toward — and are bounded by — the global cap.
        let exempt = self.is_exempt(ip);
        let key = source_key(ip);
        let mut inner = self.inner.lock().unwrap();

        if now.saturating_duration_since(inner.last_sweep) >= SWEEP_INTERVAL {
            self.sweep(&mut inner, now);
        }

        if self.max_connections > 0 && inner.total >= self.max_connections {
            return Err(Reject::GlobalCap);
        }

        if exempt {
            inner.total += 1;
            return Ok(ConnGuard {
                limiter: self.clone(),
                key: None,
                unauthenticated: false,
            });
        }

        if !inner.sources.contains_key(&key) && inner.sources.len() >= self.max_sources {
            self.sweep(&mut inner, now);
            if inner.sources.len() >= self.max_sources {
                return Err(Reject::TableFull);
            }
        }

        let source = inner.sources.entry(key).or_insert_with(|| Source {
            unauthenticated: 0,
            connects: Bucket::full(self.connects_per_min, now),
            auth_failures: Bucket::full(self.auth_failures_per_min, now),
        });

        if self.max_unauth_per_source > 0 && source.unauthenticated >= self.max_unauth_per_source {
            return Err(Reject::SourceUnauthCap);
        }
        if !source.auth_failures.has_token(self.auth_failures_per_min, now) {
            return Err(Reject::AuthFailureRate);
        }
        if !source.connects.try_take(self.connects_per_min, now) {
            return Err(Reject::ConnectRate);
        }

        source.unauthenticated += 1;
        inner.total += 1;
        Ok(ConnGuard {
            limiter: self.clone(),
            key: Some(key),
            unauthenticated: true,
        })
    }

    /// Drop sources that hold no connection and whose buckets have fully
    /// refilled — forgetting them changes nothing about future decisions.
    fn sweep(&self, inner: &mut Inner, now: Instant) {
        let (connects, failures) = (self.connects_per_min, self.auth_failures_per_min);
        inner.sources.retain(|_, s| {
            s.unauthenticated > 0
                || !s.connects.is_full(connects, now)
                || !s.auth_failures.is_full(failures, now)
        });
        inner.last_sweep = now;
    }

    /// Log a refusal, throttled per reason so a flood cannot fill the disk.
    pub fn log_reject(&self, reason: Reject, peer: IpAddr) {
        if let Some(suppressed) = self.reject_logs[reason.index()].should_log(Instant::now()) {
            tracing::warn!(
                "Refusing connection from {peer}: {} ({suppressed} similar refusals not logged)",
                reason.describe()
            );
        }
    }

    #[cfg(test)]
    fn tracked_sources(&self) -> usize {
        self.inner.lock().unwrap().sources.len()
    }

    #[cfg(test)]
    pub fn total(&self) -> usize {
        self.inner.lock().unwrap().total
    }
}

/// Holds one connection's slots; releases them when dropped.
pub struct ConnGuard {
    limiter: Arc<ConnLimiter>,
    /// `None` for exempt sources, which are not tracked per source.
    key: Option<IpAddr>,
    unauthenticated: bool,
}

impl std::fmt::Debug for ConnGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnGuard")
            .field("key", &self.key)
            .field("unauthenticated", &self.unauthenticated)
            .finish()
    }
}

impl ConnGuard {
    /// The connection authenticated: it stops counting toward the per-source
    /// unauthenticated cap (it still holds a global slot).
    pub fn mark_authenticated(&mut self) {
        if !self.unauthenticated {
            return;
        }
        self.unauthenticated = false;
        if let Some(key) = self.key {
            let mut inner = self.limiter.inner.lock().unwrap();
            if let Some(source) = inner.sources.get_mut(&key) {
                source.unauthenticated = source.unauthenticated.saturating_sub(1);
            }
        }
    }

    /// Charge a failed authentication to this connection's source.
    pub fn record_auth_failure(&self) {
        self.record_auth_failure_at(Instant::now());
    }

    pub fn record_auth_failure_at(&self, now: Instant) {
        if let Some(key) = self.key {
            let mut inner = self.limiter.inner.lock().unwrap();
            if let Some(source) = inner.sources.get_mut(&key) {
                source
                    .auth_failures
                    .drain_one(self.limiter.auth_failures_per_min, now);
            }
        }
    }
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        let mut inner = self.limiter.inner.lock().unwrap();
        inner.total = inner.total.saturating_sub(1);
        if self.unauthenticated {
            if let Some(source) = self.key.and_then(|key| inner.sources.get_mut(&key)) {
                source.unauthenticated = source.unauthenticated.saturating_sub(1);
            }
        }
    }
}

/// What to do with one failed-auth log row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogDecision {
    /// Write the row. `suppressed` rows from this source were skipped in the
    /// previous window and should be mentioned in this one.
    Write { suppressed: u32 },
    /// Over this source's per-minute budget: skip the row.
    Skip,
}

struct FailWindow {
    started: Instant,
    written: u32,
    suppressed: u32,
}

/// Per-source fixed-window limiter for `auth_fail` rows in `connection_logs`,
/// so failed logins cannot be used to fill the database.
pub struct AuthFailLogLimiter {
    per_min: u32,
    max_sources: usize,
    windows: Mutex<HashMap<IpAddr, FailWindow>>,
}

const FAIL_WINDOW: Duration = Duration::from_secs(60);

impl AuthFailLogLimiter {
    /// `per_min == 0` disables the limit (every failure is logged).
    pub fn new(per_min: u32) -> Self {
        Self::with_table_size(per_min, MAX_TRACKED_SOURCES)
    }

    fn with_table_size(per_min: u32, max_sources: usize) -> Self {
        AuthFailLogLimiter {
            per_min,
            max_sources,
            windows: Mutex::new(HashMap::new()),
        }
    }

    pub fn check(&self, ip: IpAddr) -> LogDecision {
        self.check_at(ip, Instant::now())
    }

    pub fn check_at(&self, ip: IpAddr, now: Instant) -> LogDecision {
        if self.per_min == 0 {
            return LogDecision::Write { suppressed: 0 };
        }
        let key = source_key(ip);
        let mut windows = self.windows.lock().unwrap();

        if !windows.contains_key(&key) && windows.len() >= self.max_sources {
            // Expired windows with nothing left to report carry no information.
            windows.retain(|_, w| {
                w.suppressed > 0 || now.saturating_duration_since(w.started) < FAIL_WINDOW
            });
            if windows.len() >= self.max_sources {
                // Still full: drop every expired window, losing only the
                // "N suppressed" annotations.
                windows.retain(|_, w| now.saturating_duration_since(w.started) < FAIL_WINDOW);
            }
            if windows.len() >= self.max_sources {
                return LogDecision::Skip;
            }
        }

        let window = windows.entry(key).or_insert(FailWindow {
            started: now,
            written: 0,
            suppressed: 0,
        });

        let mut carried = 0;
        if now.saturating_duration_since(window.started) >= FAIL_WINDOW {
            carried = window.suppressed;
            *window = FailWindow {
                started: now,
                written: 0,
                suppressed: 0,
            };
        }

        if window.written < self.per_min {
            window.written += 1;
            LogDecision::Write { suppressed: carried }
        } else {
            window.suppressed = window.suppressed.saturating_add(1).saturating_add(carried);
            LogDecision::Skip
        }
    }

    #[cfg(test)]
    fn tracked_sources(&self) -> usize {
        self.windows.lock().unwrap().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn cfg() -> LimitsConfig {
        LimitsConfig {
            max_connections: 100,
            max_unauth_per_ip: 3,
            conn_rate_per_min: 6,
            auth_fail_per_min: 2,
            ..LimitsConfig::default()
        }
    }

    #[test]
    fn per_source_unauthenticated_cap() {
        let limiter = ConnLimiter::new(&cfg());
        let now = Instant::now();
        let a = ip("203.0.113.7");

        let mut g1 = limiter.try_acquire_at(a, now).unwrap();
        let _g2 = limiter.try_acquire_at(a, now).unwrap();
        let g3 = limiter.try_acquire_at(a, now).unwrap();
        assert_eq!(limiter.try_acquire_at(a, now).unwrap_err(), Reject::SourceUnauthCap);

        // Another source is unaffected.
        let _other = limiter.try_acquire_at(ip("203.0.113.8"), now).unwrap();

        // Authenticating frees an unauthenticated slot but keeps the global one.
        g1.mark_authenticated();
        let _g4 = limiter.try_acquire_at(a, now).unwrap();
        assert_eq!(limiter.total(), 5);

        // So does closing a connection.
        drop(g3);
        let _g5 = limiter.try_acquire_at(a, now).unwrap();
        assert_eq!(limiter.total(), 5);
    }

    #[test]
    fn authenticated_guard_releases_slots_exactly_once() {
        let limiter = ConnLimiter::new(&cfg());
        let now = Instant::now();
        let a = ip("203.0.113.7");
        let mut g = limiter.try_acquire_at(a, now).unwrap();
        g.mark_authenticated();
        g.mark_authenticated();
        drop(g);
        assert_eq!(limiter.total(), 0);
        // All three unauthenticated slots are available again.
        let _guards: Vec<_> = (0..3).map(|_| limiter.try_acquire_at(a, now).unwrap()).collect();
    }

    #[test]
    fn global_cap_counts_every_connection() {
        let limiter = ConnLimiter::new(&LimitsConfig {
            max_connections: 2,
            ..cfg()
        });
        let now = Instant::now();
        let mut g1 = limiter.try_acquire_at(ip("198.51.100.1"), now).unwrap();
        g1.mark_authenticated(); // authenticated sessions still hold a global slot
        let g2 = limiter.try_acquire_at(ip("198.51.100.2"), now).unwrap();
        assert_eq!(
            limiter.try_acquire_at(ip("198.51.100.3"), now).unwrap_err(),
            Reject::GlobalCap
        );
        drop(g2);
        assert!(limiter.try_acquire_at(ip("198.51.100.3"), now).is_ok());
    }

    #[test]
    fn connect_rate_is_a_token_bucket() {
        let limiter = ConnLimiter::new(&cfg()); // 6 per minute, burst 6
        let t0 = Instant::now();
        let a = ip("203.0.113.9");

        for _ in 0..6 {
            // Dropped immediately, so only the rate limit is in play.
            limiter.try_acquire_at(a, t0).unwrap();
        }
        assert_eq!(limiter.try_acquire_at(a, t0).unwrap_err(), Reject::ConnectRate);

        // One token comes back every 10 s.
        let t1 = t0 + Duration::from_secs(9);
        assert_eq!(limiter.try_acquire_at(a, t1).unwrap_err(), Reject::ConnectRate);
        let t2 = t0 + Duration::from_secs(11);
        assert!(limiter.try_acquire_at(a, t2).is_ok());
        assert_eq!(limiter.try_acquire_at(a, t2).unwrap_err(), Reject::ConnectRate);

        // The bucket never holds more than its capacity.
        let t3 = t0 + Duration::from_secs(3600);
        for _ in 0..6 {
            limiter.try_acquire_at(a, t3).unwrap();
        }
        assert_eq!(limiter.try_acquire_at(a, t3).unwrap_err(), Reject::ConnectRate);
    }

    #[test]
    fn repeated_auth_failures_block_new_connections_until_refill() {
        let limiter = ConnLimiter::new(&cfg()); // 2 failures per minute
        let t0 = Instant::now();
        let a = ip("203.0.113.10");

        for _ in 0..2 {
            let guard = limiter.try_acquire_at(a, t0).unwrap();
            guard.record_auth_failure_at(t0);
        }
        assert_eq!(limiter.try_acquire_at(a, t0).unwrap_err(), Reject::AuthFailureRate);
        // Other sources are unaffected.
        assert!(limiter.try_acquire_at(ip("203.0.113.11"), t0).is_ok());

        // One failure token refills every 30 s.
        let t1 = t0 + Duration::from_secs(31);
        assert!(limiter.try_acquire_at(a, t1).is_ok());
    }

    #[test]
    fn exempt_sources_skip_per_source_limits_but_not_the_global_cap() {
        let limiter = ConnLimiter::new(&LimitsConfig {
            max_connections: 20,
            exempt_cidrs: vec!["11.0.0.0/16".into()],
            ..cfg()
        });
        let now = Instant::now();
        let probe = ip("11.0.3.4");

        let guards: Vec<_> = (0..20).map(|_| limiter.try_acquire_at(probe, now).unwrap()).collect();
        assert_eq!(limiter.tracked_sources(), 0);
        assert_eq!(limiter.try_acquire_at(probe, now).unwrap_err(), Reject::GlobalCap);
        drop(guards);
        assert_eq!(limiter.total(), 0);
    }

    #[test]
    fn idle_sources_are_evicted_by_the_sweep() {
        let limiter = ConnLimiter::new(&cfg());
        let t0 = Instant::now();
        for i in 0..50u8 {
            limiter.try_acquire_at(ip(&format!("203.0.113.{i}")), t0).unwrap();
        }
        assert_eq!(limiter.tracked_sources(), 50);

        // A connection that is still open pins its source.
        let held = limiter.try_acquire_at(ip("198.51.100.50"), t0).unwrap();

        // After the buckets refill (10 s per token here), the next sweep
        // forgets every idle source.
        let t1 = t0 + SWEEP_INTERVAL + Duration::from_secs(1);
        limiter.try_acquire_at(ip("192.0.2.1"), t1).unwrap();
        assert_eq!(limiter.tracked_sources(), 2); // the held one + the new one

        drop(held);
    }

    #[test]
    fn table_is_hard_capped_and_recovers() {
        let limiter = ConnLimiter::with_table_size(&cfg(), 4);
        let t0 = Instant::now();
        let guards: Vec<_> = (0..4u8)
            .map(|i| limiter.try_acquire_at(ip(&format!("203.0.113.{i}")), t0).unwrap())
            .collect();

        // Full of live sources: an unknown source is refused, a known one is not.
        assert_eq!(
            limiter.try_acquire_at(ip("203.0.113.200"), t0).unwrap_err(),
            Reject::TableFull
        );
        assert!(limiter.try_acquire_at(ip("203.0.113.0"), t0).is_ok());
        assert_eq!(limiter.tracked_sources(), 4);

        // Once the connections close and the buckets refill, the on-demand
        // sweep makes room again without waiting for the periodic one.
        drop(guards);
        let t1 = t0 + Duration::from_secs(30);
        assert!(limiter.try_acquire_at(ip("203.0.113.200"), t1).is_ok());
        assert_eq!(limiter.tracked_sources(), 1);
    }

    #[test]
    fn ipv6_sources_share_a_slash_64() {
        let limiter = ConnLimiter::new(&cfg());
        let now = Instant::now();
        let _a = limiter.try_acquire_at(ip("2001:db8:1:2::1"), now).unwrap();
        let _b = limiter.try_acquire_at(ip("2001:db8:1:2:ffff::9"), now).unwrap();
        let _c = limiter.try_acquire_at(ip("2001:db8:1:2:1234::"), now).unwrap();
        assert_eq!(
            limiter.try_acquire_at(ip("2001:db8:1:2::5"), now).unwrap_err(),
            Reject::SourceUnauthCap
        );
        assert!(limiter.try_acquire_at(ip("2001:db8:1:3::5"), now).is_ok());
        assert_eq!(limiter.tracked_sources(), 2);

        // IPv4-mapped addresses are the IPv4 source.
        assert_eq!(source_key(ip("::ffff:203.0.113.7")), ip("203.0.113.7"));
    }

    #[test]
    fn zero_disables_each_limit() {
        let limiter = ConnLimiter::new(&LimitsConfig {
            max_connections: 0,
            max_unauth_per_ip: 0,
            conn_rate_per_min: 0,
            auth_fail_per_min: 0,
            ..LimitsConfig::default()
        });
        let now = Instant::now();
        let a = ip("203.0.113.7");
        let guards: Vec<_> = (0..500).map(|_| limiter.try_acquire_at(a, now).unwrap()).collect();
        for g in &guards {
            g.record_auth_failure_at(now);
        }
        assert!(limiter.try_acquire_at(a, now).is_ok());
    }

    #[test]
    fn log_throttle_emits_once_per_interval_with_suppressed_count() {
        let throttle = LogThrottle::new();
        let t0 = Instant::now();
        assert_eq!(throttle.should_log(t0), Some(0));
        for _ in 0..1000 {
            assert_eq!(throttle.should_log(t0 + Duration::from_secs(1)), None);
        }
        assert_eq!(throttle.should_log(t0 + LOG_INTERVAL), Some(1000));
        assert_eq!(throttle.should_log(t0 + LOG_INTERVAL), None);
    }

    #[test]
    fn auth_fail_log_is_limited_per_source_and_reports_suppressed() {
        let limiter = AuthFailLogLimiter::new(3);
        let t0 = Instant::now();
        let a = ip("203.0.113.7");

        for _ in 0..3 {
            assert_eq!(limiter.check_at(a, t0), LogDecision::Write { suppressed: 0 });
        }
        for _ in 0..40 {
            assert_eq!(limiter.check_at(a, t0 + Duration::from_secs(5)), LogDecision::Skip);
        }
        // Another source has its own budget.
        assert_eq!(
            limiter.check_at(ip("203.0.113.8"), t0),
            LogDecision::Write { suppressed: 0 }
        );

        // The next window logs again and carries the skipped count.
        let t1 = t0 + FAIL_WINDOW;
        assert_eq!(limiter.check_at(a, t1), LogDecision::Write { suppressed: 40 });
        assert_eq!(limiter.check_at(a, t1), LogDecision::Write { suppressed: 0 });
    }

    #[test]
    fn auth_fail_log_table_is_bounded() {
        let limiter = AuthFailLogLimiter::with_table_size(1, 3);
        let t0 = Instant::now();
        for i in 0..3u8 {
            let addr = ip(&format!("203.0.113.{i}"));
            assert_eq!(limiter.check_at(addr, t0), LogDecision::Write { suppressed: 0 });
        }
        // Full of live windows: an unknown source is not logged (and not tracked).
        assert_eq!(limiter.check_at(ip("203.0.113.99"), t0), LogDecision::Skip);
        assert_eq!(limiter.tracked_sources(), 3);

        // Expired windows are evicted on demand.
        let t1 = t0 + FAIL_WINDOW;
        assert_eq!(
            limiter.check_at(ip("203.0.113.99"), t1),
            LogDecision::Write { suppressed: 0 }
        );
        assert_eq!(limiter.tracked_sources(), 1);
    }

    #[test]
    fn auth_fail_log_zero_means_unlimited() {
        let limiter = AuthFailLogLimiter::new(0);
        let now = Instant::now();
        for _ in 0..100 {
            assert_eq!(
                limiter.check_at(ip("203.0.113.7"), now),
                LogDecision::Write { suppressed: 0 }
            );
        }
        assert_eq!(limiter.tracked_sources(), 0);
    }
}
