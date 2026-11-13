//! gatehouse account-status lookups: revocation propagation for SSO users.
//!
//! When an operator deactivates a user or ends their sessions in gatehouse,
//! this server's own 30-day session tokens and live tunnels have to stop
//! working too. gatehouse exposes
//!
//! ```text
//! GET {GATEHOUSE_STATUS_URL}/internal/account?email=<email>
//! X-Gatehouse-Secret: <GATEHOUSE_STATUS_SECRET>
//! 200 {"email":"..","active":true,"revoked_before":"2026-11-13T03:00:00.000Z"|null}
//! 404 {"active":false}          (unknown email: treated as inactive)
//! ```
//!
//! and this module asks it whenever an SSO user's session is created, renewed
//! or (periodically) re-checked. Rules, per the shared contract:
//!
//! - Both env vars must be set; otherwise the feature is off and every check
//!   passes, exactly as before.
//! - Answers are cached per email for 60 seconds; a lookup times out after 2.
//! - `active == false` (or 404) is a refusal. So is a session whose login time
//!   is earlier than `revoked_before`.
//! - If gatehouse cannot be reached (network error, timeout, 5xx, a bad
//!   secret, an unreadable body) the **last successful answer** for that email
//!   is used; with no previous answer the check passes. A gatehouse outage
//!   must not become a VPN outage. The warning is logged at most once a minute.
//!
//! The HTTP call sits behind [`StatusFetcher`] so tests can inject answers.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// How long an answer is reused before gatehouse is asked again.
const CACHE_TTL: Duration = Duration::from_secs(60);
/// Per-lookup timeout.
const FETCH_TIMEOUT: Duration = Duration::from_secs(2);
/// After a failed lookup, do not try gatehouse again for this long: during an
/// outage every authentication would otherwise wait out the full timeout.
const FAILURE_BACKOFF: Duration = Duration::from_secs(10);
/// Minimum spacing of "gatehouse unreachable" warnings.
const WARN_INTERVAL: Duration = Duration::from_secs(60);

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// What gatehouse says about one account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccountStatus {
    pub active: bool,
    /// Sessions that began before this instant (unix milliseconds) are void.
    pub revoked_before_ms: Option<i64>,
}

/// Performs the actual lookup. `Err` means "could not get an answer" (the
/// caller falls back to the last good one); an unknown account is
/// `Ok(AccountStatus { active: false, .. })`.
pub trait StatusFetcher: Send + Sync {
    fn fetch<'a>(&'a self, email: &'a str) -> BoxFuture<'a, Result<AccountStatus, String>>;
}

/// Outcome of a check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    /// The account is deactivated in (or unknown to) gatehouse.
    Inactive,
    /// The session's login predates gatehouse's `revoked_before`.
    Revoked,
}

struct Cached {
    status: AccountStatus,
    fetched: Instant,
}

#[derive(Default)]
struct State {
    by_email: HashMap<String, Cached>,
    last_failure: Option<Instant>,
    last_warning: Option<Instant>,
    suppressed_warnings: u64,
}

pub struct GatehouseStatus {
    fetcher: Option<Arc<dyn StatusFetcher>>,
    state: Mutex<State>,
}

impl GatehouseStatus {
    /// Lookups switched off: every check passes.
    pub fn disabled() -> Self {
        GatehouseStatus {
            fetcher: None,
            state: Mutex::new(State::default()),
        }
    }

    pub fn with_fetcher(fetcher: Arc<dyn StatusFetcher>) -> Self {
        GatehouseStatus {
            fetcher: Some(fetcher),
            state: Mutex::new(State::default()),
        }
    }

    /// Build from `GATEHOUSE_STATUS_URL` / `GATEHOUSE_STATUS_SECRET`. Either
    /// one missing leaves the feature off.
    pub fn from_config(url: &str, secret: &str) -> Self {
        if url.is_empty() || secret.is_empty() {
            return Self::disabled();
        }
        Self::with_fetcher(Arc::new(HttpFetcher::new(url, secret)))
    }

    pub fn enabled(&self) -> bool {
        self.fetcher.is_some()
    }

    /// Drop every cached answer, as if the cache TTL had passed.
    #[cfg(test)]
    pub fn expire_cache(&self) {
        let mut state = self.state.lock().unwrap();
        state.by_email.clear();
        state.last_failure = None;
    }

    /// May a session of `email` whose login happened at `auth_time` (unix
    /// seconds) exist right now?
    pub async fn check(&self, email: &str, auth_time: i64) -> Verdict {
        self.check_at(email, auth_time, Instant::now()).await
    }

    /// [`check`](Self::check) with the clock passed in, for tests.
    pub async fn check_at(&self, email: &str, auth_time: i64, now: Instant) -> Verdict {
        let Some(fetcher) = self.fetcher.as_ref() else {
            return Verdict::Allow;
        };
        // gatehouse compares emails case-insensitively; so does the cache.
        let key = email.trim().to_lowercase();

        let (cached, backing_off) = {
            let state = self.state.lock().unwrap();
            let cached = state.by_email.get(&key).map(|c| (c.status, c.fetched));
            let backing_off = state
                .last_failure
                .is_some_and(|at| now.saturating_duration_since(at) < FAILURE_BACKOFF);
            (cached, backing_off)
        };
        if let Some((status, fetched)) = cached {
            if now.saturating_duration_since(fetched) < CACHE_TTL {
                return judge(status, auth_time);
            }
        }
        if backing_off {
            return judge_fallback(cached.map(|c| c.0), auth_time);
        }

        let fetched = match tokio::time::timeout(FETCH_TIMEOUT, fetcher.fetch(&key)).await {
            Ok(result) => result,
            Err(_) => Err(format!("timed out after {}s", FETCH_TIMEOUT.as_secs())),
        };

        match fetched {
            Ok(status) => {
                let mut state = self.state.lock().unwrap();
                state.by_email.insert(key, Cached { status, fetched: now });
                state.last_failure = None;
                judge(status, auth_time)
            }
            Err(error) => {
                let warn = {
                    let mut state = self.state.lock().unwrap();
                    state.last_failure = Some(now);
                    let due = state
                        .last_warning
                        .is_none_or(|at| now.saturating_duration_since(at) >= WARN_INTERVAL);
                    if due {
                        state.last_warning = Some(now);
                        Some(std::mem::take(&mut state.suppressed_warnings))
                    } else {
                        state.suppressed_warnings += 1;
                        None
                    }
                };
                if let Some(suppressed) = warn {
                    tracing::warn!(
                        "gatehouse status lookup failed ({error}); using the last known \
                         answer per account, or allowing when there is none \
                         ({suppressed} similar failures not logged)"
                    );
                }
                judge_fallback(cached.map(|c| c.0), auth_time)
            }
        }
    }
}

fn judge(status: AccountStatus, auth_time: i64) -> Verdict {
    if !status.active {
        return Verdict::Inactive;
    }
    match status.revoked_before_ms {
        // `auth_time` has one-second resolution, so a login in the very second
        // of the revocation is refused too; the user simply signs in again.
        Some(revoked_before) if auth_time.saturating_mul(1000) < revoked_before => Verdict::Revoked,
        _ => Verdict::Allow,
    }
}

/// gatehouse did not answer: the last good answer decides, and without one the
/// session is let through.
fn judge_fallback(last_good: Option<AccountStatus>, auth_time: i64) -> Verdict {
    match last_good {
        Some(status) => judge(status, auth_time),
        None => Verdict::Allow,
    }
}

/// The real lookup, over HTTPS with the HTTP client the server already uses
/// for OIDC discovery.
pub struct HttpFetcher {
    http: reqwest::Client,
    endpoint: String,
    secret: String,
}

#[derive(serde::Deserialize)]
struct AccountBody {
    active: bool,
    #[serde(default)]
    revoked_before: Option<String>,
}

impl HttpFetcher {
    pub fn new(base_url: &str, secret: &str) -> Self {
        let http = reqwest::Client::builder()
            .timeout(FETCH_TIMEOUT)
            .build()
            .expect("failed to build HTTP client for gatehouse");
        HttpFetcher {
            http,
            endpoint: format!("{}/internal/account", base_url.trim_end_matches('/')),
            secret: secret.to_string(),
        }
    }
}

impl StatusFetcher for HttpFetcher {
    fn fetch<'a>(&'a self, email: &'a str) -> BoxFuture<'a, Result<AccountStatus, String>> {
        Box::pin(async move {
            let response = self
                .http
                .get(&self.endpoint)
                .query(&[("email", email)])
                .header("X-Gatehouse-Secret", &self.secret)
                .send()
                .await
                // The error's Display includes the URL (and so the email);
                // keep only what kind of failure it was.
                .map_err(|e| {
                    if e.is_timeout() {
                        "timed out".to_string()
                    } else if e.is_connect() {
                        "connection failed".to_string()
                    } else {
                        "request failed".to_string()
                    }
                })?;

            let status = response.status();
            if status == reqwest::StatusCode::NOT_FOUND {
                // The contract's "unknown account" answer is a 404 *carrying*
                // `{"active":false}`. A bare 404 is something else — the route
                // is not there (gatehouse without GATEHOUSE_INTERNAL_SECRET, an
                // older gatehouse, a wrong URL) — and must not be read as
                // "every user is deactivated".
                return match response.json::<AccountBody>().await {
                    Ok(body) if !body.active => Ok(AccountStatus {
                        active: false,
                        revoked_before_ms: None,
                    }),
                    _ => Err("HTTP 404 without an account body (route missing?)".to_string()),
                };
            }
            if !status.is_success() {
                return Err(format!("HTTP {}", status.as_u16()));
            }
            let body: AccountBody = response
                .json()
                .await
                .map_err(|_| "unreadable response body".to_string())?;
            parse_body(body)
        })
    }
}

fn parse_body(body: AccountBody) -> Result<AccountStatus, String> {
    let revoked_before_ms = match body.revoked_before.as_deref() {
        None => None,
        Some(raw) => Some(
            chrono::DateTime::parse_from_rfc3339(raw)
                .map_err(|_| "unparseable revoked_before".to_string())?
                .timestamp_millis(),
        ),
    };
    Ok(AccountStatus {
        active: body.active,
        revoked_before_ms,
    })
}

#[cfg(test)]
pub mod testing {
    //! A scriptable [`StatusFetcher`] for tests in this and other modules.

    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Default)]
    pub struct FakeFetcher {
        answers: Mutex<HashMap<String, Result<AccountStatus, String>>>,
        pub calls: AtomicUsize,
    }

    impl FakeFetcher {
        pub fn new() -> Arc<Self> {
            Arc::new(FakeFetcher::default())
        }

        pub fn set(&self, email: &str, answer: Result<AccountStatus, String>) {
            self.answers.lock().unwrap().insert(email.to_string(), answer);
        }

        pub fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl StatusFetcher for FakeFetcher {
        fn fetch<'a>(&'a self, email: &'a str) -> BoxFuture<'a, Result<AccountStatus, String>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let answer = self
                .answers
                .lock()
                .unwrap()
                .get(email)
                .cloned()
                .unwrap_or_else(|| Err("no scripted answer".to_string()));
            Box::pin(async move { answer })
        }
    }

    pub const ACTIVE: AccountStatus = AccountStatus {
        active: true,
        revoked_before_ms: None,
    };
    pub const INACTIVE: AccountStatus = AccountStatus {
        active: false,
        revoked_before_ms: None,
    };
}

#[cfg(test)]
mod tests {
    use super::testing::{FakeFetcher, ACTIVE, INACTIVE};
    use super::*;

    const EMAIL: &str = "kim@datasee.co.kr";
    const LOGIN: i64 = 1_800_000_000;

    fn service(fetcher: &Arc<FakeFetcher>) -> GatehouseStatus {
        GatehouseStatus::with_fetcher(fetcher.clone())
    }

    #[tokio::test]
    async fn disabled_allows_everything_without_asking() {
        let status = GatehouseStatus::from_config("https://auth.example.com", "");
        assert!(!status.enabled());
        assert_eq!(status.check(EMAIL, LOGIN).await, Verdict::Allow);
        let status = GatehouseStatus::from_config("", "secret");
        assert!(!status.enabled());
        assert!(GatehouseStatus::from_config("https://auth.example.com", "secret").enabled());
    }

    #[tokio::test]
    async fn active_account_is_allowed_and_inactive_is_refused() {
        let fetcher = FakeFetcher::new();
        fetcher.set(EMAIL, Ok(ACTIVE));
        fetcher.set("gone@datasee.co.kr", Ok(INACTIVE));
        let status = service(&fetcher);
        assert_eq!(status.check(EMAIL, LOGIN).await, Verdict::Allow);
        assert_eq!(status.check("gone@datasee.co.kr", LOGIN).await, Verdict::Inactive);
    }

    #[tokio::test]
    async fn sessions_older_than_revoked_before_are_refused() {
        let fetcher = FakeFetcher::new();
        fetcher.set(
            EMAIL,
            Ok(AccountStatus {
                active: true,
                revoked_before_ms: Some(LOGIN * 1000 + 500),
            }),
        );
        let status = service(&fetcher);
        // Logged in before the revocation (even in the same second): refused.
        assert_eq!(status.check(EMAIL, LOGIN - 3600).await, Verdict::Revoked);
        assert_eq!(status.check(EMAIL, LOGIN).await, Verdict::Revoked);
        // Logged in afterwards: fine.
        assert_eq!(status.check(EMAIL, LOGIN + 1).await, Verdict::Allow);
    }

    #[tokio::test]
    async fn answers_are_cached_for_sixty_seconds_per_email_ignoring_case() {
        let fetcher = FakeFetcher::new();
        fetcher.set(EMAIL, Ok(ACTIVE));
        let status = service(&fetcher);
        let t0 = Instant::now();

        assert_eq!(status.check_at(EMAIL, LOGIN, t0).await, Verdict::Allow);
        // Deactivated in gatehouse; the cached answer still holds for a minute.
        fetcher.set(EMAIL, Ok(INACTIVE));
        let later = t0 + Duration::from_secs(59);
        assert_eq!(status.check_at("KIM@Datasee.co.kr", LOGIN, later).await, Verdict::Allow);
        assert_eq!(fetcher.calls(), 1);

        let expired = t0 + Duration::from_secs(61);
        assert_eq!(status.check_at(EMAIL, LOGIN, expired).await, Verdict::Inactive);
        assert_eq!(fetcher.calls(), 2);
    }

    #[tokio::test]
    async fn unreachable_with_no_previous_answer_fails_open() {
        let fetcher = FakeFetcher::new();
        fetcher.set(EMAIL, Err("connection failed".into()));
        let status = service(&fetcher);
        assert_eq!(status.check(EMAIL, LOGIN).await, Verdict::Allow);
    }

    #[tokio::test]
    async fn unreachable_uses_the_last_successful_answer() {
        let fetcher = FakeFetcher::new();
        let status = service(&fetcher);
        let t0 = Instant::now();

        // Last good answer: deactivated.
        fetcher.set(EMAIL, Ok(INACTIVE));
        assert_eq!(status.check_at(EMAIL, LOGIN, t0).await, Verdict::Inactive);
        // gatehouse goes down after the cache entry has expired: the stale
        // "inactive" still applies, however long the outage lasts.
        fetcher.set(EMAIL, Err("HTTP 503".into()));
        let down = t0 + Duration::from_secs(120);
        assert_eq!(status.check_at(EMAIL, LOGIN, down).await, Verdict::Inactive);
        let still_down = t0 + Duration::from_secs(3600);
        assert_eq!(status.check_at(EMAIL, LOGIN, still_down).await, Verdict::Inactive);

        // And the other way round: last good answer "active" keeps a user in.
        let other = "lee@datasee.co.kr";
        fetcher.set(other, Ok(ACTIVE));
        assert_eq!(status.check_at(other, LOGIN, still_down + Duration::from_secs(20)).await, Verdict::Allow);
        fetcher.set(other, Err("timed out".into()));
        let much_later = still_down + Duration::from_secs(600);
        assert_eq!(status.check_at(other, LOGIN, much_later).await, Verdict::Allow);
    }

    #[tokio::test]
    async fn failures_back_off_instead_of_hammering_gatehouse() {
        let fetcher = FakeFetcher::new();
        fetcher.set(EMAIL, Err("timed out".into()));
        let status = service(&fetcher);
        let t0 = Instant::now();

        assert_eq!(status.check_at(EMAIL, LOGIN, t0).await, Verdict::Allow);
        assert_eq!(status.check_at(EMAIL, LOGIN, t0 + Duration::from_secs(5)).await, Verdict::Allow);
        assert_eq!(fetcher.calls(), 1);
        // After the back-off it is asked again, and a recovery takes effect.
        fetcher.set(EMAIL, Ok(INACTIVE));
        assert_eq!(
            status.check_at(EMAIL, LOGIN, t0 + Duration::from_secs(11)).await,
            Verdict::Inactive
        );
        assert_eq!(fetcher.calls(), 2);
    }

    #[test]
    fn response_body_is_parsed_per_the_contract() {
        let body: AccountBody = serde_json::from_str(
            r#"{"email":"a@datasee.co.kr","active":true,"revoked_before":"2026-11-13T03:00:00.000Z"}"#,
        )
        .unwrap();
        assert_eq!(
            parse_body(body).unwrap(),
            AccountStatus {
                active: true,
                revoked_before_ms: Some(1_794_538_800_000),
            }
        );
        let body: AccountBody =
            serde_json::from_str(r#"{"email":"a@datasee.co.kr","active":true,"revoked_before":null}"#)
                .unwrap();
        assert_eq!(parse_body(body).unwrap(), super::testing::ACTIVE);
        // Garbage is a failed lookup (fall back), not "not revoked".
        let body: AccountBody =
            serde_json::from_str(r#"{"active":true,"revoked_before":"yesterday"}"#).unwrap();
        assert!(parse_body(body).is_err());
    }
}
