//! OIDC single sign-on: discovery, JWKS fetching and id_token verification.
//!
//! The client obtains an id_token from the internal IdP out of band and sends
//! it in the AUTH_REQUEST (`authType: "sso"`). This module verifies the token
//! offline against the issuer's published signing keys:
//!
//! 1. `{OIDC_ISSUER}/.well-known/openid-configuration` -> `jwks_uri`
//! 2. fetch the JWKS and cache the keys in memory, keyed by `kid`
//!    (refetched when a token references an unknown `kid`)
//! 3. validate RS256 signature, `iss`, `aud`, `exp` and `email_verified`.
//! 4. require a recent `iat` (`SSO_ID_TOKEN_MAX_AGE_SECS`, 10 minutes by
//!    default) and refuse a token that has been presented before.
//!
//! Step 4 exists because an id_token is a bearer credential with no nonce
//! here: anyone who gets hold of one (a log line, a proxy, the clipboard)
//! could otherwise open their own 30-day VPN session with it for as long as
//! the IdP's `exp` allows, as many times as they like.

use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Mutex;
use tokio::sync::RwLock;

/// Tolerated clock difference between the IdP and this server.
const CLOCK_SKEW_SECS: i64 = 60;
/// Upper bound on remembered tokens. Only tokens that passed signature
/// verification are remembered, so this is reached only if the IdP itself
/// issues that many within the max-age window; beyond it logins are refused
/// rather than letting replay protection silently lapse.
const MAX_SEEN_TOKENS: usize = 100_000;

/// Identity extracted from a verified id_token.
#[derive(Debug, Clone)]
pub struct SsoIdentity {
    /// Verified email address, lowercased.
    pub email: String,
    /// Display name, if the IdP provided one.
    pub name: Option<String>,
    /// When the IdP issued the token (`iat`, unix seconds) — the moment the
    /// user actually authenticated.
    pub issued_at: i64,
}

#[derive(Debug, Deserialize)]
struct DiscoveryDocument {
    jwks_uri: String,
}

/// The subset of an RSA JWK we need for verification.
#[derive(Debug, Clone, Deserialize)]
struct Jwk {
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    kty: String,
    /// Key use; absent or "sig" is acceptable.
    #[serde(rename = "use", default)]
    key_use: Option<String>,
    #[serde(default)]
    n: Option<String>,
    #[serde(default)]
    e: Option<String>,
}

#[derive(Debug, Deserialize)]
struct JwkSet {
    keys: Vec<Jwk>,
}

/// Claims we care about in the id_token. `iss`/`aud`/`exp` are checked by
/// `jsonwebtoken` via [`Validation`], so they need not appear here.
#[derive(Debug, Deserialize)]
struct IdTokenClaims {
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    email_verified: Option<bool>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    iat: Option<i64>,
    exp: i64,
}

/// Remembers id_tokens that have been accepted, until they could no longer be
/// accepted anyway, so each one works exactly once.
///
/// Tokens are identified by their signed part (`header.payload`): it cannot be
/// altered without breaking the signature, and it covers `jti` when the IdP
/// sets one. The set lives in memory, so a restart forgets it — the max-age
/// check bounds what a replay across a restart can use to a few minutes.
#[derive(Default)]
pub struct ReplayGuard {
    /// signed part -> unix second after which the entry can be dropped.
    seen: Mutex<HashMap<String, i64>>,
}

impl ReplayGuard {
    /// Record `token_id` as used. Returns `false` if it was used before (or
    /// the set is full). `forget_after` is when the token stops being
    /// acceptable on other grounds.
    pub fn first_use(&self, token_id: &str, forget_after: i64, now: i64) -> bool {
        let mut seen = self.seen.lock().unwrap();
        seen.retain(|_, until| *until >= now);
        if seen.contains_key(token_id) || seen.len() >= MAX_SEEN_TOKENS {
            return false;
        }
        seen.insert(token_id.to_string(), forget_after);
        true
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.seen.lock().unwrap().len()
    }
}

/// Is a token issued at `iat` recent enough at `now`?
fn fresh_enough(iat: i64, now: i64, max_age_secs: i64) -> bool {
    // Not from the future (beyond clock skew), and not older than the limit.
    iat <= now + CLOCK_SKEW_SECS && now - iat <= max_age_secs + CLOCK_SKEW_SECS
}

/// Verifies OIDC id_tokens against a single issuer, caching JWKS keys.
pub struct SsoVerifier {
    issuer: String,
    client_id: String,
    http: reqwest::Client,
    /// JWKS cache: `kid` -> RSA components (`n`, `e`).
    keys: RwLock<HashMap<String, (String, String)>>,
    /// Oldest acceptable token, by `iat`, in seconds.
    max_age_secs: i64,
    replay: ReplayGuard,
}

impl SsoVerifier {
    pub fn new(issuer: String, client_id: String, max_age_secs: i64) -> Self {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("failed to build HTTP client for OIDC");
        SsoVerifier {
            issuer,
            client_id,
            http,
            keys: RwLock::new(HashMap::new()),
            max_age_secs,
            replay: ReplayGuard::default(),
        }
    }

    /// Verify an id_token and extract the caller's identity.
    ///
    /// Errors are client-safe messages; details are logged server-side.
    pub async fn verify_id_token(&self, token: &str) -> Result<SsoIdentity, String> {
        let header = decode_header(token).map_err(|e| {
            tracing::warn!("SSO: malformed id_token header: {e}");
            "Invalid SSO token".to_string()
        })?;
        let Some(kid) = header.kid else {
            tracing::warn!("SSO: id_token has no kid header");
            return Err("Invalid SSO token".to_string());
        };

        let (n, e) = self.key_for(&kid).await?;
        let key = DecodingKey::from_rsa_components(&n, &e).map_err(|err| {
            tracing::error!("SSO: bad RSA components in JWK {kid}: {err}");
            "Invalid SSO token".to_string()
        })?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[&self.client_id]);
        // `exp` is validated by default.

        let data = decode::<IdTokenClaims>(token, &key, &validation).map_err(|e| {
            tracing::warn!("SSO: id_token rejected: {e}");
            "Invalid SSO token".to_string()
        })?;

        // The signature is good; everything after this is about *this use* of
        // the token.
        let signed_part = token.rsplit_once('.').map_or(token, |(signed, _)| signed);
        self.accept_claims(data.claims, signed_part, chrono::Utc::now().timestamp())
    }

    /// Post-signature checks: verified email, freshness, single use.
    fn accept_claims(
        &self,
        claims: IdTokenClaims,
        signed_part: &str,
        now: i64,
    ) -> Result<SsoIdentity, String> {
        if claims.email_verified != Some(true) {
            tracing::warn!("SSO: id_token email is not verified");
            return Err("SSO email is not verified".to_string());
        }
        let Some(email) = claims.email.as_deref().map(str::trim).filter(|s| !s.is_empty())
        else {
            tracing::warn!("SSO: id_token has no email claim");
            return Err("SSO token has no email".to_string());
        };
        let email = email.to_lowercase();

        let Some(iat) = claims.iat else {
            tracing::warn!("SSO: id_token for {email} has no iat claim");
            return Err("Invalid SSO token".to_string());
        };
        if !fresh_enough(iat, now, self.max_age_secs) {
            tracing::warn!(
                "SSO: id_token for {email} was issued {}s ago (limit {}s), rejecting",
                now - iat,
                self.max_age_secs
            );
            return Err("SSO token is too old — sign in again".to_string());
        }

        // Remember it for as long as it would otherwise still be accepted:
        // until it expires or ages out, whichever comes first.
        let forget_after = claims.exp.min(iat + self.max_age_secs) + CLOCK_SKEW_SECS + 60;
        if !self.replay.first_use(signed_part, forget_after, now) {
            tracing::warn!("SSO: id_token for {email} was presented a second time, rejecting");
            return Err("SSO token was already used — sign in again".to_string());
        }

        Ok(SsoIdentity {
            email,
            name: claims.name,
            issued_at: iat.min(now),
        })
    }

    /// Look up the RSA components for `kid`, refetching the JWKS when the key
    /// is not in the cache (key rotation).
    async fn key_for(&self, kid: &str) -> Result<(String, String), String> {
        if let Some(key) = self.keys.read().await.get(kid) {
            return Ok(key.clone());
        }

        self.refresh_keys().await?;

        match self.keys.read().await.get(kid) {
            Some(key) => Ok(key.clone()),
            None => {
                tracing::warn!("SSO: id_token signed with unknown kid {kid}");
                Err("Invalid SSO token".to_string())
            }
        }
    }

    /// Fetch the discovery document and JWKS, replacing the key cache.
    async fn refresh_keys(&self) -> Result<(), String> {
        let discovery_url = format!(
            "{}/.well-known/openid-configuration",
            self.issuer.trim_end_matches('/')
        );

        let discovery: DiscoveryDocument = self
            .http
            .get(&discovery_url)
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|e| {
                tracing::error!("SSO: OIDC discovery fetch failed ({discovery_url}): {e}");
                "SSO provider unavailable".to_string()
            })?
            .json()
            .await
            .map_err(|e| {
                tracing::error!("SSO: bad OIDC discovery document: {e}");
                "SSO provider unavailable".to_string()
            })?;

        let jwks: JwkSet = self
            .http
            .get(&discovery.jwks_uri)
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|e| {
                tracing::error!("SSO: JWKS fetch failed ({}): {e}", discovery.jwks_uri);
                "SSO provider unavailable".to_string()
            })?
            .json()
            .await
            .map_err(|e| {
                tracing::error!("SSO: bad JWKS document: {e}");
                "SSO provider unavailable".to_string()
            })?;

        let mut fresh = HashMap::new();
        for jwk in jwks.keys {
            let usable = jwk.kty == "RSA"
                && matches!(jwk.key_use.as_deref(), None | Some("sig"));
            if let (true, Some(kid), Some(n), Some(e)) = (usable, jwk.kid, jwk.n, jwk.e) {
                fresh.insert(kid, (n, e));
            }
        }
        tracing::info!("SSO: loaded {} signing key(s) from JWKS", fresh.len());

        *self.keys.write().await = fresh;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    //! The post-signature checks. (Signature, issuer, audience and expiry are
    //! `jsonwebtoken`'s job and need an RSA key to exercise.)

    use super::*;

    const NOW: i64 = 1_800_000_000;
    const MAX_AGE: i64 = 600;

    fn verifier() -> SsoVerifier {
        SsoVerifier::new("https://idp.example.com".into(), "opentunnel".into(), MAX_AGE)
    }

    fn claims(iat: Option<i64>) -> IdTokenClaims {
        IdTokenClaims {
            email: Some("Kim@Datasee.co.kr".into()),
            email_verified: Some(true),
            name: None,
            iat,
            exp: iat.unwrap_or(NOW) + 3600,
        }
    }

    #[test]
    fn fresh_token_is_accepted_once_and_refused_on_replay() {
        let v = verifier();
        let identity = v.accept_claims(claims(Some(NOW - 5)), "header.payload-a", NOW).unwrap();
        assert_eq!(identity.email, "kim@datasee.co.kr");
        assert_eq!(identity.issued_at, NOW - 5);

        // The very same token again — a second later or minutes later.
        let replay = v.accept_claims(claims(Some(NOW - 5)), "header.payload-a", NOW + 1);
        assert_eq!(replay.unwrap_err(), "SSO token was already used — sign in again");
        assert!(v.accept_claims(claims(Some(NOW - 5)), "header.payload-a", NOW + 300).is_err());

        // A different token for the same user is unaffected.
        assert!(v.accept_claims(claims(Some(NOW)), "header.payload-b", NOW + 1).is_ok());
    }

    #[test]
    fn token_older_than_the_max_age_is_refused() {
        let v = verifier();
        // Inside the limit (plus skew allowance) is fine.
        assert!(v.accept_claims(claims(Some(NOW - MAX_AGE)), "t1", NOW).is_ok());
        // Past it is not, even though `exp` is still an hour away.
        let old = v.accept_claims(claims(Some(NOW - MAX_AGE - CLOCK_SKEW_SECS - 1)), "t2", NOW);
        assert_eq!(old.unwrap_err(), "SSO token is too old — sign in again");
        // Nor is one from the future, or one with no iat at all.
        assert!(v.accept_claims(claims(Some(NOW + CLOCK_SKEW_SECS + 1)), "t3", NOW).is_err());
        assert!(v.accept_claims(claims(None), "t4", NOW).is_err());
    }

    #[test]
    fn refused_tokens_are_not_remembered_and_old_entries_are_dropped() {
        let v = verifier();
        assert!(v.accept_claims(claims(None), "bad", NOW).is_err());
        assert_eq!(v.replay.len(), 0);

        assert!(v.accept_claims(claims(Some(NOW)), "t1", NOW).is_ok());
        assert_eq!(v.replay.len(), 1);
        // Once the token could not be accepted anyway, its entry goes away.
        let much_later = NOW + MAX_AGE + 3600;
        assert!(v.accept_claims(claims(Some(much_later)), "t2", much_later).is_ok());
        assert_eq!(v.replay.len(), 1);
        // ...and it is still refused then, by the age check.
        assert!(v.accept_claims(claims(Some(NOW)), "t1", much_later).is_err());
    }

    #[test]
    fn unverified_email_is_refused_before_anything_is_recorded() {
        let v = verifier();
        let mut c = claims(Some(NOW));
        c.email_verified = Some(false);
        assert!(v.accept_claims(c, "t1", NOW).is_err());
        assert_eq!(v.replay.len(), 0);
    }
}
