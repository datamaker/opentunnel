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

use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use std::collections::HashMap;
use tokio::sync::RwLock;

/// Identity extracted from a verified id_token.
#[derive(Debug, Clone)]
pub struct SsoIdentity {
    /// Verified email address, lowercased.
    pub email: String,
    /// Display name, if the IdP provided one.
    pub name: Option<String>,
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
}

/// Verifies OIDC id_tokens against a single issuer, caching JWKS keys.
pub struct SsoVerifier {
    issuer: String,
    client_id: String,
    http: reqwest::Client,
    /// JWKS cache: `kid` -> RSA components (`n`, `e`).
    keys: RwLock<HashMap<String, (String, String)>>,
}

impl SsoVerifier {
    pub fn new(issuer: String, client_id: String) -> Self {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("failed to build HTTP client for OIDC");
        SsoVerifier {
            issuer,
            client_id,
            http,
            keys: RwLock::new(HashMap::new()),
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

        if data.claims.email_verified != Some(true) {
            tracing::warn!("SSO: id_token email is not verified");
            return Err("SSO email is not verified".to_string());
        }
        let Some(email) = data.claims.email.as_deref().map(str::trim).filter(|s| !s.is_empty())
        else {
            tracing::warn!("SSO: id_token has no email claim");
            return Err("SSO token has no email".to_string());
        };

        Ok(SsoIdentity {
            email: email.to_lowercase(),
            name: data.claims.name,
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
