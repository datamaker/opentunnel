//! Runtime-editable settings, stored in the database.
//!
//! Environment variables stay the bootstrap source: they are what a fresh
//! install comes up with, and they remain the only source for anything that
//! decides who may administer the server. Everything an operator legitimately
//! changes while the service runs — the split-tunnel policy above all — lives
//! here instead, so a container restart no longer discards it.
//!
//! Precedence at boot is database over environment, per key. A key absent from
//! the database falls back to its environment value, so an existing deployment
//! keeps behaving exactly as before until someone edits it.
//!
//! Deliberately *not* editable here:
//!
//! - `JWT_SECRET` — session tokens are signed with it, so being able to set it
//!   is being able to mint any session.
//! - `ADMIN_TRUSTED_PROXIES` — it decides whose `X-Auth-Email` header is
//!   believed. Editing it from behind that same header is a way to widen the
//!   trust boundary you already stand inside.
//! - `ADMIN_PASSWORD` — the break-glass credential, which needs a
//!   confirm-old-password flow rather than a settings field.
//!
//! `ADMIN_SSO_EMAILS` *is* editable: granting a colleague admin is ordinary
//! operator work, and every change is written to the audit log.

use crate::db::DbPool;
use std::collections::HashMap;

/// How a value is parsed, and how the panel should render it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Bool,
    Int,
    /// Comma-separated list.
    Csv,
}

/// Whether an edit takes effect immediately or waits for a restart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Apply {
    /// Re-read on every use, or pushed into live state when saved.
    Live,
    /// Read once during startup.
    Restart,
}

pub struct Definition {
    pub key: &'static str,
    pub kind: Kind,
    pub apply: Apply,
    pub group: &'static str,
    pub label: &'static str,
    pub help: &'static str,
}

/// Every key the panel may edit. Anything not listed here is env-only, and
/// `set` refuses it — the panel cannot be talked into writing an arbitrary key.
pub const EDITABLE: &[Definition] = &[
    Definition {
        key: "SPLIT_TUNNEL",
        kind: Kind::Bool,
        apply: Apply::Live,
        group: "스플릿 터널",
        label: "스플릿 터널 사용",
        help: "끄면 클라이언트가 모든 트래픽을 터널로 보냅니다.",
    },
    Definition {
        key: "SPLIT_INCLUDE_ROUTES",
        kind: Kind::Csv,
        apply: Apply::Live,
        group: "스플릿 터널",
        label: "고정 라우트",
        help: "CIDR 목록. 사내 대역처럼 IP가 바뀌지 않는 목적지.",
    },
    Definition {
        key: "SPLIT_INCLUDE_DOMAINS",
        kind: Kind::Csv,
        apply: Apply::Live,
        group: "스플릿 터널",
        label: "도메인",
        help: "와일드카드(*.example.com)는 서버가 해석하지 않습니다 — \
               접근돼야 하는 호스트는 명시로 넣으세요.",
    },
    Definition {
        key: "SPLIT_DNS_REFRESH_SECS",
        kind: Kind::Int,
        apply: Apply::Restart,
        group: "스플릿 터널",
        label: "도메인 재해석 주기(초)",
        help: "주기 자체는 기동 시 정해집니다.",
    },
    Definition {
        key: "VPN_DNS",
        kind: Kind::Csv,
        apply: Apply::Restart,
        group: "VPN",
        label: "DNS 서버",
        help: "접속하는 클라이언트에 내려줍니다.",
    },
    Definition {
        key: "VPN_MTU",
        kind: Kind::Int,
        apply: Apply::Restart,
        group: "VPN",
        label: "MTU",
        help: "접속하는 클라이언트에 내려줍니다.",
    },
    Definition {
        key: "SSO_ALLOWED_DOMAINS",
        kind: Kind::Csv,
        apply: Apply::Live,
        group: "SSO",
        label: "VPN 로그인 허용 도메인",
        help: "도메인 또는 전체 이메일. 비우면 IdP가 인증한 계정이 모두 허용됩니다.",
    },
    Definition {
        key: "SSO_SESSION_TTL_DAYS",
        kind: Kind::Int,
        apply: Apply::Restart,
        group: "SSO",
        label: "세션 토큰 수명(일)",
        help: "SSO 로그인으로 발급되는 토큰의 유효 기간.",
    },
    Definition {
        key: "ADMIN_SSO_EMAILS",
        kind: Kind::Csv,
        apply: Apply::Live,
        group: "관리자",
        label: "관리자 이메일",
        help: "이 패널에 로그인할 수 있는 계정. 비우면 SSO 로그인이 꺼집니다.",
    },
];

pub fn definition(key: &str) -> Option<&'static Definition> {
    EDITABLE.iter().find(|d| d.key == key)
}

/// Reject values that would not survive a round-trip through the config
/// parsers, so a typo surfaces at save time rather than at the next restart.
pub fn validate(key: &str, value: &str) -> Result<(), String> {
    let Some(def) = definition(key) else {
        return Err(format!("{key} is not editable"));
    };
    match def.kind {
        Kind::Bool => match value {
            "true" | "false" => Ok(()),
            _ => Err(format!("{key}: true 또는 false여야 합니다")),
        },
        Kind::Int => value
            .trim()
            .parse::<u32>()
            .map(|_| ())
            .map_err(|_| format!("{key}: 0 이상의 정수여야 합니다")),
        Kind::Csv => {
            if value.split(',').any(|p| p.contains(char::is_whitespace) && !p.trim().is_empty() && p.trim().contains(char::is_whitespace)) {
                return Err(format!("{key}: 항목 안에 공백을 넣을 수 없습니다"));
            }
            Ok(())
        }
    }
}

#[derive(Clone)]
pub struct Store {
    db: DbPool,
}

impl Store {
    pub fn new(db: DbPool) -> Self {
        Store { db }
    }

    /// Create the tables when missing. `schema.sql` only runs on a fresh
    /// database, so an existing deployment would never otherwise get them.
    pub async fn ensure_schema(&self) -> anyhow::Result<()> {
        let client = self.db.get().await?;
        client
            .batch_execute(
                "CREATE TABLE IF NOT EXISTS settings (
                     key         TEXT PRIMARY KEY,
                     value       TEXT NOT NULL,
                     updated_at  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
                     updated_by  TEXT
                 );
                 CREATE TABLE IF NOT EXISTS admin_audit (
                     id         BIGSERIAL PRIMARY KEY,
                     actor      TEXT NOT NULL,
                     action     TEXT NOT NULL,
                     detail     TEXT,
                     created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
                 );
                 CREATE INDEX IF NOT EXISTS admin_audit_created_idx
                     ON admin_audit (created_at DESC);",
            )
            .await?;
        Ok(())
    }

    /// Every stored override. Errors are logged and treated as "no overrides"
    /// so a database problem degrades to environment config instead of
    /// preventing startup.
    pub async fn load(&self) -> HashMap<String, String> {
        let mut out = HashMap::new();
        let client = match self.db.get().await {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("settings: database unavailable, using env only: {e}");
                return out;
            }
        };
        match client.query("SELECT key, value FROM settings", &[]).await {
            Ok(rows) => {
                for row in rows {
                    let key: String = row.get(0);
                    // Drop keys that are no longer editable (e.g. left behind
                    // by an older version) rather than applying them blindly.
                    if definition(&key).is_some() {
                        out.insert(key, row.get(1));
                    }
                }
            }
            Err(e) => tracing::error!("settings: read failed, using env only: {e}"),
        }
        out
    }

    /// Upsert one setting and record who changed it.
    pub async fn set(&self, key: &str, value: &str, actor: &str) -> Result<(), String> {
        validate(key, value)?;
        let client = self.db.get().await.map_err(|e| e.to_string())?;

        let previous: Option<String> = client
            .query_opt("SELECT value FROM settings WHERE key = $1", &[&key])
            .await
            .ok()
            .flatten()
            .map(|row| row.get(0));

        client
            .execute(
                "INSERT INTO settings (key, value, updated_by, updated_at)
                 VALUES ($1, $2, $3, CURRENT_TIMESTAMP)
                 ON CONFLICT (key) DO UPDATE
                 SET value = EXCLUDED.value,
                     updated_by = EXCLUDED.updated_by,
                     updated_at = CURRENT_TIMESTAMP",
                &[&key, &value, &actor],
            )
            .await
            .map_err(|e| e.to_string())?;

        // The audit entry carries the old value too: "who set the admin list to
        // X" is only half the story without what it was before.
        let detail = match previous {
            Some(prev) if prev == value => return Ok(()), // no-op, nothing to log
            Some(prev) => format!("{key}: {prev:?} → {value:?}"),
            None => format!("{key}: (기본값) → {value:?}"),
        };
        self.audit(actor, "settings.update", &detail).await;
        Ok(())
    }

    /// Append an audit entry. Best-effort: a failure here must not abort the
    /// operation the caller already performed.
    pub async fn audit(&self, actor: &str, action: &str, detail: &str) {
        let client = match self.db.get().await {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("audit: database unavailable ({e}); {actor} {action}: {detail}");
                return;
            }
        };
        if let Err(e) = client
            .execute(
                "INSERT INTO admin_audit (actor, action, detail) VALUES ($1, $2, $3)",
                &[&actor, &action, &detail],
            )
            .await
        {
            tracing::error!("audit: write failed ({e}); {actor} {action}: {detail}");
        }
        tracing::info!("audit: {actor} {action} — {detail}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_listed_keys_are_editable() {
        assert!(definition("SPLIT_INCLUDE_DOMAINS").is_some());
        // The keys that decide who may administer the server stay in env.
        assert!(definition("JWT_SECRET").is_none());
        assert!(definition("ADMIN_TRUSTED_PROXIES").is_none());
        assert!(definition("ADMIN_PASSWORD").is_none());
        assert!(definition("DB_PASSWORD").is_none());
    }

    #[test]
    fn set_refuses_unlisted_keys() {
        assert!(validate("JWT_SECRET", "anything").is_err());
        assert!(validate("NOT_A_KEY", "x").is_err());
    }

    #[test]
    fn bool_and_int_are_checked() {
        assert!(validate("SPLIT_TUNNEL", "true").is_ok());
        assert!(validate("SPLIT_TUNNEL", "yes").is_err());
        assert!(validate("VPN_MTU", "1400").is_ok());
        assert!(validate("VPN_MTU", "-1").is_err());
        assert!(validate("VPN_MTU", "big").is_err());
    }

    #[test]
    fn csv_accepts_empty_and_lists() {
        assert!(validate("SPLIT_INCLUDE_DOMAINS", "").is_ok());
        assert!(validate("SPLIT_INCLUDE_DOMAINS", "a.example.com,*.example.com").is_ok());
        // Surrounding whitespace is fine (it gets trimmed downstream); an
        // embedded space means a mistyped separator.
        assert!(validate("SPLIT_INCLUDE_DOMAINS", " a.example.com , b.example.com ").is_ok());
        assert!(validate("SPLIT_INCLUDE_DOMAINS", "a.example.com b.example.com").is_err());
    }
}
