//! Persisted session state: `~/.config/opentunnel/session.json`
//! (directory 0700, file 0600) plus minimal local JWT-payload parsing.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionFile {
    /// VPN server this token was issued by (host:port).
    pub server: String,
    /// IdP issuer used for the original login.
    pub issuer: String,
    /// Email from the OIDC id_token at login time (display only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// `username` claim of the session JWT (display only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// The OpenTunnel session JWT (HS256, rotated on every renew).
    pub session_token: String,
    /// Unix seconds when this token was stored.
    pub issued_at: u64,
    /// Unix seconds of the JWT `exp` claim.
    pub expires_at: u64,
}

impl SessionFile {
    pub fn is_expired(&self) -> bool {
        now_unix() >= self.expires_at
    }
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn session_path() -> Result<PathBuf, String> {
    let home = std::env::var_os("HOME").ok_or("HOME 환경변수가 없습니다")?;
    Ok(PathBuf::from(home)
        .join(".config")
        .join("opentunnel")
        .join("session.json"))
}

pub fn load() -> Result<Option<SessionFile>, String> {
    let path = session_path()?;
    let data = match fs::read(&path) {
        Ok(data) => data,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("{} 읽기 실패: {e}", path.display())),
    };
    serde_json::from_slice(&data)
        .map(Some)
        .map_err(|e| format!("{} 해석 실패 (다시 로그인하세요): {e}", path.display()))
}

pub fn save(session: &SessionFile) -> Result<PathBuf, String> {
    let path = session_path()?;
    let dir = path.parent().expect("session path has a parent");
    fs::create_dir_all(dir).map_err(|e| format!("{} 생성 실패: {e}", dir.display()))?;

    let json =
        serde_json::to_vec_pretty(session).map_err(|e| format!("세션 직렬화 실패: {e}"))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("{} 권한 설정 실패: {e}", dir.display()))?;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| format!("{} 쓰기 실패: {e}", path.display()))?;
        // In case the file pre-existed with looser permissions.
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("{} 권한 설정 실패: {e}", path.display()))?;
        file.write_all(&json)
            .map_err(|e| format!("{} 쓰기 실패: {e}", path.display()))?;
    }
    #[cfg(not(unix))]
    {
        fs::write(&path, &json).map_err(|e| format!("{} 쓰기 실패: {e}", path.display()))?;
    }

    Ok(path)
}

/// Delete the session file. Returns whether a file existed.
pub fn delete() -> Result<bool, String> {
    let path = session_path()?;
    match fs::remove_file(&path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(format!("{} 삭제 실패: {e}", path.display())),
    }
}

/// Decode a JWT payload (no signature verification — display/expiry use only).
pub fn jwt_claims(token: &str) -> Option<serde_json::Value> {
    let payload = token.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(payload).ok()?;
    serde_json::from_slice(&bytes).ok()
}

pub fn jwt_exp(token: &str) -> Option<u64> {
    jwt_claims(token)?.get("exp")?.as_u64()
}

pub fn jwt_str_claim(token: &str, name: &str) -> Option<String> {
    jwt_claims(token)?
        .get(name)?
        .as_str()
        .map(|s| s.to_string())
}

/// Format a unix timestamp as KST (UTC+9), e.g. "2026-09-24 16:12 KST".
pub fn format_kst(ts: u64) -> String {
    let t = ts as i64 + 9 * 3600;
    let days = t.div_euclid(86400);
    let secs = t.rem_euclid(86400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02} KST",
        secs / 3600,
        (secs % 3600) / 60
    )
}

/// Human-readable remaining duration, e.g. "29일 5시간".
pub fn format_remaining(expires_at: u64) -> String {
    let now = now_unix();
    if expires_at <= now {
        return "만료됨".to_string();
    }
    let left = expires_at - now;
    let days = left / 86400;
    let hours = (left % 86400) / 3600;
    let minutes = (left % 3600) / 60;
    if days > 0 {
        format!("{days}일 {hours}시간")
    } else if hours > 0 {
        format!("{hours}시간 {minutes}분")
    } else {
        format!("{minutes}분")
    }
}

/// Days-since-epoch -> (year, month, day). Howard Hinnant's civil_from_days.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097); // day of era [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // year of era
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // day of year [0, 365]
    let mp = (5 * doy + 2) / 153; // month index [0, 11], March = 0
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_from_days_epoch_and_beyond() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(19_723), (2024, 1, 1)); // 2024-01-01
    }

    #[test]
    fn jwt_exp_parses_unsigned_payload() {
        // header "{}" + payload {"exp":1234567890,"username":"a@b.c"} + fake sig
        let payload = URL_SAFE_NO_PAD.encode(br#"{"exp":1234567890,"username":"a@b.c"}"#);
        let token = format!("e30.{payload}.sig");
        assert_eq!(jwt_exp(&token), Some(1_234_567_890));
        assert_eq!(jwt_str_claim(&token, "username").as_deref(), Some("a@b.c"));
    }
}
