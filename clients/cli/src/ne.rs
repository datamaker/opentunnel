//! macOS: drive the OpenTunnel.app NetworkExtension tunnel via `scutil --nc`.
//!
//! No root needed. The tunnel re-authenticates with the session token the app
//! stored on its last connect (the server rotates it on every connect), so as
//! long as the app has logged in once, `opentunnel connect` works headlessly.
//! NOTE: that NE-stored token is SEPARATE from the CLI's session.json token.

use std::process::Command;
use std::time::Duration;

/// The app's NetworkExtension provider bundle id, as shown by `scutil --nc list`.
const NE_SERVICE_HINT: &str = "kr.co.datasee.VPNClient";
/// Internal-network smoke target reachable only through the VPN.
const SMOKE_TARGET: &str = "11.0.1.21:443";
const SMOKE_TIMEOUT: Duration = Duration::from_secs(3);
const CONNECT_WAIT: Duration = Duration::from_secs(30);
const DISCONNECT_WAIT: Duration = Duration::from_secs(10);
const POLL_INTERVAL: Duration = Duration::from_secs(1);

pub const NOT_INSTALLED_HINT: &str =
    "OpenTunnel 앱이 설치되어 있고, 앱에서 최초 1회 로그인/연결한 적이 있어야 합니다";
const TOKEN_EXPIRED_HINT: &str = "연결이 거부되었습니다. 앱(NE 설정)에 저장된 세션 토큰이 만료되었을 수 있습니다.\n\
     OpenTunnel 앱에서 한 번 로그인/연결한 뒤 다시 시도하세요.\n\
     (참고: CLI의 session.json 토큰과 앱(NE)의 토큰은 별개입니다 — `opentunnel renew`는 NE 토큰을 갱신하지 않습니다)";

fn scutil(args: &[&str]) -> Result<String, String> {
    let output = Command::new("scutil")
        .args(args)
        .output()
        .map_err(|e| format!("scutil 실행 실패: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "scutil {} 실패: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Parse `scutil --nc list` output and return the service UUID of the
/// OpenTunnel NetworkExtension entry, e.g. from a line like:
/// `* (Disconnected)   3B01D5D3-... VPN (kr.co.datasee.VPNClient) "VPN Client" [VPN:kr.co.datasee.VPNClient]`
pub fn parse_service_id(list_output: &str) -> Option<String> {
    for line in list_output.lines() {
        if !line.contains(NE_SERVICE_HINT) {
            continue;
        }
        for token in line.split_whitespace() {
            if is_service_uuid(token) {
                return Some(token.to_string());
            }
        }
    }
    None
}

fn is_service_uuid(token: &str) -> bool {
    let bytes = token.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    for (i, b) in bytes.iter().enumerate() {
        match i {
            8 | 13 | 18 | 23 => {
                if *b != b'-' {
                    return false;
                }
            }
            _ => {
                if !b.is_ascii_hexdigit() {
                    return false;
                }
            }
        }
    }
    true
}

fn find_service() -> Result<String, String> {
    let list = scutil(&["--nc", "list"])?;
    parse_service_id(&list)
        .ok_or_else(|| format!("OpenTunnel VPN 설정을 찾지 못했습니다. {NOT_INSTALLED_HINT}"))
}

/// First line of `scutil --nc status`: "Connected" / "Connecting" /
/// "Disconnected" / "Disconnecting".
fn service_state(service_id: &str) -> Result<String, String> {
    let out = scutil(&["--nc", "status", service_id])?;
    Ok(out.lines().next().unwrap_or("Unknown").trim().to_string())
}

/// Best-effort NE state for `opentunnel status` display. None when the app is
/// not installed or scutil is unavailable.
pub fn current_state() -> Option<(String, String)> {
    let service_id = find_service().ok()?;
    let state = service_state(&service_id).ok()?;
    Some((service_id, state))
}

/// Internal-network reachability probe through the tunnel. Retries a few
/// times: right after the NE reports Connected, the tunnel routes may still be
/// settling (observed live — first probe can time out, second succeeds).
async fn smoke_test() -> Result<(), String> {
    const ATTEMPTS: u32 = 4;
    let mut last_error = String::new();
    for attempt in 1..=ATTEMPTS {
        if attempt > 1 {
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        match tokio::time::timeout(SMOKE_TIMEOUT, tokio::net::TcpStream::connect(SMOKE_TARGET))
            .await
        {
            Ok(Ok(_)) => return Ok(()),
            Ok(Err(e)) => last_error = format!("{SMOKE_TARGET} 연결 실패: {e}"),
            Err(_) => last_error = format!("{SMOKE_TARGET} 연결 시간 초과"),
        }
    }
    Err(format!("{last_error} ({ATTEMPTS}회 시도)"))
}

pub async fn connect() -> Result<(), String> {
    let service_id = find_service()?;
    let state = service_state(&service_id)?;
    println!("NE 서비스: {service_id} (현재: {state})");

    if state != "Connected" {
        println!("VPN 시작 중... (scutil --nc start)");
        scutil(&["--nc", "start", &service_id])?;

        // Poll until Connected. A "Disconnected" right after start is normal;
        // only treat it as a rejection once we have seen "Connecting" first
        // (that transition means the server refused the NE-stored token).
        let mut seen_connecting = false;
        let deadline = tokio::time::Instant::now() + CONNECT_WAIT;
        loop {
            tokio::time::sleep(POLL_INTERVAL).await;
            let state = service_state(&service_id)?;
            match state.as_str() {
                "Connected" => break,
                "Connecting" => seen_connecting = true,
                "Disconnected" if seen_connecting => return Err(TOKEN_EXPIRED_HINT.to_string()),
                _ => {}
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(format!(
                    "{}초 내에 연결되지 않았습니다 (마지막 상태: {state}).\n{TOKEN_EXPIRED_HINT}",
                    CONNECT_WAIT.as_secs()
                ));
            }
        }
    } else {
        println!("이미 연결되어 있습니다.");
    }

    print!("내부망 도달성 확인 중 ({SMOKE_TARGET})... ");
    match smoke_test().await {
        Ok(()) => {
            println!("OK");
            println!("VPN 연결됨 + 내부망 도달 확인");
            Ok(())
        }
        Err(e) => {
            println!("실패");
            Err(format!(
                "VPN은 Connected 상태지만 내부망 도달성 확인에 실패했습니다: {e}\n\
                 (스플릿터널 라우트/서버 상태를 확인하세요)"
            ))
        }
    }
}

pub async fn disconnect() -> Result<(), String> {
    let service_id = find_service()?;
    let state = service_state(&service_id)?;
    if state == "Disconnected" {
        println!("이미 연결 해제 상태입니다.");
        return Ok(());
    }

    println!("VPN 중지 중... (scutil --nc stop)");
    scutil(&["--nc", "stop", &service_id])?;

    let deadline = tokio::time::Instant::now() + DISCONNECT_WAIT;
    loop {
        tokio::time::sleep(POLL_INTERVAL).await;
        let state = service_state(&service_id)?;
        if state == "Disconnected" {
            println!("VPN 연결 해제됨");
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(format!("연결 해제가 확인되지 않았습니다 (상태: {state})"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_real_scutil_list_line() {
        // Verbatim shape of `scutil --nc list` on the reference machine.
        let out = "Available network connection services in the current set (*=enabled):\n\
             * (Disconnected)   3B01D5D3-AECB-4878-8584-29DE29311CFE VPN (kr.co.datasee.VPNClient) \"VPN Client\"                     [VPN:kr.co.datasee.VPNClient]\n";
        assert_eq!(
            parse_service_id(out).as_deref(),
            Some("3B01D5D3-AECB-4878-8584-29DE29311CFE")
        );
    }

    #[test]
    fn ignores_unrelated_services() {
        let out = "* (Connected)   11111111-2222-3333-4444-555555555555 IPSec \"Other VPN\" [IPSec]\n";
        assert_eq!(parse_service_id(out), None);
    }

    #[test]
    fn uuid_shape_check() {
        assert!(is_service_uuid("3B01D5D3-AECB-4878-8584-29DE29311CFE"));
        assert!(!is_service_uuid("VPN"));
        assert!(!is_service_uuid("3B01D5D3-AECB-4878-8584-29DE29311CF")); // 35 chars
        assert!(!is_service_uuid("3B01D5D3xAECB-4878-8584-29DE29311CFE"));
    }
}
