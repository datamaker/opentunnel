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

/// Parse `scutil --nc list` output and return the service UUIDs of every
/// OpenTunnel NetworkExtension entry, e.g. from lines like:
/// `* (Disconnected)   3B01D5D3-... VPN (kr.co.datasee.VPNClient) "VPN Client" [VPN:kr.co.datasee.VPNClient]`
///
/// More than one entry is a real state, not an anomaly: an NE configuration is
/// bound to the exact app copy that saved it, so a reinstalled/rebuilt app that
/// can no longer see the old configuration creates a fresh one ("VPN Client 2")
/// and the orphan stays listed. Starting the orphan fails instantly
/// (configurationFailed), so every operation must consider all entries instead
/// of blindly taking the first line.
pub fn parse_service_ids(list_output: &str) -> Vec<String> {
    let mut ids = Vec::new();
    for line in list_output.lines() {
        if !line.contains(NE_SERVICE_HINT) {
            continue;
        }
        for token in line.split_whitespace() {
            if is_service_uuid(token) {
                ids.push(token.to_string());
                break;
            }
        }
    }
    ids
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

fn find_services() -> Result<Vec<String>, String> {
    let list = scutil(&["--nc", "list"])?;
    let ids = parse_service_ids(&list);
    if ids.is_empty() {
        return Err(format!(
            "OpenTunnel VPN 설정을 찾지 못했습니다. {NOT_INSTALLED_HINT}"
        ));
    }
    Ok(ids)
}

/// First line of `scutil --nc status`: "Connected" / "Connecting" /
/// "Disconnected" / "Disconnecting".
fn service_state(service_id: &str) -> Result<String, String> {
    let out = scutil(&["--nc", "status", service_id])?;
    Ok(out.lines().next().unwrap_or("Unknown").trim().to_string())
}

/// Best-effort NE state for `opentunnel status` display — one entry per
/// registered service. Empty when the app is not installed or scutil is
/// unavailable.
pub fn current_state() -> Vec<(String, String)> {
    let Ok(ids) = find_services() else {
        return Vec::new();
    };
    ids.into_iter()
        .filter_map(|id| service_state(&id).ok().map(|state| (id, state)))
        .collect()
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

/// Poll `scutil --nc status` across all services until one reports Connected
/// (up to 30s). Which service the app connects is its choice (it may even have
/// just created a fresh configuration), so any Connected entry counts. A
/// `Disconnected` seen only after `Connecting` on the same service means the
/// server refused the NE-stored token — reported as such once no service is
/// still making progress.
async fn poll_any_connected(service_ids: &[String]) -> Result<String, String> {
    let mut seen_connecting = vec![false; service_ids.len()];
    let mut rejected = vec![false; service_ids.len()];
    let deadline = tokio::time::Instant::now() + CONNECT_WAIT;
    loop {
        tokio::time::sleep(POLL_INTERVAL).await;
        let mut last_state = String::from("Unknown");
        for (i, id) in service_ids.iter().enumerate() {
            let state = service_state(id)?;
            match state.as_str() {
                "Connected" => return Ok(id.clone()),
                "Connecting" => seen_connecting[i] = true,
                "Disconnected" if seen_connecting[i] => rejected[i] = true,
                _ => {}
            }
            last_state = state;
        }
        if rejected.iter().all(|&r| r) && !rejected.is_empty() {
            return Err(TOKEN_EXPIRED_HINT.to_string());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(format!(
                "{}초 내에 연결되지 않았습니다 (마지막 상태: {last_state}).\n{TOKEN_EXPIRED_HINT}",
                CONNECT_WAIT.as_secs()
            ));
        }
    }
}

/// Internal-network smoke test with success/failure reporting.
async fn report_smoke() -> Result<(), String> {
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

/// After the GUI app has been asked (via deep link) to log in and connect,
/// wait for the NE tunnel to reach Connected and smoke-test reachability.
/// Requires the app to be installed (its NE service registered).
pub async fn wait_connected_and_smoke() -> Result<(), String> {
    let service_ids = find_services()?;
    println!("앱이 연결을 수행하는 동안 NE 상태를 폴링합니다...");
    poll_any_connected(&service_ids).await?;
    report_smoke().await
}

/// Direct control path (`--no-app`, or fallback): start the NE tunnel with
/// `scutil` ourselves. This does NOT update the GUI app's UI.
///
/// Tries each registered service in turn: an orphaned configuration (saved by
/// an app copy that no longer exists) fails instantly with no `Connecting`
/// transition, so on such a failure the next service gets its chance.
pub async fn connect_direct() -> Result<(), String> {
    let service_ids = find_services()?;

    for id in &service_ids {
        if service_state(id)? == "Connected" {
            println!("이미 연결되어 있습니다. ({id})");
            return report_smoke().await;
        }
    }

    let mut last_error = String::new();
    for id in &service_ids {
        println!("VPN 시작 중... (scutil --nc start {id})");
        if let Err(e) = scutil(&["--nc", "start", id]) {
            last_error = e;
            continue;
        }
        // Quick probe: an orphaned configuration fails instantly, without ever
        // reaching Connecting — skip to the next one instead of waiting 30s.
        let mut progressed = false;
        for _ in 0..3 {
            tokio::time::sleep(POLL_INTERVAL).await;
            match service_state(id)?.as_str() {
                "Connected" => return report_smoke().await,
                "Connecting" => {
                    progressed = true;
                    break;
                }
                _ => {}
            }
        }
        if !progressed {
            println!("  이 설정은 시작되지 않음 (고아 NE 설정일 수 있음) — 다음 설정 시도");
            last_error = "NE 설정이 시작되지 않았습니다 (모든 설정 시도 실패)".to_string();
            continue;
        }
        match poll_any_connected(std::slice::from_ref(id)).await {
            Ok(_) => return report_smoke().await,
            Err(e) => {
                println!("  이 설정으로는 연결 실패 — 다음 설정 시도");
                last_error = e;
            }
        }
    }
    Err(last_error)
}

pub async fn disconnect() -> Result<(), String> {
    let service_ids = find_services()?;

    let mut stopping = Vec::new();
    for id in service_ids {
        if service_state(&id)? != "Disconnected" {
            println!("VPN 중지 중... (scutil --nc stop {id})");
            scutil(&["--nc", "stop", &id])?;
            stopping.push(id);
        }
    }
    if stopping.is_empty() {
        println!("이미 연결 해제 상태입니다.");
        return Ok(());
    }

    let deadline = tokio::time::Instant::now() + DISCONNECT_WAIT;
    loop {
        tokio::time::sleep(POLL_INTERVAL).await;
        let mut remaining = String::new();
        for id in &stopping {
            let state = service_state(id)?;
            if state != "Disconnected" {
                remaining = state;
                break;
            }
        }
        if remaining.is_empty() {
            println!("VPN 연결 해제됨");
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(format!("연결 해제가 확인되지 않았습니다 (상태: {remaining})"));
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
            parse_service_ids(out),
            vec!["3B01D5D3-AECB-4878-8584-29DE29311CFE".to_string()]
        );
    }

    #[test]
    fn parses_multiple_entries_orphan_plus_fresh() {
        // Observed live: the app re-created its configuration ("VPN Client 2")
        // after the original became orphaned — both stay listed.
        let out = "Available network connection services in the current set (*=enabled):\n\
             * (Connected)      CBD991A2-C417-4D91-9F15-80117B38F573 VPN (kr.co.datasee.VPNClient) \"VPN Client 2\"                   [VPN:kr.co.datasee.VPNClient]\n\
             * (Disconnected)   3B01D5D3-AECB-4878-8584-29DE29311CFE VPN (kr.co.datasee.VPNClient) \"VPN Client\"                     [VPN:kr.co.datasee.VPNClient]\n";
        assert_eq!(
            parse_service_ids(out),
            vec![
                "CBD991A2-C417-4D91-9F15-80117B38F573".to_string(),
                "3B01D5D3-AECB-4878-8584-29DE29311CFE".to_string(),
            ]
        );
    }

    #[test]
    fn ignores_unrelated_services() {
        let out = "* (Connected)   11111111-2222-3333-4444-555555555555 IPSec \"Other VPN\" [IPSec]\n";
        assert!(parse_service_ids(out).is_empty());
    }

    #[test]
    fn uuid_shape_check() {
        assert!(is_service_uuid("3B01D5D3-AECB-4878-8584-29DE29311CFE"));
        assert!(!is_service_uuid("VPN"));
        assert!(!is_service_uuid("3B01D5D3-AECB-4878-8584-29DE29311CF")); // 35 chars
        assert!(!is_service_uuid("3B01D5D3xAECB-4878-8584-29DE29311CFE"));
    }
}
