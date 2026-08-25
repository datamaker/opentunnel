//! OpenTunnel SSO CLI — headless login/renew of VPN session tokens.
//!
//! Designed for non-interactive environments (AI agents, cron):
//! `opentunnel login` needs one human browser approval, after which
//! `opentunnel renew` rotates the 30-day session token forever without a human.

mod deeplink;
mod device_flow;
#[cfg(target_os = "macos")]
mod ne;
mod store;
mod tunnel;
mod vpn;

use clap::{Parser, Subcommand};
use std::process::ExitCode;

const DEFAULT_ISSUER: &str = "https://auth.datasee.co.kr";
const DEFAULT_CLIENT_ID: &str = "opentunnel";
const DEFAULT_SERVER: &str = "vpn.datasee.co.kr:1194";

#[derive(Parser)]
#[command(
    name = "opentunnel",
    version,
    about = "OpenTunnel SSO CLI — VPN 세션 토큰 발급/갱신 (헤드리스 환경용)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// 브라우저 device flow로 SSO 로그인 후 30일 세션 토큰 저장
    Login {
        /// OIDC issuer
        #[arg(long, default_value = DEFAULT_ISSUER)]
        issuer: String,
        /// OIDC client_id
        #[arg(long = "client-id", default_value = DEFAULT_CLIENT_ID)]
        client_id: String,
        /// VPN 서버 (host:port)
        #[arg(long, default_value = DEFAULT_SERVER)]
        server: String,
        /// 브라우저 자동 열기 생략 (URL만 출력)
        #[arg(long)]
        no_browser: bool,
        /// (macOS) OpenTunnel 앱에 로그인 상태 위임 생략
        #[arg(long)]
        no_app: bool,
    },
    /// 저장된 세션 토큰으로 재인증하고 새 토큰으로 회전 (사람 개입 불필요)
    Renew {
        /// VPN 서버 재정의 (기본: 저장된 서버)
        #[arg(long)]
        server: Option<String>,
    },
    /// 저장된 세션 상태 출력 (기본: 네트워크 호출 없음)
    Status {
        /// 서버에 실제 인증까지 검증 (renew처럼 토큰이 회전됨)
        #[arg(long)]
        check: bool,
    },
    /// 세션 토큰 raw 출력 (스크립트용, 만료 시 exit code 1)
    Token,
    /// 저장된 세션 삭제
    Logout,
    /// VPN 연결 (macOS: OpenTunnel.app에 위임 / Linux: 스탠드얼론 tun 터널, 루트 필요)
    Connect {
        /// (Linux 전용) VPN 서버 재정의 (기본: 저장된 서버)
        #[arg(long)]
        server: Option<String>,
        /// (Linux 전용) tun 인터페이스 이름
        #[arg(long, default_value = "opentun0")]
        ifname: String,
        /// (macOS) 앱 위임 없이 scutil로 직접 제어 (GUI에 반영 안 됨)
        #[arg(long)]
        no_app: bool,
    },
    /// VPN 연결 해제 (macOS: NE 터널 중지)
    Disconnect,
}

#[tokio::main]
async fn main() -> ExitCode {
    // Both this binary and reqwest enable only the ring provider, but make the
    // choice explicit so a future feature change cannot panic at runtime.
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();

    let cli = Cli::parse();
    let result = match cli.command {
        Command::Login {
            issuer,
            client_id,
            server,
            no_browser,
            no_app,
        } => login(&issuer, &client_id, &server, no_browser, no_app).await,
        Command::Renew { server } => renew(server.as_deref()).await,
        Command::Status { check } => status(check).await,
        Command::Token => token(),
        Command::Logout => logout(),
        Command::Connect {
            server,
            ifname,
            no_app,
        } => connect(server.as_deref(), &ifname, no_app).await,
        Command::Disconnect => disconnect().await,
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("오류: {message}");
            ExitCode::FAILURE
        }
    }
}

async fn login(
    issuer: &str,
    client_id: &str,
    server: &str,
    no_browser: bool,
    no_app: bool,
) -> Result<(), String> {
    let flow = device_flow::DeviceFlow::new(issuer, client_id)?;
    let auth = flow.start().await?;
    let url = auth.verification_url();

    println!();
    println!("브라우저에서 아래 주소를 열어 로그인을 승인해 주세요:");
    println!();
    println!("  ==>  {url}");
    println!();
    println!("  코드: {}  (주소에 코드가 없으면 직접 입력)", auth.user_code);
    println!();

    if !no_browser {
        open_browser(url);
    }

    println!("승인 대기 중... (Ctrl-C로 중단)");
    let id_token = flow.poll_for_id_token(&auth).await?;
    let email = store::jwt_str_claim(&id_token, "email");
    match &email {
        Some(email) => println!("SSO 승인 완료: {email}"),
        None => println!("SSO 승인 완료"),
    }

    println!("VPN 서버({server})에 인증 중...");
    let session_token = vpn::authenticate(server, "sso", &id_token).await?;

    let saved = persist(server, issuer, email, session_token)?;
    println!();
    println!("로그인 성공. 세션 토큰을 저장했습니다.");
    print_expiry(&saved);

    // macOS: reflect the login in the GUI app (login only — no connect here).
    #[cfg(target_os = "macos")]
    if !no_app {
        hand_off_login_to_app(&saved.session_token, server);
    }
    #[cfg(not(target_os = "macos"))]
    let _ = no_app;

    println!();
    println!("이후에는 사람 개입 없이 `opentunnel renew`로 토큰을 회전할 수 있습니다 (월 1회 이상 권장).");
    Ok(())
}

/// macOS: hand the freshly-minted token to the GUI app so it also shows
/// logged-in. Best-effort — never fails the CLI login.
#[cfg(target_os = "macos")]
fn hand_off_login_to_app(token: &str, server: &str) {
    if !deeplink::app_installed() {
        return; // no GUI app — CLI-only login is fine
    }
    match deeplink::hand_off_to_app(token, server, false) {
        Ok(()) => println!("OpenTunnel 앱에도 로그인 상태를 반영했습니다."),
        Err(e) => println!("(앱 로그인 반영 생략: {e})"),
    }
}

async fn renew(server_override: Option<&str>) -> Result<(), String> {
    let session = store::load()?
        .ok_or("저장된 세션이 없습니다. 먼저 `opentunnel login`을 실행하세요")?;
    let server = server_override.unwrap_or(&session.server).to_string();

    let new_token = vpn::authenticate(&server, "session", &session.session_token)
        .await
        .map_err(|e| format!("세션 갱신 실패: {e}\n토큰이 만료되었거나 거부되었습니다. `opentunnel login`이 필요합니다"))?;

    let saved = persist(&server, &session.issuer, session.email.clone(), new_token)?;
    println!("세션 토큰을 회전했습니다.");
    print_expiry(&saved);
    Ok(())
}

async fn status(check: bool) -> Result<(), String> {
    // macOS: show the OpenTunnel.app NetworkExtension state when present —
    // independent of the CLI's own session file.
    #[cfg(target_os = "macos")]
    if let Some((service_id, state)) = ne::current_state() {
        println!("NE 터널:  {state} ({service_id})");
    }

    let Some(session) = store::load()? else {
        println!("저장된 세션이 없습니다. `opentunnel login`을 실행하세요.");
        return Err("세션 없음".to_string());
    };

    let user = session
        .username
        .as_deref()
        .or(session.email.as_deref())
        .unwrap_or("(알 수 없음)");
    println!("서버:     {}", session.server);
    println!("사용자:   {user}");
    println!("발급:     {}", store::format_kst(session.issued_at));
    println!(
        "만료:     {} (남은 기간: {})",
        store::format_kst(session.expires_at),
        store::format_remaining(session.expires_at)
    );

    if session.is_expired() {
        println!("상태:     만료됨 — `opentunnel login`이 필요합니다");
        return Err("세션 만료".to_string());
    }

    if check {
        println!("서버 인증 검증 중...");
        let new_token = vpn::authenticate(&session.server, "session", &session.session_token)
            .await
            .map_err(|e| format!("서버 인증 실패: {e}\n`opentunnel login`이 필요합니다"))?;
        let saved = persist(
            &session.server,
            &session.issuer,
            session.email.clone(),
            new_token,
        )?;
        println!("상태:     유효 (서버 인증 성공, 토큰 회전됨)");
        print_expiry(&saved);
    } else {
        println!("상태:     유효 (로컬 검사만 수행 — 서버 검증은 --check)");
    }
    Ok(())
}

fn token() -> Result<(), String> {
    let session = store::load()?
        .ok_or("저장된 세션이 없습니다. `opentunnel login`을 실행하세요")?;
    if session.is_expired() {
        return Err("세션 토큰이 만료되었습니다. `opentunnel login`이 필요합니다".to_string());
    }
    println!("{}", session.session_token);
    Ok(())
}

fn logout() -> Result<(), String> {
    if store::delete()? {
        println!("세션을 삭제했습니다.");
    } else {
        println!("저장된 세션이 없습니다.");
    }
    Ok(())
}

/// VPN connect. macOS default: delegate to the GUI app via a deep link (so the
/// login+connect is reflected in the app UI), then poll NE state + smoke-test.
/// Falls back to direct `scutil` control if the app is absent or `open` fails,
/// or always with `--no-app`. Linux: standalone tun tunnel (root required).
async fn connect(_server: Option<&str>, _ifname: &str, _no_app: bool) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        if _server.is_some() {
            println!("(macOS에서는 --server가 무시됩니다 — 저장된/NE 설정의 서버를 사용)");
        }
        connect_macos(_no_app).await
    }
    #[cfg(target_os = "linux")]
    {
        if _no_app {
            println!("(Linux에는 앱 위임이 없습니다 — --no-app 무시)");
        }
        tunnel::run(_server, _ifname).await
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = _no_app;
        Err("connect는 macOS/Linux에서만 지원됩니다".to_string())
    }
}

/// macOS connect: deep-link delegation (default) with scutil fallback.
#[cfg(target_os = "macos")]
async fn connect_macos(no_app: bool) -> Result<(), String> {
    if !no_app && deeplink::app_installed() {
        // Use the CLI's stored session token; the app logs in + connects with
        // it and the server rotates it on connect.
        let session = store::load()?
            .ok_or("저장된 세션이 없습니다. 먼저 `opentunnel login`을 실행하세요")?;
        if session.is_expired() {
            return Err("세션 토큰이 만료되었습니다. `opentunnel login`이 필요합니다".to_string());
        }
        match deeplink::hand_off_to_app(&session.session_token, &session.server, true) {
            Ok(()) => {
                println!("OpenTunnel 앱에 로그인+연결을 위임했습니다 (GUI에 반영됨).");
                println!("  (딥링크 지원 앱 빌드에서만 실제 동작 — 구버전 앱이면 무시됩니다)");
                return ne::wait_connected_and_smoke().await;
            }
            Err(e) => {
                println!("경고: 앱 위임 실패({e}) — scutil 직접 경로로 폴백합니다. 앱 GUI에는 반영되지 않습니다.");
            }
        }
    } else if !no_app {
        println!("OpenTunnel 앱이 설치되어 있지 않아 scutil 직접 경로를 사용합니다 (GUI 반영 없음).");
    }

    ne::connect_direct().await
}

async fn disconnect() -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        ne::disconnect().await
    }
    #[cfg(target_os = "linux")]
    {
        Err("Linux에서는 connect가 포그라운드로 동작합니다 — 실행 중인 프로세스에 SIGINT/SIGTERM을 보내세요 (systemd: systemctl stop)".to_string())
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Err("disconnect는 macOS에서만 지원됩니다".to_string())
    }
}

/// Build the session file from a freshly-minted token and save it (0600).
pub(crate) fn persist(
    server: &str,
    issuer: &str,
    email: Option<String>,
    session_token: String,
) -> Result<store::SessionFile, String> {
    let expires_at = store::jwt_exp(&session_token)
        .ok_or("세션 토큰에서 만료 시각(exp)을 읽지 못했습니다")?;
    let session = store::SessionFile {
        server: server.to_string(),
        issuer: issuer.to_string(),
        email,
        username: store::jwt_str_claim(&session_token, "username"),
        session_token,
        issued_at: store::now_unix(),
        expires_at,
    };
    let path = store::save(&session)?;
    println!("저장 위치: {}", path.display());
    Ok(session)
}

fn print_expiry(session: &store::SessionFile) {
    println!(
        "만료:     {} (남은 기간: {})",
        store::format_kst(session.expires_at),
        store::format_remaining(session.expires_at)
    );
}

/// Best-effort: open the system browser at the verification URL.
fn open_browser(url: &str) {
    #[cfg(target_os = "macos")]
    let command = "open";
    #[cfg(not(target_os = "macos"))]
    let command = "xdg-open";

    match std::process::Command::new(command)
        .arg(url)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        Ok(_) => println!("(브라우저를 열었습니다 — 안 열리면 위 주소를 직접 여세요)"),
        Err(_) => println!("(브라우저 자동 열기 실패 — 위 주소를 직접 여세요)"),
    }
}
