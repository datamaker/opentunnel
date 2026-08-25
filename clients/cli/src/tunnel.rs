//! Linux: standalone foreground tunnel over a raw `/dev/net/tun` device.
//!
//! Requires root. Authenticates with the stored session token
//! (`authType: "session"` — the server rotates it, and the rotated token is
//! saved back to session.json), applies the pushed ConfigPush (address, MTU,
//! split-tunnel routes via `ip` commands), then pumps DataPacket frames
//! between the tun fd and the TLS stream. Framing is byte-compatible with
//! `server-rust/src/protocol/` (see `vpn.rs`). SIGINT/SIGTERM send DISCONNECT
//! and clean up. Daemonization is left to systemd (see clients/README.md).
//!
//! The route-planning helpers below are platform-independent and unit-tested
//! everywhere; only the tun/ioctl runtime is Linux-only.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use crate::vpn::ConfigPush;

/// Dotted-quad netmask -> CIDR prefix length. Rejects non-contiguous masks.
pub fn mask_to_prefix(mask: &str) -> Result<u8, String> {
    let octets: Vec<u8> = mask
        .split('.')
        .map(|part| part.parse::<u8>())
        .collect::<Result<_, _>>()
        .map_err(|_| format!("잘못된 서브넷 마스크: {mask}"))?;
    if octets.len() != 4 {
        return Err(format!("잘못된 서브넷 마스크: {mask}"));
    }
    let value = u32::from_be_bytes([octets[0], octets[1], octets[2], octets[3]]);
    let prefix = value.leading_ones();
    if value != mask_bits(prefix as u8) {
        return Err(format!("불연속 서브넷 마스크: {mask}"));
    }
    Ok(prefix as u8)
}

fn mask_bits(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix as u32)
    }
}

/// CIDRs to route through the tun device. Split tunnel routes only the pushed
/// include list; a full tunnel uses the classic half-default pair, which wins
/// over the existing default route without touching it.
pub fn plan_tun_routes(config: &ConfigPush) -> Vec<String> {
    if config.split_tunnel {
        config.included_routes.clone()
    } else {
        vec!["0.0.0.0/1".to_string(), "128.0.0.0/1".to_string()]
    }
}

/// Parse `ip -4 route show default` output: `default via <gw> dev <dev> ...`.
/// Returns (gateway, device).
pub fn parse_default_route(output: &str) -> Option<(String, String)> {
    let line = output.lines().find(|l| l.trim_start().starts_with("default"))?;
    let tokens: Vec<&str> = line.split_whitespace().collect();
    let gw = tokens.iter().position(|t| *t == "via").map(|i| tokens.get(i + 1))??;
    let dev = tokens.iter().position(|t| *t == "dev").map(|i| tokens.get(i + 1))??;
    Some((gw.to_string(), dev.to_string()))
}

#[cfg(target_os = "linux")]
pub use linux::run;

#[cfg(target_os = "linux")]
mod linux {
    use super::{mask_to_prefix, parse_default_route, plan_tun_routes};
    use crate::store;
    use crate::vpn::{
        self, MessageBuffer, MSG_DATA_PACKET, MSG_DISCONNECT, MSG_KEEPALIVE, MSG_KEEPALIVE_ACK,
    };
    use std::os::unix::io::{AsRawFd, RawFd};
    use std::process::Command;
    use std::time::Duration;
    use tokio::io::unix::AsyncFd;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::signal::unix::{signal, SignalKind};
    use tokio::time::{Instant, MissedTickBehavior};

    const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(20);
    const IDLE_TIMEOUT: Duration = Duration::from_secs(90);

    struct Tun {
        file: std::fs::File,
    }

    impl AsRawFd for Tun {
        fn as_raw_fd(&self) -> RawFd {
            self.file.as_raw_fd()
        }
    }

    /// Open /dev/net/tun and attach a non-persistent IFF_TUN|IFF_NO_PI device.
    /// The interface (and every route on it) disappears when the fd closes.
    fn create_tun(name: &str) -> Result<Tun, String> {
        const TUNSETIFF: libc::c_ulong = 0x4004_54ca; // _IOW('T', 202, int)
        const IFF_TUN: libc::c_short = 0x0001;
        const IFF_NO_PI: libc::c_short = 0x1000;

        #[repr(C)]
        struct IfReq {
            ifr_name: [u8; libc::IFNAMSIZ],
            ifr_flags: libc::c_short,
            _pad: [u8; 22],
        }

        if name.len() >= libc::IFNAMSIZ {
            return Err(format!("인터페이스 이름이 너무 깁니다: {name}"));
        }
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")
            .map_err(|e| format!("/dev/net/tun 열기 실패: {e}"))?;

        let mut ifr = IfReq {
            ifr_name: [0; libc::IFNAMSIZ],
            ifr_flags: IFF_TUN | IFF_NO_PI,
            _pad: [0; 22],
        };
        ifr.ifr_name[..name.len()].copy_from_slice(name.as_bytes());

        let fd = file.as_raw_fd();
        if unsafe { libc::ioctl(fd, TUNSETIFF, &ifr) } < 0 {
            return Err(format!(
                "tun 디바이스 생성 실패: {}",
                std::io::Error::last_os_error()
            ));
        }
        if unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) } < 0 {
            return Err(format!(
                "tun 논블로킹 설정 실패: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(Tun { file })
    }

    fn read_packet(fd: RawFd, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }

    /// Write one IP packet to the tun device. EAGAIN drops the packet — the
    /// standard lossy-VPN behavior under backpressure.
    fn write_packet(fd: RawFd, buf: &[u8]) {
        let n = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() != std::io::ErrorKind::WouldBlock {
                eprintln!("tun 쓰기 실패: {err}");
            }
        }
    }

    fn run_ip(args: &[&str]) -> Result<(), String> {
        let output = Command::new("ip")
            .args(args)
            .output()
            .map_err(|e| format!("`ip {}` 실행 실패: {e}", args.join(" ")))?;
        if !output.status.success() {
            return Err(format!(
                "`ip {}` 실패: {}",
                args.join(" "),
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        Ok(())
    }

    /// Foreground tunnel. Returns when the connection ends for any reason.
    pub async fn run(server_override: Option<&str>, ifname: &str) -> Result<(), String> {
        if unsafe { libc::geteuid() } != 0 {
            return Err(
                "tun 디바이스 생성에는 루트 권한이 필요합니다. sudo로 실행하세요".to_string()
            );
        }

        let session = store::load()?
            .ok_or("저장된 세션이 없습니다. 먼저 `opentunnel login`을 실행하세요")?;
        let server = server_override.unwrap_or(&session.server).to_string();

        println!("VPN 서버({server})에 인증 중...");
        let (tls, new_token, config) =
            vpn::connect_for_tunnel(&server, "session", &session.session_token)
                .await
                .map_err(|e| {
                    format!(
                        "세션 인증 실패: {e}\n토큰이 만료되었거나 거부되었습니다. `opentunnel login`이 필요합니다"
                    )
                })?;
        // The server rotated the token on this login — persist it immediately.
        crate::persist(&server, &session.issuer, session.email.clone(), new_token)?;

        let prefix = mask_to_prefix(&config.subnet_mask)?;
        let tun_routes = plan_tun_routes(&config);
        println!(
            "할당 IP: {}/{prefix}, MTU {}, 모드: {}",
            config.assigned_ip,
            config.mtu,
            if config.split_tunnel { "스플릿터널" } else { "전체터널" }
        );
        if !config.dns.is_empty() {
            println!(
                "서버 푸시 DNS: {} (resolv.conf는 수정하지 않습니다 — 필요 시 수동 설정)",
                config.dns.join(", ")
            );
        }
        if !config.included_domains.is_empty() {
            println!(
                "참고: 도메인 기반 스플릿터널({}개)은 CLI에서 라우팅되지 않습니다 — includedRoutes만 적용",
                config.included_domains.len()
            );
        }

        let tun = create_tun(ifname)?;
        run_ip(&["link", "set", "dev", ifname, "up", "mtu", &config.mtu.to_string()])?;
        run_ip(&[
            "addr",
            "add",
            &format!("{}/{prefix}", config.assigned_ip),
            "dev",
            ifname,
        ])?;

        // Full tunnel: the half-default routes would also swallow the VPN
        // server itself — pin a host route to it via the current gateway.
        let mut extra_route: Option<String> = None;
        if !config.split_tunnel {
            let (host, port) = vpn::split_host_port(&server)?;
            let server_ip = tokio::net::lookup_host((host.as_str(), port))
                .await
                .ok()
                .and_then(|mut addrs| addrs.find(|a| a.is_ipv4()))
                .map(|a| a.ip().to_string())
                .ok_or_else(|| format!("{host}의 IPv4 주소를 확인하지 못했습니다"))?;
            let default = Command::new("ip")
                .args(["-4", "route", "show", "default"])
                .output()
                .map_err(|e| format!("기본 라우트 조회 실패: {e}"))?;
            let (gw, dev) = parse_default_route(&String::from_utf8_lossy(&default.stdout))
                .ok_or("기존 기본 라우트를 찾지 못했습니다 (전체터널 불가)")?;
            let dest = format!("{server_ip}/32");
            run_ip(&["route", "add", &dest, "via", &gw, "dev", &dev])?;
            extra_route = Some(dest);
        }
        for route in &tun_routes {
            run_ip(&["route", "add", route, "dev", ifname])?;
        }
        println!("터널 라우트 {}개 적용. 패킷 전달 시작 (Ctrl-C로 종료)", tun_routes.len());

        let reason = pump(tls, &tun).await;

        // Cleanup: tun-bound routes vanish with the device (fd drop below);
        // only the physical-interface host route needs explicit removal.
        if let Some(dest) = extra_route {
            let _ = run_ip(&["route", "del", &dest]);
        }
        drop(tun);
        println!("종료: {reason}");
        Ok(())
    }

    /// Bidirectional packet pump. Returns a human-readable exit reason.
    async fn pump(
        tls: tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
        tun: &Tun,
    ) -> String {
        let (mut tls_r, mut tls_w) = tokio::io::split(tls);
        let tun_fd = match AsyncFd::new(tun.as_raw_fd()) {
            Ok(fd) => fd,
            Err(e) => return format!("tun 이벤트 등록 실패: {e}"),
        };
        let mut msgbuf = MessageBuffer::new();
        let mut chunk = vec![0u8; 65536];
        let mut pkt = vec![0u8; 65536];
        let mut last_rx = Instant::now();

        let mut keepalive = tokio::time::interval(KEEPALIVE_INTERVAL);
        keepalive.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut sigint = match signal(SignalKind::interrupt()) {
            Ok(s) => s,
            Err(e) => return format!("시그널 핸들러 등록 실패: {e}"),
        };
        let mut sigterm = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => return format!("시그널 핸들러 등록 실패: {e}"),
        };

        let reason = loop {
            if last_rx.elapsed() > IDLE_TIMEOUT {
                break format!("{}초간 서버 응답 없음", IDLE_TIMEOUT.as_secs());
            }
            tokio::select! {
                read = tls_r.read(&mut chunk) => match read {
                    Ok(0) => break "서버가 연결을 종료했습니다".to_string(),
                    Err(e) => break format!("수신 오류: {e}"),
                    Ok(n) => {
                        last_rx = Instant::now();
                        msgbuf.append(&chunk[..n]);
                        let mut stop: Option<String> = None;
                        while let Some((frame_type, payload)) = msgbuf.extract() {
                            match frame_type {
                                MSG_DATA_PACKET => write_packet(tun.as_raw_fd(), &payload),
                                MSG_KEEPALIVE => {
                                    if let Err(e) =
                                        vpn::write_frame(&mut tls_w, MSG_KEEPALIVE_ACK, &[]).await
                                    {
                                        stop = Some(format!("전송 오류: {e}"));
                                        break;
                                    }
                                }
                                MSG_KEEPALIVE_ACK => {}
                                MSG_DISCONNECT => {
                                    stop = Some("서버가 연결 종료를 요청했습니다".to_string());
                                    break;
                                }
                                _ => {}
                            }
                        }
                        if let Some(reason) = stop {
                            break reason;
                        }
                    }
                },
                guard = tun_fd.readable() => {
                    let mut guard = match guard {
                        Ok(guard) => guard,
                        Err(e) => break format!("tun 이벤트 오류: {e}"),
                    };
                    let mut failure = None;
                    loop {
                        match guard.try_io(|fd| read_packet(*fd.get_ref(), &mut pkt)) {
                            Ok(Ok(0)) => break,
                            Ok(Ok(n)) => {
                                if let Err(e) =
                                    vpn::write_frame(&mut tls_w, MSG_DATA_PACKET, &pkt[..n]).await
                                {
                                    failure = Some(format!("전송 오류: {e}"));
                                    break;
                                }
                            }
                            Ok(Err(e)) => {
                                failure = Some(format!("tun 읽기 오류: {e}"));
                                break;
                            }
                            Err(_would_block) => break,
                        }
                    }
                    if let Some(reason) = failure {
                        break reason;
                    }
                },
                _ = keepalive.tick() => {
                    if let Err(e) = vpn::write_frame(&mut tls_w, MSG_KEEPALIVE, &[]).await {
                        break format!("keepalive 전송 실패: {e}");
                    }
                },
                _ = sigint.recv() => break "SIGINT 수신".to_string(),
                _ = sigterm.recv() => break "SIGTERM 수신".to_string(),
            }
        };

        // Polite shutdown: DISCONNECT + TLS close_notify (server frees the IP).
        let _ = vpn::write_frame(&mut tls_w, MSG_DISCONNECT, &[]).await;
        let _ = tls_w.shutdown().await;
        reason
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(split: bool, routes: &[&str]) -> ConfigPush {
        serde_json::from_value(serde_json::json!({
            "assignedIP": "10.8.0.5",
            "subnetMask": "255.255.255.0",
            "gateway": "10.8.0.1",
            "dns": ["10.8.0.1"],
            "mtu": 1400,
            "keepaliveInterval": 10,
            "splitTunnel": split,
            "includedRoutes": routes,
            "includedDomains": []
        }))
        .unwrap()
    }

    #[test]
    fn mask_to_prefix_valid_and_invalid() {
        assert_eq!(mask_to_prefix("255.255.255.0").unwrap(), 24);
        assert_eq!(mask_to_prefix("255.255.0.0").unwrap(), 16);
        assert_eq!(mask_to_prefix("255.255.255.255").unwrap(), 32);
        assert_eq!(mask_to_prefix("0.0.0.0").unwrap(), 0);
        assert!(mask_to_prefix("255.0.255.0").is_err()); // non-contiguous
        assert!(mask_to_prefix("255.255.255").is_err());
        assert!(mask_to_prefix("banana").is_err());
    }

    #[test]
    fn route_plan_split_vs_full() {
        let split = config(true, &["11.0.0.0/16", "10.8.0.0/24"]);
        assert_eq!(plan_tun_routes(&split), vec!["11.0.0.0/16", "10.8.0.0/24"]);

        let full = config(false, &[]);
        assert_eq!(plan_tun_routes(&full), vec!["0.0.0.0/1", "128.0.0.0/1"]);
    }

    #[test]
    fn default_route_parsing() {
        let out = "default via 192.168.1.1 dev eth0 proto dhcp src 192.168.1.50 metric 100\n";
        assert_eq!(
            parse_default_route(out),
            Some(("192.168.1.1".to_string(), "eth0".to_string()))
        );
        assert_eq!(parse_default_route("10.0.0.0/8 dev eth0\n"), None);
        assert_eq!(parse_default_route(""), None);
    }
}
