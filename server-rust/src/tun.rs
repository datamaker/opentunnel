//! TUN device abstraction.
//!
//! On Linux the device is driven natively in pure Rust: we open `/dev/net/tun`,
//! configure it with the `TUNSETIFF` ioctl, and pump packets over the raw file
//! descriptor using Tokio's [`AsyncFd`]. A mock device is used in development so
//! the server runs without root or `/dev/net/tun`.

use anyhow::Context;
use std::process::Stdio;
use tokio::sync::mpsc;

/// Handle used to write packets toward the TUN device.
#[derive(Clone)]
pub struct TunHandle {
    tx: mpsc::Sender<Vec<u8>>,
}

impl TunHandle {
    /// Queue a packet to be written to the TUN device (client -> internet).
    pub async fn write(&self, packet: Vec<u8>) {
        let _ = self.tx.send(packet).await;
    }
}

/// Start a TUN device.
///
/// Returns a [`TunHandle`] for outbound writes and a receiver yielding packets
/// read from the device (internet -> client).
pub async fn start(
    name: &str,
    mtu: u32,
    gateway_cidr: &str,
    mock: bool,
) -> anyhow::Result<(TunHandle, mpsc::Receiver<Vec<u8>>)> {
    if mock {
        start_mock().await
    } else {
        start_native(name, mtu, gateway_cidr).await
    }
}

/// Mock device: drops outbound writes and never produces inbound packets.
async fn start_mock() -> anyhow::Result<(TunHandle, mpsc::Receiver<Vec<u8>>)> {
    let (write_tx, mut write_rx) = mpsc::channel::<Vec<u8>>(1024);
    let (in_tx, in_rx) = mpsc::channel::<Vec<u8>>(1024);
    // Keep the inbound sender alive so the channel stays open.
    std::mem::forget(in_tx);

    tokio::spawn(async move {
        while let Some(pkt) = write_rx.recv().await {
            tracing::debug!("mock TUN: dropping {} byte packet", pkt.len());
        }
    });

    tracing::info!("Mock TUN device created");
    Ok((TunHandle { tx: write_tx }, in_rx))
}

#[cfg(target_os = "linux")]
async fn start_native(
    name: &str,
    mtu: u32,
    gateway_cidr: &str,
) -> anyhow::Result<(TunHandle, mpsc::Receiver<Vec<u8>>)> {
    linux::start(name, mtu, gateway_cidr).await
}

#[cfg(not(target_os = "linux"))]
async fn start_native(
    _name: &str,
    _mtu: u32,
    _gateway_cidr: &str,
) -> anyhow::Result<(TunHandle, mpsc::Receiver<Vec<u8>>)> {
    anyhow::bail!("native TUN device is only supported on Linux; set NODE_ENV != production to use the mock device")
}

/// Best-effort NAT/forwarding setup (requires NET_ADMIN). Derives the subnet
/// from the gateway CIDR, e.g. `10.8.0.1/24` -> `10.8.0.0/24`.
fn setup_nat(gateway_cidr: &str, iface: &str) {
    let (gw, prefix) = gateway_cidr.split_once('/').unwrap_or((gateway_cidr, "24"));
    let subnet = match gw.rsplit_once('.') {
        Some((net, _)) => format!("{net}.0/{prefix}"),
        None => return,
    };

    let _ = std::fs::write("/proc/sys/net/ipv4/ip_forward", "1");
    let rules: [&[&str]; 3] = [
        &["-t", "nat", "-A", "POSTROUTING", "-s", &subnet, "-o", "eth0", "-j", "MASQUERADE"],
        &["-A", "FORWARD", "-i", iface, "-j", "ACCEPT"],
        &["-A", "FORWARD", "-o", iface, "-j", "ACCEPT"],
    ];
    for rule in rules {
        let _ = std::process::Command::new("iptables")
            .args(rule)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

fn run_ip(args: &[&str]) -> anyhow::Result<()> {
    let status = std::process::Command::new("ip")
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("failed to run `ip`")?;
    if !status.success() {
        anyhow::bail!("`ip {}` failed", args.join(" "));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
mod linux {
    use super::{run_ip, setup_nat, TunHandle};
    use anyhow::Context;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use tokio::io::unix::AsyncFd;
    use tokio::sync::mpsc;

    // ioctl request for setting TUN/TAP interface flags (Linux <linux/if_tun.h>).
    const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
    const MAX_PACKET: usize = 65536;

    /// Owned TUN file descriptor with an `AsRawFd` impl for `AsyncFd`.
    struct TunFd(OwnedFd);

    impl AsRawFd for TunFd {
        fn as_raw_fd(&self) -> RawFd {
            self.0.as_raw_fd()
        }
    }

    /// `struct ifreq` big enough for the interface name + flags (40 bytes on
    /// 64-bit Linux). We only touch the name and the leading flags field.
    #[repr(C)]
    struct Ifreq {
        name: [libc::c_char; libc::IFNAMSIZ],
        flags: libc::c_short,
        _pad: [u8; 22],
    }

    fn open_tun(name: &str) -> anyhow::Result<OwnedFd> {
        // Open the clone device.
        let fd = unsafe {
            libc::open(
                b"/dev/net/tun\0".as_ptr() as *const libc::c_char,
                libc::O_RDWR,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error()).context("open /dev/net/tun");
        }
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };

        // Build the ifreq and request a TUN device with no packet-info header.
        let mut ifr = Ifreq {
            name: [0; libc::IFNAMSIZ],
            flags: (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short,
            _pad: [0; 22],
        };
        let bytes = name.as_bytes();
        anyhow::ensure!(bytes.len() < libc::IFNAMSIZ, "interface name too long");
        for (dst, &b) in ifr.name.iter_mut().zip(bytes) {
            *dst = b as libc::c_char;
        }

        let rc = unsafe { libc::ioctl(owned.as_raw_fd(), TUNSETIFF, &mut ifr) };
        if rc < 0 {
            return Err(std::io::Error::last_os_error()).context("ioctl TUNSETIFF");
        }

        set_nonblocking(owned.as_raw_fd())?;
        Ok(owned)
    }

    fn set_nonblocking(fd: RawFd) -> anyhow::Result<()> {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(std::io::Error::last_os_error()).context("fcntl F_GETFL");
        }
        let rc = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
        if rc < 0 {
            return Err(std::io::Error::last_os_error()).context("fcntl F_SETFL O_NONBLOCK");
        }
        Ok(())
    }

    pub async fn start(
        name: &str,
        mtu: u32,
        gateway_cidr: &str,
    ) -> anyhow::Result<(TunHandle, mpsc::Receiver<Vec<u8>>)> {
        let fd = open_tun(name).context("failed to open TUN device")?;

        // Bring the interface up, set MTU, assign the gateway, configure NAT.
        run_ip(&["link", "set", name, "mtu", &mtu.to_string()])
            .context("failed to set TUN mtu")?;
        run_ip(&["addr", "add", gateway_cidr, "dev", name]).ok();
        run_ip(&["link", "set", name, "up"]).context("failed to bring TUN up")?;
        setup_nat(gateway_cidr, name);

        let async_fd = std::sync::Arc::new(AsyncFd::new(TunFd(fd)).context("register TUN fd")?);

        let (write_tx, write_rx) = mpsc::channel::<Vec<u8>>(1024);
        let (in_tx, in_rx) = mpsc::channel::<Vec<u8>>(1024);

        spawn_reader(async_fd.clone(), in_tx);
        spawn_writer(async_fd, write_rx);

        tracing::info!("Native Linux TUN device {name} created");
        Ok((TunHandle { tx: write_tx }, in_rx))
    }

    /// Read packets from the TUN fd and forward them to the router.
    fn spawn_reader(async_fd: std::sync::Arc<AsyncFd<TunFd>>, in_tx: mpsc::Sender<Vec<u8>>) {
        tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_PACKET];
            loop {
                let mut guard = match async_fd.readable().await {
                    Ok(g) => g,
                    Err(e) => {
                        tracing::error!("TUN readable error: {e}");
                        break;
                    }
                };
                let result = guard.try_io(|inner| {
                    let n = unsafe {
                        libc::read(
                            inner.as_raw_fd(),
                            buf.as_mut_ptr() as *mut libc::c_void,
                            buf.len(),
                        )
                    };
                    if n < 0 {
                        Err(std::io::Error::last_os_error())
                    } else {
                        Ok(n as usize)
                    }
                });

                match result {
                    Ok(Ok(0)) => break,
                    Ok(Ok(n)) => {
                        if in_tx.send(buf[..n].to_vec()).await.is_err() {
                            break;
                        }
                    }
                    Ok(Err(e)) => {
                        tracing::error!("TUN read error: {e}");
                        break;
                    }
                    // Spurious readiness; re-arm and wait again.
                    Err(_would_block) => continue,
                }
            }
            tracing::warn!("TUN reader stopped");
        });
    }

    /// Write outbound packets from the connection loop to the TUN fd.
    fn spawn_writer(async_fd: std::sync::Arc<AsyncFd<TunFd>>, mut write_rx: mpsc::Receiver<Vec<u8>>) {
        tokio::spawn(async move {
            while let Some(pkt) = write_rx.recv().await {
                let mut written = 0;
                while written < pkt.len() {
                    let mut guard = match async_fd.writable().await {
                        Ok(g) => g,
                        Err(e) => {
                            tracing::error!("TUN writable error: {e}");
                            return;
                        }
                    };
                    let result = guard.try_io(|inner| {
                        let n = unsafe {
                            libc::write(
                                inner.as_raw_fd(),
                                pkt[written..].as_ptr() as *const libc::c_void,
                                pkt.len() - written,
                            )
                        };
                        if n < 0 {
                            Err(std::io::Error::last_os_error())
                        } else {
                            Ok(n as usize)
                        }
                    });

                    match result {
                        Ok(Ok(n)) => written += n,
                        Ok(Err(e)) => {
                            tracing::error!("TUN write error: {e}");
                            break;
                        }
                        Err(_would_block) => continue,
                    }
                }
            }
            tracing::warn!("TUN writer stopped");
        });
    }
}
