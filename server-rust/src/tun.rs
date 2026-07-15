//! TUN device abstraction.
//!
//! On Linux the device is driven natively in pure Rust: we open `/dev/net/tun`,
//! configure it with the `TUNSETIFF` ioctl, and pump packets over the raw file
//! descriptor using Tokio's [`AsyncFd`]. A mock device is used in development so
//! the server runs without root or `/dev/net/tun`.

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

    tokio::spawn(async move {
        // Hold the inbound sender for the task's lifetime so the receiver stays
        // open; the mock never actually produces inbound packets.
        let _in_tx = in_tx;
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

#[cfg(target_os = "linux")]
mod linux {
    use super::{setup_nat, TunHandle};
    use anyhow::Context;
    use std::net::Ipv4Addr;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use tokio::io::unix::AsyncFd;
    use tokio::sync::mpsc;

    // ioctl request for setting TUN/TAP interface flags (Linux <linux/if_tun.h>).
    const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
    // Socket ioctls for interface configuration (Linux <bits/ioctls.h>).
    const SIOCSIFADDR: libc::c_ulong = 0x8916;
    const SIOCSIFNETMASK: libc::c_ulong = 0x891c;
    const SIOCSIFMTU: libc::c_ulong = 0x8922;
    const SIOCGIFFLAGS: libc::c_ulong = 0x8913;
    const SIOCSIFFLAGS: libc::c_ulong = 0x8914;
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

    /// `struct ifreq` with a generic 24-byte union area, used for the
    /// interface-configuration ioctls.
    #[repr(C)]
    struct IfreqCfg {
        name: [libc::c_char; libc::IFNAMSIZ],
        data: [u8; 24],
    }

    impl IfreqCfg {
        fn new(name: &str) -> anyhow::Result<Self> {
            let bytes = name.as_bytes();
            anyhow::ensure!(bytes.len() < libc::IFNAMSIZ, "interface name too long");
            let mut ifr = IfreqCfg {
                name: [0; libc::IFNAMSIZ],
                data: [0; 24],
            };
            for (dst, &b) in ifr.name.iter_mut().zip(bytes) {
                *dst = b as libc::c_char;
            }
            Ok(ifr)
        }

        /// Write a `sockaddr_in` for `addr` into the union area.
        fn set_sockaddr_in(&mut self, addr: Ipv4Addr) {
            self.data = [0; 24];
            self.data[0..2].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
            // sin_port stays 0; sin_addr is network-order, i.e. the raw octets.
            self.data[4..8].copy_from_slice(&addr.octets());
        }
    }

    fn ioctl(sock: RawFd, req: libc::c_ulong, ifr: &mut IfreqCfg, what: &str) -> anyhow::Result<()> {
        let rc = unsafe { libc::ioctl(sock, req, ifr as *mut IfreqCfg) };
        if rc < 0 {
            return Err(std::io::Error::last_os_error()).context(what.to_string());
        }
        Ok(())
    }

    /// Configure the interface (address, netmask, MTU, up) via ioctls on an
    /// AF_INET socket — the pure-Rust equivalent of `ip addr add` / `ip link set`.
    fn configure_interface(
        name: &str,
        mtu: u32,
        addr: Ipv4Addr,
        netmask: Ipv4Addr,
    ) -> anyhow::Result<()> {
        let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if sock < 0 {
            return Err(std::io::Error::last_os_error()).context("open AF_INET socket");
        }
        // Own the fd so it is closed on every return path.
        let sock = unsafe { OwnedFd::from_raw_fd(sock) };
        let fd = sock.as_raw_fd();

        // Address + netmask.
        let mut ifr = IfreqCfg::new(name)?;
        ifr.set_sockaddr_in(addr);
        ioctl(fd, SIOCSIFADDR, &mut ifr, "ioctl SIOCSIFADDR")?;

        ifr.set_sockaddr_in(netmask);
        ioctl(fd, SIOCSIFNETMASK, &mut ifr, "ioctl SIOCSIFNETMASK")?;

        // MTU (ifr_mtu is a c_int at the start of the union).
        let mut ifr = IfreqCfg::new(name)?;
        ifr.data[0..4].copy_from_slice(&(mtu as libc::c_int).to_ne_bytes());
        ioctl(fd, SIOCSIFMTU, &mut ifr, "ioctl SIOCSIFMTU")?;

        // Bring the interface up: read flags, set IFF_UP, write back.
        let mut ifr = IfreqCfg::new(name)?;
        ioctl(fd, SIOCGIFFLAGS, &mut ifr, "ioctl SIOCGIFFLAGS")?;
        let mut flags = libc::c_short::from_ne_bytes([ifr.data[0], ifr.data[1]]);
        flags |= libc::IFF_UP as libc::c_short;
        ifr.data[0..2].copy_from_slice(&flags.to_ne_bytes());
        ioctl(fd, SIOCSIFFLAGS, &mut ifr, "ioctl SIOCSIFFLAGS")?;

        Ok(())
    }

    fn netmask_from_prefix(prefix: u32) -> Ipv4Addr {
        let bits = if prefix == 0 {
            0
        } else {
            0xffff_ffffu32 << (32 - prefix.min(32))
        };
        Ipv4Addr::from(bits)
    }

    pub async fn start(
        name: &str,
        mtu: u32,
        gateway_cidr: &str,
    ) -> anyhow::Result<(TunHandle, mpsc::Receiver<Vec<u8>>)> {
        let fd = open_tun(name).context("failed to open TUN device")?;

        // Assign the gateway address/netmask, set MTU and bring the interface up
        // — all via ioctls (no `ip` shell-out) — then configure NAT.
        let (gw, prefix) = gateway_cidr.split_once('/').unwrap_or((gateway_cidr, "24"));
        let gateway: Ipv4Addr = gw.parse().context("invalid gateway address")?;
        let netmask = netmask_from_prefix(prefix.parse().unwrap_or(24));
        configure_interface(name, mtu, gateway, netmask).context("failed to configure TUN interface")?;
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
