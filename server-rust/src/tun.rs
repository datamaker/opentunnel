//! TUN device abstraction.
//!
//! Mirrors `tun/tunDevice.ts`: on Linux we reuse the existing `tun-bridge.py`
//! helper, exchanging length-prefixed packets over a Unix domain socket. A mock
//! device is used in development so the server runs without root or `/dev/net/tun`.

use anyhow::Context;
use std::process::Stdio;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::process::{Child, Command};
use tokio::sync::mpsc;

const SOCKET_PATH: &str = "/tmp/vpn-tun.sock";
const BRIDGE_PATH: &str = "/app/tun-bridge.py";

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
        start_linux(name, mtu, gateway_cidr).await
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

/// Linux device: bring up the interface, spawn `tun-bridge.py`, and pump packets
/// over its Unix socket.
async fn start_linux(
    name: &str,
    mtu: u32,
    gateway_cidr: &str,
) -> anyhow::Result<(TunHandle, mpsc::Receiver<Vec<u8>>)> {
    // Create the interface (idempotent) and set the MTU.
    run_ip(&["tuntap", "add", "dev", name, "mode", "tun"]).ok();
    run_ip(&["link", "set", name, "mtu", &mtu.to_string()])
        .context("failed to set TUN mtu")?;

    // Assign the gateway address and bring the interface up. Best-effort NAT
    // rules mirror `tunDevice.ts`; the container entrypoint also configures
    // these, so failures here are non-fatal.
    run_ip(&["addr", "add", gateway_cidr, "dev", name]).ok();
    run_ip(&["link", "set", name, "up"]).ok();
    setup_nat(gateway_cidr, name);

    // Launch the Python bridge that owns the /dev/net/tun fd.
    let mut bridge: Child = Command::new("python3")
        .arg(BRIDGE_PATH)
        .arg(name)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .context("failed to spawn tun-bridge.py")?;

    // Give the bridge a moment to create the socket, then connect.
    let stream = connect_with_retry(SOCKET_PATH, 20).await?;
    let (mut reader, mut writer) = stream.into_split();

    let (write_tx, mut write_rx) = mpsc::channel::<Vec<u8>>(1024);
    let (in_tx, in_rx) = mpsc::channel::<Vec<u8>>(1024);

    // Writer task: frame outbound packets with a 4-byte length prefix.
    tokio::spawn(async move {
        while let Some(pkt) = write_rx.recv().await {
            let mut framed = Vec::with_capacity(4 + pkt.len());
            framed.extend_from_slice(&(pkt.len() as u32).to_be_bytes());
            framed.extend_from_slice(&pkt);
            if writer.write_all(&framed).await.is_err() {
                break;
            }
        }
    });

    // Reader task: parse length-prefixed packets coming from the bridge.
    tokio::spawn(async move {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 65536];
        loop {
            match reader.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
            while buf.len() >= 4 {
                let len =
                    u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
                if buf.len() < 4 + len {
                    break;
                }
                let packet = buf[4..4 + len].to_vec();
                buf.drain(..4 + len);
                if in_tx.send(packet).await.is_err() {
                    return;
                }
            }
        }
    });

    // Reap the bridge process if it exits.
    tokio::spawn(async move {
        let status = bridge.wait().await;
        tracing::warn!("tun-bridge.py exited: {:?}", status);
    });

    tracing::info!("Linux TUN device {name} created via Python bridge");
    Ok((TunHandle { tx: write_tx }, in_rx))
}

async fn connect_with_retry(path: &str, attempts: u32) -> anyhow::Result<UnixStream> {
    for i in 0..attempts {
        match UnixStream::connect(path).await {
            Ok(s) => return Ok(s),
            Err(_) => tokio::time::sleep(std::time::Duration::from_millis(250)).await,
        }
        tracing::debug!("waiting for TUN bridge socket ({}/{attempts})", i + 1);
    }
    anyhow::bail!("timed out connecting to TUN bridge socket at {path}")
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
