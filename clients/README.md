# OpenTunnel VPN Clients

Native VPN clients for all major platforms.

## Platforms

| Platform | Language | Framework | Status |
|----------|----------|-----------|--------|
| [macOS](./macos/) | Swift | NetworkExtension | Ready |
| [iOS](./ios/) | Swift | NetworkExtension | Ready |
| [Android](./android/) | Kotlin | VpnService | Ready |
| [Windows](./windows/) | C# | WinTun | Ready |

## Building

### macOS

Requirements:
- Xcode 15+
- Apple Developer Account (for code signing)

```bash
cd macos/VPNClient
open VPNClient.xcodeproj
# Configure signing in Xcode
# Build and Run
```

### iOS

Requirements:
- Xcode 15+
- Apple Developer Account
- Physical device (VPN doesn't work in simulator)

```bash
cd ios/VPNClient
open VPNClient.xcodeproj
# Configure signing
# Build and Run on device
```

### Android

Requirements:
- Android Studio Hedgehog+
- Android SDK 24+

```bash
cd android
./gradlew assembleDebug
# Install APK on device
```

### Windows

Requirements:
- Visual Studio 2022
- .NET 6.0 SDK
- WinTun driver

```bash
cd windows
dotnet build
# Run VPNClient.exe as Administrator
```

## CLI (headless / AI agents)

[clients/cli](./cli/) is a standalone Rust binary (`opentunnel`) that performs
SSO login and 30-day session-token renewal **without ever building a tunnel** —
it authenticates against the VPN server over TLS and stores the rotated session
JWT at `~/.config/opentunnel/session.json` (mode 0600). It exists so AI agents
and cron jobs on headless machines can keep a valid VPN session indefinitely
after a single human browser approval.

### Install

Download the binary from the [GitHub release](../../../releases) assets and put
it on your PATH:

```bash
# Linux x86_64
curl -fsSLo opentunnel <release-url>/opentunnel-cli-linux-x86_64
# macOS Apple Silicon
curl -fsSLo opentunnel <release-url>/opentunnel-cli-macos-arm64

chmod +x opentunnel && sudo mv opentunnel /usr/local/bin/
```

Or build from source: `cd clients/cli && cargo build --release` (binary at
`target/release/opentunnel`).

### Usage

```bash
opentunnel login            # device flow: prints a URL, human approves once in a browser
opentunnel renew            # rotate the session token (no human needed, new 30-day TTL)
opentunnel status           # local view: user, server, expiry, time remaining (+ NE state on macOS)
opentunnel status --check   # also verifies against the server (rotates the token)
opentunnel token            # print the raw session JWT for scripts (exit 1 if expired)
opentunnel logout           # delete the stored session
opentunnel connect          # bring the VPN up (see platform notes below)
opentunnel disconnect       # bring the VPN down (macOS)
```

Defaults: issuer `https://auth.datasee.co.kr`, client-id `opentunnel`, server
`vpn.datasee.co.kr:1194` — all overridable via `--issuer` / `--client-id` /
`--server` on `login`. `--no-browser` skips opening the browser and only prints
the verification URL (useful over SSH).

### Renew pattern for AI / headless environments

The session token lives 30 days and **rotates to a fresh 30-day token on every
`renew`** — renewing at least once a month keeps the session alive forever with
no human interaction:

```bash
# one-time bootstrap (human approves the printed URL in any browser)
opentunnel login --no-browser

# then, from cron / an agent loop — e.g. weekly:
opentunnel renew || echo "session lost — a human must run: opentunnel login"
```

Non-zero exit codes signal that re-login is required, so agents can detect and
escalate. `opentunnel token` hands the current session JWT to other tooling
(e.g. a client connecting with `authType: "session"`).

### `connect` / `disconnect`

**macOS** — drives the installed OpenTunnel.app NetworkExtension tunnel via
`scutil --nc` (no root). Requirements: the app is installed and has connected
at least once (that registers the NE service and stores a session token in the
NE configuration). `connect` starts the tunnel, waits for `Connected` (up to
30s), then smoke-tests internal-network reachability (TCP 11.0.1.21:443) and
exits 0 only when both pass. `disconnect` stops it.

> **Token caveat (macOS):** the NE tunnel authenticates with the token the
> *app* stored on its last connect — this is separate from the CLI's
> `session.json`, and `opentunnel renew` does not refresh it. Because the
> server rotates the NE token on every successful connect, any machine where
> the app has logged in once keeps working indefinitely as long as it connects
> at least monthly. If `connect` fails right after `Connecting`, open the app,
> log in once, and retry.

**Linux (headless servers)** — standalone foreground tunnel over
`/dev/net/tun`, using the CLI's own session token (`sudo` required):

```bash
sudo opentunnel connect              # foreground; Ctrl-C / SIGTERM disconnects cleanly
sudo opentunnel connect --ifname vpn0 --server vpn.datasee.co.kr:1194
```

It authenticates with `authType: "session"` (the rotated token is saved back),
applies the server-pushed address/MTU, and routes only the pushed
split-tunnel CIDRs (full-tunnel config uses the `0.0.0.0/1` + `128.0.0.0/1`
pair plus a pinned host route to the VPN server). Notes: DNS servers pushed by
the server are printed but `/etc/resolv.conf` is **not** modified, and
domain-based split-tunnel entries are not routed (CIDR routes only) — for
headless use, prefer IP CIDR rules. Daemonize with systemd:

```ini
# /etc/systemd/system/opentunnel.service
[Unit]
Description=OpenTunnel VPN client
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/opentunnel connect
Restart=on-failure
RestartSec=10
# session.json lives in root's home when run by systemd:
Environment=HOME=/root

[Install]
WantedBy=multi-user.target
```

`systemctl stop opentunnel` sends SIGTERM, which triggers a clean DISCONNECT
handshake and route cleanup. (`opentunnel disconnect` is macOS-only — on Linux
the foreground process owns the tunnel.)

## Common Features

All clients implement:
- TLS 1.3 connection to server
- Username/password authentication
- VPN tunnel management
- Connection status monitoring
- Auto-reconnect

## Protocol

Clients communicate with the server using a binary protocol over TLS:

```
[type:1][length:4][payload:N]
```

See server documentation for message type details.

## Testing

1. Start the VPN server
2. Create a test user via admin panel
3. Connect with client using credentials
4. Verify internet connectivity through VPN

## Troubleshooting

### macOS/iOS
- Ensure Network Extension capability is enabled
- Check System Preferences > VPN for configuration
- View Console.app for extension logs

### Android
- Grant VPN permission when prompted
- Check Logcat for tunnel logs
- Ensure battery optimization is disabled

### Windows
- Run as Administrator
- Install WinTun driver
- Check Windows Event Viewer for errors

## License

MIT
