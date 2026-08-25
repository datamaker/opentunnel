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
opentunnel status           # local view: user, server, expiry, time remaining
opentunnel status --check   # also verifies against the server (rotates the token)
opentunnel token            # print the raw session JWT for scripts (exit 1 if expired)
opentunnel logout           # delete the stored session
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
