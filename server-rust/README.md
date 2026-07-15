# OpenTunnel VPN Server (Rust)

A Rust rewrite of the OpenTunnel VPN server, built on Tokio. It is a drop-in
replacement for the original Node.js/TypeScript server (`../server`): it speaks
the **same wire protocol** over TLS, uses the **same PostgreSQL schema**, and
exposes the **same admin HTTP API and static panel**, so existing clients and
deployments keep working unchanged.

## Why Rust

- No garbage-collector pauses on the packet path.
- Lower, more predictable memory footprint per connection.
- A single statically-linked binary instead of a Node runtime + `node_modules`.

## Architecture

| Concern | Module | Original (TS) |
|---------|--------|---------------|
| Config from env | `src/config.rs` | `config/config.ts` |
| Wire protocol / framing | `src/protocol/` | `protocol/*.ts` |
| TLS acceptor | `src/tls.rs` | `crypto/tlsServer.ts` |
| Auth + sessions (DB) | `src/auth.rs` | `auth/authService.ts` |
| IP address pool | `src/ippool.rs` | `routing/ipPool.ts` |
| Connection state machine | `src/session/connection.rs` | `session/vpnSession.ts` |
| Session registry / routing | `src/session/manager.rs` | `session/sessionManager.ts` |
| TUN device (native, pure Rust) | `src/tun.rs` | `tun/tunDevice.ts` |
| Packet router | `src/router.rs` | `routing/packetRouter.ts` |
| Admin HTTP API + UI | `src/admin.rs` | `admin/adminServer.ts` |

### Wire protocol

Frames are `[type: 1 byte][length: 4 bytes big-endian][payload: N bytes]`.
Control payloads are JSON; data packets carry raw IP packets. Message types
(`0x01` AUTH_REQUEST … `0x10` DATA_PACKET) match the original exactly. The
`KEEPALIVE_ACK` (`0x05`) handling and the unauthenticated `/health` endpoint
from the Node.js server's later fixes are included.

### Data plane

The TUN device is driven **natively in pure Rust** — `src/tun.rs` opens
`/dev/net/tun`, configures it with the `TUNSETIFF` ioctl (via `libc`), and does
async reads/writes on the raw fd with Tokio's `AsyncFd`. The interface itself
(address, netmask, MTU, up) is also configured natively via `SIOCSIF*` ioctls on
an `AF_INET` socket — no `ip`/`iproute2` and no Python. The only remaining
shell-out is a one-time `iptables` MASQUERADE rule at startup (kept for
operational visibility; it is off the packet path).

- **client → internet**: `DATA_PACKET` frames are written directly to the TUN fd.
- **internet → client**: packets read from TUN are routed to the owning session
  by destination IP and framed back to the client.

Outside production (`NODE_ENV != production`) a **mock TUN device** is used so
the server runs without root or `/dev/net/tun`.

## Build

```bash
cargo build --release   # binary at target/release/opentunnel-server
cargo test              # protocol / IP-pool unit tests
```

## Run (local)

```bash
cp .env.example .env    # then edit as needed
# Generate a dev certificate:
mkdir -p certs
openssl req -x509 -newkey rsa:2048 -keyout certs/server.key \
    -out certs/server.crt -days 365 -nodes -subj "/CN=opentunnel"
# Point DB_* at a Postgres loaded with ../server/database/schema.sql, then:
cargo run --release
```

The VPN listener defaults to `:1194` and the admin panel to `:8080`.

## Docker

```bash
docker build -t datamaker/opentunnel-rust:latest .
```

The image is self-contained (binary + admin UI, no Python) and drops in against
the existing `docker-compose.yml` / PostgreSQL setup. Requires
`--cap-add NET_ADMIN` and `--device /dev/net/tun` for the real data plane.

## Configuration

All settings come from environment variables (see `.env.example`). Both the
original `VPN_PORT`/`VPN_DNS` names and the Docker `PORT`/`DNS_SERVERS` names are
accepted for compatibility.

## Status

Initial port. Control plane (TLS, auth, config push, keepalive, session
lifecycle, DB persistence), the admin API, and bidirectional packet routing are
implemented and covered by an end-to-end test against a live PostgreSQL. The
Linux data plane uses a native, pure-Rust TUN device (no Python).
