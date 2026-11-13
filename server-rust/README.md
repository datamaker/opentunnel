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

### Authentication

`AUTH_REQUEST` (0x01) supports three modes via the optional `authType` field
(absent = `password`, so existing clients keep working):

- **`password`** — `username` + `password`, bcrypt-verified against `users`.
  On success the server mints an HS256 session JWT (`JWT_SECRET`, 24h) and
  returns it as `sessionToken`.
- **`sso`** — `token` carries an OIDC **id_token** (RS256) from the internal
  IdP. The server verifies it against the issuer's JWKS (discovered via
  `{OIDC_ISSUER}/.well-known/openid-configuration`, keys cached in memory and
  refetched on unknown `kid`), checking `iss` == `OIDC_ISSUER`, `aud` ==
  `OIDC_CLIENT_ID`, `exp`, and `email_verified == true`. The user is looked up
  by email and JIT-provisioned on first login (`username` = email,
  `password_hash` = `!sso`, so password login can never match). The session JWT
  is minted with a 30-day expiry (`SSO_SESSION_TTL_DAYS`) and an `sso: true`
  claim. Requires `OIDC_ISSUER` to be set; otherwise `sso` requests are
  rejected.
- **`session`** — `token` carries a previously-issued OpenTunnel session JWT
  (HS256), used as a reconnect credential. The server validates signature and
  expiry, re-checks the account is active, and mints a fresh token (preserving
  the SSO marker and its longer TTL). Works without any OIDC configuration.

`VPN_PASSWORD_AUTH=false` switches the `password` mode off (and refuses
session tokens that came from a password login). It defaults to on for
compatibility; **production should turn it off** once everyone uses SSO. A
failed password login always answers `Invalid credentials` — unknown user,
wrong password and disabled account are indistinguishable, including by
timing (a dummy bcrypt verification runs when there is no usable hash).

An id_token is accepted **once**, and only within
`SSO_ID_TOKEN_MAX_AGE_SECS` (default 600) of its `iat`.

#### Session lifetime and revocation

- Session tokens carry `auth_time` (the real login they descend from) and
  `iat`. Reconnecting renews the token but never moves `auth_time`; renewal is
  refused once the login is older than `SSO_SESSION_MAX_LIFETIME_DAYS`
  (default = `SSO_SESSION_TTL_DAYS`), so an SSO user really signs in at least
  that often. Tokens from before these claims existed are read as issued (and
  logged in) one TTL before their `exp`, so they keep working until they would
  have expired.
- `users.tokens_valid_after` voids every token issued before it. The admin
  panel sets it — and closes the user's live tunnels through the session
  manager — on **연결 끊기**, on deactivating a user, and on
  **모든 기기에서 로그아웃** (`POST /api/users/:id/revoke`). Deleting a user
  closes their tunnels too. The column is added at startup
  (`ALTER TABLE … ADD COLUMN IF NOT EXISTS`, nullable, no default).
- Every renewal re-checks `users.is_active`, `SSO_ALLOWED_DOMAINS` and
  gatehouse.
- **gatehouse** (`GATEHOUSE_STATUS_URL` + `GATEHOUSE_STATUS_SECRET`, both
  required): SSO logins, renewals and — every `GATEHOUSE_RECHECK_SECS`
  (default 300) — live SSO tunnels are checked against
  `GET /internal/account?email=`. Inactive/unknown accounts and logins older
  than `revoked_before` are refused and their tunnels closed. Answers are
  cached for 60 s (2 s timeout); when gatehouse is unreachable the last answer
  per account is used, and an account never looked up successfully is allowed.
  A 404 only counts as "unknown account" when it carries the contract's
  `{"active":false}` body, so pointing this at a gatehouse that does not serve
  the route yet does not lock everyone out.
- The same periodic pass closes tunnels whose user was deleted, deactivated or
  revoked, or whose login is past the absolute lifetime.

All modes then follow the same path: connection-limit check, IP allocation,
session insert, `AUTH_RESPONSE` + `CONFIG_PUSH`. SSO settings live in
`src/sso.rs` (verification) and `src/config.rs` (`OIDC_ISSUER`,
`OIDC_CLIENT_ID`, `SSO_SESSION_TTL_DAYS`).

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

## Split tunneling (destination-based routing)

By default the server runs a **full tunnel** (client installs a default route).
Enable **split tunneling** to have clients route *only* specific destinations —
IP ranges and/or domains — through the VPN, leaving everything else on their
normal connection.

Configure it via env (or at runtime via the admin API):

```bash
SPLIT_TUNNEL=true
SPLIT_INCLUDE_ROUTES=10.0.0.0/8,192.168.0.0/16   # IP CIDRs
SPLIT_INCLUDE_DOMAINS=internal.example.com,api.example.com
SPLIT_DNS_REFRESH_SECS=300                        # domain re-resolve interval
```

How domains work: the **server** resolves each domain to its IPv4 addresses
(refreshed on a timer) and folds them into the pushed route list as `/32`
entries, so even clients that can't match by domain get concrete routes. The
original domain names are pushed too (`includedDomains`) for clients that do
their own DNS-based matching.

### Client contract

The policy is delivered in the post-auth config message (`ConfigPush`):

| Field | Meaning |
|-------|---------|
| `splitTunnel` | `true` = install routes only for the lists below; `false` = full tunnel (default route) |
| `includedRoutes` | IP CIDRs to route through the tunnel (static routes + resolved domain IPs) |
| `includedDomains` | Original domains, for clients that match by domain |

The server pushes the policy; **the client applies it to its routing table**.
The server data plane is unchanged — it simply NATs whatever the client sends.

### Admin API

- `GET /api/split` — view the effective policy (static routes + resolved IPs).
- `POST /api/split` — replace it at runtime and re-resolve domains; takes effect
  for subsequently-connecting clients. Body: `{ "enabled": bool, "routes": [..], "domains": [..] }`.

## Configuration

All settings come from environment variables (see `.env.example`). Both the
original `VPN_PORT`/`VPN_DNS` names and the Docker `PORT`/`DNS_SERVERS` names are
accepted for compatibility.

### Listener limits

The VPN port faces the internet, so everything a peer can do before it has
authenticated is bounded. All of it is configurable; a count/rate of `0`
disables that limit (frame sizes and timeouts cannot be disabled).

| Variable | Default | Meaning |
|----------|---------|---------|
| `VPN_MAX_PREAUTH_FRAME_BYTES` | `16384` | Largest frame before authentication. Only the auth request has to fit. |
| `VPN_MAX_FRAME_BYTES` | `65535` | Largest frame after authentication (one tunnelled IP packet). Never below `VPN_MTU`. |
| `VPN_TLS_HANDSHAKE_TIMEOUT_SECS` | `10` | Time allowed for the TLS handshake. |
| `VPN_AUTH_TIMEOUT_SECS` | `15` | Absolute time from TCP accept to successful authentication. Reads do not extend it. |
| `VPN_MAX_CONNECTIONS` | `256` | Concurrent connections, authenticated or not. |
| `VPN_MAX_UNAUTH_PER_IP` | `32` | Concurrent not-yet-authenticated connections per source. |
| `VPN_CONN_RATE_PER_MIN` | `120` | New connections per source per minute (token bucket, burst = same value). |
| `VPN_AUTH_FAIL_PER_MIN` | `30` | Failed logins per source per minute (token bucket); while empty, new connections from the source are refused. |
| `VPN_LIMIT_EXEMPT_CIDRS` | empty | CIDRs exempt from the per-source limits (still counted toward `VPN_MAX_CONNECTIONS`). |
| `VPN_AUTH_FAIL_LOG_PER_MIN` | `10` | `auth_fail` rows stored in `connection_logs` per source per minute; the rest are counted and noted on the next row. |
| `CONNECTION_LOG_RETENTION_DAYS` | `90` | `connection_logs` rows older than this are deleted hourly. `0` keeps everything. |

A frame whose length header exceeds the limit closes the connection before any
of its body is read. A "source" is an IPv4 address or an IPv6 /64. The server
must see real client addresses for the per-source limits to mean anything:
behind a load balancer that needs TCP passthrough with client-IP preservation
(a proxy that hides the client address would make every user share one source).
Refusals and other pre-auth events are logged at most once per 10 seconds per
kind, with a count of what was not logged.

### Tunnel packet filter

Packets a client sends into the tunnel are checked in the server before they
reach the TUN device (`src/router.rs`): anything that is not an IPv4 packet
whose source is the address assigned to that session is dropped, and with
`VPN_CLIENT_ISOLATION=true` (the default) so is a packet addressed to another
client's tunnel address (the gateway stays reachable). Drops are counted on
the 60-second status line and logged at most once per 10 seconds.

## Status

Initial port. Control plane (TLS, auth, config push, keepalive, session
lifecycle, DB persistence), the admin API, and bidirectional packet routing are
implemented and covered by an end-to-end test against a live PostgreSQL. The
Linux data plane uses a native, pure-Rust TUN device (no Python).

## Admin panel security

- `ADMIN_PASSWORD` is **required in production** — password login is refused
  while the compiled-in default is in effect.
- Admin SSO login: set `ADMIN_SSO_EMAILS` (comma-separated emails or
  `@domains`) plus `OIDC_ISSUER`. The panel then shows a "Sign in with Google"
  button. If the device-flow client id is not a Web-type OAuth client, create
  one and set it as `OIDC_ADMIN_CLIENT_ID` (authorized JavaScript origin =
  the panel URL).
- VPN SSO logins are restricted with `SSO_ALLOWED_DOMAINS`
  (e.g. `datasee.co.kr`). While unset, any account the IdP verifies is
  accepted and auto-provisioned — the server logs a warning.
- Login endpoints lock an IP out for 60s after 5 consecutive failures.
- API tokens are accepted from the `Authorization: Bearer` header only.
