# OpenTunnel VPN

A modern, open-source VPN solution built from scratch. Inspired by OpenVPN but implemented with modern technologies.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Server](https://img.shields.io/badge/server-Node.js-green.svg)
![Clients](https://img.shields.io/badge/clients-iOS%20%7C%20Android%20%7C%20macOS%20%7C%20Windows-orange.svg)

## Features

- **TLS 1.3 Encryption** - Secure tunnel using modern TLS
- **Cross-Platform Clients** - Native apps for iOS, Android, macOS, and Windows
- **Simple Authentication** - Username/password with PostgreSQL backend
- **Easy Deployment** - Docker support for quick server setup
- **Admin Panel** - Web-based management interface

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Clients                                  │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐        │
│  │   iOS    │  │ Android  │  │  macOS   │  │ Windows  │        │
│  │  Swift   │  │  Kotlin  │  │  Swift   │  │   C#     │        │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘        │
│       └─────────────┴─────────────┴─────────────┘              │
│                           │                                     │
│                   TLS 1.3 Encrypted Tunnel                      │
│                      (Port 1194)                                │
└───────────────────────────┼─────────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────────┐
│                    Node.js VPN Server                           │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │ TLS Server  │  │Auth Service │  │Packet Router│             │
│  └─────────────┘  └──────┬──────┘  └─────────────┘             │
│                          │                                      │
│                   ┌──────▼──────┐                               │
│                   │ PostgreSQL  │                               │
│                   └─────────────┘                               │
└─────────────────────────────────────────────────────────────────┘
```

## Quick Start

### Server (Docker)

```bash
# Pull and run
docker run -d \
  --name opentunnel \
  --cap-add=NET_ADMIN \
  -p 1194:1194 \
  -p 8080:8080 \
  -e DB_HOST=your-db-host \
  -e DB_PASSWORD=your-password \
  datamaker/opentunnel:latest

# Or use docker-compose
docker-compose up -d
```

### Server (Manual)

```bash
cd server
npm install
npm run build

# Setup IP forwarding and NAT
sudo ./scripts/setup-server.sh

# Start server
sudo NODE_ENV=production npm start
```

### Clients

| Platform | Installation |
|----------|--------------|
| macOS | Build from source (Xcode) |
| iOS | Build from source (Xcode) |
| Android | Build from source (Android Studio) |
| Windows | Build from source (Visual Studio) |

## Protocol

Custom binary protocol over TLS:

| Message Type | Code | Description |
|--------------|------|-------------|
| AUTH_REQUEST | 0x01 | Client authentication |
| AUTH_RESPONSE | 0x02 | Server auth response |
| CONFIG_PUSH | 0x03 | VPN configuration |
| KEEPALIVE | 0x04 | Connection keepalive |
| KEEPALIVE_ACK | 0x05 | Keepalive response |
| DISCONNECT | 0x06 | Graceful disconnect |
| DATA_PACKET | 0x10 | Tunneled IP packet |

Message format: `[type:1][length:4][payload:N]`

## Configuration

### Server Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | 1194 | VPN server port |
| `ADMIN_PORT` | 8080 | Admin panel port |
| `DB_HOST` | localhost | PostgreSQL host |
| `DB_PORT` | 5432 | PostgreSQL port |
| `DB_NAME` | vpn | Database name |
| `DB_USER` | vpn | Database user |
| `DB_PASSWORD` | - | Database password |
| `VPN_SUBNET` | 10.8.0.0 | VPN IP subnet |
| `DNS_SERVERS` | 8.8.8.8,8.8.4.4 | DNS servers |

## Project Structure

```
opentunnel/
├── server/                 # Node.js VPN server
│   ├── src/
│   ├── Dockerfile
│   └── README.md
├── clients/
│   ├── ios/               # iOS client (Swift)
│   ├── android/           # Android client (Kotlin)
│   ├── macos/             # macOS client (Swift)
│   └── windows/           # Windows client (C#)
├── docs/                  # Documentation
└── docker-compose.yml
```

## Security

- TLS 1.3 for all communications
- Passwords hashed with bcrypt
- Session tokens with expiration
- IP-based rate limiting

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

- Inspired by OpenVPN
- Built with Node.js, Swift, Kotlin, and C#
