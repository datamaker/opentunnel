# OpenTunnel VPN

A lightweight, open-source VPN solution built from scratch. OpenTunnel provides secure encrypted tunneling with native clients for all major platforms.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Docker](https://img.shields.io/badge/docker-datamaker%2Fopentunnel-blue.svg)
![Clients](https://img.shields.io/badge/clients-iOS%20%7C%20Android%20%7C%20macOS%20%7C%20Windows-orange.svg)

## Features

- **Full Tunnel VPN**: Route all internet traffic through the VPN server
- **TLS 1.3 Encryption**: Secure communication using modern cryptography
- **Multi-Platform Clients**: Native apps for macOS, iOS, Android, and Windows
- **Docker Deployment**: One-command installation using Docker
- **PostgreSQL Backend**: Reliable user authentication and session management

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
│                    VPN Server (Docker)                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │ TLS Server  │  │ TUN Bridge  │  │   NAT/FW    │             │
│  │  (Node.js)  │  │  (Python)   │  │ (iptables)  │             │
│  └─────────────┘  └─────────────┘  └─────────────┘             │
│                          │                                      │
│                   ┌──────▼──────┐                               │
│                   │ PostgreSQL  │                               │
│                   └─────────────┘                               │
└─────────────────────────────────────────────────────────────────┘
```

## Quick Start

### One-Line Installation (Recommended)

```bash
curl -fsSL https://raw.githubusercontent.com/datamaker/opentunnel/main/install.sh | sudo bash
```

This will:
- Pull the Docker image from Docker Hub
- Create a docker-compose.yml configuration
- Start the VPN server and PostgreSQL database
- Enable IP forwarding on the host

### Manual Docker Installation

```bash
# Create network
docker network create vpn-network

# Start PostgreSQL
docker run -d \
  --name opentunnel-db \
  --network vpn-network \
  -e POSTGRES_USER=vpn \
  -e POSTGRES_PASSWORD=your-secure-password \
  -e POSTGRES_DB=vpn \
  postgres:15-alpine

# Start VPN Server
docker run -d \
  --name opentunnel-vpn \
  --network vpn-network \
  --cap-add=NET_ADMIN \
  --device=/dev/net/tun \
  -p 1194:1194 \
  -e DB_HOST=opentunnel-db \
  -e DB_PASSWORD=your-secure-password \
  datamaker/opentunnel:latest

# Enable IP forwarding on host
sudo sysctl -w net.ipv4.ip_forward=1
```

### Verify Installation

```bash
# Check containers are running
docker ps

# View server logs
docker logs -f opentunnel-vpn

# Test TLS connection
openssl s_client -connect localhost:1194 -tls1_3
```

## Default Credentials

| Username | Password |
|----------|----------|
| testuser | test123 |

> **Warning**: Change the default password immediately in production!

## Client Setup

### macOS Client

1. Open `clients/macos/VPNClient.xcodeproj` in Xcode
2. Update server address in `ContentView.swift`:
   ```swift
   @State private var serverAddress = "your-server-ip"
   ```
3. Build and run (⌘+R)
4. Enter credentials and click "Connect"

### iOS Client

1. Open `clients/ios/OpenTunnelVPN.xcodeproj` in Xcode
2. Select your development team for code signing
3. Update server address in the app
4. Deploy to a real device (VPN apps require physical device)
5. Go to Settings → General → VPN to enable the profile

### Android Client

1. Open `clients/android/` in Android Studio
2. Update server address in `app/src/main/java/.../VpnConfig.kt`
3. Build APK: Build → Build Bundle(s) / APK(s) → Build APK(s)
4. Install and grant VPN permissions when prompted

### Windows Client

1. Open `clients/windows/OpenTunnelVPN.sln` in Visual Studio
2. Build solution (Ctrl+Shift+B)
3. Run as Administrator (required for TAP adapter)
4. Enter server address and credentials

## Server Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `VPN_PORT` | 1194 | VPN server port |
| `VPN_SUBNET` | 10.8.0.0 | VPN client subnet |
| `VPN_NETMASK` | 255.255.255.0 | Subnet mask |
| `DNS_SERVERS` | 8.8.8.8,8.8.4.4 | DNS servers for clients |
| `DB_HOST` | localhost | PostgreSQL host |
| `DB_PORT` | 5432 | PostgreSQL port |
| `DB_NAME` | vpn | Database name |
| `DB_USER` | vpn | Database user |
| `DB_PASSWORD` | required | Database password |
| `JWT_SECRET` | auto-generated | JWT signing secret |

### Adding Users

Connect to the database and insert users:

```sql
-- Connect to database
docker exec -it opentunnel-db psql -U vpn

-- Generate bcrypt hash for password (use bcrypt online tool or node)
-- Example: password "mypassword" = "$2b$10$..."

INSERT INTO users (username, password_hash, is_active, max_connections)
VALUES ('newuser', '$2b$10$your-bcrypt-hash', true, 3);
```

## Protocol Specification

### Message Format

```
┌─────────┬──────────────┬─────────────────┐
│  Type   │    Length    │     Payload     │
│ 1 byte  │   4 bytes    │    N bytes      │
│         │  (big-endian)│                 │
└─────────┴──────────────┴─────────────────┘
```

### Message Types

| Type | Code | Description |
|------|------|-------------|
| AUTH_REQUEST | 0x01 | Client sends username/password |
| AUTH_RESPONSE | 0x02 | Server responds with success/failure |
| CONFIG_PUSH | 0x03 | Server sends VPN config (IP, DNS, etc.) |
| KEEPALIVE | 0x04 | Keepalive ping |
| KEEPALIVE_ACK | 0x05 | Keepalive acknowledgment |
| DISCONNECT | 0x06 | Graceful disconnect |
| DATA_PACKET | 0x10 | Encapsulated IP packet |

### Authentication Flow

```
Client                              Server
   │                                   │
   │──── AUTH_REQUEST ────────────────>│
   │     {username, password}          │
   │                                   │
   │<─── AUTH_RESPONSE ────────────────│
   │     {success, sessionToken}       │
   │                                   │
   │<─── CONFIG_PUSH ──────────────────│
   │     {assignedIP, gateway, dns}    │
   │                                   │
   │──── DATA_PACKET ─────────────────>│
   │     [IP packets]                  │
   │<─── DATA_PACKET ──────────────────│
   │                                   │
```

## Troubleshooting

### Connection Refused
```bash
# Check if port is open
sudo ufw allow 1194/tcp
# or
sudo iptables -A INPUT -p tcp --dport 1194 -j ACCEPT

# Verify Docker is running
docker ps | grep opentunnel
```

### No Internet Through VPN
```bash
# Enable IP forwarding on host
sudo sysctl -w net.ipv4.ip_forward=1

# Make persistent
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf

# Check NAT rules in container
docker exec opentunnel-vpn iptables -t nat -L POSTROUTING -n -v
```

### Authentication Failed
```bash
# Check server logs
docker logs opentunnel-vpn | grep -i auth

# Verify user exists in database
docker exec opentunnel-db psql -U vpn -c "SELECT username FROM users;"

# Reset user password
docker exec opentunnel-db psql -U vpn -c \
  "UPDATE users SET password_hash='new-bcrypt-hash' WHERE username='testuser';"
```

### TUN Device Error
```bash
# Ensure TUN module is loaded
sudo modprobe tun
ls -la /dev/net/tun

# Verify container has NET_ADMIN capability
docker inspect opentunnel-vpn | grep -A5 CapAdd
```

## Development

### Building from Source

```bash
# Clone repository
git clone https://github.com/datamaker/opentunnel.git
cd opentunnel/server

# Install dependencies
npm install

# Build TypeScript
npm run build

# Run in development
npm run dev
```

### Building Docker Image

```bash
cd server
docker build -t opentunnel:dev .

# Test locally
docker run --rm -it \
  --cap-add=NET_ADMIN \
  --device=/dev/net/tun \
  -p 1194:1194 \
  opentunnel:dev
```

### Project Structure

```
opentunnel/
├── server/                 # Node.js VPN server
│   ├── src/
│   │   ├── index.ts       # Entry point
│   │   ├── config/        # Configuration
│   │   ├── tun/           # TUN device management
│   │   ├── crypto/        # TLS server
│   │   ├── protocol/      # VPN protocol
│   │   ├── routing/       # Packet routing & NAT
│   │   ├── session/       # Session management
│   │   ├── auth/          # Authentication
│   │   └── db/            # Database
│   ├── tun-bridge.py      # Python TUN bridge
│   ├── Dockerfile
│   └── package.json
│
├── clients/
│   ├── ios/               # iOS client (Swift)
│   ├── android/           # Android client (Kotlin)
│   ├── macos/             # macOS client (Swift)
│   └── windows/           # Windows client (C#)
│
├── install.sh             # One-line installer
├── docker-compose.yml     # Docker Compose config
└── README.md
```

## Security Considerations

- **Change default credentials** immediately after installation
- Use **strong passwords** (16+ characters recommended)
- Keep Docker and host system **updated**
- Use a **firewall** to restrict access to management ports
- **Monitor logs** for suspicious activity
- Consider using **fail2ban** for brute-force protection

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Acknowledgments

- Inspired by OpenVPN architecture
- Built with Node.js, Python, Swift, Kotlin, and C#
- Uses PostgreSQL for reliable data storage
