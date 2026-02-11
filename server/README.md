# OpenTunnel VPN Server

Node.js-based VPN server with TLS encryption and PostgreSQL backend.

## Features

- TLS 1.3 encrypted tunnel
- Username/password authentication
- PostgreSQL session storage
- IP pool management
- Admin REST API
- Docker support

## Quick Start

### Docker (Recommended)

```bash
# Using Docker Compose (includes PostgreSQL)
docker-compose up -d

# Or standalone with external database
docker run -d \
  --name opentunnel \
  --cap-add=NET_ADMIN \
  --device=/dev/net/tun \
  -p 1194:1194 \
  -p 8080:8080 \
  -e DB_HOST=your-db-host \
  -e DB_PASSWORD=your-password \
  opentunnel/server:latest
```

### Manual Installation

```bash
# Install dependencies
npm install

# Setup database
npm run db:init

# Generate certificates
npm run certs:generate

# Build
npm run build

# Setup networking (requires root)
sudo ./scripts/setup-server.sh

# Run
sudo NODE_ENV=production npm start
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `NODE_ENV` | development | Environment mode |
| `PORT` | 1194 | VPN server port |
| `ADMIN_PORT` | 8080 | Admin API port |
| `DB_HOST` | localhost | PostgreSQL host |
| `DB_PORT` | 5432 | PostgreSQL port |
| `DB_NAME` | vpn | Database name |
| `DB_USER` | vpn | Database user |
| `DB_PASSWORD` | - | Database password |
| `VPN_SUBNET` | 10.8.0.0 | VPN client subnet |
| `DNS_SERVERS` | 8.8.8.8,8.8.4.4 | DNS servers for clients |
| `JWT_SECRET` | - | JWT signing secret |

## Admin API

### Endpoints

```
GET  /health              - Health check
GET  /api/users           - List users
POST /api/users           - Create user
GET  /api/sessions        - List active sessions
GET  /api/stats           - Server statistics
```

### Create User

```bash
curl -X POST http://localhost:8080/api/users \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "password": "password123"}'
```

## Protocol

Binary protocol over TLS:

```
[type:1 byte][length:4 bytes BE][payload:N bytes]
```

| Type | Code | Direction | Description |
|------|------|-----------|-------------|
| AUTH_REQUEST | 0x01 | C→S | Authentication |
| AUTH_RESPONSE | 0x02 | S→C | Auth result |
| CONFIG_PUSH | 0x03 | S→C | VPN config |
| KEEPALIVE | 0x04 | Both | Keep alive |
| KEEPALIVE_ACK | 0x05 | Both | Keep alive ack |
| DISCONNECT | 0x06 | Both | Disconnect |
| DATA_PACKET | 0x10 | Both | IP packet |

## Project Structure

```
server/
├── src/
│   ├── index.ts          # Entry point
│   ├── config/           # Configuration
│   ├── crypto/           # TLS server
│   ├── protocol/         # VPN protocol
│   ├── auth/             # Authentication
│   ├── session/          # Session management
│   ├── routing/          # Packet routing
│   ├── tun/              # TUN device
│   ├── db/               # Database
│   ├── admin/            # Admin API
│   └── utils/            # Utilities
├── database/
│   └── schema.sql        # DB schema
├── certs/                # TLS certificates
├── scripts/              # Setup scripts
├── Dockerfile
└── package.json
```

## Development

```bash
# Install dependencies
npm install

# Run in development mode
npm run dev

# Run tests
npm test

# Lint
npm run lint
```

## Security Notes

- Always use strong passwords
- Change default JWT_SECRET in production
- Use proper TLS certificates in production
- Configure firewall rules appropriately
- Regular security updates

## License

MIT
