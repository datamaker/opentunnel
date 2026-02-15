#!/bin/bash
#
# OpenTunnel VPN - One-line installer
# Usage: curl -fsSL https://raw.githubusercontent.com/datamaker/opentunnel/main/install.sh | sudo bash
#

set -e

INSTALL_DIR="${INSTALL_DIR:-/opt/opentunnel}"
DOCKER_IMAGE="datamaker/opentunnel:latest"
VPN_SUBNET="10.8.0.0"

echo "
   ____                   _____                       _
  / __ \                 |_   _|                     | |
 | |  | |_ __   ___ _ __   | |_   _ _ __  _ __   ___| |
 | |  | | '_ \ / _ \ '_ \  | | | | | '_ \| '_ \ / _ \ |
 | |__| | |_) |  __/ | | | | | |_| | | | | | | |  __/ |
  \____/| .__/ \___|_| |_| \_/\__,_|_| |_|_| |_|\___|_|
        | |
        |_|
"
echo "OpenTunnel VPN Installer v1.0"
echo "============================="
echo ""

# Check requirements
command -v docker >/dev/null 2>&1 || { echo "Error: Docker is required but not installed."; exit 1; }

# Check if running as root for system setup
if [ "$EUID" -ne 0 ]; then
    echo "Error: This script must be run as root (use sudo)"
    exit 1
fi

echo "Install directory: $INSTALL_DIR"
echo ""

# Create install directory
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

# Generate random passwords
DB_PASSWORD=$(openssl rand -base64 32 | tr -dc 'a-zA-Z0-9' | head -c 24)
JWT_SECRET=$(openssl rand -base64 32)

# Create docker-compose.yml
cat > docker-compose.yml << 'EOF'
version: '3.8'

services:
  vpn:
    image: datamaker/opentunnel:latest
    container_name: opentunnel-vpn
    restart: unless-stopped
    cap_add:
      - NET_ADMIN
    devices:
      - /dev/net/tun:/dev/net/tun
    ports:
      - "1194:1194"
      - "8080:8080"
    environment:
      - DB_HOST=db
      - DB_PORT=5432
      - DB_NAME=vpn
      - DB_USER=vpn
      - DB_PASSWORD=${DB_PASSWORD}
      - JWT_SECRET=${JWT_SECRET}
    depends_on:
      db:
        condition: service_healthy
    networks:
      - vpn-network

  db:
    image: postgres:15-alpine
    container_name: opentunnel-db
    restart: unless-stopped
    environment:
      - POSTGRES_USER=vpn
      - POSTGRES_PASSWORD=${DB_PASSWORD}
      - POSTGRES_DB=vpn
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U vpn"]
      interval: 5s
      timeout: 5s
      retries: 5
    networks:
      - vpn-network

networks:
  vpn-network:
    driver: bridge

volumes:
  postgres_data:
EOF

# Create .env file
cat > .env << EOF
DB_PASSWORD=$DB_PASSWORD
JWT_SECRET=$JWT_SECRET
EOF

echo "Configuration files created."
echo ""

# ============================================
# Setup Host Networking (NAT & IP Forwarding)
# ============================================
echo "Configuring host networking..."

# Enable IP forwarding
echo "  Enabling IP forwarding..."
sysctl -w net.ipv4.ip_forward=1 > /dev/null 2>&1
# Make it persistent
if [ -f /etc/sysctl.conf ]; then
    grep -q "^net.ipv4.ip_forward" /etc/sysctl.conf || echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
fi
echo "  IP forwarding enabled."

# Setup NAT rules on host
echo "  Setting up NAT rules..."

# Find default interface
DEFAULT_IFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
if [ -z "$DEFAULT_IFACE" ]; then
    DEFAULT_IFACE="eth0"
fi
echo "  Default interface: $DEFAULT_IFACE"

# Remove old rules if exist (avoid duplicates)
iptables -t nat -D POSTROUTING -s ${VPN_SUBNET}/24 -o $DEFAULT_IFACE -j MASQUERADE 2>/dev/null || true
iptables -D FORWARD -s ${VPN_SUBNET}/24 -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -d ${VPN_SUBNET}/24 -j ACCEPT 2>/dev/null || true

# Add NAT rules
iptables -t nat -A POSTROUTING -s ${VPN_SUBNET}/24 -o $DEFAULT_IFACE -j MASQUERADE
iptables -A FORWARD -s ${VPN_SUBNET}/24 -j ACCEPT
iptables -A FORWARD -d ${VPN_SUBNET}/24 -j ACCEPT
iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true

echo "  NAT rules configured."

# Save iptables rules (if iptables-persistent is installed)
if command -v netfilter-persistent >/dev/null 2>&1; then
    netfilter-persistent save 2>/dev/null || true
fi

echo ""
echo "Pulling Docker images..."
docker pull $DOCKER_IMAGE
docker pull postgres:15-alpine

echo ""
echo "Starting services..."
docker compose up -d

# Wait for PostgreSQL to be ready
echo ""
echo "Waiting for database to be ready..."
for i in {1..30}; do
    if docker exec opentunnel-db pg_isready -U vpn >/dev/null 2>&1; then
        echo "Database is ready!"
        break
    fi
    echo "  Waiting... ($i/30)"
    sleep 2
done

# Initialize database schema
echo ""
echo "Initializing database schema..."
docker exec -i opentunnel-db psql -U vpn -d vpn << 'SCHEMA_EOF'
-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    email VARCHAR(100),
    is_active BOOLEAN DEFAULT true,
    max_connections INT DEFAULT 3,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Active sessions table
CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    assigned_ip VARCHAR(15) NOT NULL,
    client_ip VARCHAR(45),
    client_platform VARCHAR(20) NOT NULL,
    client_version VARCHAR(20),
    connected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_activity TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    bytes_sent BIGINT DEFAULT 0,
    bytes_received BIGINT DEFAULT 0,
    UNIQUE(assigned_ip)
);

-- Connection logs table
CREATE TABLE IF NOT EXISTS connection_logs (
    id SERIAL PRIMARY KEY,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    session_id UUID,
    event_type VARCHAR(20) NOT NULL CHECK (event_type IN ('connect', 'disconnect', 'auth_fail', 'error')),
    client_ip VARCHAR(45),
    client_platform VARCHAR(20),
    details TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_assigned_ip ON sessions(assigned_ip);
CREATE INDEX IF NOT EXISTS idx_sessions_last_activity ON sessions(last_activity);
CREATE INDEX IF NOT EXISTS idx_connection_logs_user_id ON connection_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_connection_logs_created_at ON connection_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_connection_logs_event_type ON connection_logs(event_type);

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Trigger for users table
DROP TRIGGER IF EXISTS update_users_updated_at ON users;
CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Insert default admin user (password: admin123)
INSERT INTO users (username, password_hash, email, max_connections)
VALUES ('admin', '$2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy', 'admin@example.com', 5)
ON CONFLICT (username) DO NOTHING;

-- Sample user for testing (password: test123)
INSERT INTO users (username, password_hash, email)
VALUES ('testuser', '$2b$10$X0x7rb4SJjhsm5wBdiGTrOaDxbb18joxI08SrtEECg4R.SqjApqB2', 'test@example.com')
ON CONFLICT (username) DO NOTHING;
SCHEMA_EOF

echo "Database schema initialized!"

# Restart VPN container to pick up database
echo ""
echo "Restarting VPN server..."
docker restart opentunnel-vpn
sleep 5

# Check if VPN is running
if docker ps | grep -q opentunnel-vpn; then
    echo ""
    echo "========================================"
    echo "  OpenTunnel VPN installed successfully!"
    echo "========================================"
    echo ""
    echo "  VPN Server: $(hostname -I 2>/dev/null | awk '{print $1}' || echo 'your-server-ip'):1194"
    echo ""
    echo "  Default credentials:"
    echo "    Username: testuser"
    echo "    Password: test123"
    echo ""
    echo "  NAT Status:"
    echo "    Interface: $DEFAULT_IFACE"
    echo "    Subnet: ${VPN_SUBNET}/24"
    iptables -t nat -L POSTROUTING -n | grep -q "$VPN_SUBNET" && echo "    MASQUERADE: OK" || echo "    MASQUERADE: Check required"
    echo ""
    echo "  Management commands:"
    echo "    Status:  docker ps"
    echo "    Logs:    docker logs -f opentunnel-vpn"
    echo "    Stop:    cd $INSTALL_DIR && docker compose down"
    echo "    Start:   cd $INSTALL_DIR && docker compose up -d"
    echo ""
    echo "  Database password saved in: $INSTALL_DIR/.env"
    echo ""
else
    echo ""
    echo "Warning: VPN container may not have started correctly."
    echo "Check logs with: docker logs opentunnel-vpn"
fi
