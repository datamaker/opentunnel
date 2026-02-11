#!/bin/bash
#
# OpenTunnel VPN - One-line installer
# Usage: curl -fsSL https://raw.githubusercontent.com/datamaker/opentunnel/main/install.sh | bash
#

set -e

INSTALL_DIR="${INSTALL_DIR:-/opt/opentunnel}"
DOCKER_IMAGE="datamaker/opentunnel:latest"

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
    echo "Note: Running without root. Some features may require sudo."
    if [ "$INSTALL_DIR" = "/opt/opentunnel" ]; then
        INSTALL_DIR="$HOME/opentunnel"
    fi
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

# Enable IP forwarding on host
echo "Enabling IP forwarding..."
if [ "$EUID" -eq 0 ]; then
    sysctl -w net.ipv4.ip_forward=1 > /dev/null 2>&1 || true
    # Make it persistent
    if [ -f /etc/sysctl.conf ]; then
        grep -q "net.ipv4.ip_forward" /etc/sysctl.conf || echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    fi
else
    echo "  Note: Run 'sudo sysctl -w net.ipv4.ip_forward=1' to enable IP forwarding"
fi

echo ""
echo "Pulling Docker images..."
docker pull $DOCKER_IMAGE
docker pull postgres:15-alpine

echo ""
echo "Starting services..."
docker compose up -d

# Wait for services to start
echo ""
echo "Waiting for services to initialize..."
sleep 15

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
