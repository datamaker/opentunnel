#!/bin/bash
#
# OpenTunnel VPN - One-line installer
# Usage: curl -fsSL https://raw.githubusercontent.com/datamaker/opentunnel/main/install.sh | bash
#

set -e

REPO="https://github.com/datamaker/opentunnel.git"
INSTALL_DIR="${INSTALL_DIR:-/opt/opentunnel}"

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
echo "OpenTunnel VPN Installer"
echo "========================"
echo ""

# Check requirements
command -v docker >/dev/null 2>&1 || { echo "Error: Docker is required but not installed."; exit 1; }
command -v docker compose >/dev/null 2>&1 || command -v docker-compose >/dev/null 2>&1 || { echo "Error: Docker Compose is required but not installed."; exit 1; }

# Check if running as root for /opt installation
if [ "$INSTALL_DIR" = "/opt/opentunnel" ] && [ "$EUID" -ne 0 ]; then
    echo "Installing to /opt requires root. Using ~/opentunnel instead."
    INSTALL_DIR="$HOME/opentunnel"
fi

echo "Installing to: $INSTALL_DIR"
echo ""

# Clone or update repository
if [ -d "$INSTALL_DIR" ]; then
    echo "Updating existing installation..."
    cd "$INSTALL_DIR"
    git pull
else
    echo "Cloning repository..."
    git clone "$REPO" "$INSTALL_DIR"
    cd "$INSTALL_DIR"
fi

# Generate random password if not set
if [ -z "$DB_PASSWORD" ]; then
    DB_PASSWORD=$(openssl rand -base64 32 | tr -dc 'a-zA-Z0-9' | head -c 24)
    echo "Generated database password: $DB_PASSWORD"
fi

# Create .env file
cat > .env << EOF
DB_PASSWORD=$DB_PASSWORD
JWT_SECRET=$(openssl rand -base64 32)
EOF

echo ""
echo "Starting services..."

# Use docker compose v2 or fall back to v1
if command -v docker compose >/dev/null 2>&1; then
    docker compose up -d
else
    docker-compose up -d
fi

# Wait for services to start
echo ""
echo "Waiting for services to start..."
sleep 10

# Create default admin user
echo ""
echo "Creating default admin user..."
curl -s -X POST http://localhost:8080/api/users \
    -H "Content-Type: application/json" \
    -d '{"username": "admin", "password": "admin123"}' || true

echo ""
echo "========================================"
echo "  OpenTunnel VPN installed successfully!"
echo "========================================"
echo ""
echo "  VPN Server:    localhost:1194"
echo "  Admin Panel:   http://localhost:8080"
echo ""
echo "  Default login:"
echo "    Username: admin"
echo "    Password: admin123"
echo ""
echo "  Change password immediately!"
echo ""
echo "  To stop:  cd $INSTALL_DIR && docker compose down"
echo "  To start: cd $INSTALL_DIR && docker compose up -d"
echo "  Logs:     cd $INSTALL_DIR && docker compose logs -f"
echo ""
