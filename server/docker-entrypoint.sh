#!/bin/bash

echo "=== OpenTunnel VPN Server ==="
echo "Starting initialization..."

# Enable IP forwarding (may fail in container if read-only, host should have it enabled)
echo "Enabling IP forwarding..."
if echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null; then
    echo "IP forwarding enabled in container"
else
    echo "Note: Enable IP forwarding on host with: sudo sysctl -w net.ipv4.ip_forward=1"
fi

# Setup NAT if not already configured (may fail without NET_ADMIN)
echo "Configuring NAT rules..."
iptables -t nat -A POSTROUTING -s ${VPN_SUBNET:-10.8.0.0}/24 -o eth0 -j MASQUERADE 2>/dev/null || echo "Note: NAT rules should be configured on host"
iptables -A FORWARD -s ${VPN_SUBNET:-10.8.0.0}/24 -j ACCEPT 2>/dev/null || true
iptables -A FORWARD -d ${VPN_SUBNET:-10.8.0.0}/24 -j ACCEPT 2>/dev/null || true
iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true

# Create TUN device if it doesn't exist
if [ ! -c /dev/net/tun ]; then
    echo "Creating TUN device..."
    mkdir -p /dev/net
    mknod /dev/net/tun c 10 200
    chmod 666 /dev/net/tun
fi

# Generate certificates if they don't exist
if [ ! -f /app/certs/server.crt ]; then
    echo "Generating self-signed certificates..."
    mkdir -p /app/certs
    openssl req -x509 -newkey rsa:4096 -keyout /app/certs/server.key -out /app/certs/server.crt \
        -days 365 -nodes -subj "/CN=opentunnel-vpn"
fi

# Wait for database if configured
if [ -n "$DB_HOST" ]; then
    echo "Waiting for database at $DB_HOST:${DB_PORT:-5432}..."
    for i in {1..30}; do
        if nc -z "$DB_HOST" "${DB_PORT:-5432}" 2>/dev/null; then
            echo "Database is ready!"
            break
        fi
        echo "Waiting for database... ($i/30)"
        sleep 2
    done
fi

echo ""
echo "=== Configuration ==="
echo "  VPN Port: ${PORT:-1194}"
echo "  Admin Port: ${ADMIN_PORT:-8080}"
echo "  VPN Subnet: ${VPN_SUBNET}/24"
echo "  DNS Servers: ${DNS_SERVERS}"
echo "====================="
echo ""

echo "Starting VPN server..."
exec "$@"
