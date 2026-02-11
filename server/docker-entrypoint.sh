#!/bin/bash
set -e

echo "=== OpenTunnel VPN Server ==="
echo "Starting initialization..."

# Enable IP forwarding
echo "Enabling IP forwarding..."
echo 1 > /proc/sys/net/ipv4/ip_forward

# Setup NAT if not already configured
if ! iptables -t nat -C POSTROUTING -s ${VPN_SUBNET}/24 -j MASQUERADE 2>/dev/null; then
    echo "Configuring NAT rules..."
    iptables -t nat -A POSTROUTING -s ${VPN_SUBNET}/24 -j MASQUERADE
    iptables -A FORWARD -s ${VPN_SUBNET}/24 -j ACCEPT
    iptables -A FORWARD -d ${VPN_SUBNET}/24 -j ACCEPT
    iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
fi

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
