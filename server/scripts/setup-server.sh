#!/bin/bash

# VPN Server Setup Script
# Run with: sudo ./setup-server.sh

set -e

echo "=== VPN Server Setup ==="

# Detect OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
else
    echo "Unsupported OS: $OSTYPE"
    exit 1
fi

echo "Detected OS: $OS"

# Get main network interface
if [ "$OS" == "linux" ]; then
    INTERFACE=$(ip route | grep default | awk '{print $5}' | head -1)
else
    INTERFACE=$(route -n get default | grep interface | awk '{print $2}')
fi

echo "Network interface: $INTERFACE"

# VPN subnet
VPN_SUBNET="10.8.0.0/24"

if [ "$OS" == "linux" ]; then
    echo ""
    echo "=== Enabling IP Forwarding ==="
    sysctl -w net.ipv4.ip_forward=1
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf

    echo ""
    echo "=== Setting up NAT (iptables) ==="
    iptables -t nat -A POSTROUTING -s $VPN_SUBNET -o $INTERFACE -j MASQUERADE
    iptables -A FORWARD -s $VPN_SUBNET -j ACCEPT
    iptables -A FORWARD -d $VPN_SUBNET -j ACCEPT
    iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT

    # Save iptables rules
    if command -v iptables-save &> /dev/null; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || iptables-save > /etc/iptables.rules
    fi

    echo ""
    echo "=== Creating TUN device ==="
    if [ ! -d /dev/net ]; then
        mkdir -p /dev/net
    fi
    if [ ! -c /dev/net/tun ]; then
        mknod /dev/net/tun c 10 200
        chmod 666 /dev/net/tun
    fi

elif [ "$OS" == "macos" ]; then
    echo ""
    echo "=== Enabling IP Forwarding ==="
    sysctl -w net.inet.ip.forwarding=1

    echo ""
    echo "=== Setting up NAT (pf) ==="

    # Create pf anchor file
    cat > /etc/pf.anchors/vpn << EOF
nat on $INTERFACE from $VPN_SUBNET to any -> ($INTERFACE)
pass from $VPN_SUBNET to any
EOF

    # Add to pf.conf if not already present
    if ! grep -q "vpn" /etc/pf.conf; then
        echo "" >> /etc/pf.conf
        echo "# VPN NAT" >> /etc/pf.conf
        echo 'nat-anchor "vpn"' >> /etc/pf.conf
        echo 'anchor "vpn"' >> /etc/pf.conf
        echo 'load anchor "vpn" from "/etc/pf.anchors/vpn"' >> /etc/pf.conf
    fi

    # Enable pf
    pfctl -e 2>/dev/null || true
    pfctl -f /etc/pf.conf
fi

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Next steps:"
echo "1. Install dependencies: npm install"
echo "2. Setup database: npm run db:init"
echo "3. Generate certificates: npm run certs:generate"
echo "4. Start server: sudo NODE_ENV=production npm start"
echo ""
echo "Server will listen on port 1194"
