#!/bin/bash
# VPN Certificate Generation Script
# Generates self-signed certificates for development/testing

set -e

CERT_DIR="../server/certs"
DAYS_VALID=365
KEY_SIZE=4096

# Create certs directory
mkdir -p "$CERT_DIR"

echo "=== Generating VPN Certificates ==="

# Generate CA key and certificate
echo "1. Generating CA..."
openssl genrsa -out "$CERT_DIR/ca.key" $KEY_SIZE
openssl req -new -x509 -days $DAYS_VALID -key "$CERT_DIR/ca.key" -out "$CERT_DIR/ca.crt" \
    -subj "/C=KR/ST=Seoul/L=Seoul/O=VPN Service/OU=VPN/CN=VPN CA"

# Generate server key and CSR
echo "2. Generating Server certificate..."
openssl genrsa -out "$CERT_DIR/server.key" $KEY_SIZE
openssl req -new -key "$CERT_DIR/server.key" -out "$CERT_DIR/server.csr" \
    -subj "/C=KR/ST=Seoul/L=Seoul/O=VPN Service/OU=VPN/CN=VPN Server"

# Sign server certificate with CA
openssl x509 -req -days $DAYS_VALID -in "$CERT_DIR/server.csr" \
    -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" -CAcreateserial \
    -out "$CERT_DIR/server.crt"

# Clean up CSR
rm -f "$CERT_DIR/server.csr"

# Set permissions
chmod 600 "$CERT_DIR"/*.key
chmod 644 "$CERT_DIR"/*.crt

echo ""
echo "=== Certificates Generated ==="
echo "CA Certificate:     $CERT_DIR/ca.crt"
echo "Server Certificate: $CERT_DIR/server.crt"
echo "Server Key:         $CERT_DIR/server.key"
echo ""
echo "For production, replace these with properly signed certificates!"
