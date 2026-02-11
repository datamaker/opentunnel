# OpenTunnel VPN Server
# Multi-stage build for optimized image size

# Build stage
FROM node:20-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache python3 make g++

# Copy package files
COPY package*.json ./

# Install all dependencies (including dev)
RUN npm ci

# Copy source
COPY . .

# Build TypeScript
RUN npm run build

# Production stage
FROM node:20-alpine

LABEL maintainer="OpenTunnel Team"
LABEL description="OpenTunnel VPN Server"
LABEL version="1.0.0"

WORKDIR /app

# Install runtime dependencies
RUN apk add --no-cache \
    openssl \
    iptables \
    iproute2 \
    bash \
    curl \
    && rm -rf /var/cache/apk/*

# Copy built application
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./

# Copy certificates and scripts
COPY certs ./certs
COPY scripts ./scripts
COPY docker-entrypoint.sh /usr/local/bin/

# Make scripts executable
RUN chmod +x /usr/local/bin/docker-entrypoint.sh \
    && chmod +x scripts/*.sh 2>/dev/null || true

# Create logs directory
RUN mkdir -p logs

# Environment
ENV NODE_ENV=production
ENV PORT=1194
ENV ADMIN_PORT=8080
ENV VPN_SUBNET=10.8.0.0
ENV DNS_SERVERS=8.8.8.8,8.8.4.4

# Expose ports
EXPOSE 1194
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["node", "dist/index.js"]
