# OpenTunnel VPN Server (Rust)
# Multi-stage build for a small runtime image.

# ---- Build stage ----
FROM rust:1-slim-bookworm AS builder

WORKDIR /app

# Build dependencies (ring needs a C toolchain; pkg-config for good measure).
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Cache dependency compilation: build against a stub main first.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs \
    && cargo build --release \
    && rm -rf src

# Now build the real sources.
COPY src ./src
RUN touch src/main.rs && cargo build --release

# ---- Runtime stage ----
FROM debian:bookworm-slim

LABEL maintainer="OpenTunnel Team"
LABEL description="OpenTunnel VPN Server (Rust)"
LABEL version="1.0.0"

WORKDIR /app

# Runtime dependencies. The TUN device is handled natively in the binary, so no
# Python is needed; `ip`/`iptables` come from iproute2/iptables.
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssl \
    iptables \
    iproute2 \
    netcat-openbsd \
    bash \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy the compiled binary.
COPY --from=builder /app/target/release/opentunnel-server /usr/local/bin/opentunnel-server

# Copy runtime assets.
COPY public ./public
COPY docker-entrypoint.sh /usr/local/bin/

RUN chmod +x /usr/local/bin/docker-entrypoint.sh \
    && mkdir -p logs certs

# Environment (parity with the Node.js image).
ENV NODE_ENV=production
ENV PORT=1194
ENV ADMIN_PORT=8080
ENV VPN_SUBNET=10.8.0.0
ENV DNS_SERVERS=8.8.8.8,8.8.4.4

EXPOSE 1194
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["opentunnel-server"]
