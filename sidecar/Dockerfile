# ---------- sidecar/Dockerfile ----------
FROM node:20-slim

# Install WireGuard tools and networking utilities
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      wireguard-tools iproute2 iptables curl ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Set workdir
WORKDIR /usr/src/sidecar

# Copy package files first (for layer caching)
COPY package*.json ./

# Install production dependencies
RUN npm ci --production --no-audit --no-fund

# Copy all source code from sidecar directory
COPY . .

# Expose sidecar API port
EXPOSE 8443

# Run quick startup checks and launch the app
CMD ["sh", "-c", "\
  if ! command -v wg >/dev/null 2>&1; then \
    echo '❌ ERROR: WireGuard (wg) not found'; exit 1; \
  fi && \
  if [ ! -c /dev/net/tun ]; then \
    echo '⚠️  WARNING: /dev/net/tun missing (wg commands may fail)'; \
  fi && \
  echo '🚀 Starting Sidecar on port 8443...' && \
  node app.js"]
