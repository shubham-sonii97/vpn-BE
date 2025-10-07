# sidecar/Dockerfile
FROM node:20-slim

# Install WireGuard tools and CA certs (ABI-compatible with this image)
RUN apt-get update && \
    apt-get install -y --no-install-recommends wireguard-tools ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/sidecar
COPY package*.json ./
RUN npm install --production --no-audit --no-fund
COPY sidecar/ ./

EXPOSE 8443
CMD ["node", "app.js"]