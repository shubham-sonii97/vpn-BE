FROM node:20-slim

WORKDIR /usr/src/sidecar
COPY sidecar/package*.json ./
RUN npm ci --production

COPY sidecar/ ./

# sidecar expects env SIDECAR_SECRET, WG_IFACE, etc.
# It will listen on 8443
EXPOSE 8443

CMD ["node", "app.js"]
