FROM node:20-slim

WORKDIR /usr/src/sidecar

# copy package metadata
COPY sidecar/package*.json ./

# install production deps
RUN npm install --production --no-audit --no-fund

# copy source
COPY sidecar/ ./

EXPOSE 8443
CMD ["node", "app.js"]
