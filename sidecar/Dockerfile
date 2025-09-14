# sidecar/Dockerfile
FROM node:20-slim

WORKDIR /usr/src/sidecar

# copy root package files so npm can install deps
COPY package*.json ./

# install production deps
RUN npm install --production --no-audit --no-fund

# copy sidecar source
COPY sidecar/ ./

EXPOSE 8443
CMD ["node", "app.js"]
