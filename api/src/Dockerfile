FROM node:20-slim

WORKDIR /usr/src/app

# copy package files first (for Docker layer cache)
COPY api/package*.json ./

# install production deps (uses npm install if no package-lock.json)
RUN npm install --production --no-audit --no-fund

# copy rest of source
COPY api/ ./

ENV NODE_ENV=production
EXPOSE 4000

CMD ["node", "src/index.js"]
