# api/Dockerfile
FROM node:20-slim

# create app directory
WORKDIR /usr/src/app

# copy root package.json and package-lock (if present)
# Note: this expects your repo root to have package.json / package-lock.json
COPY package*.json ./

# install production deps (works even if no lockfile)
RUN npm install --production --no-audit --no-fund

# copy api source into image
COPY api/ ./ 

ENV NODE_ENV=production
EXPOSE 4000

CMD ["node", "src/index.js"]
