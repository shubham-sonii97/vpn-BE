# api/Dockerfile (fixed)
FROM node:20-slim

# use /usr/src as project root so node_modules is visible to /usr/src/db and /usr/src/app
WORKDIR /usr/src/api/

# copy root package.json / package-lock if present into /usr/src
COPY package*.json ./

# install production deps at /usr/src/node_modules so all subfolders can resolve them
RUN npm install --production --no-audit --no-fund

# copy db and api source into image under /usr/src
# COPY db/ ./db/
# COPY api/ ./app/

ENV NODE_ENV=production
EXPOSE 4000

CMD ["node", "src/index.js"]
