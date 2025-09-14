FROM node:20-slim

# app dir
WORKDIR /usr/src/app

# copy only package files first (speed up rebuilds)
COPY api/package*.json ./ 
RUN npm ci --production

# copy source
COPY api/ ./ 

ENV NODE_ENV=production
EXPOSE 4000

CMD ["node", "src/index.js"]
