# api/src/Dockerfile
# Build from repo root context (it will copy api/src and db/ from there)

FROM node:20-slim AS builder
WORKDIR /workspace

# Copy package files (from repo root) and install build deps
COPY package*.json ./
RUN npm ci

# Copy the whole repo into the builder workspace
COPY . .

# ---------- runtime stage ----------
FROM node:20-slim AS runtime

# create non-root user
RUN addgroup --system appgroup && adduser --system --ingroup appgroup appuser

# set app workdir
WORKDIR /usr/src/app

# copy production deps only
COPY --from=builder /workspace/package*.json ./
RUN npm ci --omit=dev --no-audit --no-fund

# copy app source (from repo's api/src)
COPY --from=builder /workspace/api/src ./ 

# copy db folder into /usr/db so imports like '../../db/db.js' resolve to /usr/db/db.js
COPY --from=builder /workspace/db /usr/db

# create a symlink so modules required by /usr/db/db.js resolve correctly:
# /usr/db/node_modules -> /usr/src/app/node_modules
RUN mkdir -p /usr/db && ln -s /usr/src/app/node_modules /usr/db/node_modules || true

# ensure permissions
RUN chown -R appuser:appgroup /usr/src/app /usr/db

ENV NODE_ENV=production
EXPOSE 4000

USER appuser
CMD ["node", "index.js"]
