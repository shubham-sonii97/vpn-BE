# ---------- builder stage ----------
FROM node:20-slim AS builder
WORKDIR /workspace

# copy root package files
COPY package*.json ./
RUN npm ci

# copy full repo so runtime files can be copied later
COPY . .

# optional build step if you have TypeScript
# RUN npm run build

# ---------- runtime stage ----------
FROM node:20-slim AS runtime

# create non-root user
RUN addgroup --system appgroup && adduser --system --ingroup appgroup appuser

# Set WORKDIR to /usr so node_modules are installed under /usr/node_modules
WORKDIR /usr

# Copy package.json from builder and install production deps here at /usr/node_modules
COPY --from=builder /workspace/package*.json ./
RUN npm ci --omit=dev --no-audit --no-fund

# Create expected folders and copy runtime sources
RUN mkdir -p /usr/db /usr/src/src
COPY --from=builder /workspace/db /usr/db
COPY --from=builder /workspace/api/src /usr/src/src

ENV NODE_ENV=production
EXPOSE 4000

USER appuser

# Start your app (path you used previously)
CMD ["node", "/usr/src/src/index.js"]