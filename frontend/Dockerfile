# ============================================================
# SENTINEL-TRACE — Frontend Dockerfile
# Sprint 0: Project Foundation
# ============================================================
# Multi-stage build:
#   Stage 1 (builder): Node 20-alpine — npm build
#   Stage 2 (runner):  nginx-alpine   — serve static assets
# ============================================================

# ── Stage 1: Build ───────────────────────────────────────────
FROM node:20-alpine AS builder

WORKDIR /app

# Copy package files first for layer cache optimisation
COPY package*.json ./
RUN npm ci --silent

# Copy source and build
COPY . .
ARG VITE_API_BASE_URL=http://localhost:8000
ENV VITE_API_BASE_URL=$VITE_API_BASE_URL

RUN npm run build

# ── Stage 2: Serve ───────────────────────────────────────────
FROM nginx:1.25-alpine AS runner

# Remove default nginx config and copy our custom config
RUN rm /etc/nginx/conf.d/default.conf
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Copy built assets from builder stage
COPY --from=builder /app/dist /usr/share/nginx/html

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=5s \
    CMD wget -qO- http://127.0.0.1:80/ || exit 1

CMD ["nginx", "-g", "daemon off;"]
