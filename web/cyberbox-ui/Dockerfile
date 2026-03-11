# ---------------------------------------------------------------------------
# Stage 1 — Build
# ---------------------------------------------------------------------------
FROM node:22-alpine AS build

WORKDIR /app

# Install dependencies first (layer cache)
COPY package.json package-lock.json* ./
RUN npm ci --legacy-peer-deps

# Copy source and build
COPY . .
RUN npm run build

# ---------------------------------------------------------------------------
# Stage 2 — Runtime
# ---------------------------------------------------------------------------
FROM nginxinc/nginx-unprivileged:alpine-slim

# Default backend URL (override at runtime via env)
ENV BACKEND_URL=http://cyberbox-api:8080

# Copy built assets
COPY --from=build /app/dist /usr/share/nginx/html

# Copy nginx config template
COPY nginx.conf /etc/nginx/templates/nginx.conf.template

# nginx:alpine-slim ships docker-entrypoint.d scripts that run envsubst on
# /etc/nginx/templates/*.template → /etc/nginx/*.conf automatically, which
# resolves ${BACKEND_URL} at container start.

EXPOSE 3000

# Override default CMD to use our config (generated from template)
CMD ["nginx", "-g", "daemon off;"]
