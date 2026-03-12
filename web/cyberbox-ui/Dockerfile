# ---------------------------------------------------------------------------
# Stage 1 — Build
# ---------------------------------------------------------------------------
FROM node:22-alpine AS build

WORKDIR /app

# Install dependencies first (layer cache)
COPY package.json package-lock.json* ./
RUN npm ci --legacy-peer-deps

# Entra ID / MSAL config — pass at build time via --build-arg
# VITE_AZURE_REDIRECT_URI intentionally left empty so msalConfig.ts
# falls back to window.location.origin (works on any domain).
ARG VITE_AZURE_CLIENT_ID=YOUR_CLIENT_ID
ARG VITE_AZURE_TENANT_ID=YOUR_TENANT_ID
ENV VITE_AZURE_CLIENT_ID=$VITE_AZURE_CLIENT_ID
ENV VITE_AZURE_TENANT_ID=$VITE_AZURE_TENANT_ID

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

# Copy nginx config as template (envsubst resolves ${BACKEND_URL} at startup)
COPY nginx.conf /etc/nginx/nginx.conf.template

# Replace the default entrypoint to envsubst our full nginx.conf then start
# (the default entrypoint only templates conf.d/ which can't have top-level directives)
CMD ["/bin/sh", "-c", "envsubst '${BACKEND_URL}' < /etc/nginx/nginx.conf.template > /tmp/nginx.conf && nginx -c /tmp/nginx.conf -g 'daemon off;'"]

EXPOSE 3000
