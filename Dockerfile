# ── Build stage ──
FROM node:20-alpine AS builder

WORKDIR /app

# Install deps
COPY package.json package-lock.json* ./
RUN npm ci

# Copy source and build
COPY . .
RUN npm run build

# ── Serve stage ──
FROM nginx:alpine

LABEL org.opencontainers.image.source="https://github.com/mshermancyber/Waldo-Hunt"
LABEL description="WaldoHunt — Insider Threat SPL Generator"
LABEL version="2.0.0"

# Remove default nginx content
RUN rm -rf /usr/share/nginx/html/*

# Copy built React app
COPY --from=builder /app/release/ /usr/share/nginx/html/

# Copy nginx config
COPY nginx/waldohunt.conf /etc/nginx/conf.d/default.conf

# Generate self-signed TLS cert
RUN apk add --no-cache openssl && \
    mkdir -p /etc/nginx/certs && \
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
      -keyout /etc/nginx/certs/waldohunt.key \
      -out /etc/nginx/certs/waldohunt.crt \
      -subj "/C=US/ST=VA/L=Reston/O=WaldoHunt/CN=localhost" && \
    apk del openssl

EXPOSE 80 443

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget -qO- http://localhost/health || exit 1

CMD ["nginx", "-g", "daemon off;"]
