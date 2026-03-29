FROM debian:12-slim

LABEL maintainer="mshermancyber"
LABEL description="WaldoHunt - Insider Threat SPL Generator"
LABEL version="BETA 1"

# Install nginx and clean up apt cache in a single layer
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        nginx \
        curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Remove default nginx site config and default html
RUN rm -f /etc/nginx/sites-enabled/default \
    && rm -rf /var/www/html/*

# Copy our nginx site config
COPY nginx/waldohunt.conf /etc/nginx/sites-available/waldohunt.conf

# Enable the site
RUN ln -s /etc/nginx/sites-available/waldohunt.conf /etc/nginx/sites-enabled/waldohunt.conf

# Copy application files into web root
COPY html/ /var/www/waldohunt/

# Set correct permissions
RUN chown -R www-data:www-data /var/www/waldohunt \
    && chmod -R 755 /var/www/waldohunt

# Nginx runs on port 80 inside container
EXPOSE 80

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost/health || exit 1

# Run nginx in foreground (required for Docker)
CMD ["nginx", "-g", "daemon off;"]
