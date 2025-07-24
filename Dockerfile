# Multi-stage build for PostgreSQL Honeypot Extension

FROM postgres:15-alpine AS builder

# Install build dependencies
RUN apk add --no-cache \
    build-base \
    postgresql-dev \
    curl \
    krb5-dev

# Set working directory
WORKDIR /build

# Copy extension source files
COPY pg_honeypot.c .
COPY pg_honeypot_patterns.h .
COPY pg_honeypot.control .
COPY pg_honeypot--1.0.sql .
COPY Makefile .

# Build and install the extension
RUN make && make install

# Production image
FROM postgres:15-alpine

# Install runtime dependencies
RUN apk add --no-cache \
    python3 \
    py3-pip \
    py3-psycopg2 \
    py3-requests \
    curl \
    bash

# Copy extension from builder
COPY --from=builder /usr/local/lib/postgresql/ /usr/local/lib/postgresql/
COPY --from=builder /usr/local/share/postgresql/extension/ /usr/local/share/postgresql/extension/

# Set working directory
WORKDIR /app

# Copy Python scripts
COPY honeypot_listener.py .
COPY honeypot_monitor.py .

# Make scripts executable
RUN chmod +x honeypot_listener.py honeypot_monitor.py

# Copy initialization scripts
COPY docker/init-honeypot.sql /docker-entrypoint-initdb.d/01-init-honeypot.sql
COPY docker/init-infinite-honeypot.sql /docker-entrypoint-initdb.d/02-init-infinite.sql

# Create directory for logs
RUN mkdir -p /app/logs

# Environment variables
ENV HONEYPOT_HOST=0.0.0.0
ENV HONEYPOT_PORT=8080
ENV POSTGRES_DB=postgres
ENV POSTGRES_USER=postgres
ENV POSTGRES_PASSWORD=honeypot123

# Expose ports
EXPOSE 5432 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD pg_isready -U $POSTGRES_USER -d $POSTGRES_DB && \
      curl -f http://localhost:8080/health || exit 1

# Copy startup script
COPY docker/start-services.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/start-services.sh

# Use custom startup script
CMD ["/usr/local/bin/start-services.sh"]