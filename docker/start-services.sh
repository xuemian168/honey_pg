#!/bin/bash

# Start PostgreSQL Honeypot Services
# This script starts both PostgreSQL and the Python honeypot listener

set -e

echo "Starting PostgreSQL Honeypot Services..."

# Function to handle shutdown
shutdown_services() {
    echo "Shutting down services..."
    if [[ -n "$LISTENER_PID" ]]; then
        kill "$LISTENER_PID" 2>/dev/null || true
    fi
    if [[ -n "$PG_PID" ]]; then
        kill "$PG_PID" 2>/dev/null || true
    fi
    exit 0
}

# Set up signal handlers
trap shutdown_services SIGTERM SIGINT

# Start PostgreSQL in the background
echo "Starting PostgreSQL..."
docker-entrypoint.sh postgres &
PG_PID=$!

# Wait for PostgreSQL to be ready
echo "Waiting for PostgreSQL to start..."
sleep 10

# Wait for PostgreSQL to accept connections
until pg_isready -U "$POSTGRES_USER" -d "$POSTGRES_DB"; do
    echo "Waiting for PostgreSQL to accept connections..."
    sleep 2
done

echo "PostgreSQL is ready!"

# Verify honeypot tables are created
echo "Verifying honeypot installation..."
psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "SELECT COUNT(*) FROM pg_views WHERE viewname LIKE 'honeypot_%';" | grep -q "3" && \
    echo "✓ Honeypot tables created successfully" || \
    echo "⚠ Warning: Honeypot tables may not be fully initialized"

# Start the Python honeypot monitor (includes web interface)
echo "Starting Honeypot Monitor on port $HONEYPOT_PORT..."
cd /app
python3 honeypot_monitor.py &
LISTENER_PID=$!

echo "Honeypot services started successfully!"
echo "PostgreSQL running with PID: $PG_PID"
echo "Honeypot Listener running with PID: $LISTENER_PID"
echo ""
echo "Services Status:"
echo "- PostgreSQL: port 5432"
echo "- Honeypot Monitor: port $HONEYPOT_PORT"
echo "- Web Interface: http://localhost:$HONEYPOT_PORT/"
echo "- Alert endpoint: http://localhost:$HONEYPOT_PORT/alert"
echo ""
echo "To test the honeypot:"
echo "1. Connect to PostgreSQL: psql -h localhost -U $POSTGRES_USER -d $POSTGRES_DB"
echo "2. Query a honeypot table: SELECT * FROM honeypot_financial_view LIMIT 10;"
echo "3. Test infinite data: SELECT * FROM honeypot_customer_view LIMIT 100;"
echo "4. Check logs: docker logs <container_name>"
echo ""
echo "⚠️  WARNING: Queries without LIMIT will run forever!"
echo "   Example: SELECT COUNT(*) FROM honeypot_financial_view; -- Never completes!"

# Wait for either process to exit
wait $PG_PID $LISTENER_PID