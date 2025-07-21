# PostgreSQL Honeypot Extension Makefile

EXTENSION = pg_honeypot
DATA = pg_honeypot--1.0.sql
MODULES = pg_honeypot

# PostgreSQL build system
PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)

# Additional targets for development
.PHONY: install-dev uninstall clean-logs test docker

# Development installation (includes Python dependencies)
install-dev: install
	@echo "Installing Python dependencies..."
	pip install -r requirements.txt
	@echo "Making Python listener executable..."
	chmod +x honeypot_listener.py

# Uninstall extension
uninstall:
	@echo "Uninstalling pg_honeypot extension..."
	$(MAKE) -f $(PGXS) uninstall

# Clean log files
clean-logs:
	@echo "Cleaning log files..."
	rm -f honeypot.log honeypot_alerts.json

# Basic test (requires running PostgreSQL instance)
test:
	@echo "Testing pg_honeypot extension..."
	@echo "Ensure PostgreSQL is running and accessible"
	python3 honeypot_listener.py --check-db

# Docker build
docker:
	@echo "Building Docker image..."
	docker build -t pg_honeypot:latest .

# Docker compose setup
docker-compose:
	@echo "Starting services with docker-compose..."
	docker-compose up -d

# Development setup
dev-setup: install-dev
	@echo "Development setup complete!"
	@echo ""
	@echo "Next steps:"
	@echo "1. Ensure PostgreSQL is running"
	@echo "2. Connect to your database and run: CREATE EXTENSION pg_honeypot;"
	@echo "3. Start the listener: python3 honeypot_listener.py"
	@echo "4. Create honeypot tables: SELECT pg_honeypot_create_table('sensitive_data');"

# Help target
help:
	@echo "Available targets:"
	@echo "  all          - Build the extension (default)"
	@echo "  install      - Install the extension"
	@echo "  install-dev  - Install extension and Python dependencies"
	@echo "  uninstall    - Uninstall the extension"
	@echo "  clean        - Clean build files"
	@echo "  clean-logs   - Clean log files"
	@echo "  test         - Test the extension"
	@echo "  docker       - Build Docker image"
	@echo "  docker-compose - Start services with docker-compose"
	@echo "  dev-setup    - Complete development setup"
	@echo "  help         - Show this help"