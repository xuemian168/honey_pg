[中文](./README.zh.md) | English

# PostgreSQL Honeypot Extension

A PostgreSQL security extension that creates honeypot tables to detect unauthorized database access. When someone reads from these tables, notifications are sent to a specified API endpoint. This is a defensive cybersecurity tool for database administrators.

## 🚀 Quick Start (One-Click Deploy)

### 1. Clone and Start
```bash
git clone <repository>
cd pg_honeypot
./start.sh
```

### 2. Access Dashboard
- **Web Dashboard**: http://localhost:8080
- **Database**: localhost:5432 (user: postgres, password: honeypot123)

### 3. Test the Honeypot
```bash
# Trigger honeypot alert
docker-compose exec postgres psql -U postgres -d postgres -c "SELECT * FROM honeypot_customer_view LIMIT 1;"
```

### 4. View Real-time Alerts
Check the dashboard at http://localhost:8080 to see the alert appear instantly!

## 📋 Features

- 🍯 **Honeypot Tables**: Automatically create tables with fake sensitive data
- ⚠️ **Real-time Alerts**: Instant HTTP notifications on access
- 📊 **Web Dashboard**: Simple interface to view alert history and statistics
- 🐳 **Containerized**: One-click deployment with all dependencies
- 🔧 **Developer Friendly**: Complete build system and development tools

## 🏗️ Simplified Architecture (2 Containers)

The system now consists of just **2 containers** for simplified deployment:

### Core Services
1. **PostgreSQL Container** (`honeypot_postgres`)
   - Main database with honeypot tables (port 5432)
   - Automatic honeypot table creation
   - Alert logging to database

2. **Monitor Container** (`honeypot_monitor`)
   - HTTP API server (port 8080)
   - Web dashboard interface
   - Database alert monitoring
   - External webhook forwarding

### Data Flow
```
Honeypot Access → PostgreSQL Alert Table → Monitor Service → Web Dashboard + External Webhook
```

### Benefits of New Architecture
- ✅ **Simplified deployment**: Only 2 containers instead of 4
- ✅ **Reduced complexity**: All monitoring logic in one service
- ✅ **Better performance**: Direct database monitoring
- ✅ **Easier maintenance**: Fewer moving parts
- ✅ **Single access point**: All features on one port (8080)

## 📦 Installation Options

### Option 1: One-Click Start (Recommended)

**Use the provided start script for easiest deployment:**
```bash
./start.sh
```

**Manual Docker Compose commands:**
```bash
# Start services
docker-compose up -d --build

# Check status
docker-compose ps

# View logs
docker-compose logs -f monitor

# Stop services
docker-compose down
```

### Option 2: Manual Installation

**1. Install Dependencies**
```bash
# Install PostgreSQL development packages
sudo apt-get install postgresql-server-dev-all

# Install Python dependencies
pip install -r requirements.txt
```

**2. Build Extension**
```bash
make
sudo make install
```

**3. Initialize Database**
```sql
CREATE EXTENSION pg_honeypot;
```

**4. Start Monitor Service**
```bash
# Start the unified monitor service
python3 honeypot_monitor.py
```

## 🎯 Usage Guide

### Basic Usage

**1. Connect to Database**
```bash
psql -h localhost -U postgres -d postgres
# Password: honeypot123
```

**2. View Available Honeypot Tables**
```sql
-- List all honeypot views
\dv honeypot*

-- Available honeypot tables:
-- honeypot_customer_view    (customer data)
-- honeypot_financial_view   (financial records)
-- honeypot_employee_view    (employee information)
```

**3. Trigger Honeypot Alerts**
```sql
-- Querying any honeypot table will trigger alerts
SELECT * FROM honeypot_customer_view LIMIT 3;
SELECT account_number, balance FROM honeypot_financial_view;
SELECT employee_id, salary FROM honeypot_employee_view;
```

**4. View Alert Records**
```sql
-- Check alerts in database
SELECT * FROM honeypot_alerts ORDER BY created_at DESC LIMIT 5;
```

### Advanced Configuration

**Creating Custom Honeypot Tables**
```sql
-- Create new honeypot table
CREATE TABLE secret_projects (
    id SERIAL PRIMARY KEY,
    project_code VARCHAR(20) DEFAULT 'PROJ-' || LPAD(floor(random() * 10000)::TEXT, 4, '0'),
    classified_info TEXT DEFAULT 'Top Secret Project Data',
    budget DECIMAL(15,2) DEFAULT round((random() * 1000000)::numeric, 2)
);

-- Insert fake data
INSERT INTO secret_projects DEFAULT VALUES;

-- Create honeypot view
CREATE VIEW honeypot_secrets_view AS 
SELECT *, log_honeypot_access_function('secret_projects') as _alert 
FROM secret_projects;

-- Grant permissions to test user
GRANT SELECT ON honeypot_secrets_view TO honeypot_test;
```

**Monitoring and Alerting**
```bash
# View real-time PostgreSQL alerts
docker-compose logs -f postgres | grep "HONEYPOT ALERT"

# View monitor service logs
docker-compose logs -f monitor

# Check service health
curl http://localhost:8080/health

# Get alerts via API
curl http://localhost:8080/api/alerts
```

## 🔧 Development and Debugging

### Development Environment
```bash
# Clone project
git clone <repository>
cd pg_honeypot

# Development setup
make dev-setup

# Build Docker image
make docker
```

### Debugging Commands
```bash
# Check database connection
python3 honeypot_forwarder.py --check-db

# Test HTTP API
curl -X POST http://localhost:8080/alert \
  -H "Content-Type: application/json" \
  -d '{"alert":"Test alert","table":"test_table","user":"test_user"}'

# Check alerts API response
curl http://localhost:8090/api/alerts | python3 -m json.tool
```

### Troubleshooting

**Common Issues and Solutions**

1. **Container Startup Failures**
   ```bash
   # Check port conflicts
   netstat -tlnp | grep -E "(5432|8080|8090)"
   
   # Clean up old containers
   docker-compose -f docker-compose-simple.yml down -v
   ```

2. **Database Connection Failures**
   ```bash
   # Check database status
   docker-compose -f docker-compose-simple.yml logs postgres
   
   # Test connection
   docker exec pg_honeypot_simple pg_isready -U postgres
   ```

3. **Alerts Not Showing**
   ```bash
   # Check forwarder status
   docker-compose -f docker-compose-simple.yml logs honeypot_forwarder
   
   # Manual alert test
   docker exec pg_honeypot_simple psql -U postgres -d postgres -c "SELECT * FROM honeypot_customer_view LIMIT 1;"
   ```

## 🔒 Security Considerations

This extension is designed to detect unauthorized database access. Ensure you:

1. **Isolate honeypot tables**: Keep honeypot tables in separate schemas
2. **Appropriate permissions**: Use proper permissions to make tables appear legitimate
3. **Monitor API endpoints**: Monitor the API endpoint for alerts
4. **Keep code secure**: Keep extension code secure and updated
5. **Production security**: Change default passwords and use secure API endpoints in production
6. **Log management**: Regularly clean and backup alert logs

## 📚 File Structure

```
pg_honeypot/
├── pg_honeypot.c              # PostgreSQL C extension source
├── pg_honeypot.control        # Extension control file
├── pg_honeypot--1.0.sql       # SQL definition file
├── honeypot_listener.py       # Python HTTP alert listener
├── honeypot_forwarder.py      # Database-to-HTTP alert forwarder
├── dashboard/
│   └── dashboard.py           # Web dashboard interface
├── docker-compose-simple.yml  # Docker Compose configuration
├── init-simple.sql            # Database initialization script
├── requirements.txt           # Python dependencies
├── Makefile                   # Build system
└── README.zh.md               # Chinese documentation
```

## 🤝 Contributing

Issues and Pull Requests are welcome to improve this project.

## 📄 License

This project is intended for educational and defensive security purposes only.

---

**Important**: This is a legitimate defensive security tool designed to help database administrators detect unauthorized access. Please use it only for defensive purposes.

