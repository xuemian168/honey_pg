[中文](./README.zh.md) | English

# PostgreSQL Honeypot Extension

A PostgreSQL security extension that creates honeypot tables to detect unauthorized database access. When someone reads from these tables, notifications are sent to a specified API endpoint. This is a defensive cybersecurity tool for database administrators.

## 🚀 Quick Start (Docker Recommended)

### 1. One-Click Deploy
```bash
git clone <repository>
cd pg_honeypot
docker-compose -f docker-compose-simple.yml up -d
```

### 2. Test the Honeypot
```bash
# Connect to database (password: honeypot123)
psql -h localhost -U postgres -d postgres

# Query honeypot table to trigger alert
SELECT * FROM honeypot_customer_view LIMIT 1;
```

### 3. View Alerts
- **Web Dashboard**: http://localhost:8090
- **API Endpoint**: http://localhost:8080

## 📋 Features

- 🍯 **Honeypot Tables**: Automatically create tables with fake sensitive data
- ⚠️ **Real-time Alerts**: Instant HTTP notifications on access
- 📊 **Web Dashboard**: Simple interface to view alert history and statistics
- 🐳 **Containerized**: One-click deployment with all dependencies
- 🔧 **Developer Friendly**: Complete build system and development tools

## 🏗️ Architecture

The system consists of the following components:

### Core Services
1. **PostgreSQL Database**: Main database with honeypot functionality (port 5432)
2. **Python Alert Listener**: HTTP server that receives honeypot alerts (port 8080)
3. **Alert Forwarder**: Reads alerts from database and forwards to HTTP API
4. **Web Dashboard**: Simple interface to view alerts (port 8090)

### Data Flow
```
Honeypot Access → PostgreSQL Log → Database Alert Table → Forwarder → HTTP API → Web Dashboard
```

## 📦 Installation Options

### Option 1: Docker Compose (Recommended)

**Start Services**
```bash
docker-compose -f docker-compose-simple.yml up -d
```

**Check Status**
```bash
docker-compose -f docker-compose-simple.yml ps
```

**View Logs**
```bash
docker-compose -f docker-compose-simple.yml logs -f
```

**Stop Services**
```bash
docker-compose -f docker-compose-simple.yml down
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

**4. Start Python Services**
```bash
# Start alert listener
python3 honeypot_listener.py &

# Start forwarder
python3 honeypot_forwarder.py &

# Start web dashboard
cd dashboard && python3 dashboard.py &
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
docker-compose -f docker-compose-simple.yml logs -f postgres | grep "HONEYPOT ALERT"

# View HTTP listener logs
docker-compose -f docker-compose-simple.yml logs -f honeypot_listener

# View alert forwarder logs
docker-compose -f docker-compose-simple.yml logs -f honeypot_forwarder
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

