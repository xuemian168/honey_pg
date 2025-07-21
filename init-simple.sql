-- Simple initialization script for PostgreSQL honeypot (without C extension)
-- This creates simple trigger-based honeypot tables using pure SQL

\c postgres;

-- Create a function to log honeypot access
CREATE OR REPLACE FUNCTION log_honeypot_access()
RETURNS TRIGGER AS $$
DECLARE
    alert_json TEXT;
    user_name TEXT := current_user;
    client_addr TEXT := inet_client_addr()::TEXT;
    timestamp_str TEXT := NOW()::TEXT;
BEGIN
    -- Construct JSON alert
    alert_json := json_build_object(
        'alert', 'Honeypot table accessed',
        'table', TG_TABLE_NAME,
        'user', user_name,
        'client_ip', COALESCE(client_addr, 'local'),
        'timestamp', timestamp_str
    )::TEXT;
    
    -- Log to PostgreSQL log
    RAISE WARNING 'HONEYPOT ALERT: %', alert_json;
    
    -- Try to send HTTP alert (this won't work in standard PostgreSQL but shows intent)
    -- In a real scenario, you'd use a background job or external process
    
    -- Store in a log table
    INSERT INTO honeypot_alerts (alert_data, created_at)
    VALUES (alert_json::JSON, NOW());
    
    RETURN NULL; -- Don't block the query
END;
$$ LANGUAGE plpgsql;

-- Create alerts table
CREATE TABLE IF NOT EXISTS honeypot_alerts (
    id SERIAL PRIMARY KEY,
    alert_data JSON,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Create honeypot tables with fake sensitive data
CREATE TABLE customer_data (
    id SERIAL PRIMARY KEY,
    customer_id VARCHAR(20) DEFAULT 'CUST-' || LPAD(floor(random() * 10000)::TEXT, 4, '0'),
    ssn VARCHAR(11) DEFAULT '###-##-' || LPAD(floor(random() * 10000)::TEXT, 4, '0'),
    credit_card VARCHAR(19) DEFAULT '4532-' || LPAD(floor(random() * 10000)::TEXT, 4, '0') || '-' || LPAD(floor(random() * 10000)::TEXT, 4, '0') || '-' || LPAD(floor(random() * 10000)::TEXT, 4, '0'),
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE financial_records (
    id SERIAL PRIMARY KEY,
    account_number VARCHAR(20) DEFAULT 'ACC-' || LPAD(floor(random() * 100000)::TEXT, 8, '0'),
    balance DECIMAL(15,2) DEFAULT round((random() * 100000)::numeric, 2),
    routing_number VARCHAR(9) DEFAULT LPAD(floor(random() * 1000000000)::TEXT, 9, '0'),
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE employee_info (
    id SERIAL PRIMARY KEY,
    employee_id VARCHAR(10) DEFAULT 'EMP' || LPAD(floor(random() * 100000)::TEXT, 5, '0'),
    salary INTEGER DEFAULT floor(random() * 150000 + 30000),
    api_key VARCHAR(40) DEFAULT 'sk-' || substr(md5(random()::text), 1, 32),
    password_hash VARCHAR(60) DEFAULT '$2b$12$' || substr(md5(random()::text), 1, 53),
    created_at TIMESTAMP DEFAULT NOW()
);

-- Insert some fake data
INSERT INTO customer_data DEFAULT VALUES;
INSERT INTO customer_data DEFAULT VALUES;
INSERT INTO customer_data DEFAULT VALUES;

INSERT INTO financial_records DEFAULT VALUES;
INSERT INTO financial_records DEFAULT VALUES;

INSERT INTO employee_info DEFAULT VALUES;
INSERT INTO employee_info DEFAULT VALUES;

-- Create a simpler function for view-based detection (must be created before views)
CREATE OR REPLACE FUNCTION log_honeypot_access_function(table_name TEXT)
RETURNS TEXT AS $$
DECLARE
    alert_json TEXT;
    user_name TEXT := current_user;
    client_addr TEXT := inet_client_addr()::TEXT;
    timestamp_str TEXT := NOW()::TEXT;
BEGIN
    -- Construct JSON alert
    alert_json := json_build_object(
        'alert', 'Honeypot table accessed via view',
        'table', table_name,
        'user', user_name,
        'client_ip', COALESCE(client_addr, 'local'),
        'timestamp', timestamp_str
    )::TEXT;
    
    -- Log to PostgreSQL log
    RAISE WARNING 'HONEYPOT ALERT: %', alert_json;
    
    -- Store in log table (with error handling)
    BEGIN
        INSERT INTO honeypot_alerts (alert_data, created_at)
        VALUES (alert_json::JSON, NOW());
    EXCEPTION WHEN OTHERS THEN
        -- If insert fails, just log it
        RAISE WARNING 'Failed to insert honeypot alert: %', SQLERRM;
    END;
    
    RETURN 'alert_logged';
END;
$$ LANGUAGE plpgsql;

-- Create view-based honeypot detection
CREATE VIEW honeypot_customer_view AS 
SELECT *, log_honeypot_access_function('customer_data') as _alert 
FROM customer_data;

CREATE VIEW honeypot_financial_view AS 
SELECT *, log_honeypot_access_function('financial_records') as _alert 
FROM financial_records;

CREATE VIEW honeypot_employee_view AS 
SELECT *, log_honeypot_access_function('employee_info') as _alert 
FROM employee_info;

-- Create a test user
CREATE USER honeypot_test WITH PASSWORD 'test123';
GRANT CONNECT ON DATABASE postgres TO honeypot_test;
GRANT USAGE ON SCHEMA public TO honeypot_test;
GRANT SELECT ON customer_data, financial_records, employee_info TO honeypot_test;
GRANT SELECT ON honeypot_customer_view, honeypot_financial_view, honeypot_employee_view TO honeypot_test;
GRANT SELECT ON honeypot_alerts TO honeypot_test;
GRANT INSERT ON honeypot_alerts TO honeypot_test;

-- Log setup completion
DO $$
BEGIN
    RAISE NOTICE '🍯 PostgreSQL Simple Honeypot initialized successfully!';
    RAISE NOTICE 'Created honeypot tables: customer_data, financial_records, employee_info';
    RAISE NOTICE 'Test user created: honeypot_test (password: test123)';
    RAISE NOTICE 'Test command: SELECT * FROM customer_data;';
END $$;