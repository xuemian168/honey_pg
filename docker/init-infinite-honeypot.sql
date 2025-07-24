-- Automated PostgreSQL Honeypot Initialization with Infinite Data
-- This script runs automatically when the Docker container starts

\echo 'Initializing PostgreSQL Honeypot with Infinite Data Generation...'
\echo '================================================================'

-- Create honeypot schema
CREATE SCHEMA IF NOT EXISTS honeypot;

-- Create infinite data generator function (Pure SQL - no extension needed)
CREATE OR REPLACE FUNCTION honeypot.generate_infinite_data(
    pattern text DEFAULT 'mixed',
    start_at bigint DEFAULT 1
)
RETURNS TABLE(
    id bigint,
    sensitive_data text,
    created_at timestamptz
)
LANGUAGE sql
AS $$
    SELECT 
        series.n as id,
        CASE 
            WHEN pattern = 'credit_card' THEN
                'Credit Card: 4532-' || 
                LPAD(((series.n * 1234) % 10000)::text, 4, '0') || '-' ||
                LPAD(((series.n * 5678) % 10000)::text, 4, '0') || '-' ||
                LPAD(((series.n * 9012) % 10000)::text, 4, '0') ||
                ' | CVV: ' || LPAD(((series.n * 3) % 1000)::text, 3, '0') ||
                ' | Exp: ' || LPAD((((series.n % 12) + 1))::text, 2, '0') || '/27'
            WHEN pattern = 'ssn' THEN
                'SSN: ' || 
                LPAD(((series.n * 11) % 999)::text, 3, '0') || '-' ||
                LPAD(((series.n * 13) % 99)::text, 2, '0') || '-' ||
                LPAD(((series.n * 17) % 9999)::text, 4, '0') ||
                ' | Name: ' || 
                (ARRAY['Smith', 'Johnson', 'Williams', 'Brown', 'Jones', 'Garcia', 'Miller', 'Davis'])[1 + (series.n % 8)]
            WHEN pattern = 'api_key' THEN
                'API Key: sk-' || substr(md5(series.n::text || 'secret'), 1, 32) ||
                ' | Service: ' || (ARRAY['payment', 'auth', 'data', 'admin'])[1 + (series.n % 4)]
            WHEN pattern = 'account' THEN
                'Account: ACC-' || LPAD((series.n * 97)::text, 8, '0') ||
                ' | Balance: $' || TO_CHAR(((series.n * 123.45) % 100000)::numeric, 'FM999,999.00') ||
                ' | Routing: ' || LPAD(((series.n * 7) % 1000000000)::text, 9, '0')
            WHEN pattern = 'employee' THEN
                'Employee ID: EMP-' || LPAD(series.n::text, 6, '0') ||
                ' | Dept: ' || (ARRAY['IT', 'HR', 'Finance', 'Sales', 'Admin'])[1 + (series.n % 5)] ||
                ' | Access: ' || (ARRAY['Basic', 'Standard', 'Admin', 'Super'])[1 + (series.n % 4)]
            ELSE
                -- Mixed sensitive data
                CASE (series.n % 6)
                    WHEN 0 THEN 'Credit Card: 4532-' || LPAD(((series.n * 1234) % 10000)::text, 4, '0') || '-****-****'
                    WHEN 1 THEN 'SSN: ***-**-' || LPAD(((series.n * 17) % 9999)::text, 4, '0')
                    WHEN 2 THEN 'API Key: sk-' || substr(md5(series.n::text), 1, 16) || '...'
                    WHEN 3 THEN 'Password: ' || substr(md5(series.n::text || 'pass'), 1, 8) || '!@#'
                    WHEN 4 THEN 'Account: ACC-' || LPAD(series.n::text, 8, '0') || ' ($' || ((series.n * 99.9) % 50000)::numeric(8,2)::text || ')'
                    ELSE 'Phone: +1-' || LPAD(((series.n * 7) % 999)::text, 3, '0') || '-' || 
                         LPAD(((series.n * 11) % 999)::text, 3, '0') || '-' || 
                         LPAD(((series.n * 13) % 9999)::text, 4, '0')
                END
        END as sensitive_data,
        now() - ((random() * 365)::int || ' days')::interval + 
                (series.n || ' seconds')::interval as created_at
    FROM generate_series(start_at, 9223372036854775807) as series(n);
$$;

-- Create alert logging table
CREATE TABLE IF NOT EXISTS honeypot.alerts (
    id SERIAL PRIMARY KEY,
    alert_time TIMESTAMP DEFAULT NOW(),
    table_name TEXT,
    user_name TEXT,
    client_ip TEXT,
    query_type TEXT,
    rows_accessed INTEGER
);

-- Create alert function
CREATE OR REPLACE FUNCTION honeypot.log_access()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO honeypot.alerts (table_name, user_name, client_ip, query_type, rows_accessed)
    VALUES (
        TG_TABLE_NAME,
        current_user,
        inet_client_addr()::text,
        TG_OP,
        1
    );
    
    -- Also log to PostgreSQL log
    RAISE WARNING 'HONEYPOT ACCESS: Table % accessed by user % from %', 
        TG_TABLE_NAME, current_user, COALESCE(inet_client_addr()::text, 'local');
    
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- Create honeypot tables with infinite data

-- 1. Financial Records (Infinite)
CREATE TABLE honeypot.financial_seed (
    id SERIAL PRIMARY KEY,
    account_number VARCHAR(20),
    balance DECIMAL(10,2),
    routing_number VARCHAR(20),
    created_at TIMESTAMP DEFAULT NOW()
);

-- Insert minimal seed data
INSERT INTO honeypot.financial_seed (account_number, balance, routing_number) VALUES
('ACC-00097024', 60110.57, '285614017'),
('ACC-00066898', 81618.09, '588296258');

-- Create infinite view
CREATE OR REPLACE VIEW honeypot_financial_view AS
WITH seed_data AS (
    SELECT 
        id::bigint,
        'Account: ' || account_number || 
        ' | Balance: $' || TO_CHAR(balance, 'FM999,999.00') || 
        ' | Routing: ' || routing_number as sensitive_data,
        created_at,
        'seed_data' as _source
    FROM honeypot.financial_seed
),
max_id AS (
    SELECT COALESCE(MAX(id), 0) as max_id FROM seed_data
)
SELECT 
    id,
    SPLIT_PART(sensitive_data, ' | ', 1) as account_info,
    SPLIT_PART(SPLIT_PART(sensitive_data, ' | ', 2), ': $', 2)::decimal as balance,
    SPLIT_PART(SPLIT_PART(sensitive_data, ' | ', 3), ': ', 2) as routing_number,
    created_at,
    'alert_logged' as _alert
FROM (
    SELECT * FROM seed_data
    UNION ALL
    SELECT *, 'generated' as _source 
    FROM honeypot.generate_infinite_data('account', (SELECT max_id + 1 FROM max_id))
) combined_data;

-- Create access trigger
CREATE TRIGGER honeypot_financial_trigger
    AFTER SELECT ON honeypot.financial_seed
    FOR EACH STATEMENT
    EXECUTE FUNCTION honeypot.log_access();

-- 2. Customer Records (Infinite)
CREATE TABLE honeypot.customer_seed (
    id SERIAL PRIMARY KEY,
    customer_id VARCHAR(20),
    ssn VARCHAR(20),
    credit_card VARCHAR(30),
    created_at TIMESTAMP DEFAULT NOW()
);

INSERT INTO honeypot.customer_seed (customer_id, ssn, credit_card) VALUES
('CUST-0024', '###-##-7094', '4532-9145-3674-5005'),
('CUST-4369', '###-##-9529', '4532-6210-4807-6847'),
('CUST-6636', '###-##-3050', '4532-4771-3553-0747');

CREATE OR REPLACE VIEW honeypot_customer_view AS
WITH seed_data AS (
    SELECT 
        id::bigint,
        customer_id,
        ssn,
        credit_card,
        created_at
    FROM honeypot.customer_seed
),
max_id AS (
    SELECT COALESCE(MAX(id), 0) as max_id FROM seed_data
),
generated AS (
    SELECT 
        id,
        'CUST-' || LPAD(((id * 13) % 999999)::text, 6, '0') as customer_id,
        SPLIT_PART(sensitive_data, ' | ', 1) as ssn_info,
        'Credit Card: 4532-' || 
        LPAD(((id * 1234) % 10000)::text, 4, '0') || '-' ||
        LPAD(((id * 5678) % 10000)::text, 4, '0') || '-' ||
        LPAD(((id * 9012) % 10000)::text, 4, '0') as credit_card,
        created_at
    FROM honeypot.generate_infinite_data('ssn', (SELECT max_id + 1 FROM max_id))
)
SELECT 
    id,
    customer_id,
    COALESCE(ssn, REPLACE(ssn_info, 'SSN: ', '')) as ssn,
    COALESCE(credit_card, 'N/A') as credit_card,
    created_at,
    'alert_logged' as _alert
FROM (
    SELECT * FROM seed_data
    UNION ALL
    SELECT id, customer_id, ssn_info as ssn, credit_card, created_at FROM generated
) combined_data;

CREATE TRIGGER honeypot_customer_trigger
    AFTER SELECT ON honeypot.customer_seed
    FOR EACH STATEMENT
    EXECUTE FUNCTION honeypot.log_access();

-- 3. Employee Records (Infinite)
CREATE TABLE honeypot.employee_seed (
    id SERIAL PRIMARY KEY,
    employee_id VARCHAR(20),
    department VARCHAR(50),
    sensitive_info TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

INSERT INTO honeypot.employee_seed (employee_id, department, sensitive_info) VALUES
('EMP-001', 'IT', 'Admin credentials: admin/P@ssw0rd123'),
('EMP-002', 'Finance', 'Bank Access: routing-123456789');

CREATE OR REPLACE VIEW honeypot_employee_view AS
WITH seed_data AS (
    SELECT 
        id::bigint,
        employee_id,
        department,
        sensitive_info,
        created_at
    FROM honeypot.employee_seed
),
max_id AS (
    SELECT COALESCE(MAX(id), 0) as max_id FROM seed_data
)
SELECT * FROM (
    SELECT * FROM seed_data
    UNION ALL
    SELECT 
        id,
        SPLIT_PART(sensitive_data, ' | ', 1) as employee_id,
        SPLIT_PART(sensitive_data, ' | ', 2) as department,
        sensitive_data as sensitive_info,
        created_at
    FROM honeypot.generate_infinite_data('employee', (SELECT max_id + 1 FROM max_id))
) combined_data;

CREATE TRIGGER honeypot_employee_trigger
    AFTER SELECT ON honeypot.employee_seed
    FOR EACH STATEMENT
    EXECUTE FUNCTION honeypot.log_access();

-- Create convenience functions
CREATE OR REPLACE FUNCTION honeypot_query(
    table_name text,
    limit_rows integer DEFAULT 100
)
RETURNS TABLE(id bigint, data text, created_at timestamptz)
LANGUAGE plpgsql
AS $$
BEGIN
    IF limit_rows > 10000 THEN
        limit_rows := 10000; -- Safety limit
    END IF;
    
    RETURN QUERY EXECUTE format(
        'SELECT id::bigint, sensitive_data::text, created_at::timestamptz 
         FROM %I LIMIT %s',
        table_name,
        limit_rows
    );
EXCEPTION
    WHEN OTHERS THEN
        RETURN QUERY 
        SELECT series.n, 
               'Error accessing table - generated data #' || series.n, 
               now()
        FROM generate_series(1, limit_rows) as series(n);
END;
$$;

-- Create public wrapper functions for monitoring
CREATE OR REPLACE FUNCTION get_honeypot_status()
RETURNS TABLE(
    setting text,
    value text
)
LANGUAGE sql
AS $$
    SELECT 'Total Honeypot Tables', COUNT(*)::text 
    FROM pg_views 
    WHERE viewname LIKE 'honeypot_%'
    UNION ALL
    SELECT 'Total Alerts Logged', COUNT(*)::text 
    FROM honeypot.alerts
    UNION ALL
    SELECT 'Infinite Data Enabled', 'Yes'
    UNION ALL
    SELECT 'Max Rows Safety Limit', '10000';
$$;

CREATE OR REPLACE FUNCTION list_honeypot_tables()
RETURNS TABLE(
    table_name text,
    table_type text,
    seed_rows bigint
)
LANGUAGE sql
AS $$
    SELECT 
        viewname::text,
        'infinite_honeypot'::text,
        (SELECT COUNT(*) FROM honeypot.financial_seed 
         WHERE viewname = 'honeypot_financial_view')::bigint
    FROM pg_views
    WHERE viewname LIKE 'honeypot_%'
    ORDER BY viewname;
$$;

-- Final setup message
\echo ''
\echo 'PostgreSQL Honeypot with Infinite Data Generation initialized successfully!'
\echo '========================================================================='
\echo ''
\echo 'Available honeypot tables:'
\echo '  - honeypot_financial_view (infinite account data)'
\echo '  - honeypot_customer_view (infinite customer/SSN data)'
\echo '  - honeypot_employee_view (infinite employee data)'
\echo ''
\echo 'Test with:'
\echo '  SELECT * FROM honeypot_financial_view LIMIT 100;'
\echo ''
\echo 'Warning: Queries without LIMIT will run forever!'
\echo ''