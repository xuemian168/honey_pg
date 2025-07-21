-- PostgreSQL Honeypot Initialization Script
-- This script runs when the container starts for the first time

\c postgres;

-- Create the honeypot extension
CREATE EXTENSION IF NOT EXISTS pg_honeypot;

-- Set default API URL (points to the Python listener in the same container)
SELECT pg_honeypot_set_api_url('http://localhost:8080/alert');

-- Create some example honeypot tables
SELECT pg_honeypot_create_table('customer_data');
SELECT pg_honeypot_create_table('financial_records');
SELECT pg_honeypot_create_table('employee_info');

-- Create a regular user for testing (don't use superuser in production)
CREATE USER honeypot_test WITH PASSWORD 'test123';
GRANT CONNECT ON DATABASE postgres TO honeypot_test;
GRANT USAGE ON SCHEMA public TO honeypot_test;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO honeypot_test;

-- Log the setup
DO $$
BEGIN
    RAISE NOTICE 'PostgreSQL Honeypot Extension initialized successfully';
    RAISE NOTICE 'Created honeypot tables: customer_data, financial_records, employee_info';
    RAISE NOTICE 'Test user created: honeypot_test (password: test123)';
    RAISE NOTICE 'API URL set to: http://localhost:8080/alert';
END $$;