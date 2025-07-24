-- PostgreSQL Honeypot Extension SQL Definition File

-- Function to set the API URL for honeypot alerts
CREATE OR REPLACE FUNCTION pg_honeypot_set_api_url(text)
RETURNS boolean
AS 'MODULE_PATHNAME', 'pg_honeypot_set_api_url'
LANGUAGE C STRICT;

-- Function to create a honeypot table with triggers
CREATE OR REPLACE FUNCTION pg_honeypot_create_table(text)
RETURNS boolean
AS 'MODULE_PATHNAME', 'pg_honeypot_create_table'
LANGUAGE C STRICT;

-- Trigger function that gets called when honeypot table is accessed
CREATE OR REPLACE FUNCTION honeypot_trigger_function()
RETURNS trigger
AS 'MODULE_PATHNAME', 'honeypot_trigger_function'
LANGUAGE C;

-- Create a schema for honeypot tables (optional, for organization)
CREATE SCHEMA IF NOT EXISTS honeypot;

COMMENT ON SCHEMA honeypot IS 'Schema containing honeypot tables for intrusion detection';

-- Function to create infinite honeypot table with minimal disk storage
CREATE OR REPLACE FUNCTION pg_honeypot_create_infinite_table(
    table_name text,
    seed_rows integer DEFAULT 5,
    pattern_type text DEFAULT 'mixed'
)
RETURNS boolean
AS 'MODULE_PATHNAME', 'pg_honeypot_create_infinite_table'
LANGUAGE C STRICT;

-- Function to generate infinite honeypot data
CREATE OR REPLACE FUNCTION generate_honeypot_data(start_id bigint)
RETURNS TABLE(id bigint, sensitive_data text, created_at timestamptz)
AS 'MODULE_PATHNAME', 'generate_honeypot_data'
LANGUAGE C STRICT;

-- Function to configure infinite data behavior
CREATE OR REPLACE FUNCTION pg_honeypot_set_infinite_config(
    max_rows_per_query integer DEFAULT NULL,
    delay_ms_per_row integer DEFAULT NULL,
    randomize boolean DEFAULT NULL
)
RETURNS boolean
AS 'MODULE_PATHNAME', 'pg_honeypot_set_infinite_config'
LANGUAGE C;

-- Grant permissions for the extension functions
GRANT EXECUTE ON FUNCTION pg_honeypot_set_api_url(text) TO PUBLIC;
GRANT EXECUTE ON FUNCTION pg_honeypot_create_table(text) TO PUBLIC;
GRANT EXECUTE ON FUNCTION honeypot_trigger_function() TO PUBLIC;
GRANT EXECUTE ON FUNCTION pg_honeypot_create_infinite_table(text, integer, text) TO PUBLIC;
GRANT EXECUTE ON FUNCTION generate_honeypot_data(bigint) TO PUBLIC;
GRANT EXECUTE ON FUNCTION pg_honeypot_set_infinite_config(integer, integer, boolean) TO PUBLIC;