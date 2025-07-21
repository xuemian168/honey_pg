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

-- Grant permissions for the extension functions
GRANT EXECUTE ON FUNCTION pg_honeypot_set_api_url(text) TO PUBLIC;
GRANT EXECUTE ON FUNCTION pg_honeypot_create_table(text) TO PUBLIC;
GRANT EXECUTE ON FUNCTION honeypot_trigger_function() TO PUBLIC;