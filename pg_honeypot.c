#include "postgres.h"
#include "fmgr.h"
#include "utils/builtins.h"
#include "utils/guc.h"
#include "catalog/pg_type.h"
#include "executor/spi.h"
#include "commands/trigger.h"
#include "utils/rel.h"
#include "utils/lsyscache.h"
#include "access/htup_details.h"
#include "miscadmin.h"
#include "tcop/utility.h"
#include "utils/memutils.h"
#include "utils/timestamp.h"

PG_MODULE_MAGIC;

static char *honeypot_api_url = NULL;

void _PG_init(void);
void honeypot_main(Datum main_arg);

PG_FUNCTION_INFO_V1(pg_honeypot_set_api_url);
PG_FUNCTION_INFO_V1(pg_honeypot_create_table);
PG_FUNCTION_INFO_V1(honeypot_trigger_function);

static void
send_honeypot_alert(const char *table_name, const char *user_name, const char *client_addr)
{
    StringInfoData buf;
    initStringInfo(&buf);
    
    appendStringInfo(&buf, 
        "curl -X POST -H \"Content-Type: application/json\" "
        "-d '{\"alert\":\"Honeypot table accessed\",\"table\":\"%s\",\"user\":\"%s\",\"client_ip\":\"%s\",\"timestamp\":\"%s\"}' "
        "%s &",
        table_name,
        user_name ? user_name : "unknown",
        client_addr ? client_addr : "unknown",
        timestamptz_to_str(GetCurrentTimestamp()),
        honeypot_api_url ? honeypot_api_url : "http://localhost:8080/alert"
    );
    
    if (system(buf.data) != 0)
    {
        elog(WARNING, "pg_honeypot: Failed to send alert for table %s", table_name);
    }
    
    pfree(buf.data);
}

Datum
pg_honeypot_set_api_url(PG_FUNCTION_ARGS)
{
    text *url_text = PG_GETARG_TEXT_PP(0);
    char *url = text_to_cstring(url_text);
    
    if (honeypot_api_url)
        pfree(honeypot_api_url);
        
    honeypot_api_url = pstrdup(url);
    
    elog(NOTICE, "pg_honeypot: API URL set to %s", honeypot_api_url);
    
    PG_RETURN_BOOL(true);
}

Datum
pg_honeypot_create_table(PG_FUNCTION_ARGS)
{
    text *table_name_text = PG_GETARG_TEXT_PP(0);
    char *table_name = text_to_cstring(table_name_text);
    StringInfoData buf;
    int ret;
    
    SPI_connect();
    
    initStringInfo(&buf);
    
    appendStringInfo(&buf,
        "CREATE TABLE %s ("
        "id SERIAL PRIMARY KEY, "
        "sensitive_data TEXT DEFAULT 'CONFIDENTIAL DATA', "
        "created_at TIMESTAMP DEFAULT NOW()"
        ");",
        table_name);
    
    ret = SPI_exec(buf.data, 0);
    if (ret != SPI_OK_UTILITY)
    {
        SPI_finish();
        ereport(ERROR,
            (errcode(ERRCODE_INTERNAL_ERROR),
             errmsg("pg_honeypot: Failed to create table %s", table_name)));
    }
    
    resetStringInfo(&buf);
    
    appendStringInfo(&buf,
        "CREATE TRIGGER honeypot_trigger_%s "
        "BEFORE SELECT ON %s "
        "FOR EACH STATEMENT "
        "EXECUTE FUNCTION honeypot_trigger_function('%s');",
        table_name, table_name, table_name);
    
    ret = SPI_exec(buf.data, 0);
    if (ret != SPI_OK_UTILITY)
    {
        SPI_finish();
        ereport(ERROR,
            (errcode(ERRCODE_INTERNAL_ERROR),
             errmsg("pg_honeypot: Failed to create trigger for table %s", table_name)));
    }
    
    appendStringInfo(&buf,
        "INSERT INTO %s (sensitive_data) VALUES "
        "('Social Security Numbers: 123-45-6789, 987-65-4321'), "
        "('Credit Card: 4532-1234-5678-9012'), "
        "('API Keys: sk-1234567890abcdef'), "
        "('Passwords: admin123, password!@#');",
        table_name);
    
    ret = SPI_exec(buf.data, 0);
    
    SPI_finish();
    
    elog(NOTICE, "pg_honeypot: Created honeypot table %s with trigger", table_name);
    
    pfree(buf.data);
    
    PG_RETURN_BOOL(true);
}

Datum
honeypot_trigger_function(PG_FUNCTION_ARGS)
{
    TriggerData *trigdata = (TriggerData *) fcinfo->context;
    char *table_name;
    char *user_name;
    char *client_addr;
    
    if (!CALLED_AS_TRIGGER(fcinfo))
        ereport(ERROR,
            (errcode(ERRCODE_E_R_I_E_TRIGGER_PROTOCOL_VIOLATED),
             errmsg("honeypot_trigger_function: not called by trigger manager")));
    
    table_name = SPI_getrelname(trigdata->tg_relation);
    user_name = GetUserNameFromId(GetUserId(), false);
    client_addr = "unknown"; // Simplified - would need libpq for real client IP
    
    elog(WARNING, "pg_honeypot: HONEYPOT ACCESSED! Table: %s, User: %s, Client: %s", 
         table_name, user_name, client_addr ? client_addr : "local");
    
    send_honeypot_alert(table_name, user_name, client_addr);
    
    PG_RETURN_NULL();
}

void
_PG_init(void)
{
    DefineCustomStringVariable("pg_honeypot.api_url",
                             "API URL for honeypot alerts",
                             NULL,
                             &honeypot_api_url,
                             "http://localhost:8080/alert",
                             PGC_SUSET,
                             0,
                             NULL,
                             NULL,
                             NULL);
    
    elog(LOG, "pg_honeypot extension loaded");
}