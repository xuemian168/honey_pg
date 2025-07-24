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
#include "funcapi.h"
#include "pg_honeypot_patterns.h"

PG_MODULE_MAGIC;

static char *honeypot_api_url = NULL;
static int32 honeypot_max_rows_per_query = 0;
static int32 honeypot_delay_ms_per_row = 0;
static bool honeypot_randomize = false;

void _PG_init(void);
void honeypot_main(Datum main_arg);

PG_FUNCTION_INFO_V1(pg_honeypot_set_api_url);
PG_FUNCTION_INFO_V1(pg_honeypot_create_table);
PG_FUNCTION_INFO_V1(honeypot_trigger_function);
PG_FUNCTION_INFO_V1(pg_honeypot_create_infinite_table);
PG_FUNCTION_INFO_V1(generate_honeypot_data);
PG_FUNCTION_INFO_V1(pg_honeypot_set_infinite_config);

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
    
    DefineCustomIntVariable("pg_honeypot.max_rows_per_query",
                          "Maximum rows returned per query (0 = unlimited)",
                          NULL,
                          &honeypot_max_rows_per_query,
                          0,
                          0, INT_MAX,
                          PGC_SUSET,
                          0,
                          NULL,
                          NULL,
                          NULL);
    
    DefineCustomIntVariable("pg_honeypot.delay_ms_per_row",
                          "Delay in milliseconds per generated row",
                          NULL,
                          &honeypot_delay_ms_per_row,
                          0,
                          0, 1000,
                          PGC_SUSET,
                          0,
                          NULL,
                          NULL,
                          NULL);
    
    DefineCustomBoolVariable("pg_honeypot.randomize",
                           "Randomize generated data",
                           NULL,
                           &honeypot_randomize,
                           false,
                           PGC_SUSET,
                           0,
                           NULL,
                           NULL,
                           NULL);
    
    elog(LOG, "pg_honeypot extension loaded");
}

Datum
pg_honeypot_set_infinite_config(PG_FUNCTION_ARGS)
{
    if (!PG_ARGISNULL(0))
        honeypot_max_rows_per_query = PG_GETARG_INT32(0);
    
    if (!PG_ARGISNULL(1))
        honeypot_delay_ms_per_row = PG_GETARG_INT32(1);
    
    if (!PG_ARGISNULL(2))
        honeypot_randomize = PG_GETARG_BOOL(2);
    
    elog(NOTICE, "pg_honeypot: Infinite config updated - max_rows: %d, delay_ms: %d, randomize: %s",
         honeypot_max_rows_per_query, honeypot_delay_ms_per_row, 
         honeypot_randomize ? "true" : "false");
    
    PG_RETURN_BOOL(true);
}

Datum
generate_honeypot_data(PG_FUNCTION_ARGS)
{
    FuncCallContext *funcctx;
    int64 start_id;
    int64 current_id;
    TupleDesc tupdesc;
    Datum values[3];
    bool nulls[3] = {false, false, false};
    HeapTuple tuple;
    
    if (SRF_IS_FIRSTCALL())
    {
        MemoryContext oldcontext;
        
        funcctx = SRF_FIRSTCALL_INIT();
        oldcontext = MemoryContextSwitchTo(funcctx->multi_call_memory_ctx);
        
        start_id = PG_GETARG_INT64(0);
        funcctx->user_fctx = palloc(sizeof(int64));
        *(int64*)funcctx->user_fctx = start_id;
        
        if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
            ereport(ERROR,
                    (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
                     errmsg("function returning record called in context "
                            "that cannot accept type record")));
        
        funcctx->tuple_desc = BlessTupleDesc(tupdesc);
        
        MemoryContextSwitchTo(oldcontext);
    }
    
    funcctx = SRF_PERCALL_SETUP();
    
    if (honeypot_max_rows_per_query > 0 && 
        funcctx->call_cntr >= honeypot_max_rows_per_query)
    {
        SRF_RETURN_DONE(funcctx);
    }
    
    if (honeypot_delay_ms_per_row > 0)
    {
        pg_usleep(honeypot_delay_ms_per_row * 1000L);
    }
    
    start_id = *(int64*)funcctx->user_fctx;
    current_id = start_id + funcctx->call_cntr;
    
    if (honeypot_randomize)
    {
        current_id = current_id * 1103515245LL + 12345;
    }
    
    values[0] = Int64GetDatum(current_id);
    values[1] = CStringGetTextDatum(generate_fake_sensitive_data(current_id, PATTERN_MIXED));
    values[2] = TimestampTzGetDatum(GetCurrentTimestamp());
    
    tuple = heap_form_tuple(funcctx->tuple_desc, values, nulls);
    
    SRF_RETURN_NEXT(funcctx, HeapTupleGetDatum(tuple));
}

Datum
pg_honeypot_create_infinite_table(PG_FUNCTION_ARGS)
{
    text *table_name_text = PG_GETARG_TEXT_PP(0);
    char *table_name = text_to_cstring(table_name_text);
    int32 seed_rows = PG_GETARG_INT32(1);
    text *pattern_type_text = PG_GETARG_TEXT_PP(2);
    char *pattern_type = text_to_cstring(pattern_type_text);
    StringInfoData buf;
    DataPatternType pattern;
    int ret;
    int i;
    
    if (seed_rows < 1 || seed_rows > 100)
        seed_rows = 5;
    
    SPI_connect();
    
    initStringInfo(&buf);
    
    appendStringInfo(&buf,
        "CREATE TABLE %s_seed ("
        "id BIGINT PRIMARY KEY, "
        "sensitive_data TEXT, "
        "created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()"
        ");",
        table_name);
    
    ret = SPI_exec(buf.data, 0);
    if (ret != SPI_OK_UTILITY)
    {
        SPI_finish();
        ereport(ERROR,
            (errcode(ERRCODE_INTERNAL_ERROR),
             errmsg("pg_honeypot: Failed to create seed table %s_seed", table_name)));
    }
    
    resetStringInfo(&buf);
    
    /* Determine pattern type */
    pattern = PATTERN_MIXED;
    if (strcmp(pattern_type, "ssn") == 0) pattern = PATTERN_SSN;
    else if (strcmp(pattern_type, "credit_card") == 0) pattern = PATTERN_CREDIT_CARD;
    else if (strcmp(pattern_type, "api_key") == 0) pattern = PATTERN_API_KEY;
    else if (strcmp(pattern_type, "password") == 0) pattern = PATTERN_PASSWORD;
    else if (strcmp(pattern_type, "email") == 0) pattern = PATTERN_EMAIL;
    else if (strcmp(pattern_type, "phone") == 0) pattern = PATTERN_PHONE;
    
    for (i = 1; i <= seed_rows; i++)
    {
        appendStringInfo(&buf,
            "INSERT INTO %s_seed (id, sensitive_data) VALUES (%d, '%s'); ",
            table_name, i, generate_fake_sensitive_data(i, pattern));
    }
    
    ret = SPI_exec(buf.data, 0);
    
    resetStringInfo(&buf);
    
    appendStringInfo(&buf,
        "CREATE VIEW %s AS "
        "SELECT * FROM %s_seed "
        "UNION ALL "
        "SELECT * FROM generate_honeypot_data(%d::bigint) "
        "AS t(id bigint, sensitive_data text, created_at timestamptz);",
        table_name, table_name, seed_rows + 1);
    
    ret = SPI_exec(buf.data, 0);
    if (ret != SPI_OK_UTILITY)
    {
        SPI_finish();
        ereport(ERROR,
            (errcode(ERRCODE_INTERNAL_ERROR),
             errmsg("pg_honeypot: Failed to create infinite view %s", table_name)));
    }
    
    resetStringInfo(&buf);
    
    appendStringInfo(&buf,
        "CREATE RULE honeypot_alert_%s AS "
        "ON SELECT TO %s "
        "DO ALSO SELECT honeypot_trigger_function('%s');",
        table_name, table_name, table_name);
    
    ret = SPI_exec(buf.data, 0);
    
    SPI_finish();
    
    elog(NOTICE, "pg_honeypot: Created infinite honeypot table %s with %d seed rows", 
         table_name, seed_rows);
    
    pfree(buf.data);
    
    PG_RETURN_BOOL(true);
}