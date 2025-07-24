#ifndef PG_HONEYPOT_PATTERNS_H
#define PG_HONEYPOT_PATTERNS_H

#include "postgres.h"
#include "utils/builtins.h"

typedef enum {
    PATTERN_SSN,
    PATTERN_CREDIT_CARD,
    PATTERN_API_KEY,
    PATTERN_PASSWORD,
    PATTERN_EMAIL,
    PATTERN_PHONE,
    PATTERN_MIXED
} DataPatternType;

static const char *ssn_prefixes[] = {
    "123", "456", "789", "321", "654", "987", "111", "222", "333", "444"
};

static const char *credit_card_prefixes[] = {
    "4532", "4539", "4556", "4916", "5123", "5456", "5789", "3412", "3456", "3789"
};

static const char *api_key_prefixes[] = {
    "sk-", "pk-", "api-", "key-", "token-", "secret-", "auth-", "access-"
};

static const char *password_patterns[] = {
    "Admin", "Password", "Secret", "Master", "Super", "Root", "User", "Guest"
};

static const char *email_domains[] = {
    "@company.com", "@secure.net", "@internal.org", "@private.io", "@confidential.com"
};

static inline char*
generate_ssn(int64 seed)
{
    int prefix_idx = seed % 10;
    int middle = (seed / 10) % 100;
    int last = (seed / 1000) % 10000;
    
    return psprintf("%s-%02d-%04d", ssn_prefixes[prefix_idx], middle, last);
}

static inline char*
generate_credit_card(int64 seed)
{
    int prefix_idx = seed % 10;
    int64 middle = (seed * 1234567) % 100000000;
    int last = (seed * 89) % 10000;
    
    return psprintf("%s-%04ld-%04ld-%04d", 
                    credit_card_prefixes[prefix_idx],
                    (long)(middle / 10000), (long)(middle % 10000), last);
}

static inline char*
generate_api_key(int64 seed)
{
    int prefix_idx = seed % 8;
    char key[33];
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    int64 temp = seed * 9876543210LL;
    
    for (int i = 0; i < 32; i++) {
        temp = (temp * 1103515245LL + 12345) & 0x7fffffffLL;
        key[i] = charset[temp % 62];
    }
    key[32] = '\0';
    
    return psprintf("%s%s", api_key_prefixes[prefix_idx], key);
}

static inline char*
generate_password(int64 seed)
{
    int pattern_idx = seed % 8;
    int number = (seed * 123) % 10000;
    char special[] = "!@#$%^&*";
    int special_idx = seed % 8;
    
    return psprintf("%s%04d%c", password_patterns[pattern_idx], number, special[special_idx]);
}

static inline char*
generate_email(int64 seed)
{
    char username[20];
    const char charset[] = "abcdefghijklmnopqrstuvwxyz";
    int64 temp = seed * 987654321LL;
    int domain_idx = seed % 5;
    
    for (int i = 0; i < 8; i++) {
        temp = (temp * 1103515245LL + 12345) & 0x7fffffffLL;
        username[i] = charset[temp % 26];
    }
    username[8] = '\0';
    
    return psprintf("%s.%ld%s", username, seed % 1000, email_domains[domain_idx]);
}

static inline char*
generate_phone(int64 seed)
{
    int area = 200 + (seed % 800);
    int exchange = 200 + ((seed * 13) % 800);
    int number = (seed * 17) % 10000;
    
    return psprintf("+1-%03d-%03d-%04d", area, exchange, number);
}

static inline char*
generate_fake_sensitive_data(int64 seed, DataPatternType pattern)
{
    switch (pattern) {
        case PATTERN_SSN:
            return generate_ssn(seed);
        case PATTERN_CREDIT_CARD:
            return generate_credit_card(seed);
        case PATTERN_API_KEY:
            return generate_api_key(seed);
        case PATTERN_PASSWORD:
            return generate_password(seed);
        case PATTERN_EMAIL:
            return generate_email(seed);
        case PATTERN_PHONE:
            return generate_phone(seed);
        case PATTERN_MIXED:
            {
                int type = seed % 6;
                StringInfoData buf;
                initStringInfo(&buf);
                
                switch (type) {
                    case 0:
                        appendStringInfo(&buf, "SSN: %s", generate_ssn(seed));
                        break;
                    case 1:
                        appendStringInfo(&buf, "Credit Card: %s", generate_credit_card(seed));
                        break;
                    case 2:
                        appendStringInfo(&buf, "API Key: %s", generate_api_key(seed));
                        break;
                    case 3:
                        appendStringInfo(&buf, "Password: %s", generate_password(seed));
                        break;
                    case 4:
                        appendStringInfo(&buf, "Email: %s", generate_email(seed));
                        break;
                    case 5:
                        appendStringInfo(&buf, "Phone: %s", generate_phone(seed));
                        break;
                }
                
                return buf.data;
            }
        default:
            return pstrdup("CONFIDENTIAL DATA");
    }
}

#endif /* PG_HONEYPOT_PATTERNS_H */