#include "wardd/config.h"
#include "wardd/ban.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum section {
    SECTION_ROOT = 0,
    SECTION_GEO,
    SECTION_XDP,
    SECTION_XDP_ENDPOINT,
    SECTION_BAN,
    SECTION_BAN_AUTO,
    SECTION_NGINX,
    SECTION_FIREWALL,
};

struct parse_state {
    enum section section;
    unsigned long long root_fields;
    unsigned long long geo_fields;
    unsigned long long xdp_fields;
    unsigned long long ban_fields;
    unsigned long long auto_ban_fields;
    unsigned long long nginx_fields;
    unsigned long long firewall_fields;
    unsigned long long endpoint_fields[WARDD_MAX_ENDPOINTS];
    size_t endpoint_index;
};

static void set_error(char *error, size_t error_size, size_t line, const char *format, ...)
{
    va_list args;
    int offset = 0;

    if (error == NULL || error_size == 0) {
        return;
    }

    if (line > 0) {
        offset = snprintf(error, error_size, "line %zu: ", line);
        if (offset < 0 || (size_t)offset >= error_size) {
            return;
        }
    } else {
        error[0] = '\0';
    }

    va_start(args, format);
    (void)vsnprintf(error + (size_t)offset, error_size - (size_t)offset, format, args);
    va_end(args);
}

static char *trim_left(char *text)
{
    while (*text != '\0' && isspace((unsigned char)*text)) {
        text++;
    }
    return text;
}

static void trim_right(char *text)
{
    size_t length = strlen(text);

    while (length > 0 && isspace((unsigned char)text[length - 1])) {
        text[--length] = '\0';
    }
}

static void strip_comment(char *text)
{
    bool quoted = false;
    bool escaped = false;

    for (char *cursor = text; *cursor != '\0'; cursor++) {
        if (escaped) {
            escaped = false;
            continue;
        }
        if (quoted && *cursor == '\\') {
            escaped = true;
            continue;
        }
        if (*cursor == '"') {
            quoted = !quoted;
            continue;
        }
        if (!quoted && *cursor == '#') {
            *cursor = '\0';
            return;
        }
    }
}

static int parse_string(
    const char *value,
    char *output,
    size_t output_size,
    char *error,
    size_t error_size,
    size_t line
)
{
    size_t output_length = 0;
    const char *cursor = value;

    if (*cursor++ != '"') {
        set_error(error, error_size, line, "expected a double-quoted string");
        return -1;
    }

    while (*cursor != '\0' && *cursor != '"') {
        unsigned char next = (unsigned char)*cursor++;

        if (next == '\\') {
            switch (*cursor) {
            case '\\':
            case '"':
                next = (unsigned char)*cursor++;
                break;
            case 'n':
                next = '\n';
                cursor++;
                break;
            case 'r':
                next = '\r';
                cursor++;
                break;
            case 't':
                next = '\t';
                cursor++;
                break;
            default:
                set_error(error, error_size, line, "unsupported string escape");
                return -1;
            }
        }

        if (next < 0x20) {
            set_error(error, error_size, line, "control character in string");
            return -1;
        }
        if (output_length + 1 >= output_size) {
            set_error(error, error_size, line, "string is too long");
            return -1;
        }
        output[output_length++] = (char)next;
    }

    if (*cursor != '"') {
        set_error(error, error_size, line, "unterminated string");
        return -1;
    }
    cursor++;
    while (isspace((unsigned char)*cursor)) {
        cursor++;
    }
    if (*cursor != '\0') {
        set_error(error, error_size, line, "unexpected characters after string");
        return -1;
    }

    output[output_length] = '\0';
    return 0;
}

static int parse_bool(
    const char *value,
    bool *output,
    char *error,
    size_t error_size,
    size_t line
)
{
    if (strcmp(value, "true") == 0) {
        *output = true;
        return 0;
    }
    if (strcmp(value, "false") == 0) {
        *output = false;
        return 0;
    }
    set_error(error, error_size, line, "expected true or false");
    return -1;
}

static int parse_u64(
    const char *value,
    uint64_t *output,
    char *error,
    size_t error_size,
    size_t line
)
{
    char *end = NULL;
    unsigned long long number;

    if (*value == '\0' || *value == '-' || *value == '+') {
        set_error(error, error_size, line, "expected an unsigned integer");
        return -1;
    }
    errno = 0;
    number = strtoull(value, &end, 10);
    if (errno != 0 || end == value) {
        set_error(error, error_size, line, "invalid unsigned integer");
        return -1;
    }
    while (isspace((unsigned char)*end)) {
        end++;
    }
    if (*end != '\0') {
        set_error(error, error_size, line, "unexpected characters after integer");
        return -1;
    }
    *output = (uint64_t)number;
    return 0;
}

static int parse_double_value(
    const char *value,
    double *output,
    char *error,
    size_t error_size,
    size_t line
)
{
    char *end = NULL;
    double number;

    errno = 0;
    number = strtod(value, &end);
    if (errno != 0 || end == value) {
        set_error(error, error_size, line, "invalid floating-point value");
        return -1;
    }
    while (isspace((unsigned char)*end)) {
        end++;
    }
    if (*end != '\0') {
        set_error(error, error_size, line, "unexpected characters after number");
        return -1;
    }
    *output = number;
    return 0;
}

static int parse_scaled_string(
    const char *value,
    uint64_t *output,
    bool duration,
    char *error,
    size_t error_size,
    size_t line
)
{
    char text[64];
    char *end = NULL;
    unsigned long long number;
    uint64_t multiplier = 0;

    if (parse_string(value, text, sizeof(text), error, error_size, line) != 0) {
        return -1;
    }

    errno = 0;
    number = strtoull(text, &end, 10);
    if (errno != 0 || end == text || number == 0) {
        set_error(error, error_size, line, "scaled value must start with a positive integer");
        return -1;
    }

    if (duration) {
        if (strcmp(end, "s") == 0) {
            multiplier = 1;
        } else if (strcmp(end, "m") == 0) {
            multiplier = 60;
        } else if (strcmp(end, "h") == 0) {
            multiplier = 60 * 60;
        } else if (strcmp(end, "d") == 0) {
            multiplier = 24 * 60 * 60;
        } else {
            set_error(error, error_size, line, "duration suffix must be s, m, h, or d");
            return -1;
        }
    } else {
        if (strcmp(end, "B") == 0) {
            multiplier = 1;
        } else if (strcmp(end, "KiB") == 0) {
            multiplier = 1024;
        } else if (strcmp(end, "MiB") == 0) {
            multiplier = 1024 * 1024;
        } else if (strcmp(end, "GiB") == 0) {
            multiplier = 1024ULL * 1024ULL * 1024ULL;
        } else {
            set_error(error, error_size, line, "size suffix must be B, KiB, MiB, or GiB");
            return -1;
        }
    }

    if ((uint64_t)number > UINT64_MAX / multiplier) {
        set_error(error, error_size, line, "scaled value overflows uint64");
        return -1;
    }
    *output = (uint64_t)number * multiplier;
    return 0;
}

static int parse_ports(
    const char *value,
    uint16_t *ports,
    size_t *port_count,
    char *error,
    size_t error_size,
    size_t line
)
{
    const char *cursor = value;
    size_t count = 0;

    while (isspace((unsigned char)*cursor)) {
        cursor++;
    }
    if (*cursor++ != '[') {
        set_error(error, error_size, line, "expected an array of TCP ports");
        return -1;
    }

    for (;;) {
        char *end = NULL;
        unsigned long port;

        while (isspace((unsigned char)*cursor)) {
            cursor++;
        }
        if (*cursor == ']') {
            cursor++;
            break;
        }
        if (count == WARDD_MAX_BAN_PORTS) {
            set_error(error, error_size, line, "too many protected TCP ports");
            return -1;
        }

        errno = 0;
        port = strtoul(cursor, &end, 10);
        if (errno != 0 || end == cursor || port == 0 || port > UINT16_MAX) {
            set_error(error, error_size, line, "invalid TCP port");
            return -1;
        }
        for (size_t index = 0; index < count; index++) {
            if (ports[index] == (uint16_t)port) {
                set_error(error, error_size, line, "duplicate TCP port %lu", port);
                return -1;
            }
        }
        ports[count++] = (uint16_t)port;
        cursor = end;

        while (isspace((unsigned char)*cursor)) {
            cursor++;
        }
        if (*cursor == ',') {
            cursor++;
            continue;
        }
        if (*cursor == ']') {
            cursor++;
            break;
        }
        set_error(error, error_size, line, "expected ',' or ']' in port array");
        return -1;
    }

    while (isspace((unsigned char)*cursor)) {
        cursor++;
    }
    if (*cursor != '\0') {
        set_error(error, error_size, line, "unexpected characters after port array");
        return -1;
    }
    if (count == 0) {
        set_error(error, error_size, line, "protected TCP port array cannot be empty");
        return -1;
    }

    *port_count = count;
    return 0;
}

static int parse_address_array(
    const char *value,
    char addresses[WARDD_MAX_BAN_EXEMPT][WARDD_ADDRESS_LEN],
    size_t *address_count,
    char *error,
    size_t error_size,
    size_t line
)
{
    const char *cursor = value;
    size_t count = 0;

    while (isspace((unsigned char)*cursor)) cursor++;
    if (*cursor++ != '[') {
        set_error(error, error_size, line, "expected an array of exempt IP networks");
        return -1;
    }
    for (;;) {
        const char *start;
        size_t length;

        while (isspace((unsigned char)*cursor)) cursor++;
        if (*cursor == ']') {
            cursor++;
            break;
        }
        if (*cursor++ != '"' || count == WARDD_MAX_BAN_EXEMPT) {
            set_error(error, error_size, line, "invalid or excessive ban exempt entries");
            return -1;
        }
        start = cursor;
        while (*cursor != '\0' && *cursor != '"') {
            if (*cursor == '\\' || (unsigned char)*cursor < 0x20) {
                set_error(error, error_size, line, "ban exempt entries cannot contain escapes or controls");
                return -1;
            }
            cursor++;
        }
        if (*cursor != '"') {
            set_error(error, error_size, line, "unterminated ban exempt entry");
            return -1;
        }
        length = (size_t)(cursor - start);
        if (length == 0 || length >= WARDD_ADDRESS_LEN) {
            set_error(error, error_size, line, "ban exempt entry is empty or too long");
            return -1;
        }
        memcpy(addresses[count], start, length);
        addresses[count][length] = '\0';
        for (size_t index = 0; index < count; ++index) {
            if (strcmp(addresses[index], addresses[count]) == 0) {
                set_error(error, error_size, line, "duplicate ban exempt entry");
                return -1;
            }
        }
        count++;
        cursor++;
        while (isspace((unsigned char)*cursor)) cursor++;
        if (*cursor == ',') {
            cursor++;
            continue;
        }
        if (*cursor == ']') {
            cursor++;
            break;
        }
        set_error(error, error_size, line, "expected ',' or ']' in ban exempt array");
        return -1;
    }
    while (isspace((unsigned char)*cursor)) cursor++;
    if (*cursor != '\0') {
        set_error(error, error_size, line, "unexpected characters after ban exempt array");
        return -1;
    }
    *address_count = count;
    return 0;
}

static int mark_field(
    unsigned long long *fields,
    unsigned int bit,
    const char *key,
    char *error,
    size_t error_size,
    size_t line
)
{
    const unsigned long long mask = 1ULL << bit;

    if ((*fields & mask) != 0) {
        set_error(error, error_size, line, "duplicate key '%s'", key);
        return -1;
    }
    *fields |= mask;
    return 0;
}

static int parse_enum_string(
    const char *value,
    const char *const *names,
    size_t count,
    int *output,
    char *error,
    size_t error_size,
    size_t line
)
{
    char text[WARDD_NAME_LEN];

    if (parse_string(value, text, sizeof(text), error, error_size, line) != 0) {
        return -1;
    }
    for (size_t index = 0; index < count; index++) {
        if (strcmp(text, names[index]) == 0) {
            *output = (int)index;
            return 0;
        }
    }
    set_error(error, error_size, line, "unsupported value '%s'", text);
    return -1;
}

static int parse_section(
    char *line_text,
    struct parse_state *state,
    struct wardd_config *config,
    char *error,
    size_t error_size,
    size_t line
)
{
    const size_t length = strlen(line_text);
    bool array = false;
    char *name;

    if (length >= 4 && line_text[0] == '[' && line_text[1] == '[' &&
        line_text[length - 2] == ']' && line_text[length - 1] == ']') {
        array = true;
        line_text[length - 2] = '\0';
        name = trim_left(line_text + 2);
    } else if (length >= 3 && line_text[0] == '[' && line_text[length - 1] == ']') {
        line_text[length - 1] = '\0';
        name = trim_left(line_text + 1);
    } else {
        set_error(error, error_size, line, "malformed section header");
        return -1;
    }
    trim_right(name);

    if (array) {
        if (strcmp(name, "xdp.geo_endpoint") != 0) {
            set_error(error, error_size, line, "unknown array section '%s'", name);
            return -1;
        }
        if (config->xdp.endpoint_count == WARDD_MAX_ENDPOINTS) {
            set_error(error, error_size, line, "too many XDP geo endpoints");
            return -1;
        }
        state->endpoint_index = config->xdp.endpoint_count++;
        state->section = SECTION_XDP_ENDPOINT;
        return 0;
    }

    if (strcmp(name, "geo") == 0) {
        state->section = SECTION_GEO;
    } else if (strcmp(name, "xdp") == 0) {
        state->section = SECTION_XDP;
    } else if (strcmp(name, "ban") == 0) {
        state->section = SECTION_BAN;
    } else if (strcmp(name, "ban.auto") == 0) {
        state->section = SECTION_BAN_AUTO;
    } else if (strcmp(name, "nginx") == 0) {
        state->section = SECTION_NGINX;
    } else if (strcmp(name, "firewall") == 0) {
        state->section = SECTION_FIREWALL;
    } else {
        set_error(error, error_size, line, "unknown section '%s'", name);
        return -1;
    }
    return 0;
}

static int parse_root_key(
    const char *key,
    const char *value,
    struct parse_state *state,
    struct wardd_config *config,
    char *error,
    size_t error_size,
    size_t line
)
{
    uint64_t version;

    if (strcmp(key, "version") != 0) {
        set_error(error, error_size, line, "unknown root key '%s'", key);
        return -1;
    }
    if (mark_field(&state->root_fields, 0, key, error, error_size, line) != 0 ||
        parse_u64(value, &version, error, error_size, line) != 0) {
        return -1;
    }
    if (version > UINT32_MAX) {
        set_error(error, error_size, line, "configuration version is too large");
        return -1;
    }
    config->version = (uint32_t)version;
    return 0;
}

static int parse_geo_key(
    const char *key,
    const char *value,
    struct parse_state *state,
    struct wardd_config *config,
    char *error,
    size_t error_size,
    size_t line
)
{
    unsigned int bit;

    if (strcmp(key, "country") == 0) {
        bit = 0;
        if (mark_field(&state->geo_fields, bit, key, error, error_size, line) != 0) return -1;
        return parse_string(value, config->geo.country, sizeof(config->geo.country), error, error_size, line);
    }
    if (strcmp(key, "provider") == 0) {
        bit = 1;
        if (mark_field(&state->geo_fields, bit, key, error, error_size, line) != 0) return -1;
        return parse_string(value, config->geo.provider, sizeof(config->geo.provider), error, error_size, line);
    }
    if (strcmp(key, "url") == 0) {
        bit = 2;
        if (mark_field(&state->geo_fields, bit, key, error, error_size, line) != 0) return -1;
        return parse_string(value, config->geo.url, sizeof(config->geo.url), error, error_size, line);
    }
    if (strcmp(key, "checksum_url") == 0) {
        bit = 3;
        if (mark_field(&state->geo_fields, bit, key, error, error_size, line) != 0) return -1;
        return parse_string(value, config->geo.checksum_url, sizeof(config->geo.checksum_url), error, error_size, line);
    }
    if (strcmp(key, "update_interval") == 0) {
        bit = 4;
        if (mark_field(&state->geo_fields, bit, key, error, error_size, line) != 0) return -1;
        return parse_scaled_string(value, &config->geo.update_interval_seconds, true, error, error_size, line);
    }
    if (strcmp(key, "max_age") == 0) {
        bit = 5;
        if (mark_field(&state->geo_fields, bit, key, error, error_size, line) != 0) return -1;
        return parse_scaled_string(value, &config->geo.max_age_seconds, true, error, error_size, line);
    }
    if (strcmp(key, "max_download_size") == 0) {
        bit = 6;
        if (mark_field(&state->geo_fields, bit, key, error, error_size, line) != 0) return -1;
        return parse_scaled_string(value, &config->geo.max_download_bytes, false, error, error_size, line);
    }
    if (strcmp(key, "max_change_ratio") == 0) {
        bit = 7;
        if (mark_field(&state->geo_fields, bit, key, error, error_size, line) != 0) return -1;
        return parse_double_value(value, &config->geo.max_change_ratio, error, error_size, line);
    }
    set_error(error, error_size, line, "unknown geo key '%s'", key);
    return -1;
}

static int parse_xdp_key(
    const char *key,
    const char *value,
    struct parse_state *state,
    struct wardd_config *config,
    char *error,
    size_t error_size,
    size_t line
)
{
    static const char *const attach_names[] = {"auto", "native", "generic", "off"};
    static const char *const action_names[] = {"observe", "enforce"};
    int parsed;

    if (strcmp(key, "enabled") == 0) {
        if (mark_field(&state->xdp_fields, 0, key, error, error_size, line) != 0) return -1;
        return parse_bool(value, &config->xdp.enabled, error, error_size, line);
    }
    if (strcmp(key, "interface") == 0) {
        if (mark_field(&state->xdp_fields, 1, key, error, error_size, line) != 0) return -1;
        return parse_string(value, config->xdp.interface, sizeof(config->xdp.interface), error, error_size, line);
    }
    if (strcmp(key, "attach_mode") == 0) {
        if (mark_field(&state->xdp_fields, 2, key, error, error_size, line) != 0 ||
            parse_enum_string(value, attach_names, 4, &parsed, error, error_size, line) != 0) return -1;
        config->xdp.attach_mode = (enum wardd_attach_mode)parsed;
        return 0;
    }
    if (strcmp(key, "generic_fallback") == 0) {
        if (mark_field(&state->xdp_fields, 3, key, error, error_size, line) != 0) return -1;
        return parse_bool(value, &config->xdp.generic_fallback, error, error_size, line);
    }
    if (strcmp(key, "geo_action") == 0 || strcmp(key, "ban_action") == 0) {
        const unsigned int bit = strcmp(key, "geo_action") == 0 ? 4 : 5;
        if (mark_field(&state->xdp_fields, bit, key, error, error_size, line) != 0 ||
            parse_enum_string(value, action_names, 2, &parsed, error, error_size, line) != 0) return -1;
        if (bit == 4) config->xdp.geo_action = (enum wardd_action)parsed;
        else config->xdp.ban_action = (enum wardd_action)parsed;
        return 0;
    }
    set_error(error, error_size, line, "unknown xdp key '%s'", key);
    return -1;
}

static int parse_endpoint_key(
    const char *key,
    const char *value,
    struct parse_state *state,
    struct wardd_config *config,
    char *error,
    size_t error_size,
    size_t line
)
{
    struct wardd_geo_endpoint *endpoint = &config->xdp.endpoints[state->endpoint_index];
    unsigned long long *fields = &state->endpoint_fields[state->endpoint_index];
    uint64_t port;

    if (strcmp(key, "address") == 0) {
        if (mark_field(fields, 0, key, error, error_size, line) != 0) return -1;
        return parse_string(value, endpoint->address, sizeof(endpoint->address), error, error_size, line);
    }
    if (strcmp(key, "protocol") == 0) {
        if (mark_field(fields, 1, key, error, error_size, line) != 0) return -1;
        return parse_string(value, endpoint->protocol, sizeof(endpoint->protocol), error, error_size, line);
    }
    if (strcmp(key, "port") == 0) {
        if (mark_field(fields, 2, key, error, error_size, line) != 0 ||
            parse_u64(value, &port, error, error_size, line) != 0) return -1;
        if (port == 0 || port > UINT16_MAX) {
            set_error(error, error_size, line, "endpoint port must be between 1 and 65535");
            return -1;
        }
        endpoint->port = (uint16_t)port;
        return 0;
    }
    set_error(error, error_size, line, "unknown xdp.geo_endpoint key '%s'", key);
    return -1;
}

static int parse_ban_key(
    const char *key,
    const char *value,
    struct parse_state *state,
    struct wardd_config *config,
    char *error,
    size_t error_size,
    size_t line
)
{
    if (strcmp(key, "protected_tcp_ports") == 0) {
        if (mark_field(&state->ban_fields, 0, key, error, error_size, line) != 0) return -1;
        return parse_ports(
            value,
            config->ban.protected_tcp_ports,
            &config->ban.protected_tcp_port_count,
            error,
            error_size,
            line
        );
    }
    if (strcmp(key, "exempt") == 0) {
        if (mark_field(&state->ban_fields, 1, key, error, error_size, line) != 0) return -1;
        return parse_address_array(
            value,
            config->ban.exempt,
            &config->ban.exempt_count,
            error,
            error_size,
            line
        );
    }
    set_error(error, error_size, line, "unknown ban key '%s'", key);
    return -1;
}

static int parse_auto_ban_key(
    const char *key,
    const char *value,
    struct parse_state *state,
    struct wardd_config *config,
    char *error,
    size_t error_size,
    size_t line
)
{
    struct wardd_auto_ban_config *automatic = &config->ban.automatic;
    uint64_t *duration_output = NULL;
    unsigned int bit;

    if (strcmp(key, "enabled") == 0) {
        if (mark_field(&state->auto_ban_fields, 0, key, error, error_size, line) != 0) return -1;
        return parse_bool(value, &automatic->enabled, error, error_size, line);
    }
    if (strcmp(key, "event_source") == 0) {
        if (mark_field(&state->auto_ban_fields, 1, key, error, error_size, line) != 0) return -1;
        return parse_string(value, automatic->event_source, sizeof(automatic->event_source), error, error_size, line);
    }
    if (strcmp(key, "rejections") == 0) {
        if (mark_field(&state->auto_ban_fields, 3, key, error, error_size, line) != 0) return -1;
        return parse_u64(value, &automatic->rejections, error, error_size, line);
    }
    if (strcmp(key, "window") == 0) {
        bit = 2;
        duration_output = &automatic->window_seconds;
    } else if (strcmp(key, "first_duration") == 0) {
        bit = 4;
        duration_output = &automatic->first_duration_seconds;
    } else if (strcmp(key, "second_duration") == 0) {
        bit = 5;
        duration_output = &automatic->second_duration_seconds;
    } else if (strcmp(key, "third_duration") == 0) {
        bit = 6;
        duration_output = &automatic->third_duration_seconds;
    } else if (strcmp(key, "strike_retention") == 0) {
        bit = 7;
        duration_output = &automatic->strike_retention_seconds;
    } else {
        set_error(error, error_size, line, "unknown ban.auto key '%s'", key);
        return -1;
    }
    if (mark_field(&state->auto_ban_fields, bit, key, error, error_size, line) != 0) return -1;
    return parse_scaled_string(value, duration_output, true, error, error_size, line);
}

static int parse_nginx_key(
    const char *key,
    const char *value,
    struct parse_state *state,
    struct wardd_config *config,
    char *error,
    size_t error_size,
    size_t line
)
{
    if (strcmp(key, "enabled") == 0) {
        if (mark_field(&state->nginx_fields, 0, key, error, error_size, line) != 0) return -1;
        return parse_bool(value, &config->nginx.enabled, error, error_size, line);
    }
    if (strcmp(key, "generated_dir") == 0) {
        if (mark_field(&state->nginx_fields, 1, key, error, error_size, line) != 0) return -1;
        return parse_string(value, config->nginx.generated_dir, sizeof(config->nginx.generated_dir), error, error_size, line);
    }
    if (strcmp(key, "limit_event_log") == 0) {
        if (mark_field(&state->nginx_fields, 2, key, error, error_size, line) != 0) return -1;
        return parse_string(value, config->nginx.limit_event_log, sizeof(config->nginx.limit_event_log), error, error_size, line);
    }
    if (strcmp(key, "limit_zone") == 0) {
        if (mark_field(&state->nginx_fields, 3, key, error, error_size, line) != 0) return -1;
        return parse_string(value, config->nginx.limit_zone, sizeof(config->nginx.limit_zone), error, error_size, line);
    }
    set_error(error, error_size, line, "unknown nginx key '%s'", key);
    return -1;
}

static int parse_firewall_key(
    const char *key,
    const char *value,
    struct parse_state *state,
    struct wardd_config *config,
    char *error,
    size_t error_size,
    size_t line
)
{
    static const char *const ownership_names[] = {"external", "host", "none"};
    int parsed;

    if (strcmp(key, "ownership") == 0) {
        if (mark_field(&state->firewall_fields, 0, key, error, error_size, line) != 0 ||
            parse_enum_string(value, ownership_names, 3, &parsed, error, error_size, line) != 0) return -1;
        config->firewall.ownership = (enum wardd_firewall_ownership)parsed;
        return 0;
    }
    if (strcmp(key, "manage") == 0) {
        if (mark_field(&state->firewall_fields, 1, key, error, error_size, line) != 0) return -1;
        return parse_bool(value, &config->firewall.manage, error, error_size, line);
    }
    set_error(error, error_size, line, "unknown firewall key '%s'", key);
    return -1;
}

static int parse_key_value(
    char *line_text,
    struct parse_state *state,
    struct wardd_config *config,
    char *error,
    size_t error_size,
    size_t line
)
{
    char *equals = strchr(line_text, '=');
    char *key;
    char *value;

    if (equals == NULL) {
        set_error(error, error_size, line, "expected key = value");
        return -1;
    }
    *equals = '\0';
    key = trim_left(line_text);
    trim_right(key);
    value = trim_left(equals + 1);
    trim_right(value);

    if (*key == '\0' || *value == '\0') {
        set_error(error, error_size, line, "empty key or value");
        return -1;
    }

    switch (state->section) {
    case SECTION_ROOT:
        return parse_root_key(key, value, state, config, error, error_size, line);
    case SECTION_GEO:
        return parse_geo_key(key, value, state, config, error, error_size, line);
    case SECTION_XDP:
        return parse_xdp_key(key, value, state, config, error, error_size, line);
    case SECTION_XDP_ENDPOINT:
        return parse_endpoint_key(key, value, state, config, error, error_size, line);
    case SECTION_BAN:
        return parse_ban_key(key, value, state, config, error, error_size, line);
    case SECTION_BAN_AUTO:
        return parse_auto_ban_key(key, value, state, config, error, error_size, line);
    case SECTION_NGINX:
        return parse_nginx_key(key, value, state, config, error, error_size, line);
    case SECTION_FIREWALL:
        return parse_firewall_key(key, value, state, config, error, error_size, line);
    }
    set_error(error, error_size, line, "internal parser state error");
    return -1;
}

static bool is_https_url(const char *url)
{
    return strncmp(url, "https://", 8) == 0 && url[8] != '\0';
}

static bool valid_interface_name(const char *name)
{
    if (*name == '\0') {
        return false;
    }
    for (const unsigned char *cursor = (const unsigned char *)name; *cursor != '\0'; cursor++) {
        if (!(isalnum(*cursor) || *cursor == '_' || *cursor == '-' || *cursor == '.')) {
            return false;
        }
    }
    return true;
}

static bool valid_endpoint_address(const char *address)
{
    struct in_addr ipv4;
    struct in6_addr ipv6;

    return strcmp(address, "*") == 0 ||
        inet_pton(AF_INET, address, &ipv4) == 1 ||
        inet_pton(AF_INET6, address, &ipv6) == 1;
}

static int validate_config(
    const struct wardd_config *config,
    const struct parse_state *state,
    char *error,
    size_t error_size
)
{
    if ((state->root_fields & 1ULL) == 0 || config->version != 1) {
        set_error(error, error_size, 0, "configuration version must be 1");
        return -1;
    }
    if (state->geo_fields != 0xffULL) {
        set_error(error, error_size, 0, "the geo section is incomplete");
        return -1;
    }
    if (state->xdp_fields != 0x3fULL) {
        set_error(error, error_size, 0, "the xdp section is incomplete");
        return -1;
    }
    if ((state->ban_fields & 0x1ULL) == 0) {
        set_error(error, error_size, 0, "the ban section is incomplete");
        return -1;
    }
    if (state->auto_ban_fields != 0 && state->auto_ban_fields != 0xffULL) {
        set_error(error, error_size, 0, "the ban.auto section is incomplete");
        return -1;
    }
    if (state->nginx_fields != 0x7ULL && state->nginx_fields != 0xfULL) {
        set_error(error, error_size, 0, "the nginx section is incomplete");
        return -1;
    }
    if (state->firewall_fields != 0x3ULL) {
        set_error(error, error_size, 0, "the firewall section is incomplete");
        return -1;
    }
    if (strlen(config->geo.country) != 2 ||
        !isupper((unsigned char)config->geo.country[0]) ||
        !isupper((unsigned char)config->geo.country[1])) {
        set_error(error, error_size, 0, "geo.country must be a two-letter uppercase code");
        return -1;
    }
    if (strcmp(config->geo.provider, "mmdb") != 0) {
        set_error(error, error_size, 0, "only the mmdb geo provider is supported");
        return -1;
    }
    if (!is_https_url(config->geo.url) || !is_https_url(config->geo.checksum_url)) {
        set_error(error, error_size, 0, "geo URLs must use HTTPS");
        return -1;
    }
    if (config->geo.update_interval_seconds == 0 ||
        config->geo.max_age_seconds < config->geo.update_interval_seconds) {
        set_error(error, error_size, 0, "geo.max_age must be at least update_interval");
        return -1;
    }
    if (config->geo.max_download_bytes < 1024 || config->geo.max_download_bytes > 1024ULL * 1024ULL * 1024ULL) {
        set_error(error, error_size, 0, "geo.max_download_size must be between 1KiB and 1GiB");
        return -1;
    }
    if (!(config->geo.max_change_ratio > 0.0 && config->geo.max_change_ratio <= 1.0)) {
        set_error(error, error_size, 0, "geo.max_change_ratio must be greater than 0 and at most 1");
        return -1;
    }
    if (config->xdp.enabled) {
        if (!valid_interface_name(config->xdp.interface)) {
            set_error(error, error_size, 0, "xdp.interface is missing or invalid");
            return -1;
        }
        if (config->xdp.attach_mode == WARDD_ATTACH_OFF) {
            set_error(error, error_size, 0, "xdp.enabled cannot be true when attach_mode is off");
            return -1;
        }
        if (config->xdp.endpoint_count == 0) {
            set_error(error, error_size, 0, "at least one xdp.geo_endpoint is required when XDP is enabled");
            return -1;
        }
    }
    for (size_t index = 0; index < config->xdp.endpoint_count; index++) {
        const struct wardd_geo_endpoint *endpoint = &config->xdp.endpoints[index];
        if (state->endpoint_fields[index] != 0x7ULL) {
            set_error(error, error_size, 0, "each xdp.geo_endpoint requires address, protocol, and port");
            return -1;
        }
        if (!valid_endpoint_address(endpoint->address)) {
            set_error(error, error_size, 0, "xdp.geo_endpoint address is invalid");
            return -1;
        }
        if (strcmp(endpoint->protocol, "tcp") != 0) {
            set_error(error, error_size, 0, "only TCP geo endpoints are supported in configuration version 1");
            return -1;
        }
    }
    if (config->ban.protected_tcp_port_count == 0) {
        set_error(error, error_size, 0, "ban.protected_tcp_ports is required");
        return -1;
    }
    for (size_t index = 0; index < config->ban.exempt_count; ++index) {
        char normalized[WARDD_BAN_NETWORK_LEN];
        char normalization_error[128];
        if (wardd_ban_normalize(
                config->ban.exempt[index], normalized, normalization_error, sizeof(normalization_error)
            ) != 0 || strcmp(normalized, config->ban.exempt[index]) != 0) {
            set_error(error, error_size, 0, "ban.exempt entries must be canonical IP addresses or CIDRs");
            return -1;
        }
        for (size_t previous = 0; previous < index; ++previous) {
            if (strcmp(config->ban.exempt[previous], normalized) == 0) {
                set_error(error, error_size, 0, "ban.exempt contains a duplicate network");
                return -1;
            }
        }
    }
    if (config->ban.automatic.enabled &&
        (strcmp(config->ban.automatic.event_source, "nginx_limit_req") != 0 ||
         config->ban.automatic.window_seconds == 0 ||
         config->ban.automatic.rejections < 2 ||
         config->ban.automatic.rejections > 50000 ||
         config->ban.automatic.first_duration_seconds == 0 ||
         config->ban.automatic.second_duration_seconds == 0 ||
         config->ban.automatic.third_duration_seconds == 0 ||
         config->ban.automatic.strike_retention_seconds == 0)) {
        set_error(error, error_size, 0,
            "enabled automatic ban requires nginx_limit_req, threshold >= 2, durations, and strike retention");
        return -1;
    }
    if (config->ban.automatic.enabled && !config->nginx.enabled) {
        set_error(error, error_size, 0, "automatic ban requires enabled Nginx event integration");
        return -1;
    }
    if (config->nginx.enabled &&
        (config->nginx.generated_dir[0] != '/' || config->nginx.limit_event_log[0] != '/' ||
         !valid_interface_name(config->nginx.limit_zone))) {
        set_error(error, error_size, 0, "enabled nginx integration requires absolute paths");
        return -1;
    }
    if (config->firewall.manage) {
        set_error(error, error_size, 0, "firewall.manage must remain false in configuration version 1");
        return -1;
    }
    return 0;
}

void wardd_config_init(struct wardd_config *config)
{
    memset(config, 0, sizeof(*config));
    config->xdp.attach_mode = WARDD_ATTACH_AUTO;
    config->xdp.geo_action = WARDD_ACTION_OBSERVE;
    config->xdp.ban_action = WARDD_ACTION_OBSERVE;
    config->firewall.ownership = WARDD_FIREWALL_NONE;
    (void)snprintf(config->nginx.limit_zone, sizeof(config->nginx.limit_zone), "wardd_default");
}

int wardd_config_load(
    const char *path,
    struct wardd_config *config,
    char *error,
    size_t error_size
)
{
    FILE *file;
    char *line_buffer = NULL;
    size_t line_capacity = 0;
    size_t line_number = 0;
    struct parse_state state = {.section = SECTION_ROOT};
    int result = -1;

    if (path == NULL || config == NULL) {
        set_error(error, error_size, 0, "path and config are required");
        return -1;
    }

    wardd_config_init(config);
    file = fopen(path, "r");
    if (file == NULL) {
        set_error(error, error_size, 0, "cannot open %s: %s", path, strerror(errno));
        return -1;
    }

    while (getline(&line_buffer, &line_capacity, file) >= 0) {
        char *line_text;
        line_number++;
        strip_comment(line_buffer);
        trim_right(line_buffer);
        line_text = trim_left(line_buffer);
        if (*line_text == '\0') {
            continue;
        }
        if (*line_text == '[') {
            if (parse_section(line_text, &state, config, error, error_size, line_number) != 0) {
                goto done;
            }
        } else if (parse_key_value(line_text, &state, config, error, error_size, line_number) != 0) {
            goto done;
        }
    }
    if (ferror(file)) {
        set_error(error, error_size, line_number, "failed while reading configuration: %s", strerror(errno));
        goto done;
    }
    if (validate_config(config, &state, error, error_size) != 0) {
        goto done;
    }
    result = 0;

done:
    free(line_buffer);
    (void)fclose(file);
    return result;
}

const char *wardd_action_name(enum wardd_action action)
{
    return action == WARDD_ACTION_ENFORCE ? "enforce" : "observe";
}

const char *wardd_attach_mode_name(enum wardd_attach_mode mode)
{
    static const char *const names[] = {"auto", "native", "generic", "off"};
    return mode >= WARDD_ATTACH_AUTO && mode <= WARDD_ATTACH_OFF ? names[mode] : "unknown";
}

const char *wardd_firewall_ownership_name(enum wardd_firewall_ownership ownership)
{
    static const char *const names[] = {"external", "host", "none"};
    return ownership >= WARDD_FIREWALL_EXTERNAL && ownership <= WARDD_FIREWALL_NONE
        ? names[ownership]
        : "unknown";
}
