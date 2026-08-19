#include "wardd/auto_ban.h"

#include "wardd/ban.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define AUTO_STATE_HEADER "wardd-auto-ban-state-v1"
#define AUTO_STATE_MAX_BYTES (16U * 1024U * 1024U)
#define AUTO_STATE_MAX_RECORDS 65536U
#define AUTO_STATE_MAX_EVENTS 100000U
#define AUTO_PATH_LEN 1024

struct rejection_event {
    uint64_t time;
    char request_id[WARDD_AUTO_EVENT_FIELD_LEN];
};

struct auto_record {
    char network[WARDD_ADDRESS_LEN];
    uint64_t strikes;
    uint64_t last_strike;
    struct rejection_event *events;
    size_t event_count;
    size_t event_capacity;
};

struct auto_records {
    struct auto_record *items;
    size_t count;
    size_t capacity;
    size_t total_events;
};

static void set_error(char *error, size_t error_size, const char *format, ...)
{
    va_list arguments;

    if (error == NULL || error_size == 0) return;
    va_start(arguments, format);
    (void)vsnprintf(error, error_size, format, arguments);
    va_end(arguments);
}

const char *wardd_auto_ban_disposition_name(enum wardd_auto_ban_disposition disposition)
{
    static const char *const names[] = {
        "disabled", "not_rejected", "unconfirmed", "stale", "non_public",
        "exempt", "duplicate", "counted", "triggered",
    };
    return disposition <= WARDD_AUTO_BAN_TRIGGERED ? names[disposition] : "unknown";
}

static bool safe_event_field(const char *text)
{
    size_t length;

    if (text == NULL || (length = strlen(text)) == 0 || length >= WARDD_AUTO_EVENT_FIELD_LEN) return false;
    for (const unsigned char *cursor = (const unsigned char *)text; *cursor != '\0'; ++cursor) {
        if (!( (*cursor >= 'a' && *cursor <= 'z') || (*cursor >= 'A' && *cursor <= 'Z') ||
               (*cursor >= '0' && *cursor <= '9') || *cursor == '.' || *cursor == '_' ||
               *cursor == '-' || *cursor == ':' )) return false;
    }
    return true;
}

static bool public_ipv4(const unsigned char address[4])
{
    if (address[0] == 0 || address[0] == 10 || address[0] == 127 || address[0] >= 224) return false;
    if (address[0] == 100 && (address[1] & 0xc0U) == 0x40U) return false;
    if (address[0] == 169 && address[1] == 254) return false;
    if (address[0] == 172 && address[1] >= 16 && address[1] <= 31) return false;
    if (address[0] == 192 && address[1] == 168) return false;
    if (address[0] == 192 && address[1] == 0 && (address[2] == 0 || address[2] == 2)) return false;
    if (address[0] == 198 && (address[1] == 18 || address[1] == 19)) return false;
    if (address[0] == 198 && address[1] == 51 && address[2] == 100) return false;
    if (address[0] == 203 && address[1] == 0 && address[2] == 113) return false;
    return true;
}

static bool public_ipv6(const unsigned char address[16])
{
    if ((address[0] & 0xe0U) != 0x20U) return false;
    if (address[0] == 0x20 && address[1] == 0x01 && address[2] == 0x0d && address[3] == 0xb8) return false;
    return true;
}

static bool prefix_matches(const unsigned char *address, const unsigned char *network, unsigned int prefix)
{
    const size_t whole = prefix / 8U;
    const unsigned int remaining = prefix % 8U;

    if (whole != 0 && memcmp(address, network, whole) != 0) return false;
    if (remaining == 0) return true;
    const unsigned char mask = (unsigned char)(0xffU << (8U - remaining));
    return (address[whole] & mask) == (network[whole] & mask);
}

static bool address_is_exempt(const struct wardd_ban_config *config, int family, const unsigned char *address)
{
    for (size_t index = 0; index < config->exempt_count; ++index) {
        char copy[WARDD_ADDRESS_LEN];
        char *slash;
        char *end;
        unsigned long prefix;
        unsigned char network[16] = {0};

        (void)snprintf(copy, sizeof(copy), "%s", config->exempt[index]);
        slash = strchr(copy, '/');
        if (slash != NULL) *slash++ = '\0';
        if (inet_pton(family, copy, network) != 1) continue;
        prefix = family == AF_INET ? 32U : 128U;
        if (slash != NULL) {
            errno = 0;
            prefix = strtoul(slash, &end, 10);
            if (errno != 0 || *end != '\0') continue;
        }
        if (prefix_matches(address, network, (unsigned int)prefix)) return true;
    }
    return false;
}

static int classify_peer(
    const struct wardd_ban_config *config,
    const char *peer,
    char normalized[WARDD_ADDRESS_LEN],
    bool *public,
    bool *exempt,
    char *error,
    size_t error_size
)
{
    unsigned char address[16] = {0};
    int family;

    if (peer == NULL || strchr(peer, '/') != NULL ||
        wardd_ban_normalize(peer, normalized, error, error_size) != 0) {
        set_error(error, error_size, "automatic ban peer must be one exact IP address");
        return -1;
    }
    if (inet_pton(AF_INET, normalized, address) == 1) family = AF_INET;
    else if (inet_pton(AF_INET6, normalized, address) == 1) family = AF_INET6;
    else {
        set_error(error, error_size, "automatic ban peer is invalid");
        return -1;
    }
    *public = family == AF_INET ? public_ipv4(address) : public_ipv6(address);
    *exempt = address_is_exempt(config, family, address);
    return 0;
}

static int ensure_parent(const char *path, char parent[AUTO_PATH_LEN], char *error, size_t error_size)
{
    char *slash;
    struct stat status;

    if (path == NULL || path[0] != '/' || strlen(path) >= AUTO_PATH_LEN) {
        set_error(error, error_size, "automatic ban state path must be a bounded absolute path");
        return -1;
    }
    (void)snprintf(parent, AUTO_PATH_LEN, "%s", path);
    slash = strrchr(parent, '/');
    if (slash == parent) slash[1] = '\0';
    else *slash = '\0';
    for (char *cursor = parent + 1; ; ++cursor) {
        if (*cursor != '/' && *cursor != '\0') continue;
        const char saved = *cursor;
        *cursor = '\0';
        if (mkdir(parent, 0750) != 0 && errno != EEXIST) {
            set_error(error, error_size, "cannot create %s: %s", parent, strerror(errno));
            return -1;
        }
        if (lstat(parent, &status) != 0 || !S_ISDIR(status.st_mode)) {
            set_error(error, error_size, "%s is not a real directory", parent);
            return -1;
        }
        *cursor = saved;
        if (saved == '\0') break;
    }
    return 0;
}

static int lock_state(const char *path, char parent[AUTO_PATH_LEN], char *error, size_t error_size)
{
    char lock_path[AUTO_PATH_LEN];
    struct stat status;
    int lock;

    if (ensure_parent(path, parent, error, error_size) != 0 ||
        snprintf(lock_path, sizeof(lock_path), "%s.lock", path) >= (int)sizeof(lock_path)) {
        if (error != NULL && error[0] == '\0') set_error(error, error_size, "automatic ban lock path is too long");
        return -1;
    }
    lock = open(lock_path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0640);
    if (lock < 0 || fstat(lock, &status) != 0 || !S_ISREG(status.st_mode) || flock(lock, LOCK_EX) != 0) {
        const int saved_errno = errno;
        if (lock >= 0) (void)close(lock);
        set_error(error, error_size, "cannot safely lock automatic ban state: %s", strerror(saved_errno));
        return -1;
    }
    return lock;
}

static void free_records(struct auto_records *records)
{
    for (size_t index = 0; index < records->count; ++index) free(records->items[index].events);
    free(records->items);
    memset(records, 0, sizeof(*records));
}

static int reserve_record(struct auto_records *records, char *error, size_t error_size)
{
    if (records->count == records->capacity) {
        size_t capacity = records->capacity == 0 ? 16U : records->capacity * 2U;
        struct auto_record *items;
        if (capacity > AUTO_STATE_MAX_RECORDS) capacity = AUTO_STATE_MAX_RECORDS;
        if (records->count == capacity) {
            set_error(error, error_size, "automatic ban state has too many addresses");
            return -1;
        }
        items = realloc(records->items, capacity * sizeof(*items));
        if (items == NULL) {
            set_error(error, error_size, "cannot allocate automatic ban state");
            return -1;
        }
        records->items = items;
        records->capacity = capacity;
    }
    memset(&records->items[records->count], 0, sizeof(records->items[records->count]));
    return 0;
}

static int append_event(
    struct auto_records *records,
    struct auto_record *record,
    uint64_t time,
    const char *request_id,
    char *error,
    size_t error_size
)
{
    if (records->total_events >= AUTO_STATE_MAX_EVENTS) {
        set_error(error, error_size, "automatic ban state has too many events");
        return -1;
    }
    if (record->event_count == record->event_capacity) {
        const size_t capacity = record->event_capacity == 0 ? 8U : record->event_capacity * 2U;
        struct rejection_event *events = realloc(record->events, capacity * sizeof(*events));
        if (events == NULL) {
            set_error(error, error_size, "cannot allocate automatic ban events");
            return -1;
        }
        record->events = events;
        record->event_capacity = capacity;
    }
    record->events[record->event_count].time = time;
    (void)snprintf(record->events[record->event_count].request_id, WARDD_AUTO_EVENT_FIELD_LEN, "%s", request_id);
    record->event_count++;
    records->total_events++;
    return 0;
}

static int parse_u64(const char *text, uint64_t *value)
{
    char *end;
    unsigned long long parsed;
    errno = 0;
    parsed = strtoull(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0') return -1;
    *value = (uint64_t)parsed;
    return 0;
}

static int load_state(const char *path, struct auto_records *records, char *error, size_t error_size)
{
    char *line = NULL;
    size_t line_capacity = 0;
    struct stat status;
    int descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    FILE *file;
    size_t line_number = 0;

    if (descriptor < 0) {
        if (errno == ENOENT) return 0;
        set_error(error, error_size, "cannot open automatic ban state: %s", strerror(errno));
        return -1;
    }
    file = fdopen(descriptor, "r");
    if (file == NULL) {
        const int saved_errno = errno;
        (void)close(descriptor);
        set_error(error, error_size, "cannot read automatic ban state: %s", strerror(saved_errno));
        return -1;
    }
    if (fstat(fileno(file), &status) != 0 || !S_ISREG(status.st_mode) || status.st_size < 0 ||
        (uint64_t)status.st_size > AUTO_STATE_MAX_BYTES) {
        set_error(error, error_size, "automatic ban state is not a bounded regular file");
        (void)fclose(file);
        return -1;
    }
    for (;;) {
        const ssize_t bytes = getline(&line, &line_capacity, file);
        char *network;
        char *strikes;
        char *last;
        char *events;
        size_t length;

        if (bytes < 0) break;
        if ((uint64_t)bytes > AUTO_STATE_MAX_BYTES) {
            set_error(error, error_size, "automatic ban state line is too large");
            goto failed;
        }
        length = (size_t)bytes;

        line_number++;
        if (length == 0 || line[length - 1] != '\n') {
            set_error(error, error_size, "automatic ban state line %zu is incomplete", line_number);
            goto failed;
        }
        line[--length] = '\0';
        if (line_number == 1) {
            if (strcmp(line, AUTO_STATE_HEADER) != 0) {
                set_error(error, error_size, "unsupported automatic ban state header");
                goto failed;
            }
            continue;
        }
        network = line;
        strikes = strchr(network, '\t');
        if (strikes != NULL) *strikes++ = '\0';
        last = strikes == NULL ? NULL : strchr(strikes, '\t');
        if (last != NULL) *last++ = '\0';
        events = last == NULL ? NULL : strchr(last, '\t');
        if (events != NULL) *events++ = '\0';
        char normalized[WARDD_ADDRESS_LEN];
        if (strikes == NULL || last == NULL || events == NULL || strchr(events, '\t') != NULL ||
            strchr(network, '/') != NULL ||
            wardd_ban_normalize(network, normalized, error, error_size) != 0 || strcmp(network, normalized) != 0) {
            set_error(error, error_size, "invalid network on automatic ban state line %zu", line_number);
            goto failed;
        }
        if (reserve_record(records, error, error_size) != 0) goto failed;
        for (size_t previous = 0; previous < records->count; ++previous) {
            if (strcmp(records->items[previous].network, network) == 0) {
                set_error(error, error_size, "duplicate network on automatic ban state line %zu", line_number);
                goto failed;
            }
        }
        struct auto_record *record = &records->items[records->count++];
        if (parse_u64(strikes, &record->strikes) != 0 || parse_u64(last, &record->last_strike) != 0) {
            set_error(error, error_size, "invalid strike state on line %zu", line_number);
            goto failed;
        }
        if (record->strikes > 3 || (record->strikes == 0) != (record->last_strike == 0)) {
            set_error(error, error_size, "inconsistent strike state on line %zu", line_number);
            goto failed;
        }
        (void)snprintf(record->network, sizeof(record->network), "%s", network);
        if (strcmp(events, "-") != 0) {
            char *token = events;
            for (;;) {
                char *comma = strchr(token, ',');
                char *colon;
                uint64_t event_time;
                if (comma != NULL) *comma = '\0';
                colon = strchr(token, ':');
                if (colon == NULL) {
                    set_error(error, error_size, "invalid event state on line %zu", line_number);
                    goto failed;
                }
                *colon++ = '\0';
                if (parse_u64(token, &event_time) != 0 || !safe_event_field(colon) ||
                    append_event(records, record, event_time, colon, error, error_size) != 0) goto failed;
                for (size_t previous = 0; previous + 1 < record->event_count; ++previous) {
                    if (strcmp(record->events[previous].request_id, colon) == 0) {
                        set_error(error, error_size, "duplicate request ID on state line %zu", line_number);
                        goto failed;
                    }
                }
                if (comma == NULL) break;
                token = comma + 1;
            }
        }
    }
    if (ferror(file) || line_number == 0) {
        set_error(error, error_size, "cannot read complete automatic ban state");
        goto failed;
    }
    if (fclose(file) != 0) {
        free(line);
        set_error(error, error_size, "cannot close automatic ban state: %s", strerror(errno));
        return -1;
    }
    free(line);
    return 0;

failed:
    (void)fclose(file);
    free(line);
    return -1;
}

static int save_state(
    const char *path,
    const char *parent,
    const struct auto_records *records,
    char *error,
    size_t error_size
)
{
    char temporary[AUTO_PATH_LEN];
    struct stat status;
    FILE *file;
    int directory;

    errno = 0;
    const int inspect_status = lstat(path, &status);
    if (inspect_status == 0 && !S_ISREG(status.st_mode)) {
        set_error(error, error_size, "refusing to replace non-regular automatic ban state");
        return -1;
    } else if (inspect_status != 0 && errno != ENOENT) {
        set_error(error, error_size, "cannot inspect automatic ban state: %s", strerror(errno));
        return -1;
    }
    if (snprintf(temporary, sizeof(temporary), "%s.tmp.%ld", path, (long)getpid()) >= (int)sizeof(temporary)) {
        set_error(error, error_size, "temporary automatic ban path is too long");
        return -1;
    }
    file = fopen(temporary, "wxe");
    if (file == NULL) {
        set_error(error, error_size, "cannot create automatic ban state: %s", strerror(errno));
        return -1;
    }
    if (fchmod(fileno(file), 0640) != 0 || fprintf(file, "%s\n", AUTO_STATE_HEADER) < 0) goto write_failed;
    for (size_t index = 0; index < records->count; ++index) {
        const struct auto_record *record = &records->items[index];
        if (fprintf(file, "%s\t%llu\t%llu\t", record->network,
                (unsigned long long)record->strikes, (unsigned long long)record->last_strike) < 0) goto write_failed;
        if (record->event_count == 0) {
            if (fputc('-', file) == EOF) goto write_failed;
        } else {
            for (size_t event = 0; event < record->event_count; ++event) {
                if (fprintf(file, "%s%llu:%s", event == 0 ? "" : ",",
                        (unsigned long long)record->events[event].time,
                        record->events[event].request_id) < 0) goto write_failed;
            }
        }
        if (fputc('\n', file) == EOF) goto write_failed;
    }
    if (fflush(file) != 0 || fsync(fileno(file)) != 0) goto write_failed;
    if (fclose(file) != 0) {
        file = NULL;
        goto close_failed;
    }
    file = NULL;
    if (rename(temporary, path) != 0) {
        set_error(error, error_size, "cannot activate automatic ban state: %s", strerror(errno));
        (void)unlink(temporary);
        return -1;
    }
    directory = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory < 0 || fsync(directory) != 0) {
        set_error(error, error_size, "cannot flush automatic ban state directory: %s", strerror(errno));
        if (directory >= 0) (void)close(directory);
        return -1;
    }
    (void)close(directory);
    return 0;

write_failed:
    set_error(error, error_size, "cannot write automatic ban state: %s", strerror(errno));
    (void)fclose(file);
    (void)unlink(temporary);
    return -1;
close_failed:
    set_error(error, error_size, "cannot close automatic ban state: %s", strerror(errno));
    (void)unlink(temporary);
    return -1;
}

static struct auto_record *find_record(struct auto_records *records, const char *network)
{
    for (size_t index = 0; index < records->count; ++index) {
        if (strcmp(records->items[index].network, network) == 0) return &records->items[index];
    }
    return NULL;
}

static void prune_records(
    struct auto_records *records,
    const struct wardd_auto_ban_config *config,
    uint64_t now
)
{
    size_t write_record = 0;
    records->total_events = 0;
    for (size_t index = 0; index < records->count; ++index) {
        struct auto_record *record = &records->items[index];
        size_t write_event = 0;
        for (size_t event = 0; event < record->event_count; ++event) {
            if (record->events[event].time <= now && now - record->events[event].time < config->window_seconds) {
                record->events[write_event++] = record->events[event];
            }
        }
        record->event_count = write_event;
        records->total_events += write_event;
        if (record->last_strike != 0 && now >= record->last_strike &&
            now - record->last_strike >= config->strike_retention_seconds) {
            record->strikes = 0;
            record->last_strike = 0;
        }
        if (record->event_count == 0 && record->strikes == 0) {
            free(record->events);
            record->events = NULL;
            continue;
        }
        if (write_record != index) records->items[write_record] = records->items[index];
        write_record++;
    }
    records->count = write_record;
}

int wardd_auto_ban_process(
    const struct wardd_ban_config *config,
    const char *state_path,
    const struct wardd_auto_ban_event *event,
    uint64_t now_realtime_seconds,
    wardd_auto_ban_apply apply,
    void *apply_context,
    struct wardd_auto_ban_decision *decision,
    char *error,
    size_t error_size
)
{
    struct auto_records records = {0};
    struct auto_record *record;
    char parent[AUTO_PATH_LEN];
    bool public = false;
    bool exempt = false;
    int lock = -1;
    int result = -1;

    if (error != NULL && error_size > 0) error[0] = '\0';
    if (config == NULL || event == NULL || decision == NULL) {
        set_error(error, error_size, "automatic ban configuration, event, and decision are required");
        return -1;
    }
    memset(decision, 0, sizeof(*decision));
    if (!config->automatic.enabled) {
        decision->disposition = WARDD_AUTO_BAN_DISABLED;
        return 0;
    }
    if (strcmp(config->automatic.event_source, "nginx_limit_req") != 0 ||
        config->automatic.window_seconds == 0 || config->automatic.rejections < 2 ||
        config->automatic.rejections > 50000 || config->automatic.first_duration_seconds == 0 ||
        config->automatic.second_duration_seconds == 0 || config->automatic.third_duration_seconds == 0 ||
        config->automatic.strike_retention_seconds == 0) {
        set_error(error, error_size, "automatic ban configuration is incomplete or unsafe");
        return -1;
    }
    if (!event->limiter_rejected) {
        decision->disposition = WARDD_AUTO_BAN_NOT_REJECTED;
        return 0;
    }
    if (!event->confirmed_peer) {
        decision->disposition = WARDD_AUTO_BAN_UNCONFIRMED;
        return 0;
    }
    if (!safe_event_field(event->server) || !safe_event_field(event->zone) ||
        !safe_event_field(event->request_id)) {
        set_error(error, error_size, "automatic ban event fields are missing or unsafe");
        return -1;
    }
    if ((event->event_realtime_seconds > now_realtime_seconds &&
         event->event_realtime_seconds - now_realtime_seconds > 5U) ||
        (event->event_realtime_seconds <= now_realtime_seconds &&
         now_realtime_seconds - event->event_realtime_seconds >= config->automatic.window_seconds)) {
        decision->disposition = WARDD_AUTO_BAN_STALE;
        return 0;
    }
    if (classify_peer(config, event->peer, decision->network, &public, &exempt, error, error_size) != 0) return -1;
    if (!public) {
        decision->disposition = WARDD_AUTO_BAN_NON_PUBLIC;
        return 0;
    }
    if (exempt) {
        decision->disposition = WARDD_AUTO_BAN_EXEMPT;
        return 0;
    }

    lock = lock_state(state_path, parent, error, error_size);
    if (lock < 0 || load_state(state_path, &records, error, error_size) != 0) goto done;
    prune_records(&records, &config->automatic, now_realtime_seconds);
    record = find_record(&records, decision->network);
    if (record == NULL) {
        if (reserve_record(&records, error, error_size) != 0) goto done;
        record = &records.items[records.count++];
        (void)snprintf(record->network, sizeof(record->network), "%s", decision->network);
    }
    for (size_t index = 0; index < record->event_count; ++index) {
        if (strcmp(record->events[index].request_id, event->request_id) == 0) {
            decision->disposition = WARDD_AUTO_BAN_DUPLICATE;
            decision->window_count = record->event_count;
            result = save_state(state_path, parent, &records, error, error_size);
            goto done;
        }
    }
    if (append_event(&records, record, event->event_realtime_seconds, event->request_id, error, error_size) != 0) {
        goto done;
    }
    decision->window_count = record->event_count;
    if (record->event_count < config->automatic.rejections) {
        decision->disposition = WARDD_AUTO_BAN_COUNTED;
        result = save_state(state_path, parent, &records, error, error_size);
        goto done;
    }

    if (record->last_strike == 0 || now_realtime_seconds < record->last_strike ||
        now_realtime_seconds - record->last_strike >= config->automatic.strike_retention_seconds) {
        record->strikes = 1;
    } else if (record->strikes < 3) {
        record->strikes++;
    }
    record->last_strike = now_realtime_seconds;
    records.total_events -= record->event_count;
    record->event_count = 0;
    decision->disposition = WARDD_AUTO_BAN_TRIGGERED;
    decision->strike = record->strikes;
    decision->duration_seconds = record->strikes == 1 ? config->automatic.first_duration_seconds :
        record->strikes == 2 ? config->automatic.second_duration_seconds : config->automatic.third_duration_seconds;
    if (now_realtime_seconds > UINT64_MAX - decision->duration_seconds) {
        set_error(error, error_size, "automatic ban expiry overflows realtime");
        goto done;
    }
    decision->expires_realtime_seconds = now_realtime_seconds + decision->duration_seconds;
    if (apply == NULL || apply(event, decision, apply_context, error, error_size) != 0) goto done;
    result = save_state(state_path, parent, &records, error, error_size);

done:
    free_records(&records);
    if (lock >= 0) {
        (void)flock(lock, LOCK_UN);
        (void)close(lock);
    }
    return result;
}
