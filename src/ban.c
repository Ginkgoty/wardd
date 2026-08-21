#include "wardd/ban.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define BAN_STATE_HEADER "wardd-ban-state-v1"
#define BAN_STATE_MAX_BYTES (4U * 1024U * 1024U)
#define BAN_STATE_MAX_ENTRIES 65536U
#define BAN_PATH_LEN 1024

struct ban_record {
    char network[WARDD_BAN_NETWORK_LEN];
    uint64_t expires_realtime_seconds;
};

struct ban_records {
    struct ban_record *items;
    size_t count;
    size_t capacity;
};

static void set_error(char *error, size_t error_size, const char *format, ...)
{
    va_list arguments;

    if (error == NULL || error_size == 0) return;
    va_start(arguments, format);
    (void)vsnprintf(error, error_size, format, arguments);
    va_end(arguments);
}

static void mask_address(unsigned char *address, unsigned int prefix, size_t bytes)
{
    const size_t whole = prefix / 8U;
    const unsigned int remainder = prefix % 8U;

    if (whole < bytes && remainder != 0) {
        address[whole] &= (unsigned char)(0xffU << (8U - remainder));
    }
    const size_t start = whole + (remainder == 0 ? 0U : 1U);
    if (start < bytes) memset(address + start, 0, bytes - start);
}

/*
 * Special-purpose ranges, in the order they are reported. Sourced from the
 * IANA IPv4/IPv6 special-purpose address registries; only the ranges an
 * operator can plausibly type by mistake are listed, since the point is to
 * interrupt a mistake rather than to enumerate the registry.
 */
struct reserved_range {
    int family;
    const char *network;
    unsigned int prefix;
    const char *label;
};

static const struct reserved_range reserved_ranges[] = {
    {AF_INET, "0.0.0.0", 8, "0.0.0.0/8 this network"},
    {AF_INET, "10.0.0.0", 8, "10.0.0.0/8 private (RFC 1918)"},
    {AF_INET, "100.64.0.0", 10, "100.64.0.0/10 carrier NAT (RFC 6598)"},
    {AF_INET, "127.0.0.0", 8, "127.0.0.0/8 loopback"},
    {AF_INET, "169.254.0.0", 16, "169.254.0.0/16 link-local"},
    {AF_INET, "172.16.0.0", 12, "172.16.0.0/12 private (RFC 1918)"},
    {AF_INET, "192.0.0.0", 24, "192.0.0.0/24 IETF protocol assignments"},
    {AF_INET, "192.0.2.0", 24, "192.0.2.0/24 documentation"},
    {AF_INET, "192.168.0.0", 16, "192.168.0.0/16 private (RFC 1918)"},
    {AF_INET, "198.18.0.0", 15, "198.18.0.0/15 benchmarking"},
    {AF_INET, "198.51.100.0", 24, "198.51.100.0/24 documentation"},
    {AF_INET, "203.0.113.0", 24, "203.0.113.0/24 documentation"},
    {AF_INET, "224.0.0.0", 4, "224.0.0.0/4 multicast"},
    {AF_INET, "240.0.0.0", 4, "240.0.0.0/4 reserved"},
    {AF_INET6, "::", 128, "::/128 unspecified"},
    {AF_INET6, "::1", 128, "::1/128 loopback"},
    {AF_INET6, "::ffff:0:0", 96, "::ffff:0:0/96 IPv4-mapped"},
    {AF_INET6, "100::", 64, "100::/64 discard-only"},
    {AF_INET6, "2001:db8::", 32, "2001:db8::/32 documentation"},
    {AF_INET6, "fc00::", 7, "fc00::/7 unique local"},
    {AF_INET6, "fe80::", 10, "fe80::/10 link-local"},
    {AF_INET6, "ff00::", 8, "ff00::/8 multicast"},
};

static bool prefix_matches(
    const unsigned char *left,
    const unsigned char *right,
    unsigned int prefix
)
{
    const size_t whole = prefix / 8U;
    const unsigned int remaining = prefix % 8U;

    if (whole != 0 && memcmp(left, right, whole) != 0) return false;
    if (remaining == 0) return true;
    const unsigned char mask = (unsigned char)(0xffU << (8U - remaining));
    return (left[whole] & mask) == (right[whole] & mask);
}

size_t wardd_ban_reserved_overlap(const char *network, char *summary, size_t summary_size)
{
    char normalized[WARDD_BAN_NETWORK_LEN];
    char address_text[WARDD_BAN_NETWORK_LEN];
    unsigned char address[16] = {0};
    char *slash;
    char *end;
    unsigned long prefix;
    unsigned int maximum;
    size_t used = 0;
    size_t matches = 0;
    int family;

    if (summary != NULL && summary_size > 0) summary[0] = '\0';
    if (wardd_ban_normalize(network, normalized, NULL, 0) != 0) return 0;
    (void)snprintf(address_text, sizeof(address_text), "%s", normalized);
    slash = strchr(address_text, '/');
    if (slash != NULL) *slash++ = '\0';
    if (inet_pton(AF_INET, address_text, address) == 1) {
        family = AF_INET;
        maximum = 32;
    } else if (inet_pton(AF_INET6, address_text, address) == 1) {
        family = AF_INET6;
        maximum = 128;
    } else {
        return 0;
    }
    prefix = maximum;
    if (slash != NULL) {
        errno = 0;
        prefix = strtoul(slash, &end, 10);
        if (errno != 0 || *end != '\0' || prefix > maximum) return 0;
    }

    for (size_t index = 0; index < sizeof(reserved_ranges) / sizeof(reserved_ranges[0]); ++index) {
        const struct reserved_range *range = &reserved_ranges[index];
        unsigned char reserved[16] = {0};

        if (range->family != family) continue;
        if (inet_pton(range->family, range->network, reserved) != 1) continue;
        /*
         * Two networks overlap when they agree over the shorter of the two
         * prefixes: either one contains the other, or they are disjoint.
         */
        if (!prefix_matches(
                address, reserved, (unsigned int)prefix < range->prefix ? (unsigned int)prefix : range->prefix
            )) {
            continue;
        }
        matches++;
        if (summary == NULL || summary_size == 0) continue;
        const int written = snprintf(
            summary + used, summary_size - used, "%s%s", used == 0 ? "" : ", ", range->label
        );
        if (written < 0 || (size_t)written >= summary_size - used) {
            /* Keep the truncated list well formed rather than half a label. */
            summary[used] = '\0';
            summary_size = used + 1;
            continue;
        }
        used += (size_t)written;
    }
    return matches;
}

int wardd_ban_normalize(
    const char *input,
    char output[WARDD_BAN_NETWORK_LEN],
    char *error,
    size_t error_size
)
{
    unsigned char address[16] = {0};
    char copy[WARDD_BAN_NETWORK_LEN];
    char formatted[INET6_ADDRSTRLEN];
    char *slash;
    char *end;
    unsigned long prefix = 0;
    unsigned int maximum;
    int family;

    if (error != NULL && error_size > 0) error[0] = '\0';
    if (input == NULL || input[0] == '\0' || strlen(input) >= sizeof(copy)) {
        set_error(error, error_size, "IP or CIDR is missing or too long");
        return -1;
    }
    (void)snprintf(copy, sizeof(copy), "%s", input);
    slash = strchr(copy, '/');
    if (slash != NULL) {
        if (slash == copy || slash[1] == '\0' || strchr(slash + 1, '/') != NULL) {
            set_error(error, error_size, "invalid CIDR %s", input);
            return -1;
        }
        *slash = '\0';
        errno = 0;
        prefix = strtoul(slash + 1, &end, 10);
        if (errno != 0 || end == slash + 1 || *end != '\0' || prefix == 0) {
            set_error(error, error_size, "invalid or unsafe CIDR prefix in %s", input);
            return -1;
        }
    }
    if (inet_pton(AF_INET, copy, address) == 1) {
        family = AF_INET;
        maximum = 32;
    } else if (inet_pton(AF_INET6, copy, address) == 1) {
        family = AF_INET6;
        maximum = 128;
    } else {
        set_error(error, error_size, "invalid IP or CIDR %s", input);
        return -1;
    }
    if (slash != NULL && prefix > maximum) {
        set_error(error, error_size, "invalid prefix in %s", input);
        return -1;
    }
    if (slash != NULL) mask_address(address, (unsigned int)prefix, family == AF_INET ? 4U : 16U);
    if (inet_ntop(family, address, formatted, sizeof(formatted)) == NULL ||
        snprintf(output, WARDD_BAN_NETWORK_LEN, slash == NULL ? "%s" : "%s/%lu", formatted, prefix) >=
            WARDD_BAN_NETWORK_LEN) {
        set_error(error, error_size, "cannot normalize %s", input);
        return -1;
    }
    return 0;
}

static int ensure_parent_directory(const char *path, char parent[BAN_PATH_LEN], char *error, size_t error_size)
{
    char *slash;
    struct stat status;

    if (path == NULL || path[0] != '/' || strlen(path) >= BAN_PATH_LEN) {
        set_error(error, error_size, "ban state path must be a bounded absolute path");
        return -1;
    }
    (void)snprintf(parent, BAN_PATH_LEN, "%s", path);
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

static int lock_store(const char *path, char parent[BAN_PATH_LEN], char *error, size_t error_size)
{
    char lock_path[BAN_PATH_LEN];
    struct stat status;
    int lock;

    if (ensure_parent_directory(path, parent, error, error_size) != 0 ||
        snprintf(lock_path, sizeof(lock_path), "%s.lock", path) >= (int)sizeof(lock_path)) {
        if (error != NULL && error[0] == '\0') set_error(error, error_size, "ban lock path is too long");
        return -1;
    }
    lock = open(lock_path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0640);
    if (lock < 0 || fstat(lock, &status) != 0 || !S_ISREG(status.st_mode)) {
        const int saved_errno = errno;
        if (lock >= 0) (void)close(lock);
        set_error(error, error_size, "cannot safely open ban state lock: %s", strerror(saved_errno));
        return -1;
    }
    if (flock(lock, LOCK_EX) != 0) {
        const int saved_errno = errno;
        (void)close(lock);
        set_error(error, error_size, "cannot lock ban state: %s", strerror(saved_errno));
        return -1;
    }
    return lock;
}

static int reserve_record(struct ban_records *records, char *error, size_t error_size)
{
    size_t capacity;
    struct ban_record *items;

    if (records->count >= BAN_STATE_MAX_ENTRIES) {
        set_error(error, error_size, "ban state exceeds %u entries", BAN_STATE_MAX_ENTRIES);
        return -1;
    }
    if (records->count < records->capacity) return 0;
    capacity = records->capacity == 0 ? 16U : records->capacity * 2U;
    if (capacity > BAN_STATE_MAX_ENTRIES) capacity = BAN_STATE_MAX_ENTRIES;
    items = realloc(records->items, capacity * sizeof(*items));
    if (items == NULL) {
        set_error(error, error_size, "cannot allocate ban state");
        return -1;
    }
    records->items = items;
    records->capacity = capacity;
    return 0;
}

static int compare_records(const void *left, const void *right)
{
    const struct ban_record *a = left;
    const struct ban_record *b = right;
    return strcmp(a->network, b->network);
}

static int load_records(const char *path, struct ban_records *records, char *error, size_t error_size)
{
    struct stat status;
    char line[256];
    FILE *file;
    int descriptor;
    size_t line_number = 0;

    descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) {
        if (errno == ENOENT) return 0;
        set_error(error, error_size, "cannot open ban state: %s", strerror(errno));
        return -1;
    }
    file = fdopen(descriptor, "r");
    if (file == NULL) {
        const int saved_errno = errno;
        (void)close(descriptor);
        set_error(error, error_size, "cannot read ban state: %s", strerror(saved_errno));
        return -1;
    }
    if (fstat(fileno(file), &status) != 0 || !S_ISREG(status.st_mode) || status.st_size < 0 ||
        (uint64_t)status.st_size > BAN_STATE_MAX_BYTES) {
        set_error(error, error_size, "ban state is not a bounded regular file");
        (void)fclose(file);
        return -1;
    }
    while (fgets(line, sizeof(line), file) != NULL) {
        char normalized[WARDD_BAN_NETWORK_LEN];
        char *tab;
        char *end;
        unsigned long long expires;
        size_t length;

        line_number++;
        length = strlen(line);
        if (length == 0 || line[length - 1] != '\n') {
            set_error(error, error_size, "ban state line %zu is too long or incomplete", line_number);
            goto failed;
        }
        line[--length] = '\0';
        if (length > 0 && line[length - 1] == '\r') line[--length] = '\0';
        if (line_number == 1) {
            if (strcmp(line, BAN_STATE_HEADER) != 0) {
                set_error(error, error_size, "unsupported ban state header");
                goto failed;
            }
            continue;
        }
        tab = strchr(line, '\t');
        if (tab == NULL || tab == line || strchr(tab + 1, '\t') != NULL) {
            set_error(error, error_size, "invalid ban state line %zu", line_number);
            goto failed;
        }
        *tab = '\0';
        if (wardd_ban_normalize(line, normalized, error, error_size) != 0 || strcmp(line, normalized) != 0) {
            set_error(error, error_size, "non-canonical network on ban state line %zu", line_number);
            goto failed;
        }
        errno = 0;
        expires = strtoull(tab + 1, &end, 10);
        if (errno != 0 || end == tab + 1 || *end != '\0') {
            set_error(error, error_size, "invalid expiry on ban state line %zu", line_number);
            goto failed;
        }
        if (reserve_record(records, error, error_size) != 0) goto failed;
        (void)snprintf(records->items[records->count].network, WARDD_BAN_NETWORK_LEN, "%s", normalized);
        records->items[records->count].expires_realtime_seconds = (uint64_t)expires;
        records->count++;
    }
    if (ferror(file) || line_number == 0) {
        set_error(error, error_size, "cannot read complete ban state");
        goto failed;
    }
    if (fclose(file) != 0) {
        set_error(error, error_size, "cannot close ban state: %s", strerror(errno));
        return -1;
    }
    qsort(records->items, records->count, sizeof(*records->items), compare_records);
    for (size_t index = 1; index < records->count; ++index) {
        if (strcmp(records->items[index - 1].network, records->items[index].network) == 0) {
            set_error(error, error_size, "duplicate network in ban state");
            return -1;
        }
    }
    return 0;

failed:
    (void)fclose(file);
    return -1;
}

static int save_records(
    const char *path,
    const char *parent,
    struct ban_records *records,
    char *error,
    size_t error_size
)
{
    char temporary[BAN_PATH_LEN];
    struct stat status;
    FILE *file;
    int directory = -1;

    if (lstat(path, &status) == 0) {
        if (!S_ISREG(status.st_mode)) {
            set_error(error, error_size, "refusing to replace non-regular ban state");
            return -1;
        }
    } else if (errno != ENOENT) {
        set_error(error, error_size, "cannot inspect ban state: %s", strerror(errno));
        return -1;
    }
    if (snprintf(temporary, sizeof(temporary), "%s.tmp.%ld", path, (long)getpid()) >= (int)sizeof(temporary)) {
        set_error(error, error_size, "temporary ban state path is too long");
        return -1;
    }
    qsort(records->items, records->count, sizeof(*records->items), compare_records);
    file = fopen(temporary, "wxe");
    if (file == NULL) {
        set_error(error, error_size, "cannot create temporary ban state: %s", strerror(errno));
        return -1;
    }
    if (fchmod(fileno(file), 0640) != 0 || fprintf(file, "%s\n", BAN_STATE_HEADER) < 0) goto write_failed;
    for (size_t index = 0; index < records->count; ++index) {
        if (fprintf(
                file,
                "%s\t%llu\n",
                records->items[index].network,
                (unsigned long long)records->items[index].expires_realtime_seconds
            ) < 0) goto write_failed;
    }
    if (fflush(file) != 0 || fsync(fileno(file)) != 0) goto write_failed;
    if (fclose(file) != 0) {
        file = NULL;
        goto close_failed;
    }
    file = NULL;
    if (rename(temporary, path) != 0) {
        set_error(error, error_size, "cannot activate ban state: %s", strerror(errno));
        (void)unlink(temporary);
        return -1;
    }
    directory = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory < 0 || fsync(directory) != 0) {
        set_error(error, error_size, "cannot flush ban state directory: %s", strerror(errno));
        if (directory >= 0) (void)close(directory);
        return -1;
    }
    (void)close(directory);
    return 0;

write_failed:
    set_error(error, error_size, "cannot write ban state: %s", strerror(errno));
    (void)fclose(file);
    (void)unlink(temporary);
    return -1;
close_failed:
    set_error(error, error_size, "cannot flush ban state: %s", strerror(errno));
    (void)unlink(temporary);
    return -1;
}

static ssize_t find_record(const struct ban_records *records, const char *network)
{
    for (size_t index = 0; index < records->count; ++index) {
        if (strcmp(records->items[index].network, network) == 0) return (ssize_t)index;
    }
    return -1;
}

int wardd_ban_store_upsert(
    const char *path,
    const char *network,
    uint64_t duration_seconds,
    uint64_t now_realtime_seconds,
    char normalized[WARDD_BAN_NETWORK_LEN],
    char *error,
    size_t error_size
)
{
    struct ban_records records = {0};
    char parent[BAN_PATH_LEN];
    uint64_t expiry = 0;
    ssize_t found;
    int lock = -1;
    int result = -1;

    if (error != NULL && error_size > 0) error[0] = '\0';
    if (wardd_ban_normalize(network, normalized, error, error_size) != 0) return -1;
    if (duration_seconds != 0) {
        if (now_realtime_seconds > UINT64_MAX - duration_seconds) {
            set_error(error, error_size, "ban expiry overflows realtime representation");
            return -1;
        }
        expiry = now_realtime_seconds + duration_seconds;
    }
    lock = lock_store(path, parent, error, error_size);
    if (lock < 0 || load_records(path, &records, error, error_size) != 0) goto done;
    found = find_record(&records, normalized);
    if (found < 0) {
        if (reserve_record(&records, error, error_size) != 0) goto done;
        found = (ssize_t)records.count++;
        (void)snprintf(records.items[found].network, WARDD_BAN_NETWORK_LEN, "%s", normalized);
    }
    records.items[found].expires_realtime_seconds = expiry;
    result = save_records(path, parent, &records, error, error_size);

done:
    free(records.items);
    if (lock >= 0) {
        (void)flock(lock, LOCK_UN);
        (void)close(lock);
    }
    return result;
}

int wardd_ban_store_remove(
    const char *path,
    const char *network,
    char normalized[WARDD_BAN_NETWORK_LEN],
    char *error,
    size_t error_size
)
{
    struct ban_records records = {0};
    char parent[BAN_PATH_LEN];
    ssize_t found;
    int lock = -1;
    int result = -1;

    if (error != NULL && error_size > 0) error[0] = '\0';
    if (wardd_ban_normalize(network, normalized, error, error_size) != 0) return -1;
    lock = lock_store(path, parent, error, error_size);
    if (lock < 0 || load_records(path, &records, error, error_size) != 0) goto done;
    found = find_record(&records, normalized);
    if (found < 0) {
        set_error(error, error_size, "ban %s is not present in durable state", normalized);
        goto done;
    }
    records.items[found] = records.items[records.count - 1];
    records.count--;
    result = save_records(path, parent, &records, error, error_size);

done:
    free(records.items);
    if (lock >= 0) {
        (void)flock(lock, LOCK_UN);
        (void)close(lock);
    }
    return result;
}

int wardd_ban_store_visit(
    const char *path,
    uint64_t now_realtime_seconds,
    bool prune_expired,
    wardd_ban_store_visitor visitor,
    void *context,
    size_t *active_count,
    size_t *pruned_count,
    char *error,
    size_t error_size
)
{
    struct ban_records records = {0};
    char parent[BAN_PATH_LEN];
    size_t active = 0;
    size_t pruned = 0;
    int lock = -1;
    int result = -1;

    if (error != NULL && error_size > 0) error[0] = '\0';
    if (active_count != NULL) *active_count = 0;
    if (pruned_count != NULL) *pruned_count = 0;
    lock = lock_store(path, parent, error, error_size);
    if (lock < 0 || load_records(path, &records, error, error_size) != 0) goto done;
    const size_t original_count = records.count;
    size_t write_index = 0;
    for (size_t read_index = 0; read_index < original_count; ++read_index) {
        const bool expired = records.items[read_index].expires_realtime_seconds != 0 &&
            records.items[read_index].expires_realtime_seconds <= now_realtime_seconds;
        if (expired) {
            pruned++;
            if (!prune_expired) records.items[write_index++] = records.items[read_index];
            continue;
        }
        if (visitor != NULL && visitor(
                records.items[read_index].network,
                records.items[read_index].expires_realtime_seconds,
                context
            ) != 0) {
            set_error(error, error_size, "ban state visitor rejected %s", records.items[read_index].network);
            goto done;
        }
        records.items[write_index++] = records.items[read_index];
        active++;
    }
    records.count = write_index;
    if (prune_expired && pruned != 0 && save_records(path, parent, &records, error, error_size) != 0) goto done;
    if (active_count != NULL) *active_count = active;
    if (pruned_count != NULL) *pruned_count = pruned;
    result = 0;

done:
    free(records.items);
    if (lock >= 0) {
        (void)flock(lock, LOCK_UN);
        (void)close(lock);
    }
    return result;
}
