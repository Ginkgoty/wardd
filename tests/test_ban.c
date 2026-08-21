#include "wardd/ban.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int failures;

#define CHECK(condition, message) \
    do { \
        if (!(condition)) { \
            fprintf(stderr, "FAIL: %s (line %d)\n", (message), __LINE__); \
            failures++; \
        } \
    } while (0)

struct visit_context {
    size_t count;
    bool saw_permanent;
    bool saw_temporary;
};

static int visit_ban(const char *network, uint64_t expiry, void *opaque)
{
    struct visit_context *context = opaque;

    context->count++;
    if (strcmp(network, "203.0.113.8") == 0 && expiry == 0) context->saw_permanent = true;
    if (strcmp(network, "2001:db8:1200::/40") == 0 && expiry == 1060) context->saw_temporary = true;
    return 0;
}

int main(void)
{
    char directory[] = "/tmp/wardd-ban-test-XXXXXX";
    char path[512];
    char lock_path[1024];
    char normalized[WARDD_BAN_NETWORK_LEN];
    char error[512];
    struct visit_context context = {0};
    struct stat status;
    size_t active = 0;
    size_t pruned = 0;

    CHECK(mkdtemp(directory) != NULL, "create ban test directory");
    (void)snprintf(path, sizeof(path), "%s/state/bans.state", directory);
    (void)snprintf(lock_path, sizeof(lock_path), "%s.lock", path);
    CHECK(
        wardd_ban_store_upsert(path, "203.0.113.8", 0, 1000, normalized, error, sizeof(error)) == 0,
        error
    );
    CHECK(strcmp(normalized, "203.0.113.8") == 0, "normalize exact IP");
    CHECK(
        wardd_ban_store_upsert(
            path,
            "2001:db8:1234::1/40",
            60,
            1000,
            normalized,
            error,
            sizeof(error)
        ) == 0,
        error
    );
    CHECK(strcmp(normalized, "2001:db8:1200::/40") == 0, "mask and normalize CIDR");
    CHECK(stat(path, &status) == 0 && S_ISREG(status.st_mode) && (status.st_mode & 0777) == 0640,
        "durable state has protected permissions");
    CHECK(
        wardd_ban_store_visit(
            path, 1001, true, visit_ban, &context, &active, &pruned, error, sizeof(error)
        ) == 0,
        error
    );
    CHECK(active == 2 && pruned == 0 && context.count == 2, "visit active durable bans");
    CHECK(context.saw_permanent && context.saw_temporary, "preserve expiry semantics");

    context = (struct visit_context){0};
    CHECK(
        wardd_ban_store_visit(
            path, 1060, true, visit_ban, &context, &active, &pruned, error, sizeof(error)
        ) == 0,
        error
    );
    CHECK(active == 1 && pruned == 1 && context.saw_permanent, "prune expired ban atomically");
    CHECK(
        wardd_ban_store_remove(path, "203.0.113.8", normalized, error, sizeof(error)) == 0,
        error
    );
    CHECK(
        wardd_ban_store_visit(path, 2000, true, NULL, NULL, &active, &pruned, error, sizeof(error)) == 0 &&
            active == 0,
        "remove durable ban"
    );
    CHECK(wardd_ban_normalize("0.0.0.0/0", normalized, error, sizeof(error)) != 0, "reject IPv4 /0");
    CHECK(wardd_ban_normalize("::/0", normalized, error, sizeof(error)) != 0, "reject IPv6 /0");

    static const struct {
        const char *network;
        size_t expected;
        const char *fragment;
    } reserved_cases[] = {
        {"10.0.0.0/8", 1, "RFC 1918"},
        {"10.1.2.3", 1, "10.0.0.0/8"},
        {"172.16.0.0/12", 1, "RFC 1918"},
        {"172.20.3.0/24", 1, "172.16.0.0/12"},
        {"192.168.1.5", 1, "192.168.0.0/16"},
        {"127.0.0.1", 1, "loopback"},
        {"169.254.1.1", 1, "link-local"},
        {"100.64.0.0/10", 1, "carrier NAT"},
        /* A short prefix straddles several ranges; all of them are reported. */
        {"0.0.0.0/4", 2, "10.0.0.0/8"},
        {"fc00::/7", 1, "unique local"},
        {"fe80::1", 1, "link-local"},
        {"::1", 1, "loopback"},
        /* Ordinary public space must stay silent, or the warning becomes noise. */
        {"8.8.8.8", 0, NULL},
        {"1.1.1.0/24", 0, NULL},
        {"2001:4860:4860::8888", 0, NULL},
        {"2400:cb00::/32", 0, NULL},
    };
    for (size_t index = 0; index < sizeof(reserved_cases) / sizeof(reserved_cases[0]); ++index) {
        char summary[WARDD_BAN_RESERVED_SUMMARY_LEN];
        const size_t matched =
            wardd_ban_reserved_overlap(reserved_cases[index].network, summary, sizeof(summary));
        CHECK(matched == reserved_cases[index].expected, reserved_cases[index].network);
        if (reserved_cases[index].fragment != NULL) {
            CHECK(strstr(summary, reserved_cases[index].fragment) != NULL, reserved_cases[index].network);
        } else {
            CHECK(summary[0] == '\0', reserved_cases[index].network);
        }
    }
    /*
     * A buffer that holds the first label but not the second must yield that
     * label whole. Reporting half a range name would be worse than reporting
     * one fewer.
     */
    char narrow[sizeof("0.0.0.0/8 this network")];
    CHECK(wardd_ban_reserved_overlap("0.0.0.0/4", narrow, sizeof(narrow)) == 2 &&
        strcmp(narrow, "0.0.0.0/8 this network") == 0,
        "reserved summary truncates on a whole label");
    CHECK(wardd_ban_reserved_overlap("not-an-address", NULL, 0) == 0,
        "invalid input reports no reserved overlap");

    (void)unlink(path);
    (void)unlink(lock_path);
    (void)snprintf(path, sizeof(path), "%s/state", directory);
    (void)rmdir(path);
    (void)rmdir(directory);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
