#ifndef WARDD_BAN_H
#define WARDD_BAN_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define WARDD_BAN_NETWORK_LEN 64

typedef int (*wardd_ban_store_visitor)(
    const char *network,
    uint64_t expires_realtime_seconds,
    void *context
);

int wardd_ban_normalize(
    const char *input,
    char output[WARDD_BAN_NETWORK_LEN],
    char *error,
    size_t error_size
);

int wardd_ban_store_upsert(
    const char *path,
    const char *network,
    uint64_t duration_seconds,
    uint64_t now_realtime_seconds,
    char normalized[WARDD_BAN_NETWORK_LEN],
    char *error,
    size_t error_size
);

int wardd_ban_store_remove(
    const char *path,
    const char *network,
    char normalized[WARDD_BAN_NETWORK_LEN],
    char *error,
    size_t error_size
);

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
);

#endif
