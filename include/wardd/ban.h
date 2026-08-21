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

#define WARDD_BAN_RESERVED_SUMMARY_LEN 256

/*
 * Report the special-purpose address ranges a ban network overlaps: RFC 1918
 * private space, loopback, link-local, carrier NAT, multicast and the
 * documentation ranges. Banning those is permitted -- an operator may run wardd
 * where such addresses are genuinely hostile -- but it is almost always a
 * mistake worth interrupting for, since it can lock out management access.
 *
 * Returns the number of ranges the network overlaps, zero for ordinary public
 * space, and writes a bounded human-readable list into `summary`. This answers
 * a different question from the automatic-ban peer test in auto_ban.c, which
 * classifies one exact address rather than an operator-supplied network;
 * tests/test_auto_ban.c asserts the two agree on the ranges that matter.
 */
size_t wardd_ban_reserved_overlap(
    const char *network,
    char *summary,
    size_t summary_size
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
