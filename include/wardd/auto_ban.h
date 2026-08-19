#ifndef WARDD_AUTO_BAN_H
#define WARDD_AUTO_BAN_H

#include "wardd/config.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define WARDD_AUTO_EVENT_FIELD_LEN 128

enum wardd_auto_ban_disposition {
    WARDD_AUTO_BAN_DISABLED = 0,
    WARDD_AUTO_BAN_NOT_REJECTED,
    WARDD_AUTO_BAN_UNCONFIRMED,
    WARDD_AUTO_BAN_STALE,
    WARDD_AUTO_BAN_NON_PUBLIC,
    WARDD_AUTO_BAN_EXEMPT,
    WARDD_AUTO_BAN_DUPLICATE,
    WARDD_AUTO_BAN_COUNTED,
    WARDD_AUTO_BAN_TRIGGERED,
};

struct wardd_auto_ban_event {
    char peer[WARDD_ADDRESS_LEN];
    char server[WARDD_AUTO_EVENT_FIELD_LEN];
    char zone[WARDD_AUTO_EVENT_FIELD_LEN];
    char request_id[WARDD_AUTO_EVENT_FIELD_LEN];
    uint64_t event_realtime_seconds;
    bool limiter_rejected;
    bool confirmed_peer;
};

struct wardd_auto_ban_decision {
    enum wardd_auto_ban_disposition disposition;
    char network[WARDD_ADDRESS_LEN];
    uint64_t window_count;
    uint64_t strike;
    uint64_t duration_seconds;
    uint64_t expires_realtime_seconds;
};

typedef int (*wardd_auto_ban_apply)(
    const struct wardd_auto_ban_event *event,
    const struct wardd_auto_ban_decision *decision,
    void *context,
    char *error,
    size_t error_size
);

const char *wardd_auto_ban_disposition_name(enum wardd_auto_ban_disposition disposition);

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
);

#endif
