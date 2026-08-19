#ifndef WARDD_RUNTIME_H
#define WARDD_RUNTIME_H

#include "wardd/auto_ban.h"
#include "wardd/config.h"

#include <stddef.h>

struct wardd_runtime_paths {
    const char *ban_state;
    const char *bpf_pin_root;
    const char *audit_log;
};

struct wardd_auto_apply_context {
    const struct wardd_config *config;
    const struct wardd_runtime_paths *paths;
    char outcome[32];
};

int wardd_runtime_apply_automatic_ban(
    const struct wardd_auto_ban_event *event,
    const struct wardd_auto_ban_decision *decision,
    void *context,
    char *error,
    size_t error_size
);

#endif
