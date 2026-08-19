#ifndef WARDD_AUDIT_H
#define WARDD_AUDIT_H

#include "wardd/auto_ban.h"

#include <stddef.h>

int wardd_audit_auto_ban(
    const char *path,
    const struct wardd_auto_ban_event *event,
    const struct wardd_auto_ban_decision *decision,
    const char *outcome,
    char *error,
    size_t error_size
);

#endif
