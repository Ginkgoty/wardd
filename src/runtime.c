#include "wardd/runtime.h"

#include "wardd/audit.h"
#include "wardd/ban.h"
#include "wardd/xdp.h"

#include <stdio.h>

int wardd_runtime_apply_automatic_ban(
    const struct wardd_auto_ban_event *event,
    const struct wardd_auto_ban_decision *decision,
    void *opaque,
    char *error,
    size_t error_size
)
{
    struct wardd_auto_apply_context *context = opaque;
    struct wardd_xdp_status status;
    char normalized[WARDD_BAN_NETWORK_LEN];
    char operation_error[1024];
    uint64_t issued;

    if (context == NULL || context->config == NULL || context->paths == NULL ||
        decision->expires_realtime_seconds < decision->duration_seconds) {
        if (error != NULL && error_size > 0) {
            (void)snprintf(error, error_size, "automatic ban runtime context is invalid");
        }
        return -1;
    }
    issued = decision->expires_realtime_seconds - decision->duration_seconds;
    if (wardd_ban_store_upsert(
            context->paths->ban_state,
            decision->network,
            decision->duration_seconds,
            issued,
            normalized,
            operation_error,
            sizeof(operation_error)
        ) != 0) {
        (void)snprintf(context->outcome, sizeof(context->outcome), "durable_failed");
        (void)wardd_audit_auto_ban(
            context->paths->audit_log, event, decision, context->outcome, NULL, 0
        );
        if (error != NULL && error_size > 0) {
            (void)snprintf(error, error_size, "cannot persist automatic ban: %s", operation_error);
        }
        return -1;
    }
    (void)snprintf(context->outcome, sizeof(context->outcome), "durable_pending");
    if (wardd_xdp_get_status(
            context->config->xdp.interface, &status, operation_error, sizeof(operation_error)
        ) == 0 && status.wardd_attached &&
        wardd_xdp_ban_add(
            context->config->xdp.interface,
            context->paths->bpf_pin_root,
            normalized,
            decision->duration_seconds,
            operation_error,
            sizeof(operation_error)
        ) == 0) {
        (void)snprintf(context->outcome, sizeof(context->outcome), "durable_live");
    }
    return wardd_audit_auto_ban(
        context->paths->audit_log,
        event,
        decision,
        context->outcome,
        error,
        error_size
    );
}
