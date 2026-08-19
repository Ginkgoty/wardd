#ifndef WARDD_XDP_H
#define WARDD_XDP_H

#include "wardd/config.h"
#include "wardd/bpf_shared.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct wardd_xdp_status {
    bool attached;
    bool legacy;
    bool wardd_attached;
    unsigned int interface_index;
    unsigned int program_count;
    uint32_t wardd_program_id;
    char mode[16];
};

struct wardd_xdp_attach_result {
    unsigned int interface_index;
    uint32_t program_id;
    size_t ipv4_prefixes;
    size_t ipv6_prefixes;
    char mode[16];
};

int wardd_xdp_available(void);

int wardd_xdp_get_status(
    const char *interface_name,
    struct wardd_xdp_status *status,
    char *error,
    size_t error_size
);

int wardd_xdp_attach_observe(
    const char *object_path,
    const char *pin_root,
    const char *snapshot_root,
    const struct wardd_config *config,
    struct wardd_xdp_attach_result *result,
    char *error,
    size_t error_size
);

int wardd_xdp_detach(
    const char *interface_name,
    const char *pin_root,
    char *error,
    size_t error_size
);

/*
 * Remove pins left behind when the process that created them died without
 * detaching. Attach refuses to reuse a pin root that is already populated, so
 * without this a crash leaves the data plane unmanageable until an operator
 * removes the pins by hand. Refuses to run while a wardd program is attached.
 */
int wardd_xdp_cleanup_pins(
    const char *interface_name,
    const char *pin_root,
    size_t *removed,
    char *error,
    size_t error_size
);

int wardd_xdp_set_action(
    const char *interface_name,
    const char *pin_root,
    bool geo_action,
    enum wardd_action action,
    char *error,
    size_t error_size
);

int wardd_xdp_sync_geo(
    const char *interface_name,
    const char *pin_root,
    const char *snapshot_root,
    size_t *ipv4_prefixes,
    size_t *ipv6_prefixes,
    char *error,
    size_t error_size
);

/*
 * Effective policy currently programmed into the pinned runtime_cfg map. This
 * is deliberately distinct from the configured action in wardd_xdp_config:
 * attachment always starts in observe mode, so the configured value is an
 * administrator's intent and this one is what the kernel is doing.
 */
struct wardd_xdp_actions {
    enum wardd_action geo_action;
    enum wardd_action ban_action;
};

int wardd_xdp_read_actions(
    const char *pin_root,
    struct wardd_xdp_actions *actions,
    char *error,
    size_t error_size
);

int wardd_xdp_read_metrics(
    const char *pin_root,
    uint64_t counters[WARDD_STAT_COUNT],
    char *error,
    size_t error_size
);

typedef int (*wardd_ban_visitor)(
    const char *network,
    uint64_t expires_monotonic_ns,
    void *context
);

int wardd_xdp_ban_add(
    const char *interface_name,
    const char *pin_root,
    const char *network,
    uint64_t duration_seconds,
    char *error,
    size_t error_size
);

int wardd_xdp_ban_remove(
    const char *interface_name,
    const char *pin_root,
    const char *network,
    char *error,
    size_t error_size
);

int wardd_xdp_ban_list(
    const char *pin_root,
    wardd_ban_visitor visitor,
    void *context,
    char *error,
    size_t error_size
);

#endif
