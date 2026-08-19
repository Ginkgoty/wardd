#ifndef WARDD_SNAPSHOT_H
#define WARDD_SNAPSHOT_H

#include "wardd/fetch.h"
#include "wardd/geo.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define WARDD_SNAPSHOT_ID_LEN 128

struct wardd_geo_diff {
    size_t old_prefixes;
    size_t new_prefixes;
    size_t added_prefixes;
    size_t removed_prefixes;
    double change_ratio;
};

struct wardd_snapshot_result {
    char id[WARDD_SNAPSHOT_ID_LEN];
    char source_sha256[WARDD_SHA256_HEX_LEN];
    struct wardd_geo_compile_result compile;
    struct wardd_geo_diff diff;
    bool existed;
    bool pending_review;
};

struct wardd_snapshot_status {
    char current[WARDD_SNAPSHOT_ID_LEN];
    char previous[WARDD_SNAPSHOT_ID_LEN];
    size_t snapshot_count;
    bool current_approved;
};

int wardd_geo_snapshot_create(
    const char *mmdb_path,
    const char country[3],
    const char *snapshot_root,
    uint64_t max_source_bytes,
    double max_change_ratio,
    struct wardd_snapshot_result *result,
    char *error,
    size_t error_size
);

int wardd_geo_snapshot_diff(
    const char *snapshot_root,
    const char *old_id,
    const char *new_id,
    struct wardd_geo_diff *diff,
    char *error,
    size_t error_size
);

int wardd_geo_snapshot_approve(
    const char *snapshot_root,
    const char *snapshot_id,
    char *error,
    size_t error_size
);

int wardd_geo_snapshot_activate(
    const char *snapshot_root,
    const char *generated_directory,
    const char *snapshot_id,
    const char *nginx_binary,
    char *error,
    size_t error_size
);

int wardd_geo_snapshot_rollback(
    const char *snapshot_root,
    const char *generated_directory,
    const char *nginx_binary,
    char *error,
    size_t error_size
);

int wardd_geo_snapshot_activate_live(
    const char *snapshot_root,
    const char *generated_directory,
    const char *snapshot_id,
    const char *nginx_binary,
    char *error,
    size_t error_size
);

int wardd_geo_snapshot_rollback_live(
    const char *snapshot_root,
    const char *generated_directory,
    const char *nginx_binary,
    char *error,
    size_t error_size
);

int wardd_geo_snapshot_status(
    const char *snapshot_root,
    struct wardd_snapshot_status *status,
    char *error,
    size_t error_size
);

#endif
