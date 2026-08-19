#ifndef WARDD_GEO_H
#define WARDD_GEO_H

#include <stddef.h>
#include <stdint.h>

#define WARDD_MMDB_TYPE_LEN 128

struct wardd_geo_compile_result {
    uint64_t build_epoch;
    uint64_t visited_nodes;
    size_t ipv4_prefixes;
    size_t ipv6_prefixes;
    char database_type[WARDD_MMDB_TYPE_LEN];
};

/*
 * Compile one MMDB country into sorted prefix files and an Nginx geo include.
 * Output paths must refer to files in a staging directory which is not active.
 */
int wardd_geo_compile_mmdb(
    const char *mmdb_path,
    const char country[3],
    const char *ipv4_output_path,
    const char *ipv6_output_path,
    const char *nginx_output_path,
    struct wardd_geo_compile_result *result,
    char *error,
    size_t error_size
);

int wardd_geo_mmdb_available(void);

#endif
