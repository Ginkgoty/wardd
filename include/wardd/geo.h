#ifndef WARDD_GEO_H
#define WARDD_GEO_H

#include "wardd/config.h"

#include <stddef.h>
#include <stdint.h>

#define WARDD_MMDB_TYPE_LEN 128

struct wardd_geo_compile_result {
    uint64_t build_epoch;
    uint64_t visited_nodes;
    size_t ipv4_prefixes;
    size_t ipv6_prefixes;
    /*
     * Bit N is set when the database contained at least one record for
     * countries->codes[N]. A requested country that contributes nothing is not an
     * error -- a regional database legitimately may not carry it -- but the
     * operator should be told rather than left with a silently smaller policy.
     */
    uint32_t matched_countries;
    char database_type[WARDD_MMDB_TYPE_LEN];
};

/*
 * Compile one or more MMDB countries into merged prefix files and an Nginx geo
 * include. The prefixes of every listed country are merged into one allow set;
 * the data plane evaluates membership, not which country matched.
 * Output paths must refer to files in a staging directory which is not active.
 */
int wardd_geo_compile_mmdb(
    const char *mmdb_path,
    const struct wardd_country_set *countries,
    const char *ipv4_output_path,
    const char *ipv6_output_path,
    const char *nginx_output_path,
    struct wardd_geo_compile_result *result,
    char *error,
    size_t error_size
);

int wardd_geo_mmdb_available(void);

#endif
