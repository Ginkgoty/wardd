#include "wardd/geo.h"

#include <stdio.h>
#include <string.h>

int wardd_geo_compile_mmdb(
    const char *mmdb_path,
    const char country[3],
    const char *ipv4_output_path,
    const char *ipv6_output_path,
    const char *nginx_output_path,
    struct wardd_geo_compile_result *result,
    char *error,
    size_t error_size
)
{
    (void)mmdb_path;
    (void)country;
    (void)ipv4_output_path;
    (void)ipv6_output_path;
    (void)nginx_output_path;
    if (result != NULL) {
        memset(result, 0, sizeof(*result));
    }
    if (error != NULL && error_size > 0) {
        (void)snprintf(error, error_size, "wardd was built without libmaxminddb support");
    }
    return -1;
}

int wardd_geo_mmdb_available(void)
{
    return 0;
}
