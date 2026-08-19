#include "wardd/geo.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int failures;

#define CHECK(condition, message) \
    do { \
        if (!(condition)) { \
            fprintf(stderr, "FAIL: %s (line %d)\n", (message), __LINE__); \
            failures++; \
        } \
    } while (0)

static int count_lines(const char *path)
{
    FILE *file = fopen(path, "r");
    int lines = 0;
    int character;

    if (file == NULL) return -1;
    while ((character = fgetc(file)) != EOF) {
        if (character == '\n') lines++;
    }
    (void)fclose(file);
    return lines;
}

static int file_contains(const char *path, const char *needle)
{
    FILE *file = fopen(path, "r");
    char line[512];

    if (file == NULL) return -1;
    while (fgets(line, sizeof(line), file) != NULL) {
        if (strstr(line, needle) != NULL) {
            (void)fclose(file);
            return 1;
        }
    }
    (void)fclose(file);
    return 0;
}

int main(void)
{
    char directory[] = "/tmp/wardd-geo-test-XXXXXX";
    char ipv4_path[256];
    char ipv6_path[256];
    char nginx_path[256];
    char error[512] = {0};
    struct wardd_geo_compile_result result;
    struct wardd_geo_compile_result failed_result;
    struct stat status;

    CHECK(wardd_geo_mmdb_available() == 1, "MMDB support must be available");
    CHECK(mkdtemp(directory) != NULL, "create temporary directory");
    (void)snprintf(ipv4_path, sizeof(ipv4_path), "%s/cn-v4.txt", directory);
    (void)snprintf(ipv6_path, sizeof(ipv6_path), "%s/cn-v6.txt", directory);
    (void)snprintf(nginx_path, sizeof(nginx_path), "%s/nginx-cn.conf", directory);

    CHECK(
        wardd_geo_compile_mmdb(
            WARDD_TEST_MMDB_PATH,
            "CN",
            ipv4_path,
            ipv6_path,
            nginx_path,
            &result,
            error,
            sizeof(error)
        ) == 0,
        error
    );
    CHECK(result.ipv4_prefixes > 0, "compiled IPv4 prefixes");
    CHECK(result.ipv6_prefixes > 0, "compiled IPv6 prefixes");
    CHECK(result.visited_nodes > 0, "visited MMDB nodes");
    CHECK(result.database_type[0] != '\0', "database type");
    CHECK(count_lines(ipv4_path) == (int)result.ipv4_prefixes, "IPv4 line count");
    CHECK(count_lines(ipv6_path) == (int)result.ipv6_prefixes, "IPv6 line count");
    CHECK(
        count_lines(nginx_path) == (int)(result.ipv4_prefixes + result.ipv6_prefixes + 1),
        "Nginx line count"
    );
    CHECK(stat(nginx_path, &status) == 0 && status.st_size > 0, "Nginx output exists");
    CHECK(file_contains(ipv6_path, "::ffff:") == 0, "IPv4-mapped networks are not duplicated as IPv6");
    CHECK(
        wardd_geo_compile_mmdb(
            WARDD_TEST_MMDB_PATH,
            "CN",
            ipv4_path,
            ipv6_path,
            nginx_path,
            &failed_result,
            error,
            sizeof(error)
        ) != 0,
        "existing outputs must not be replaced"
    );
    CHECK(stat(nginx_path, &status) == 0 && status.st_size > 0, "failed compile preserves existing output");

    (void)unlink(ipv4_path);
    (void)unlink(ipv6_path);
    (void)unlink(nginx_path);
    (void)rmdir(directory);

    if (failures != 0) {
        fprintf(stderr, "%d MMDB test(s) failed\n", failures);
        return EXIT_FAILURE;
    }
    printf(
        "compiled %zu IPv4 and %zu IPv6 prefixes from %s\n",
        result.ipv4_prefixes,
        result.ipv6_prefixes,
        result.database_type
    );
    return EXIT_SUCCESS;
}
