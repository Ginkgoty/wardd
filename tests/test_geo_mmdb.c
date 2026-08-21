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
    struct wardd_geo_compile_result multi_result;
    const struct wardd_country_set only_cn = {.codes = {"CN"}, .count = 1};
    const struct wardd_country_set cn_and_jp = {.codes = {"CN", "JP"}, .count = 2};
    const struct wardd_country_set cn_and_absent = {.codes = {"CN", "ZZ"}, .count = 2};
    struct stat status;

    CHECK(wardd_geo_mmdb_available() == 1, "MMDB support must be available");
    CHECK(mkdtemp(directory) != NULL, "create temporary directory");
    (void)snprintf(ipv4_path, sizeof(ipv4_path), "%s/geo-v4.txt", directory);
    (void)snprintf(ipv6_path, sizeof(ipv6_path), "%s/geo-v6.txt", directory);
    (void)snprintf(nginx_path, sizeof(nginx_path), "%s/nginx-geo.conf", directory);

    CHECK(
        wardd_geo_compile_mmdb(
            WARDD_TEST_MMDB_PATH,
            &only_cn,
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
            &only_cn,
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

    /*
     * Two countries merge into one allow set. The data plane only ever asks
     * whether a source is in the set, so the result must be the union of both
     * countries' prefixes and nothing else.
     */
    CHECK(
        wardd_geo_compile_mmdb(
            WARDD_TEST_MMDB_PATH,
            &cn_and_jp,
            ipv4_path,
            ipv6_path,
            nginx_path,
            &multi_result,
            error,
            sizeof(error)
        ) == 0,
        error
    );
    CHECK(multi_result.ipv4_prefixes > result.ipv4_prefixes, "adding a country adds IPv4 prefixes");
    CHECK(multi_result.ipv6_prefixes > result.ipv6_prefixes, "adding a country adds IPv6 prefixes");
    CHECK(multi_result.matched_countries == 0x3U, "both requested countries were found");
    CHECK(file_contains(ipv4_path, "203.0.113.0/24") != 0, "the second country's IPv4 prefix is present");
    CHECK(file_contains(ipv6_path, "2001:db8:2::/48") != 0, "the second country's IPv6 prefix is present");
    CHECK(file_contains(ipv4_path, "192.0.2.0/25") != 0, "the first country's prefixes are retained");
    (void)unlink(ipv4_path);
    (void)unlink(ipv6_path);
    (void)unlink(nginx_path);

    /*
     * A country the database never mentions is reported through
     * matched_countries rather than failing the compile: a regional database
     * legitimately may not carry it, but the operator must be able to tell.
     */
    CHECK(
        wardd_geo_compile_mmdb(
            WARDD_TEST_MMDB_PATH,
            &cn_and_absent,
            ipv4_path,
            ipv6_path,
            nginx_path,
            &multi_result,
            error,
            sizeof(error)
        ) == 0,
        error
    );
    CHECK(multi_result.matched_countries == 0x1U, "an absent country is reported, not fatal");
    CHECK(multi_result.ipv4_prefixes == result.ipv4_prefixes,
        "an absent country contributes no prefixes");
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
