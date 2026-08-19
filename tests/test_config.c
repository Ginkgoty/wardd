#include "wardd/config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;

#define CHECK(condition, message) \
    do { \
        if (!(condition)) { \
            fprintf(stderr, "FAIL: %s (line %d)\n", (message), __LINE__); \
            failures++; \
        } \
    } while (0)

static void fixture_path(char *output, size_t output_size, const char *name)
{
    const int written = snprintf(
        output,
        output_size,
        "%s/tests/fixtures/%s",
        WARDD_TEST_SOURCE_DIR,
        name
    );
    if (written < 0 || (size_t)written >= output_size) {
        fprintf(stderr, "fixture path overflow\n");
        exit(EXIT_FAILURE);
    }
}

static void test_valid_config(void)
{
    char path[1024];
    char error[512];
    struct wardd_config config;

    fixture_path(path, sizeof(path), "valid.toml");
    CHECK(wardd_config_load(path, &config, error, sizeof(error)) == 0, error);
    CHECK(config.version == 1, "schema version");
    CHECK(strcmp(config.geo.country, "CN") == 0, "country");
    CHECK(config.geo.update_interval_seconds == 86400, "update interval");
    CHECK(config.geo.max_age_seconds == 1209600, "max age");
    CHECK(config.geo.max_download_bytes == 32ULL * 1024ULL * 1024ULL, "download size");
    CHECK(config.xdp.enabled, "XDP enabled");
    CHECK(config.xdp.endpoint_count == 2, "endpoint count");
    CHECK(config.xdp.endpoints[0].port == 443, "first endpoint port");
    CHECK(config.ban.protected_tcp_port_count == 3, "ban port count");
    CHECK(config.ban.exempt_count == 2, "ban exempt count");
    CHECK(config.ban.automatic.window_seconds == 60, "auto-ban window");
    CHECK(config.firewall.ownership == WARDD_FIREWALL_EXTERNAL, "firewall ownership");
    CHECK(!config.firewall.manage, "firewall is unmanaged");
}

static void test_invalid_fixture(const char *name, const char *expected_error)
{
    char path[1024];
    char error[512] = {0};
    struct wardd_config config;

    fixture_path(path, sizeof(path), name);
    CHECK(wardd_config_load(path, &config, error, sizeof(error)) != 0, "fixture must be invalid");
    CHECK(strstr(error, expected_error) != NULL, error);
}

int main(void)
{
    test_valid_config();
    test_invalid_fixture("unknown-key.toml", "unknown xdp key");
    test_invalid_fixture("managed-firewall.toml", "firewall.manage must remain false");
    test_invalid_fixture("udp-endpoint.toml", "only TCP geo endpoints");

    if (failures != 0) {
        fprintf(stderr, "%d config test(s) failed\n", failures);
        return EXIT_FAILURE;
    }
    printf("all config tests passed\n");
    return EXIT_SUCCESS;
}
