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
    CHECK(config.geo.countries.count == 1 && strcmp(config.geo.countries.codes[0], "CN") == 0,
        "a single country string parses as a one-element set");
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

/*
 * The order the administrator writes the countries in must not leak into the
 * parsed set, because the snapshot identity is derived from it: writing
 * ["JP", "CN"] and ["CN", "JP"] has to compile to the same snapshot.
 */
static void test_country_array(void)
{
    char path[1024];
    char error[512];
    char token[WARDD_COUNTRY_TOKEN_LEN];
    struct wardd_config config;

    fixture_path(path, sizeof(path), "multi-country.toml");
    CHECK(wardd_config_load(path, &config, error, sizeof(error)) == 0, error);
    CHECK(config.geo.countries.count == 3, "country array length");
    CHECK(strcmp(config.geo.countries.codes[0], "CN") == 0 &&
        strcmp(config.geo.countries.codes[1], "DE") == 0 &&
        strcmp(config.geo.countries.codes[2], "JP") == 0,
        "country array is sorted regardless of written order");
    CHECK(wardd_country_set_token(&config.geo.countries, token, sizeof(token)) == 0 &&
        strcmp(token, "CN_DE_JP") == 0, "country set renders a canonical token");

    char narrow[4];
    CHECK(wardd_country_set_token(&config.geo.countries, narrow, sizeof(narrow)) != 0 &&
        narrow[0] == '\0', "an undersized token buffer fails rather than truncating");
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
    test_country_array();
    test_invalid_fixture("duplicate-country.toml", "duplicate geo.country entry");
    test_invalid_fixture("lowercase-country.toml", "two-letter uppercase codes");
    test_invalid_fixture("empty-country.toml", "at least one country");

    if (failures != 0) {
        fprintf(stderr, "%d config test(s) failed\n", failures);
        return EXIT_FAILURE;
    }
    printf("all config tests passed\n");
    return EXIT_SUCCESS;
}
