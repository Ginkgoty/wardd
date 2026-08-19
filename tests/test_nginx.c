#include "wardd/nginx.h"

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

static int write_file(const char *path, const char *contents)
{
    FILE *file = fopen(path, "wx");
    if (file == NULL) return -1;
    if (fputs(contents, file) == EOF) {
        (void)fclose(file);
        return -1;
    }
    return fclose(file) == 0 ? 0 : -1;
}

int main(void)
{
    char directory[] = "/tmp/wardd-nginx-test-XXXXXX";
    char include_path[256];
    char geo_path[256];
    char server_path[256];
    char current_directory[256];
    char current_include[256];
    char event_path[256];
    char error[1024];
    struct stat status;

    CHECK(mkdtemp(directory) != NULL, "create Nginx test directory");
    (void)snprintf(include_path, sizeof(include_path), "%s/cn.conf", directory);
    (void)snprintf(geo_path, sizeof(geo_path), "%s/wardd-geo.conf", directory);
    (void)snprintf(server_path, sizeof(server_path), "%s/wardd-cn-only.conf", directory);
    (void)snprintf(current_directory, sizeof(current_directory), "%s/current", directory);
    (void)snprintf(current_include, sizeof(current_include), "%s/current/nginx-cn.conf", directory);
    (void)snprintf(event_path, sizeof(event_path), "%s/limit-events.log", directory);
    CHECK(write_file(include_path, "1.0.1.0/24 1;\n2400:3200::/32 1;\n") == 0, "write Nginx fixture");
    CHECK(
        wardd_nginx_check_include(WARDD_TEST_NGINX, include_path, error, sizeof(error)) == 0,
        error
    );
    CHECK(mkdir(current_directory, 0750) == 0, "create generated current directory");
    CHECK(write_file(current_include, "1.0.1.0/24 1;\n2400:3200::/32 1;\n") == 0,
        "write generated current fixture");
    CHECK(wardd_nginx_render(directory, event_path, "api", error, sizeof(error)) == 0, error);
    CHECK(stat(geo_path, &status) == 0 && S_ISREG(status.st_mode), "render geo include");
    CHECK(stat(server_path, &status) == 0 && S_ISREG(status.st_mode), "render server include");
    CHECK(wardd_nginx_check_http_include(WARDD_TEST_NGINX, geo_path, error, sizeof(error)) == 0, error);
    CHECK(wardd_nginx_test_live("/bin/true", error, sizeof(error)) == 0, "fixed-argument live test");
    CHECK(wardd_nginx_reload_live("/bin/true", error, sizeof(error)) == 0, "fixed-argument reload");
    CHECK(wardd_nginx_test_live("/bin/false", error, sizeof(error)) != 0, "report live test failure");

    (void)unlink(include_path);
    (void)unlink(geo_path);
    (void)unlink(server_path);
    (void)unlink(current_include);
    (void)unlink(event_path);
    (void)rmdir(current_directory);
    (void)rmdir(directory);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
