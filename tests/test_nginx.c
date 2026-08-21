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
    (void)snprintf(server_path, sizeof(server_path), "%s/wardd-geo-allow.conf", directory);
    (void)snprintf(current_directory, sizeof(current_directory), "%s/current", directory);
    (void)snprintf(current_include, sizeof(current_include), "%s/current/nginx-geo.conf", directory);
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

    /*
     * Wiring test against a real Nginx: wardd writes one drop-in of its own
     * into the configuration directory and never edits a file the
     * administrator wrote, so a failed check has to leave the tree exactly as
     * it found it.
     */
    {
        char conf_dir[256];
        char bad_dir[256];
        char bad_geo[320];
        char wrapper[256];
        char live_conf[256];
        char dropin[320];
        char script[1024];
        char live[1024];
        static char dump[WARDD_NGINX_DUMP_LEN];
        char dropin_contents[1024];
        FILE *file;

        (void)snprintf(conf_dir, sizeof(conf_dir), "%s/conf.d", directory);
        (void)snprintf(bad_dir, sizeof(bad_dir), "%s/broken", directory);
        (void)snprintf(bad_geo, sizeof(bad_geo), "%s/wardd-geo.conf", bad_dir);
        (void)snprintf(wrapper, sizeof(wrapper), "%s/nginx-wrapper", directory);
        (void)snprintf(live_conf, sizeof(live_conf), "%s/nginx.conf", directory);
        (void)snprintf(dropin, sizeof(dropin), "%s/wardd.conf", conf_dir);
        CHECK(mkdir(conf_dir, 0750) == 0, "create Nginx configuration directory");
        CHECK(mkdir(bad_dir, 0750) == 0, "create broken generated directory");
        CHECK(write_file(bad_geo, "this is not valid nginx configuration\n") == 0,
            "write a generated include Nginx will reject");
        (void)snprintf(
            live,
            sizeof(live),
            "pid nginx.pid;\nerror_log stderr notice;\nevents {}\n"
            "http {\n    access_log off;\n    include %s/*.conf;\n}\n",
            conf_dir
        );
        CHECK(write_file(live_conf, live) == 0, "write live Nginx configuration");
        (void)snprintf(
            script,
            sizeof(script),
            "#!/bin/sh\nexec %s -p %s -c %s \"$@\"\n",
            WARDD_TEST_NGINX, directory, live_conf
        );
        CHECK(write_file(wrapper, script) == 0, "write Nginx wrapper");
        CHECK(chmod(wrapper, 0700) == 0, "make the Nginx wrapper executable");

        CHECK(wardd_nginx_dropin_path(directory, dropin_contents, sizeof(dropin_contents),
            error, sizeof(error)) == 0, error);
        CHECK(wardd_nginx_dropin_path(geo_path, dropin_contents, sizeof(dropin_contents),
            error, sizeof(error)) != 0, "a file is not a configuration directory");

        CHECK(wardd_nginx_enable(wrapper, conf_dir, directory, error, sizeof(error)) == 0, error);
        CHECK(stat(dropin, &status) == 0 && S_ISREG(status.st_mode), "enable writes one drop-in");
        CHECK(wardd_nginx_enable(wrapper, conf_dir, directory, error, sizeof(error)) == 0,
            "enable is idempotent");
        CHECK(wardd_nginx_dump_config(wrapper, dump, sizeof(dump), error, sizeof(error)) == 0, error);
        CHECK(strstr(dump, geo_path) != NULL, "the dumped live configuration includes wardd");

        /* A drop-in Nginx refuses must not survive: it would break the next
           unrelated reload long after wardctl exited. */
        CHECK(wardd_nginx_enable(wrapper, conf_dir, bad_dir, error, sizeof(error)) != 0,
            "a rejected configuration fails the enable");
        file = fopen(dropin, "r");
        CHECK(file != NULL, "the previous drop-in is restored");
        if (file != NULL) {
            const size_t bytes = fread(dropin_contents, 1, sizeof(dropin_contents) - 1, file);
            dropin_contents[bytes] = '\0';
            (void)fclose(file);
            CHECK(strstr(dropin_contents, geo_path) != NULL,
                "rollback restores the working include, not the rejected one");
            CHECK(strstr(dropin_contents, bad_geo) == NULL, "the rejected include is gone");
        }
        CHECK(wardd_nginx_test_live(wrapper, error, sizeof(error)) == 0,
            "the live configuration still loads after a failed enable");

        CHECK(wardd_nginx_disable(wrapper, conf_dir, error, sizeof(error)) == 1, "disable removes it");
        CHECK(stat(dropin, &status) != 0, "the drop-in is gone");
        CHECK(wardd_nginx_disable(wrapper, conf_dir, error, sizeof(error)) == 0,
            "disabling twice reports nothing to do");

        (void)unlink(bad_geo);
        (void)unlink(wrapper);
        (void)unlink(live_conf);
        (void)rmdir(bad_dir);
        (void)rmdir(conf_dir);
    }

    (void)unlink(include_path);
    (void)unlink(geo_path);
    (void)unlink(server_path);
    (void)unlink(current_include);
    (void)unlink(event_path);
    (void)rmdir(current_directory);
    (void)rmdir(directory);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
