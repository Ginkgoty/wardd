#include "wardd/nginx.h"
#include "wardd/nginx_events.h"

#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int failures;

#define CHECK(condition, message) \
    do { \
        if (!(condition)) { \
            fprintf(stderr, "FAIL: %s (line %d)\n", (message), __LINE__); \
            failures++; \
        } \
    } while (0)

static void pause_short(void)
{
    const struct timespec delay = {.tv_nsec = 25000000L};
    (void)nanosleep(&delay, NULL);
}

static int write_file(const char *path, const char *contents)
{
    FILE *file = fopen(path, "wx");
    if (file == NULL) return -1;
    if (fputs(contents, file) == EOF) {
        (void)fclose(file);
        return -1;
    }
    return fclose(file);
}

static int reserve_port(void)
{
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t length = sizeof(address);
    int descriptor = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (descriptor < 0 || bind(descriptor, (struct sockaddr *)&address, sizeof(address)) != 0 ||
        getsockname(descriptor, (struct sockaddr *)&address, &length) != 0) {
        if (descriptor >= 0) (void)close(descriptor);
        return -1;
    }
    const int port = ntohs(address.sin_port);
    (void)close(descriptor);
    return port;
}

static int request_once(int port)
{
    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_port = htons((uint16_t)port),
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
    };
    static const char request[] = "GET / HTTP/1.0\r\nHost: service.example.com\r\n\r\n";
    char response[1024];
    int descriptor = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (descriptor < 0 || connect(descriptor, (struct sockaddr *)&address, sizeof(address)) != 0 ||
        write(descriptor, request, sizeof(request) - 1) != (ssize_t)(sizeof(request) - 1)) {
        if (descriptor >= 0) (void)close(descriptor);
        return -1;
    }
    while (read(descriptor, response, sizeof(response)) > 0) {}
    (void)close(descriptor);
    return 0;
}

int main(void)
{
    char directory[] = "/tmp/wardd-nginx-live-test-XXXXXX";
    char generated[512];
    char current[1024];
    char current_include[1536];
    char geo_include[768];
    char server_include[768];
    char event_log[512];
    char config_path[512];
    char html_directory[512];
    char index_path[768];
    char nginx_pid[512];
    char error_log[512];
    char configuration[4096];
    char error[2048];
    char line[2048] = {0};
    struct wardd_auto_ban_event event;
    pid_t child = -1;
    int port;

    CHECK(mkdtemp(directory) != NULL, "create live Nginx test directory");
    port = reserve_port();
    CHECK(port > 0, "reserve loopback port");
    (void)snprintf(generated, sizeof(generated), "%s/generated", directory);
    (void)snprintf(current, sizeof(current), "%s/current", generated);
    (void)snprintf(current_include, sizeof(current_include), "%s/nginx-geo.conf", current);
    (void)snprintf(geo_include, sizeof(geo_include), "%s/wardd-geo.conf", generated);
    (void)snprintf(server_include, sizeof(server_include), "%s/wardd-geo-allow.conf", generated);
    (void)snprintf(event_log, sizeof(event_log), "%s/events.log", directory);
    (void)snprintf(config_path, sizeof(config_path), "%s/nginx.conf", directory);
    (void)snprintf(html_directory, sizeof(html_directory), "%s/html", directory);
    (void)snprintf(index_path, sizeof(index_path), "%s/index.html", html_directory);
    (void)snprintf(nginx_pid, sizeof(nginx_pid), "%s/nginx.pid", directory);
    (void)snprintf(error_log, sizeof(error_log), "%s/error.log", directory);
    CHECK(mkdir(generated, 0750) == 0 && mkdir(current, 0750) == 0 && mkdir(html_directory, 0750) == 0,
        "create live Nginx directories");
    CHECK(write_file(current_include, "127.0.0.0/8 1;\n") == 0, "write CN fixture include");
    CHECK(write_file(index_path, "ok\n") == 0, "write static response fixture");
    CHECK(wardd_nginx_render(generated, event_log, "api", error, sizeof(error)) == 0, error);
    CHECK(
        snprintf(
            configuration,
            sizeof(configuration),
            "pid %s;\nerror_log %s notice;\nevents {}\nhttp {\n"
            "include %s;\n"
            "limit_req_zone $binary_remote_addr zone=api:1m rate=1r/m;\n"
            "server { listen 127.0.0.1:%d; server_name service.example.com;\n"
            "location / { limit_req zone=api; root %s; }\n}\n}\n",
            nginx_pid,
            error_log,
            geo_include,
            port,
            html_directory
        ) < (int)sizeof(configuration),
        "render isolated live Nginx config"
    );
    CHECK(write_file(config_path, configuration) == 0, "write isolated live Nginx config");

    child = fork();
    if (child == 0) {
        execl(
            WARDD_TEST_NGINX,
            WARDD_TEST_NGINX,
            "-p", directory,
            "-c", config_path,
            "-g", "daemon off; master_process off;",
            (char *)NULL
        );
        _exit(127);
    }
    CHECK(child > 0, "start isolated real Nginx");
    for (int attempt = 0; attempt < 120 && request_once(port) != 0; ++attempt) pause_short();
    CHECK(request_once(port) == 0, "send accepted Nginx request");
    CHECK(request_once(port) == 0 && request_once(port) == 0, "send rate-limited Nginx requests");
    for (int attempt = 0; attempt < 120; ++attempt) {
        FILE *file = fopen(event_log, "r");
        if (file != NULL) {
            if (fgets(line, sizeof(line), file) != NULL) {
                (void)fclose(file);
                break;
            }
            (void)fclose(file);
        }
        pause_short();
    }
    if (child > 0) {
        (void)kill(child, SIGTERM);
        (void)waitpid(child, NULL, 0);
        child = -1;
    }
    const size_t line_length = strlen(line);
    if (line_length > 0 && line[line_length - 1] == '\n') line[line_length - 1] = '\0';
    CHECK(line[0] != '\0', "real Nginx emits structured REJECTED event");
    CHECK(wardd_nginx_event_parse(line, &event, error, sizeof(error)) == 0, error);
    CHECK(strcmp(event.peer, "127.0.0.1") == 0 && strcmp(event.server, "service.example.com") == 0 &&
        strcmp(event.zone, "api") == 0 && event.confirmed_peer,
        "real Nginx event matches wardd trust schema");

    if (child > 0) {
        (void)kill(child, SIGTERM);
        (void)waitpid(child, NULL, 0);
    }
    static const char *const paths[] = {
        "nginx.conf", "nginx.pid", "error.log", "events.log", "html/index.html",
        "generated/current/nginx-geo.conf", "generated/wardd-geo.conf", "generated/wardd-geo-allow.conf"
    };
    for (size_t index = 0; index < sizeof(paths) / sizeof(paths[0]); ++index) {
        char path[1024];
        (void)snprintf(path, sizeof(path), "%s/%s", directory, paths[index]);
        (void)unlink(path);
    }
    (void)rmdir(html_directory);
    (void)rmdir(current);
    (void)rmdir(generated);
    (void)rmdir(directory);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
