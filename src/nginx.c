#include "wardd/nginx.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define COMMAND_OUTPUT_SIZE 4096
#define NGINX_PATH_SIZE 1024

extern char **environ;

static void set_error(char *error, size_t error_size, const char *format, ...)
{
    va_list arguments;

    if (error == NULL || error_size == 0) return;
    va_start(arguments, format);
    (void)vsnprintf(error, error_size, format, arguments);
    va_end(arguments);
}

static int ensure_directory(const char *path, char *error, size_t error_size)
{
    char copy[NGINX_PATH_SIZE];

    if (path == NULL || path[0] != '/' || strlen(path) >= sizeof(copy)) {
        set_error(error, error_size, "generated directory must be a bounded absolute path");
        return -1;
    }
    (void)snprintf(copy, sizeof(copy), "%s", path);
    for (char *cursor = copy + 1; ; ++cursor) {
        if (*cursor != '/' && *cursor != '\0') continue;
        const char saved = *cursor;
        struct stat status;
        *cursor = '\0';
        if (mkdir(copy, 0750) != 0 && errno != EEXIST) {
            set_error(error, error_size, "cannot create %s: %s", copy, strerror(errno));
            return -1;
        }
        if (lstat(copy, &status) != 0 || !S_ISDIR(status.st_mode)) {
            set_error(error, error_size, "%s is not a real directory", copy);
            return -1;
        }
        *cursor = saved;
        if (saved == '\0') break;
    }
    return 0;
}

static int quote_nginx_path(const char *path, char *output, size_t output_size)
{
    size_t used = 0;

    if (path == NULL || output == NULL || output_size < 3) return -1;
    output[used++] = '"';
    for (const unsigned char *cursor = (const unsigned char *)path; *cursor != '\0'; ++cursor) {
        if (*cursor < 0x20 || *cursor == 0x7f) return -1;
        if (*cursor == '"' || *cursor == '\\') {
            if (used + 2 >= output_size) return -1;
            output[used++] = '\\';
        } else if (used + 1 >= output_size) {
            return -1;
        }
        output[used++] = (char)*cursor;
    }
    if (used + 2 > output_size) return -1;
    output[used++] = '"';
    output[used] = '\0';
    return 0;
}

static bool safe_zone_name(const char *zone)
{
    if (zone == NULL || zone[0] == '\0') return false;
    for (const unsigned char *cursor = (const unsigned char *)zone; *cursor != '\0'; ++cursor) {
        if (!( (*cursor >= 'a' && *cursor <= 'z') || (*cursor >= 'A' && *cursor <= 'Z') ||
               (*cursor >= '0' && *cursor <= '9') || *cursor == '_' || *cursor == '-' ||
               *cursor == '.' )) return false;
    }
    return true;
}

static int replace_file(
    const char *path,
    const char *contents,
    char *error,
    size_t error_size
)
{
    char temporary[NGINX_PATH_SIZE];
    struct stat status;
    FILE *file;
    int length;

    length = snprintf(temporary, sizeof(temporary), "%s.tmp.%ld", path, (long)getpid());
    if (length < 0 || (size_t)length >= sizeof(temporary)) {
        set_error(error, error_size, "generated output path is too long");
        return -1;
    }
    if (lstat(path, &status) == 0) {
        if (!S_ISREG(status.st_mode)) {
            set_error(error, error_size, "refusing to replace non-regular file %s", path);
            return -1;
        }
    } else if (errno != ENOENT) {
        set_error(error, error_size, "cannot inspect %s: %s", path, strerror(errno));
        return -1;
    }
    file = fopen(temporary, "wx");
    if (file == NULL) {
        set_error(error, error_size, "cannot create %s: %s", temporary, strerror(errno));
        return -1;
    }
    if (fchmod(fileno(file), 0640) != 0 || fputs(contents, file) == EOF ||
        fflush(file) != 0 || fsync(fileno(file)) != 0) {
        const int saved_errno = errno;
        (void)fclose(file);
        (void)unlink(temporary);
        set_error(error, error_size, "cannot write %s: %s", temporary, strerror(saved_errno));
        return -1;
    }
    if (fclose(file) != 0) {
        const int saved_errno = errno;
        (void)unlink(temporary);
        set_error(error, error_size, "cannot close %s: %s", temporary, strerror(saved_errno));
        return -1;
    }
    if (rename(temporary, path) != 0) {
        const int saved_errno = errno;
        (void)unlink(temporary);
        set_error(error, error_size, "cannot activate %s: %s", path, strerror(saved_errno));
        return -1;
    }
    return 0;
}

int wardd_nginx_render(
    const char *generated_directory,
    const char *limit_event_log,
    const char *limit_zone,
    char *error,
    size_t error_size
)
{
    char include_path[NGINX_PATH_SIZE];
    char quoted_path[NGINX_PATH_SIZE * 2];
    char quoted_log[NGINX_PATH_SIZE * 2];
    char geo_path[NGINX_PATH_SIZE];
    char server_path[NGINX_PATH_SIZE];
    char geo_contents[NGINX_PATH_SIZE * 5];
    static const char server_contents[] =
        "# Generated by wardd; include this file only in a server block.\n"
        "if ($wardd_client_geo_allowed = 0) {\n"
        "    return 444;\n"
        "}\n";

    if (error != NULL && error_size > 0) error[0] = '\0';
    if (ensure_directory(generated_directory, error, error_size) != 0) return -1;
    if (snprintf(include_path, sizeof(include_path), "%s/current/nginx-geo.conf", generated_directory) >=
            (int)sizeof(include_path) ||
        snprintf(geo_path, sizeof(geo_path), "%s/wardd-geo.conf", generated_directory) >=
            (int)sizeof(geo_path) ||
        snprintf(server_path, sizeof(server_path), "%s/wardd-geo-allow.conf", generated_directory) >=
            (int)sizeof(server_path) ||
        quote_nginx_path(include_path, quoted_path, sizeof(quoted_path)) != 0 ||
        limit_event_log == NULL || limit_event_log[0] != '/' ||
        quote_nginx_path(limit_event_log, quoted_log, sizeof(quoted_log)) != 0 ||
        !safe_zone_name(limit_zone)) {
        set_error(error, error_size, "generated Nginx path is too long or unsafe");
        return -1;
    }
    if (snprintf(
            geo_contents,
            sizeof(geo_contents),
            "# Generated by wardd; include this file only in the http block.\n"
            "geo $wardd_client_geo_allowed {\n"
            "    default 0;\n"
            "    include %s;\n"
            "}\n"
            "map $limit_req_status $wardd_limit_rejected {\n"
            "    default 0;\n"
            "    REJECTED 1;\n"
            "}\n"
            "log_format wardd_limit escape=json\n"
            "    '{\"schema\":1,\"peer\":\"$remote_addr\",\"server\":\"$server_name\","
            "\"zone\":\"%s\",\"status\":\"$limit_req_status\","
            "\"request_id\":\"$request_id\",\"epoch\":\"$msec\"}';\n"
            "access_log %s wardd_limit if=$wardd_limit_rejected;\n",
            quoted_path,
            limit_zone,
            quoted_log
        ) >= (int)sizeof(geo_contents)) {
        set_error(error, error_size, "generated Nginx configuration is too large");
        return -1;
    }
    if (replace_file(geo_path, geo_contents, error, error_size) != 0 ||
        replace_file(server_path, server_contents, error, error_size) != 0) {
        return -1;
    }
    return 0;
}

int wardd_nginx_check_include(
    const char *nginx_binary,
    const char *include_path,
    char *error,
    size_t error_size
)
{
    char directory[] = "/tmp/wardd-nginx-check-XXXXXX";
    char config_path[NGINX_PATH_SIZE] = {0};
    char quoted_include[NGINX_PATH_SIZE * 2];
    char configuration[NGINX_PATH_SIZE * 3];
    char command_output[COMMAND_OUTPUT_SIZE] = {0};
    int output_pipe[2] = {-1, -1};
    FILE *file = NULL;
    pid_t child;
    posix_spawn_file_actions_t file_actions;
    bool file_actions_initialized = false;
    int child_status = 0;
    size_t output_used = 0;
    int return_value = -1;

    if (error != NULL && error_size > 0) error[0] = '\0';
    if (nginx_binary == NULL || nginx_binary[0] == '\0' || include_path == NULL ||
        include_path[0] != '/' || quote_nginx_path(include_path, quoted_include, sizeof(quoted_include)) != 0) {
        set_error(error, error_size, "Nginx binary and a safe absolute include path are required");
        return -1;
    }
    if (mkdtemp(directory) == NULL ||
        snprintf(config_path, sizeof(config_path), "%s/nginx.conf", directory) >= (int)sizeof(config_path) ||
        snprintf(
            configuration,
            sizeof(configuration),
            "pid nginx.pid;\n"
            "error_log stderr notice;\n"
            "events {}\n"
            "http {\n"
            "    access_log off;\n"
            "    geo $wardd_client_geo_allowed {\n"
            "        default 0;\n"
            "        include %s;\n"
            "    }\n"
            "}\n",
            quoted_include
        ) >= (int)sizeof(configuration)) {
        set_error(error, error_size, "cannot prepare isolated Nginx check");
        goto done;
    }
    file = fopen(config_path, "wx");
    if (file == NULL) {
        set_error(error, error_size, "cannot write isolated Nginx check: %s", strerror(errno));
        goto done;
    }
    if (fputs(configuration, file) == EOF) {
        set_error(error, error_size, "cannot write isolated Nginx check: %s", strerror(errno));
        goto done;
    }
    if (fclose(file) != 0) {
        file = NULL;
        set_error(error, error_size, "cannot close isolated Nginx check: %s", strerror(errno));
        goto done;
    }
    file = NULL;
    if (pipe(output_pipe) != 0) {
        set_error(error, error_size, "cannot create Nginx check pipe: %s", strerror(errno));
        goto done;
    }
    if (fcntl(output_pipe[0], F_SETFD, FD_CLOEXEC) != 0 ||
        fcntl(output_pipe[1], F_SETFD, FD_CLOEXEC) != 0) {
        const int saved_errno = errno;
        (void)close(output_pipe[0]);
        (void)close(output_pipe[1]);
        output_pipe[0] = -1;
        output_pipe[1] = -1;
        set_error(error, error_size, "cannot protect Nginx check pipe: %s", strerror(saved_errno));
        goto done;
    }
    int spawn_status = posix_spawn_file_actions_init(&file_actions);
    if (spawn_status != 0) {
        set_error(error, error_size, "cannot prepare Nginx check: %s", strerror(spawn_status));
        goto done;
    }
    file_actions_initialized = true;
    spawn_status = posix_spawn_file_actions_addclose(&file_actions, output_pipe[0]);
    if (spawn_status == 0) {
        spawn_status = posix_spawn_file_actions_adddup2(&file_actions, output_pipe[1], STDOUT_FILENO);
    }
    if (spawn_status == 0) {
        spawn_status = posix_spawn_file_actions_adddup2(&file_actions, output_pipe[1], STDERR_FILENO);
    }
    if (spawn_status == 0) {
        spawn_status = posix_spawn_file_actions_addclose(&file_actions, output_pipe[1]);
    }
    if (spawn_status != 0) {
        set_error(error, error_size, "cannot prepare Nginx check descriptors: %s", strerror(spawn_status));
        goto done;
    }
    char *const arguments[] = {
        (char *)nginx_binary,
        "-t",
        "-q",
        "-p",
        directory,
        "-c",
        config_path,
        NULL,
    };
    spawn_status = posix_spawnp(&child, nginx_binary, &file_actions, NULL, arguments, environ);
    if (spawn_status != 0) {
        set_error(error, error_size, "cannot start Nginx check: %s", strerror(spawn_status));
        goto done;
    }
    (void)close(output_pipe[1]);
    output_pipe[1] = -1;
    for (;;) {
        char chunk[512];
        ssize_t bytes = read(output_pipe[0], chunk, sizeof(chunk));
        if (bytes < 0 && errno == EINTR) continue;
        if (bytes <= 0) break;
        const size_t available = sizeof(command_output) - output_used - 1;
        const size_t copy = (size_t)bytes < available ? (size_t)bytes : available;
        if (copy != 0) {
            memcpy(command_output + output_used, chunk, copy);
            output_used += copy;
        }
    }
    command_output[output_used] = '\0';
    (void)close(output_pipe[0]);
    output_pipe[0] = -1;
    if (waitpid(child, &child_status, 0) < 0) {
        set_error(error, error_size, "cannot wait for Nginx check: %s", strerror(errno));
        goto done;
    }
    if (!WIFEXITED(child_status) || WEXITSTATUS(child_status) != 0) {
        set_error(
            error,
            error_size,
            "isolated nginx -t failed%s%s",
            command_output[0] == '\0' ? "" : ": ",
            command_output
        );
        goto done;
    }
    return_value = 0;

done:
    if (file_actions_initialized) (void)posix_spawn_file_actions_destroy(&file_actions);
    if (file != NULL) (void)fclose(file);
    if (output_pipe[0] >= 0) (void)close(output_pipe[0]);
    if (output_pipe[1] >= 0) (void)close(output_pipe[1]);
    if (config_path[0] != '\0') (void)unlink(config_path);
    (void)rmdir(directory);
    return return_value;
}

static int run_live_command(
    const char *nginx_binary,
    char *const arguments[],
    const char *operation,
    char *capture,
    size_t capture_size,
    char *error,
    size_t error_size
)
{
    char local_output[COMMAND_OUTPUT_SIZE] = {0};
    char *const command_output = capture != NULL && capture_size != 0 ? capture : local_output;
    const size_t command_output_size = capture != NULL && capture_size != 0
        ? capture_size : sizeof(local_output);
    int output_pipe[2] = {-1, -1};
    posix_spawn_file_actions_t actions;
    bool actions_initialized = false;
    pid_t child;
    int child_status;
    size_t output_used = 0;
    int result = -1;

    if (error != NULL && error_size > 0) error[0] = '\0';
    if (nginx_binary == NULL || nginx_binary[0] == '\0' || operation == NULL) {
        set_error(error, error_size, "Nginx binary is required");
        return -1;
    }
    if (pipe(output_pipe) != 0) {
        set_error(error, error_size, "cannot create Nginx %s pipe: %s", operation, strerror(errno));
        goto done;
    }
    if (fcntl(output_pipe[0], F_SETFD, FD_CLOEXEC) != 0 ||
        fcntl(output_pipe[1], F_SETFD, FD_CLOEXEC) != 0) {
        const int saved_errno = errno;
        (void)close(output_pipe[0]);
        (void)close(output_pipe[1]);
        output_pipe[0] = -1;
        output_pipe[1] = -1;
        set_error(error, error_size, "cannot protect Nginx %s pipe: %s", operation, strerror(saved_errno));
        goto done;
    }
    int status = posix_spawn_file_actions_init(&actions);
    if (status != 0) {
        set_error(error, error_size, "cannot prepare Nginx %s: %s", operation, strerror(status));
        goto done;
    }
    actions_initialized = true;
    status = posix_spawn_file_actions_addclose(&actions, output_pipe[0]);
    if (status == 0) status = posix_spawn_file_actions_adddup2(&actions, output_pipe[1], STDOUT_FILENO);
    if (status == 0) status = posix_spawn_file_actions_adddup2(&actions, output_pipe[1], STDERR_FILENO);
    if (status == 0) status = posix_spawn_file_actions_addclose(&actions, output_pipe[1]);
    if (status != 0) {
        set_error(error, error_size, "cannot prepare Nginx %s descriptors: %s", operation, strerror(status));
        goto done;
    }
    status = posix_spawnp(&child, nginx_binary, &actions, NULL, arguments, environ);
    if (status != 0) {
        set_error(error, error_size, "cannot start Nginx %s: %s", operation, strerror(status));
        goto done;
    }
    (void)close(output_pipe[1]);
    output_pipe[1] = -1;
    for (;;) {
        char chunk[512];
        const ssize_t bytes = read(output_pipe[0], chunk, sizeof(chunk));
        if (bytes < 0 && errno == EINTR) continue;
        if (bytes <= 0) break;
        const size_t available = command_output_size - output_used - 1;
        const size_t copy = (size_t)bytes < available ? (size_t)bytes : available;
        if (copy != 0) {
            memcpy(command_output + output_used, chunk, copy);
            output_used += copy;
        }
    }
    command_output[output_used] = '\0';
    (void)close(output_pipe[0]);
    output_pipe[0] = -1;
    if (waitpid(child, &child_status, 0) < 0) {
        set_error(error, error_size, "cannot wait for Nginx %s: %s", operation, strerror(errno));
        goto done;
    }
    if (!WIFEXITED(child_status) || WEXITSTATUS(child_status) != 0) {
        set_error(
            error,
            error_size,
            "Nginx %s failed%s%.512s",
            operation,
            command_output[0] == '\0' ? "" : ": ",
            command_output
        );
        goto done;
    }
    result = 0;

done:
    if (actions_initialized) (void)posix_spawn_file_actions_destroy(&actions);
    if (output_pipe[0] >= 0) (void)close(output_pipe[0]);
    if (output_pipe[1] >= 0) (void)close(output_pipe[1]);
    return result;
}

int wardd_nginx_test_live(const char *nginx_binary, char *error, size_t error_size)
{
    char *const arguments[] = {(char *)nginx_binary, "-t", "-q", NULL};
    return run_live_command(nginx_binary, arguments, "live configuration test", NULL, 0, error, error_size);
}

int wardd_nginx_reload_live(const char *nginx_binary, char *error, size_t error_size)
{
    char *const arguments[] = {(char *)nginx_binary, "-s", "reload", NULL};
    return run_live_command(nginx_binary, arguments, "reload", NULL, 0, error, error_size);
}

int wardd_nginx_check_http_include(
    const char *nginx_binary,
    const char *include_path,
    char *error,
    size_t error_size
)
{
    char directory[] = "/tmp/wardd-nginx-http-check-XXXXXX";
    char config_path[NGINX_PATH_SIZE] = {0};
    char quoted_include[NGINX_PATH_SIZE * 2];
    char configuration[NGINX_PATH_SIZE * 3];
    FILE *file = NULL;
    int result = -1;

    if (nginx_binary == NULL || nginx_binary[0] == '\0' || include_path == NULL ||
        include_path[0] != '/' || quote_nginx_path(include_path, quoted_include, sizeof(quoted_include)) != 0) {
        set_error(error, error_size, "Nginx binary and safe absolute http include are required");
        return -1;
    }
    if (mkdtemp(directory) == NULL ||
        snprintf(config_path, sizeof(config_path), "%s/nginx.conf", directory) >= (int)sizeof(config_path) ||
        snprintf(
            configuration,
            sizeof(configuration),
            "pid nginx.pid;\n"
            "error_log stderr notice;\n"
            "events {}\n"
            "http {\n"
            "    include %s;\n"
            "}\n",
            quoted_include
        ) >= (int)sizeof(configuration)) {
        set_error(error, error_size, "cannot prepare generated Nginx integration check");
        goto done;
    }
    file = fopen(config_path, "wx");
    if (file == NULL) {
        set_error(error, error_size, "cannot write generated Nginx integration check: %s", strerror(errno));
        goto done;
    }
    if (fputs(configuration, file) == EOF) {
        set_error(error, error_size, "cannot write generated Nginx integration check: %s", strerror(errno));
        goto done;
    }
    if (fclose(file) != 0) {
        file = NULL;
        set_error(error, error_size, "cannot close generated Nginx integration check: %s", strerror(errno));
        goto done;
    }
    file = NULL;
    char *const arguments[] = {
        (char *)nginx_binary, "-t", "-q", "-p", directory, "-c", config_path, NULL,
    };
    result = run_live_command(
        nginx_binary, arguments, "generated http integration test", NULL, 0, error, error_size
    );

done:
    if (file != NULL) (void)fclose(file);
    if (config_path[0] != '\0') (void)unlink(config_path);
    (void)rmdir(directory);
    return result;
}

int wardd_nginx_dump_config(
    const char *nginx_binary,
    char *output,
    size_t output_size,
    char *error,
    size_t error_size
)
{
    char *const arguments[] = {(char *)nginx_binary, "-T", NULL};

    if (output == NULL || output_size == 0) {
        set_error(error, error_size, "a dump buffer is required");
        return -1;
    }
    output[0] = '\0';
    if (run_live_command(
            nginx_binary, arguments, "configuration dump", output, output_size, error, error_size
        ) != 0) {
        return -1;
    }
    if (strlen(output) == output_size - 1) {
        set_error(error, error_size, "the Nginx configuration dump exceeds %zu bytes", output_size - 1);
        return -1;
    }
    return 0;
}

int wardd_nginx_dropin_path(
    const char *conf_dir,
    char *output,
    size_t output_size,
    char *error,
    size_t error_size
)
{
    struct stat status;

    if (conf_dir == NULL || conf_dir[0] != '/' || output == NULL) {
        set_error(error, error_size, "nginx.conf_dir must be an absolute path");
        return -1;
    }
    if (lstat(conf_dir, &status) != 0 || !S_ISDIR(status.st_mode)) {
        set_error(error, error_size, "%s is not a directory; is Nginx installed?", conf_dir);
        return -1;
    }
    if (snprintf(output, output_size, "%s/wardd.conf", conf_dir) >= (int)output_size) {
        set_error(error, error_size, "the Nginx drop-in path is too long");
        return -1;
    }
    return 0;
}

static int read_small_file(const char *path, char *output, size_t output_size, bool *found)
{
    FILE *file = fopen(path, "r");
    size_t bytes;

    *found = false;
    output[0] = '\0';
    if (file == NULL) return errno == ENOENT ? 0 : -1;
    bytes = fread(output, 1, output_size - 1, file);
    output[bytes] = '\0';
    if (ferror(file) != 0) {
        (void)fclose(file);
        return -1;
    }
    (void)fclose(file);
    *found = true;
    return 0;
}

int wardd_nginx_enable(
    const char *nginx_binary,
    const char *conf_dir,
    const char *generated_directory,
    char *error,
    size_t error_size
)
{
    char dropin_path[NGINX_PATH_SIZE];
    char include_path[NGINX_PATH_SIZE];
    char quoted_include[NGINX_PATH_SIZE * 2];
    char contents[NGINX_PATH_SIZE * 3];
    char previous[NGINX_PATH_SIZE * 3];
    bool had_previous = false;

    if (error != NULL && error_size > 0) error[0] = '\0';
    if (nginx_binary == NULL || nginx_binary[0] == '\0' || generated_directory == NULL ||
        generated_directory[0] != '/') {
        set_error(error, error_size, "an Nginx binary and an absolute generated directory are required");
        return -1;
    }
    if (wardd_nginx_dropin_path(conf_dir, dropin_path, sizeof(dropin_path), error, error_size) != 0) {
        return -1;
    }
    if (snprintf(include_path, sizeof(include_path), "%s/wardd-geo.conf", generated_directory) >=
            (int)sizeof(include_path) ||
        quote_nginx_path(include_path, quoted_include, sizeof(quoted_include)) != 0) {
        set_error(error, error_size, "the generated http include path is too long or unsafe");
        return -1;
    }
    if (snprintf(
            contents,
            sizeof(contents),
            "# Generated by wardd; remove with: wardctl nginx disable\n"
            "# This belongs in the http block, which is where Nginx includes this\n"
            "# directory by default. The per-server include is a separate manual step.\n"
            "include %s;\n",
            quoted_include
        ) >= (int)sizeof(contents)) {
        set_error(error, error_size, "the generated Nginx drop-in is too large");
        return -1;
    }
    if (read_small_file(dropin_path, previous, sizeof(previous), &had_previous) != 0) {
        set_error(error, error_size, "cannot read %s: %s", dropin_path, strerror(errno));
        return -1;
    }
    if (had_previous && strcmp(previous, contents) == 0) {
        return wardd_nginx_test_live(nginx_binary, error, error_size);
    }
    if (replace_file(dropin_path, contents, error, error_size) != 0) return -1;
    if (wardd_nginx_test_live(nginx_binary, error, error_size) != 0) {
        /*
         * Leaving a drop-in behind that Nginx refuses to load would break the
         * next unrelated reload, so a failed check puts the tree back exactly
         * as it was before returning the failure.
         */
        if (had_previous) (void)replace_file(dropin_path, previous, NULL, 0);
        else (void)unlink(dropin_path);
        return -1;
    }
    return 0;
}

int wardd_nginx_disable(
    const char *nginx_binary,
    const char *conf_dir,
    char *error,
    size_t error_size
)
{
    char dropin_path[NGINX_PATH_SIZE];
    char previous[NGINX_PATH_SIZE * 3];
    bool had_previous = false;

    if (error != NULL && error_size > 0) error[0] = '\0';
    if (wardd_nginx_dropin_path(conf_dir, dropin_path, sizeof(dropin_path), error, error_size) != 0) {
        return -1;
    }
    if (read_small_file(dropin_path, previous, sizeof(previous), &had_previous) != 0) {
        set_error(error, error_size, "cannot read %s: %s", dropin_path, strerror(errno));
        return -1;
    }
    if (!had_previous) return 0;
    if (unlink(dropin_path) != 0) {
        set_error(error, error_size, "cannot remove %s: %s", dropin_path, strerror(errno));
        return -1;
    }
    if (wardd_nginx_test_live(nginx_binary, error, error_size) != 0) {
        (void)replace_file(dropin_path, previous, NULL, 0);
        return -1;
    }
    return 1;
}
