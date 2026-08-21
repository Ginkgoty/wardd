#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
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

static int write_config(const char *path, const char *directory, const char *event_log)
{
    FILE *file = fopen(path, "wx");
    if (file == NULL) return -1;
    const int status = fprintf(
        file,
        "version = 1\n\n"
        "[geo]\ncountry = \"CN\"\nprovider = \"mmdb\"\n"
        "url = \"https://rules.example.test/country-lite.mmdb\"\n"
        "checksum_url = \"https://rules.example.test/country-lite.mmdb.sha256sum\"\n"
        "update_interval = \"24h\"\nmax_age = \"14d\"\nmax_download_size = \"32MiB\"\n"
        "max_change_ratio = 0.20\n\n"
        "[xdp]\nenabled = false\ninterface = \"warddtest0\"\nattach_mode = \"off\"\n"
        "generic_fallback = false\ngeo_action = \"observe\"\nban_action = \"observe\"\n\n"
        "[ban]\nprotected_tcp_ports = [22, 80, 443]\nexempt = []\n\n"
        "[ban.auto]\nenabled = true\nevent_source = \"nginx_limit_req\"\nwindow = \"60s\"\n"
        "rejections = 3\nfirst_duration = \"10m\"\nsecond_duration = \"1h\"\n"
        "third_duration = \"24h\"\nstrike_retention = \"7d\"\n\n"
        "[nginx]\nenabled = true\ngenerated_dir = \"%s/generated\"\n"
        "limit_event_log = \"%s\"\nlimit_zone = \"api\"\n\n"
        "[firewall]\nownership = \"none\"\nmanage = false\n",
        directory,
        event_log
    );
    if (status < 0) {
        (void)fclose(file);
        return -1;
    }
    return fclose(file) == 0 ? 0 : -1;
}

static int send_command(const char *socket_path, const char *command, char *response, size_t response_size)
{
    struct sockaddr_un address = {0};
    int descriptor = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    size_t used = 0;

    if (descriptor < 0) return -1;
    if (strlen(socket_path) >= sizeof(address.sun_path)) {
        (void)close(descriptor);
        return -1;
    }
    address.sun_family = AF_UNIX;
    (void)snprintf(address.sun_path, sizeof(address.sun_path), "%s", socket_path);
    if (connect(descriptor, (struct sockaddr *)&address, sizeof(address)) != 0 ||
        dprintf(descriptor, "%s\n", command) < 0 || shutdown(descriptor, SHUT_WR) != 0) {
        (void)close(descriptor);
        return -1;
    }
    while (used + 1 < response_size) {
        ssize_t bytes = read(descriptor, response + used, response_size - used - 1);
        if (bytes < 0 && errno == EINTR) continue;
        if (bytes <= 0) break;
        used += (size_t)bytes;
    }
    response[used] = '\0';
    (void)close(descriptor);
    return 0;
}

static int append_events(const char *path, unsigned long long epoch)
{
    FILE *file = fopen(path, "a");
    if (file == NULL) return -1;
    for (int index = 1; index <= 3; ++index) {
        if (fprintf(
                file,
                "{\"schema\":1,\"peer\":\"8.8.4.4\",\"server\":\"service.example.com\","
                "\"zone\":\"api\",\"status\":\"REJECTED\",\"request_id\":\"daemon-%d\","
                "\"epoch\":\"%llu.000\"}\n",
                index,
                epoch
            ) < 0) {
            (void)fclose(file);
            return -1;
        }
    }
    if (fflush(file) != 0) {
        (void)fclose(file);
        return -1;
    }
    return fclose(file) == 0 ? 0 : -1;
}

static bool file_contains(const char *path, const char *needle)
{
    char buffer[4096];
    FILE *file = fopen(path, "r");
    if (file == NULL) return false;
    const size_t bytes = fread(buffer, 1, sizeof(buffer) - 1, file);
    buffer[bytes] = '\0';
    (void)fclose(file);
    return strstr(buffer, needle) != NULL;
}

int main(void)
{
    char directory[] = "/tmp/wardd-daemon-events-test-XXXXXX";
    char config[512];
    char socket_path[512];
    char event_log[512];
    char ban_state[512];
    char auto_state[512];
    char audit_log[512];
    char cursor[512];
    char pin_root[512];
    char response[4096];
    pid_t child = -1;
    int child_status = 0;
    const time_t now = time(NULL);

    CHECK(mkdtemp(directory) != NULL, "create daemon event test directory");
    (void)snprintf(config, sizeof(config), "%s/wardd.toml", directory);
    (void)snprintf(socket_path, sizeof(socket_path), "%s/wardd.sock", directory);
    (void)snprintf(event_log, sizeof(event_log), "%s/events.log", directory);
    (void)snprintf(ban_state, sizeof(ban_state), "%s/bans.state", directory);
    (void)snprintf(auto_state, sizeof(auto_state), "%s/auto.state", directory);
    (void)snprintf(audit_log, sizeof(audit_log), "%s/audit.jsonl", directory);
    (void)snprintf(cursor, sizeof(cursor), "%s/cursor", directory);
    (void)snprintf(pin_root, sizeof(pin_root), "%s/no-bpf", directory);
    CHECK(write_config(config, directory, event_log) == 0, "write daemon integration config");
    CHECK(now > 1 && append_events(event_log, (unsigned long long)now - 1U) == 0,
        "create non-empty initial event log fixture");
    /* The first start intentionally tails the pre-existing content above. */

    child = fork();
    if (child == 0) {
        execl(
            WARDD_TEST_DAEMON,
            WARDD_TEST_DAEMON,
            "--config", config,
            "--socket", socket_path,
            "--ban-state", ban_state,
            "--auto-state", auto_state,
            "--audit-log", audit_log,
            "--event-cursor", cursor,
            "--pin-root", pin_root,
            (char *)NULL
        );
        _exit(127);
    }
    CHECK(child > 0, "start wardd event daemon");
    for (int attempt = 0; attempt < 120 && access(socket_path, F_OK) != 0; ++attempt) pause_short();
    CHECK(access(socket_path, F_OK) == 0, "daemon control socket is ready");
    for (int attempt = 0; attempt < 120 && access(cursor, F_OK) != 0; ++attempt) pause_short();
    CHECK(access(cursor, F_OK) == 0, "daemon establishes initial tail cursor");
    CHECK(now > 0 && append_events(event_log, (unsigned long long)now) == 0, "append structured Nginx events");
    for (int attempt = 0; attempt < 160 && !file_contains(ban_state, "8.8.4.4"); ++attempt) pause_short();
    CHECK(file_contains(ban_state, "8.8.4.4"), "daemon creates durable ban from third rejection");
    /* The ban is persisted before the audit record is appended and before the
       processed counter advances, because the audit record states an outcome
       that is only known once the live apply has been attempted. Waiting on the
       ban state alone therefore observes the daemon mid-decision; poll for the
       later steps rather than assuming they have already happened. */
    for (int attempt = 0;
        attempt < 160 && !file_contains(audit_log, "\"outcome\":\"durable_pending\"");
        ++attempt) pause_short();
    CHECK(file_contains(audit_log, "\"outcome\":\"durable_pending\""), "daemon appends audit event");
    int status_result = -1;
    for (int attempt = 0; attempt < 160; ++attempt) {
        status_result = send_command(socket_path, "STATUS TEXT", response, sizeof(response));
        if (status_result != 0 || strstr(response, "Nginx events processed: 3") != NULL) break;
        pause_short();
    }
    CHECK(status_result == 0, "read daemon status");
    CHECK(strstr(response, "Nginx event ingestion: healthy") != NULL &&
        strstr(response, "Nginx events processed: 3") != NULL,
        "daemon reports healthy Nginx ingestion");
    CHECK(send_command(socket_path, "SHUTDOWN", response, sizeof(response)) == 0, "stop daemon");
    for (int attempt = 0; attempt < 120; ++attempt) {
        const pid_t waited = waitpid(child, &child_status, WNOHANG);
        if (waited == child) {
            child = -1;
            break;
        }
        pause_short();
    }
    CHECK(child < 0 && WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0,
        "daemon exits cleanly");
    if (child > 0) {
        (void)kill(child, SIGTERM);
        (void)waitpid(child, NULL, 0);
    }

    static const char *const names[] = {
        "wardd.toml", "wardd.sock", "events.log", "bans.state", "bans.state.lock",
        "auto.state", "auto.state.lock", "audit.jsonl", "cursor"
    };
    for (size_t index = 0; index < sizeof(names) / sizeof(names[0]); ++index) {
        char path[768];
        (void)snprintf(path, sizeof(path), "%s/%s", directory, names[index]);
        (void)unlink(path);
    }
    (void)rmdir(directory);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
