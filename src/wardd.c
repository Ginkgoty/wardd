#include "wardd/config.h"
#include "wardd/auto_ban.h"
#include "wardd/geo.h"
#include "wardd/nginx_events.h"
#include "wardd/runtime.h"
#include "wardd/snapshot.h"
#include "wardd/version.h"
#include "wardd/xdp.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define DEFAULT_CONFIG_PATH "/etc/wardd/wardd.toml"
#define DEFAULT_SOCKET_PATH "/run/wardd/wardd.sock"
#define DEFAULT_SNAPSHOT_ROOT "/var/lib/wardd/snapshots"
#define DEFAULT_BAN_STATE "/var/lib/wardd/bans.state"
#define DEFAULT_AUTO_BAN_STATE "/var/lib/wardd/auto-ban.state"
#define DEFAULT_AUDIT_LOG "/var/lib/wardd/audit.jsonl"
#define DEFAULT_EVENT_CURSOR "/var/lib/wardd/nginx-events.cursor"
#define DEFAULT_BPF_PIN_ROOT "/sys/fs/bpf/wardd"
#define REQUEST_SIZE 256

static volatile sig_atomic_t stopping;

struct daemon_runtime {
    bool event_enabled;
    bool event_degraded;
    bool event_paused;
    uint64_t events_processed;
    uint64_t events_rejected_logged;
    uint64_t last_event_epoch;
    const char *auto_state;
    struct wardd_nginx_event_reader reader;
    struct wardd_runtime_paths paths;
    struct wardd_auto_apply_context apply;
};

static void handle_signal(int signal_number)
{
    (void)signal_number;
    stopping = 1;
}

static void usage(FILE *stream)
{
    fprintf(
        stream,
        "Usage: wardd [--config PATH] [--socket PATH] [--ban-state PATH] [--auto-state PATH]\n"
        "             [--audit-log PATH] [--event-cursor PATH] [--pin-root PATH]\n"
        "             [--check-config] [--version]\n"
    );
}

static int prepare_socket_path(const char *path)
{
    struct stat status;
    struct sockaddr_un address = {0};
    int probe_fd;

    if (lstat(path, &status) != 0) {
        return errno == ENOENT ? 0 : -1;
    }
    if (!S_ISSOCK(status.st_mode) || status.st_uid != geteuid()) {
        errno = EEXIST;
        return -1;
    }

    probe_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (probe_fd < 0) {
        return -1;
    }
    address.sun_family = AF_UNIX;
    (void)snprintf(address.sun_path, sizeof(address.sun_path), "%s", path);
    if (connect(probe_fd, (struct sockaddr *)&address, sizeof(address)) == 0) {
        (void)close(probe_fd);
        errno = EADDRINUSE;
        return -1;
    }
    const int connect_errno = errno;
    (void)close(probe_fd);
    if (connect_errno != ECONNREFUSED && connect_errno != ENOENT) {
        errno = connect_errno;
        return -1;
    }
    return unlink(path);
}

static int create_server_socket(const char *path)
{
    struct sockaddr_un address = {0};
    int server_fd;

    if (strlen(path) >= sizeof(address.sun_path)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    if (prepare_socket_path(path) != 0) {
        return -1;
    }

    server_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (server_fd < 0) {
        return -1;
    }

    address.sun_family = AF_UNIX;
    (void)snprintf(address.sun_path, sizeof(address.sun_path), "%s", path);
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) != 0 ||
        chmod(path, 0600) != 0 ||
        listen(server_fd, 16) != 0) {
        const int saved_errno = errno;
        (void)close(server_fd);
        (void)unlink(path);
        errno = saved_errno;
        return -1;
    }
    return server_fd;
}

/*
 * Defense in depth. The socket is already created 0600 under a 0750 runtime
 * directory, but SHUTDOWN is an unauthenticated kill switch for anyone who
 * does reach it, and --socket can place the socket outside that directory.
 */
static bool peer_is_authorized(int client_fd)
{
    struct ucred credentials;
    socklen_t length = sizeof(credentials);

    if (getsockopt(client_fd, SOL_SOCKET, SO_PEERCRED, &credentials, &length) != 0 ||
        length != sizeof(credentials)) {
        return false;
    }
    return credentials.uid == 0 || credentials.uid == geteuid();
}

static int read_request(int client_fd, char *buffer, size_t buffer_size)
{
    size_t used = 0;

    while (used + 1 < buffer_size) {
        ssize_t received = read(client_fd, buffer + used, buffer_size - used - 1);
        if (received < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (received == 0) {
            break;
        }
        used += (size_t)received;
        if (memchr(buffer, '\n', used) != NULL) {
            break;
        }
    }
    buffer[used] = '\0';
    char *newline = strchr(buffer, '\n');
    if (newline != NULL) {
        *newline = '\0';
    }
    return 0;
}

/*
 * Attachment always programs observe mode, so config->xdp.{geo,ban}_action is
 * the administrator's intent, not what the kernel is enforcing. Report both:
 * a status line that echoes only the configured value tells an operator that
 * enforcement is on while every packet is still being passed.
 */
enum effective_action_state {
    EFFECTIVE_NOT_ATTACHED = 0,
    EFFECTIVE_UNKNOWN,
    EFFECTIVE_KNOWN,
};

static enum effective_action_state read_effective_actions(
    const struct wardd_config *config,
    const struct daemon_runtime *runtime,
    struct wardd_xdp_actions *actions
)
{
    struct wardd_xdp_status xdp_status;
    const char *pin_root = runtime->paths.bpf_pin_root != NULL
        ? runtime->paths.bpf_pin_root
        : DEFAULT_BPF_PIN_ROOT;

    if (wardd_xdp_get_status(config->xdp.interface, &xdp_status, NULL, 0) != 0) return EFFECTIVE_UNKNOWN;
    if (!xdp_status.wardd_attached || xdp_status.legacy) return EFFECTIVE_NOT_ATTACHED;
    if (wardd_xdp_read_actions(pin_root, actions, NULL, 0) != 0) return EFFECTIVE_UNKNOWN;
    return EFFECTIVE_KNOWN;
}

static const char *effective_action_name(
    enum effective_action_state state,
    enum wardd_action action
)
{
    if (state == EFFECTIVE_NOT_ATTACHED) return "not_attached";
    if (state == EFFECTIVE_UNKNOWN) return "unknown";
    return wardd_action_name(action);
}

static void respond_status_text(
    int client_fd,
    const struct wardd_config *config,
    const struct daemon_runtime *runtime
)
{
    struct wardd_snapshot_status snapshot_status;
    struct wardd_xdp_status xdp_status;
    char snapshot_error[256];
    const bool have_snapshot_status = wardd_geo_snapshot_status(
        DEFAULT_SNAPSHOT_ROOT,
        &snapshot_status,
        snapshot_error,
        sizeof(snapshot_error)
    ) == 0;
    const bool have_xdp_status = wardd_xdp_get_status(
        config->xdp.interface,
        &xdp_status,
        NULL,
        0
    ) == 0;
    struct wardd_xdp_actions effective = {WARDD_ACTION_OBSERVE, WARDD_ACTION_OBSERVE};
    const enum effective_action_state effective_state = read_effective_actions(config, runtime, &effective);

    (void)dprintf(
        client_fd,
        "Daemon: running\n"
        "Version: %s\n"
        "Config schema: %u\n"
        "Country: %s\n"
        "XDP configured: %s\n"
        "XDP attached: %s\n"
        "XDP active mode: %s\n"
        "XDP attach preference: %s\n"
        "Geo action: %s (configured) / %s (effective)\n"
        "Ban action: %s (configured) / %s (effective)\n"
        "Automatic ban: %s\n"
        "Nginx event ingestion: %s\n"
        "Nginx events processed: %llu\n"
        "Nginx events rejected: %llu\n"
        "MMDB compiler: %s\n"
        "Geo snapshot: %s\n"
        "Firewall ownership: %s (unmanaged)\n"
        "Runtime phase: GeoIP control plane and explicit libxdp management\n",
        WARDD_VERSION,
        config->version,
        config->geo.country,
        config->xdp.enabled ? "yes" : "no",
        have_xdp_status && xdp_status.wardd_attached ? "yes" : "no",
        have_xdp_status && xdp_status.attached ? xdp_status.mode : "none",
        wardd_attach_mode_name(config->xdp.attach_mode),
        wardd_action_name(config->xdp.geo_action),
        effective_action_name(effective_state, effective.geo_action),
        wardd_action_name(config->xdp.ban_action),
        effective_action_name(effective_state, effective.ban_action),
        config->ban.automatic.enabled ? "enabled" : "disabled",
        !runtime->event_enabled ? "disabled" : runtime->event_degraded ? "degraded" : "healthy",
        (unsigned long long)runtime->events_processed,
        (unsigned long long)runtime->reader.rejected_events,
        wardd_geo_mmdb_available() ? "available" : "unavailable",
        !have_snapshot_status || snapshot_status.current[0] == '\0' ? "not_ready" : snapshot_status.current,
        wardd_firewall_ownership_name(config->firewall.ownership)
    );
}

static void respond_status_json(
    int client_fd,
    const struct wardd_config *config,
    const struct daemon_runtime *runtime
)
{
    struct wardd_snapshot_status snapshot_status;
    struct wardd_xdp_status xdp_status;
    char snapshot_error[256];
    const bool have_snapshot_status = wardd_geo_snapshot_status(
        DEFAULT_SNAPSHOT_ROOT,
        &snapshot_status,
        snapshot_error,
        sizeof(snapshot_error)
    ) == 0;
    const bool have_xdp_status = wardd_xdp_get_status(
        config->xdp.interface,
        &xdp_status,
        NULL,
        0
    ) == 0;
    struct wardd_xdp_actions effective = {WARDD_ACTION_OBSERVE, WARDD_ACTION_OBSERVE};
    const enum effective_action_state effective_state = read_effective_actions(config, runtime, &effective);

    (void)dprintf(
        client_fd,
        "{\"daemon\":\"running\",\"version\":\"%s\","
        "\"config_schema\":%u,\"country\":\"%s\","
        "\"xdp_configured\":%s,\"xdp_attached\":%s,"
        "\"xdp_mode\":\"%s\","
        "\"attach_preference\":\"%s\",\"geo_action\":\"%s\","
        "\"ban_action\":\"%s\","
        "\"geo_action_effective\":\"%s\",\"ban_action_effective\":\"%s\","
        "\"mmdb_compiler\":%s,"
        "\"automatic_ban_enabled\":%s,\"nginx_event_ingestion\":\"%s\","
        "\"nginx_events_processed\":%llu,"
        "\"nginx_events_rejected\":%llu,"
        "\"geo_snapshot\":\"%s\","
        "\"firewall_ownership\":\"%s\","
        "\"firewall_managed\":false,\"runtime_phase\":\"geo_xdp_control_plane\"}\n",
        WARDD_VERSION,
        config->version,
        config->geo.country,
        config->xdp.enabled ? "true" : "false",
        have_xdp_status && xdp_status.wardd_attached ? "true" : "false",
        have_xdp_status && xdp_status.attached ? xdp_status.mode : "none",
        wardd_attach_mode_name(config->xdp.attach_mode),
        wardd_action_name(config->xdp.geo_action),
        wardd_action_name(config->xdp.ban_action),
        effective_action_name(effective_state, effective.geo_action),
        effective_action_name(effective_state, effective.ban_action),
        wardd_geo_mmdb_available() ? "true" : "false",
        config->ban.automatic.enabled ? "true" : "false",
        !runtime->event_enabled ? "disabled" : runtime->event_degraded ? "degraded" : "healthy",
        (unsigned long long)runtime->events_processed,
        (unsigned long long)runtime->reader.rejected_events,
        !have_snapshot_status || snapshot_status.current[0] == '\0' ? "not_ready" : snapshot_status.current,
        wardd_firewall_ownership_name(config->firewall.ownership)
    );
}

static void handle_client(
    int client_fd,
    const struct wardd_config *config,
    const struct daemon_runtime *runtime
)
{
    char request[REQUEST_SIZE];

    if (read_request(client_fd, request, sizeof(request)) != 0) {
        return;
    }
    if (strcmp(request, "PING") == 0) {
        (void)dprintf(client_fd, "PONG\n");
    } else if (strcmp(request, "STATUS TEXT") == 0) {
        respond_status_text(client_fd, config, runtime);
    } else if (strcmp(request, "STATUS JSON") == 0) {
        respond_status_json(client_fd, config, runtime);
    } else if (strcmp(request, "SHUTDOWN") == 0) {
        (void)dprintf(client_fd, "OK shutting down\n");
        stopping = 1;
    } else {
        (void)dprintf(client_fd, "ERROR unsupported command\n");
    }
}

static int handle_nginx_event(
    const struct wardd_auto_ban_event *event,
    void *opaque,
    char *error,
    size_t error_size
)
{
    struct daemon_runtime *runtime = opaque;
    struct wardd_auto_ban_decision decision;
    const time_t now = time(NULL);

    if (now < 0) {
        (void)snprintf(error, error_size, "cannot read realtime clock for Nginx event");
        return -1;
    }
    runtime->apply.outcome[0] = '\0';
    if (wardd_auto_ban_process(
            &runtime->apply.config->ban,
            runtime->auto_state,
            event,
            (uint64_t)now,
            wardd_runtime_apply_automatic_ban,
            &runtime->apply,
            &decision,
            error,
            error_size
        ) != 0) return -1;
    runtime->events_processed++;
    runtime->last_event_epoch = event->event_realtime_seconds;
    if (decision.disposition == WARDD_AUTO_BAN_TRIGGERED) {
        fprintf(
            stderr,
            "wardd: automatic ban peer=%s zone=%s count=%llu strike=%llu duration=%llu outcome=%s\n",
            decision.network,
            event->zone,
            (unsigned long long)decision.window_count,
            (unsigned long long)decision.strike,
            (unsigned long long)decision.duration_seconds,
            runtime->apply.outcome
        );
    }
    return 0;
}

int main(int argc, char **argv)
{
    const char *config_path = DEFAULT_CONFIG_PATH;
    const char *socket_path = DEFAULT_SOCKET_PATH;
    const char *ban_state = DEFAULT_BAN_STATE;
    const char *auto_state = DEFAULT_AUTO_BAN_STATE;
    const char *audit_log = DEFAULT_AUDIT_LOG;
    const char *event_cursor = DEFAULT_EVENT_CURSOR;
    const char *pin_root = DEFAULT_BPF_PIN_ROOT;
    bool check_config = false;
    struct wardd_config config;
    char error[512];
    int server_fd;
    struct sigaction action = {0};
    struct daemon_runtime runtime = {0};

    runtime.reader.descriptor = -1;

    for (int index = 1; index < argc; index++) {
        if (strcmp(argv[index], "--config") == 0 && index + 1 < argc) {
            config_path = argv[++index];
        } else if (strcmp(argv[index], "--socket") == 0 && index + 1 < argc) {
            socket_path = argv[++index];
        } else if (strcmp(argv[index], "--ban-state") == 0 && index + 1 < argc) {
            ban_state = argv[++index];
        } else if (strcmp(argv[index], "--auto-state") == 0 && index + 1 < argc) {
            auto_state = argv[++index];
        } else if (strcmp(argv[index], "--audit-log") == 0 && index + 1 < argc) {
            audit_log = argv[++index];
        } else if (strcmp(argv[index], "--event-cursor") == 0 && index + 1 < argc) {
            event_cursor = argv[++index];
        } else if (strcmp(argv[index], "--pin-root") == 0 && index + 1 < argc) {
            pin_root = argv[++index];
        } else if (strcmp(argv[index], "--check-config") == 0) {
            check_config = true;
        } else if (strcmp(argv[index], "--version") == 0) {
            printf("wardd %s\n", WARDD_VERSION);
            return EXIT_SUCCESS;
        } else if (strcmp(argv[index], "--help") == 0) {
            usage(stdout);
            return EXIT_SUCCESS;
        } else {
            usage(stderr);
            return EXIT_FAILURE;
        }
    }

    if (wardd_config_load(config_path, &config, error, sizeof(error)) != 0) {
        fprintf(stderr, "wardd: invalid configuration: %s\n", error);
        return EXIT_FAILURE;
    }
    if (check_config) {
        printf("configuration is valid: %s\n", config_path);
        return EXIT_SUCCESS;
    }

    runtime.event_enabled = config.ban.automatic.enabled && config.nginx.enabled;
    runtime.auto_state = auto_state;
    runtime.paths = (struct wardd_runtime_paths){
        .ban_state = ban_state,
        .bpf_pin_root = pin_root,
        .audit_log = audit_log,
    };
    runtime.apply = (struct wardd_auto_apply_context){.config = &config, .paths = &runtime.paths};
    if (runtime.event_enabled && wardd_nginx_event_reader_init(
            &runtime.reader,
            config.nginx.limit_event_log,
            event_cursor,
            error,
            sizeof(error)
        ) != 0) {
        fprintf(stderr, "wardd: cannot initialize Nginx event reader: %s\n", error);
        return EXIT_FAILURE;
    }

    (void)umask(0077);
    server_fd = create_server_socket(socket_path);
    if (server_fd < 0) {
        fprintf(stderr, "wardd: cannot create control socket %s: %s\n", socket_path, strerror(errno));
        return EXIT_FAILURE;
    }

    action.sa_handler = handle_signal;
    (void)sigemptyset(&action.sa_mask);
    (void)sigaction(SIGINT, &action, NULL);
    (void)sigaction(SIGTERM, &action, NULL);

    fprintf(stderr, "wardd %s running; control socket %s\n", WARDD_VERSION, socket_path);
    while (!stopping) {
        struct pollfd descriptor = {.fd = server_fd, .events = POLLIN};
        const int timeout = runtime.event_enabled && !runtime.event_paused ? 250 : -1;
        const int poll_status = poll(&descriptor, 1, timeout);
        if (poll_status < 0) {
            if (errno == EINTR) continue;
            fprintf(stderr, "wardd: control poll failed: %s\n", strerror(errno));
            break;
        }
        if (poll_status > 0 && (descriptor.revents & POLLIN) != 0) {
            int client_fd = accept(server_fd, NULL, NULL);
            if (client_fd < 0) {
                if (errno == EINTR) continue;
                fprintf(stderr, "wardd: accept failed: %s\n", strerror(errno));
                break;
            }
            (void)fcntl(client_fd, F_SETFD, FD_CLOEXEC);
            if (peer_is_authorized(client_fd)) {
                handle_client(client_fd, &config, &runtime);
            } else {
                (void)dprintf(client_fd, "ERROR unauthorized\n");
            }
            (void)close(client_fd);
        }
        if (runtime.event_enabled && !runtime.event_paused) {
            size_t processed = 0;
            errno = 0;
            if (wardd_nginx_event_reader_step(
                    &runtime.reader,
                    handle_nginx_event,
                    &runtime,
                    256,
                    &processed,
                    error,
                    sizeof(error)
                ) != 0) {
                const int reader_errno = errno;
                if (!runtime.event_degraded) fprintf(stderr, "wardd: Nginx event ingestion degraded: %s\n", error);
                runtime.event_degraded = true;
                if (!(runtime.reader.descriptor < 0 && reader_errno == ENOENT)) {
                    runtime.event_paused = true;
                    fprintf(stderr, "wardd: automatic Nginx event bans paused until daemon restart\n");
                }
            } else if (runtime.event_degraded) {
                runtime.event_degraded = false;
                fprintf(stderr, "wardd: Nginx event ingestion recovered\n");
            }
            if (runtime.reader.rejected_events > runtime.events_rejected_logged) {
                fprintf(
                    stderr,
                    "wardd: skipped %llu malformed Nginx event line(s) (total %llu, last: %s)\n",
                    (unsigned long long)(runtime.reader.rejected_events - runtime.events_rejected_logged),
                    (unsigned long long)runtime.reader.rejected_events,
                    runtime.reader.last_reject_reason
                );
                runtime.events_rejected_logged = runtime.reader.rejected_events;
            }
        }
    }

    wardd_nginx_event_reader_close(&runtime.reader);
    (void)close(server_fd);
    (void)unlink(socket_path);
    return EXIT_SUCCESS;
}
