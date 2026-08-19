#include "wardd/audit.h"
#include "wardd/auto_ban.h"
#include "wardd/ban.h"
#include "wardd/config.h"
#include "wardd/fetch.h"
#include "wardd/geo.h"
#include "wardd/nginx.h"
#include "wardd/runtime.h"
#include "wardd/snapshot.h"
#include "wardd/version.h"
#include "wardd/xdp.h"

#include <errno.h>
#include <net/if.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#define DEFAULT_CONFIG_PATH "/etc/wardd/wardd.toml"
#define DEFAULT_SOCKET_PATH "/run/wardd/wardd.sock"
#define DEFAULT_SNAPSHOT_ROOT "/var/lib/wardd/snapshots"
#define DEFAULT_NGINX_BINARY "nginx"
#ifndef WARDD_DEFAULT_BPF_OBJECT
#define WARDD_DEFAULT_BPF_OBJECT "/usr/lib/wardd/wardd.bpf.o"
#endif
#define DEFAULT_BPF_OBJECT WARDD_DEFAULT_BPF_OBJECT
#define DEFAULT_BPF_PIN_ROOT "/sys/fs/bpf/wardd"
#define DEFAULT_BAN_STATE "/var/lib/wardd/bans.state"
#define DEFAULT_AUTO_BAN_STATE "/var/lib/wardd/auto-ban.state"
#define DEFAULT_AUDIT_LOG "/var/lib/wardd/audit.jsonl"

struct command_options {
    const char *config_path;
    const char *snapshot_root;
    const char *nginx_binary;
    const char *bpf_object;
    const char *bpf_pin_root;
    const char *ban_state;
    const char *auto_ban_state;
    const char *audit_log;
};

static void usage(FILE *stream)
{
    fprintf(
        stream,
        "Usage:\n"
        "  wardctl [--socket PATH] status [--json]\n"
        "  wardctl [--socket PATH] shutdown\n"
        "  wardctl config validate [PATH]\n"
        "  wardctl geo compile MMDB OUTPUT_DIR [--country CC]\n"
        "  wardctl geo import MMDB [--config PATH] [--state-dir PATH]\n"
        "  wardctl geo update [--config PATH] [--state-dir PATH]\n"
        "  wardctl geo status [--state-dir PATH]\n"
        "  wardctl geo diff SNAPSHOT [--state-dir PATH]\n"
        "  wardctl geo approve SNAPSHOT [--state-dir PATH]\n"
        "  wardctl geo activate SNAPSHOT [--reload] [--config PATH] [--state-dir PATH] [--nginx PATH]\n"
        "  wardctl geo rollback [--reload] [--config PATH] [--state-dir PATH] [--nginx PATH]\n"
        "  wardctl nginx render [--config PATH]\n"
        "  wardctl nginx check [SNAPSHOT] [--state-dir PATH] [--nginx PATH]\n"
        "  wardctl xdp status [--config PATH]\n"
        "  wardctl xdp attach --observe [--config PATH] [--state-dir PATH] [--object PATH] [--pin-root PATH]\n"
        "  wardctl xdp set-action geo|ban observe|enforce [--config PATH] [--pin-root PATH]\n"
        "  wardctl xdp sync-geo [--config PATH] [--state-dir PATH] [--pin-root PATH]\n"
        "  wardctl xdp metrics [--pin-root PATH]\n"
        "  wardctl xdp detach [--config PATH] [--pin-root PATH]\n"
        "  wardctl ban add IP|CIDR (--duration D|--permanent) [--config PATH] [--pin-root PATH] [--ban-state PATH]\n"
        "  wardctl ban remove IP|CIDR [--config PATH] [--pin-root PATH] [--ban-state PATH]\n"
        "  wardctl ban list [--ban-state PATH]\n"
        "  wardctl ban sync [--config PATH] [--pin-root PATH] [--ban-state PATH]\n"
        "  wardctl ban event PEER REJECTED SERVER ZONE REQUEST_ID EPOCH --confirmed-peer [OPTIONS]\n"
        "  wardctl doctor [--config PATH]\n"
        "  wardctl --version\n"
    );
}

static int parse_command_options(
    int argc,
    char **argv,
    int start,
    struct command_options *options
)
{
    options->config_path = DEFAULT_CONFIG_PATH;
    options->snapshot_root = DEFAULT_SNAPSHOT_ROOT;
    options->nginx_binary = DEFAULT_NGINX_BINARY;
    options->bpf_object = DEFAULT_BPF_OBJECT;
    options->bpf_pin_root = DEFAULT_BPF_PIN_ROOT;
    options->ban_state = DEFAULT_BAN_STATE;
    options->auto_ban_state = DEFAULT_AUTO_BAN_STATE;
    options->audit_log = DEFAULT_AUDIT_LOG;

    while (start < argc) {
        if (start + 1 >= argc) return -1;
        if (strcmp(argv[start], "--config") == 0) {
            options->config_path = argv[start + 1];
        } else if (strcmp(argv[start], "--state-dir") == 0) {
            options->snapshot_root = argv[start + 1];
        } else if (strcmp(argv[start], "--nginx") == 0) {
            options->nginx_binary = argv[start + 1];
        } else if (strcmp(argv[start], "--object") == 0) {
            options->bpf_object = argv[start + 1];
        } else if (strcmp(argv[start], "--pin-root") == 0) {
            options->bpf_pin_root = argv[start + 1];
        } else if (strcmp(argv[start], "--ban-state") == 0) {
            options->ban_state = argv[start + 1];
        } else if (strcmp(argv[start], "--auto-state") == 0) {
            options->auto_ban_state = argv[start + 1];
        } else if (strcmp(argv[start], "--audit-log") == 0) {
            options->audit_log = argv[start + 1];
        } else {
            return -1;
        }
        start += 2;
    }
    return 0;
}

static int connect_control_socket(const char *path)
{
    struct sockaddr_un address = {0};
    int socket_fd;

    if (strlen(path) >= sizeof(address.sun_path)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    socket_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (socket_fd < 0) {
        return -1;
    }
    address.sun_family = AF_UNIX;
    (void)snprintf(address.sun_path, sizeof(address.sun_path), "%s", path);
    if (connect(socket_fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        const int saved_errno = errno;
        (void)close(socket_fd);
        errno = saved_errno;
        return -1;
    }
    return socket_fd;
}

static int send_command(const char *socket_path, const char *command)
{
    int socket_fd = connect_control_socket(socket_path);
    char buffer[4096];

    if (socket_fd < 0) {
        fprintf(stderr, "wardctl: cannot connect to %s: %s\n", socket_path, strerror(errno));
        return EXIT_FAILURE;
    }
    if (dprintf(socket_fd, "%s\n", command) < 0 || shutdown(socket_fd, SHUT_WR) != 0) {
        fprintf(stderr, "wardctl: cannot send command: %s\n", strerror(errno));
        (void)close(socket_fd);
        return EXIT_FAILURE;
    }

    for (;;) {
        ssize_t received = read(socket_fd, buffer, sizeof(buffer));
        if (received < 0) {
            if (errno == EINTR) continue;
            fprintf(stderr, "wardctl: cannot read response: %s\n", strerror(errno));
            (void)close(socket_fd);
            return EXIT_FAILURE;
        }
        if (received == 0) break;
        if (fwrite(buffer, 1, (size_t)received, stdout) != (size_t)received) {
            (void)close(socket_fd);
            return EXIT_FAILURE;
        }
    }
    (void)close(socket_fd);
    return EXIT_SUCCESS;
}

static int validate_config_command(const char *path)
{
    struct wardd_config config;
    char error[512];

    if (wardd_config_load(path, &config, error, sizeof(error)) != 0) {
        fprintf(stderr, "invalid configuration: %s\n", error);
        return EXIT_FAILURE;
    }
    printf(
        "configuration is valid: schema=%u country=%s endpoints=%zu firewall=%s\n",
        config.version,
        config.geo.country,
        config.xdp.endpoint_count,
        wardd_firewall_ownership_name(config.firewall.ownership)
    );
    return EXIT_SUCCESS;
}

static int doctor_command(const char *path)
{
    struct wardd_config config;
    struct wardd_snapshot_status snapshot_status;
    struct utsname system_info;
    char error[512];
    bool warning = false;

    if (wardd_config_load(path, &config, error, sizeof(error)) != 0) {
        fprintf(stderr, "Config: invalid (%s)\n", error);
        return EXIT_FAILURE;
    }
    printf("Config: valid (schema %u)\n", config.version);
    printf("MMDB compiler: %s\n", wardd_geo_mmdb_available() ? "available" : "unavailable");
    printf("Firewall ownership: %s, managed: no\n", wardd_firewall_ownership_name(config.firewall.ownership));
    if (uname(&system_info) == 0) {
        printf("Kernel: %s %s %s\n", system_info.sysname, system_info.release, system_info.machine);
    } else {
        printf("Kernel: unavailable (%s)\n", strerror(errno));
        warning = true;
    }
    printf(
        "Kernel BTF: %s\n",
        access("/sys/kernel/btf/vmlinux", R_OK) == 0 ? "available" : "unavailable"
    );
    printf("Nginx: %s\n", access("/usr/sbin/nginx", X_OK) == 0 ? "available" : "unavailable");
    if (wardd_geo_snapshot_status(DEFAULT_SNAPSHOT_ROOT, &snapshot_status, error, sizeof(error)) == 0) {
        printf(
            "Geo snapshot: %s (%zu stored)\n",
            snapshot_status.current[0] == '\0' ? "not_ready" : snapshot_status.current,
            snapshot_status.snapshot_count
        );
    } else {
        printf("Geo snapshot: unavailable (%s)\n", error);
        warning = true;
    }

    if (config.xdp.enabled) {
        unsigned int interface_index = if_nametoindex(config.xdp.interface);
        struct wardd_xdp_status xdp_status;
        if (interface_index == 0) {
            printf("XDP interface: %s (not present)\n", config.xdp.interface);
            warning = true;
        } else {
            printf("XDP interface: %s (ifindex %u)\n", config.xdp.interface, interface_index);
            if (wardd_xdp_get_status(config.xdp.interface, &xdp_status, error, sizeof(error)) == 0) {
                printf(
                    "XDP live state: %s%s%s\n",
                    xdp_status.attached ? "attached" : "none",
                    xdp_status.attached ? ", mode=" : "",
                    xdp_status.attached ? xdp_status.mode : ""
                );
            } else {
                printf("XDP live state: unavailable (%s)\n", error);
                warning = true;
            }
        }
        if (access("/sys/fs/bpf", R_OK | X_OK) == 0) {
            printf("bpffs: accessible\n");
        } else {
            printf("bpffs: unavailable (%s)\n", strerror(errno));
            warning = true;
        }
    } else {
        printf("XDP: disabled by configuration\n");
    }

    printf("Live mutation policy: XDP requires explicit wardctl; host/cloud firewall management is disabled\n");
    return warning ? 2 : EXIT_SUCCESS;
}

static int geo_compile_command(const char *mmdb_path, const char *output_directory, const char *country)
{
    char ipv4_path[1024];
    char ipv6_path[1024];
    char nginx_path[1024];
    char error[512];
    struct wardd_geo_compile_result result;
    int lengths[3];

    lengths[0] = snprintf(ipv4_path, sizeof(ipv4_path), "%s/cn-v4.txt", output_directory);
    lengths[1] = snprintf(ipv6_path, sizeof(ipv6_path), "%s/cn-v6.txt", output_directory);
    lengths[2] = snprintf(nginx_path, sizeof(nginx_path), "%s/nginx-cn.conf", output_directory);
    for (size_t index = 0; index < 3; index++) {
        if (lengths[index] < 0 || lengths[index] >= (int)sizeof(ipv4_path)) {
            fprintf(stderr, "wardctl: output path is too long\n");
            return EXIT_FAILURE;
        }
    }

    if (wardd_geo_compile_mmdb(
            mmdb_path,
            country,
            ipv4_path,
            ipv6_path,
            nginx_path,
            &result,
            error,
            sizeof(error)
        ) != 0) {
        fprintf(stderr, "wardctl: MMDB compilation failed: %s\n", error);
        return EXIT_FAILURE;
    }
    printf(
        "compiled country=%s ipv4=%zu ipv6=%zu database=%s build_epoch=%llu\n",
        country,
        result.ipv4_prefixes,
        result.ipv6_prefixes,
        result.database_type,
        (unsigned long long)result.build_epoch
    );
    return EXIT_SUCCESS;
}

static int load_config(const char *path, struct wardd_config *config)
{
    char error[512];

    if (wardd_config_load(path, config, error, sizeof(error)) != 0) {
        fprintf(stderr, "wardctl: invalid configuration: %s\n", error);
        return -1;
    }
    return 0;
}

static void print_snapshot_result(const struct wardd_snapshot_result *result)
{
    printf(
        "snapshot=%s state=%s source_sha256=%s ipv4=%zu ipv6=%zu",
        result->id,
        result->pending_review ? "pending_review" : "approved",
        result->source_sha256,
        result->compile.ipv4_prefixes,
        result->compile.ipv6_prefixes
    );
    if (result->existed) printf(" existing=yes");
    if (result->diff.old_prefixes != 0 || result->diff.new_prefixes != 0) {
        printf(
            " added=%zu removed=%zu change_ratio=%.6f",
            result->diff.added_prefixes,
            result->diff.removed_prefixes,
            result->diff.change_ratio
        );
    }
    putchar('\n');
}

static int geo_import_command(const char *mmdb_path, const struct command_options *options)
{
    struct wardd_config config;
    struct wardd_snapshot_result result;
    char error[1024];

    if (load_config(options->config_path, &config) != 0) return EXIT_FAILURE;
    if (wardd_geo_snapshot_create(
            mmdb_path,
            config.geo.country,
            options->snapshot_root,
            config.geo.max_download_bytes,
            config.geo.max_change_ratio,
            &result,
            error,
            sizeof(error)
        ) != 0) {
        fprintf(stderr, "wardctl: cannot import GeoIP snapshot: %s\n", error);
        return EXIT_FAILURE;
    }
    print_snapshot_result(&result);
    return EXIT_SUCCESS;
}

static int geo_update_command(const struct command_options *options)
{
    struct wardd_config config;
    struct wardd_fetch_result fetch_result;
    struct wardd_snapshot_result snapshot_result;
    char directory[] = "/tmp/wardd-geo-update-XXXXXX";
    char mmdb_path[256];
    char checksum_path[256];
    char digest[WARDD_SHA256_HEX_LEN];
    char error[1024];
    int return_value = EXIT_FAILURE;

    if (load_config(options->config_path, &config) != 0) return EXIT_FAILURE;
    (void)umask(0077);
    if (mkdtemp(directory) == NULL ||
        snprintf(mmdb_path, sizeof(mmdb_path), "%s/source.mmdb", directory) >= (int)sizeof(mmdb_path) ||
        snprintf(checksum_path, sizeof(checksum_path), "%s/source.sha256sum", directory) >=
            (int)sizeof(checksum_path)) {
        fprintf(stderr, "wardctl: cannot create private update directory: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }
    if (wardd_https_download(
            config.geo.checksum_url,
            checksum_path,
            64U * 1024U,
            NULL,
            error,
            sizeof(error)
        ) != 0 ||
        wardd_https_download(
            config.geo.url,
            mmdb_path,
            config.geo.max_download_bytes,
            &fetch_result,
            error,
            sizeof(error)
        ) != 0 ||
        wardd_verify_sha256(mmdb_path, checksum_path, digest, error, sizeof(error)) != 0) {
        fprintf(stderr, "wardctl: GeoIP update rejected: %s\n", error);
        goto done;
    }
    if (wardd_geo_snapshot_create(
            mmdb_path,
            config.geo.country,
            options->snapshot_root,
            config.geo.max_download_bytes,
            config.geo.max_change_ratio,
            &snapshot_result,
            error,
            sizeof(error)
        ) != 0) {
        fprintf(stderr, "wardctl: cannot create GeoIP snapshot: %s\n", error);
        goto done;
    }
    printf(
        "downloaded=%llu verified_sha256=%s ",
        (unsigned long long)fetch_result.bytes,
        digest
    );
    print_snapshot_result(&snapshot_result);
    return_value = EXIT_SUCCESS;

done:
    (void)unlink(mmdb_path);
    (void)unlink(checksum_path);
    (void)rmdir(directory);
    return return_value;
}

static int geo_status_command(const struct command_options *options)
{
    struct wardd_snapshot_status status;
    char error[512];

    if (wardd_geo_snapshot_status(options->snapshot_root, &status, error, sizeof(error)) != 0) {
        fprintf(stderr, "wardctl: cannot read GeoIP status: %s\n", error);
        return EXIT_FAILURE;
    }
    printf(
        "snapshots=%zu current=%s previous=%s current_approved=%s\n",
        status.snapshot_count,
        status.current[0] == '\0' ? "none" : status.current,
        status.previous[0] == '\0' ? "none" : status.previous,
        status.current_approved ? "yes" : "no"
    );
    return EXIT_SUCCESS;
}

static int geo_diff_command(const char *new_id, const struct command_options *options)
{
    struct wardd_snapshot_status status;
    struct wardd_geo_diff diff;
    char error[512];

    if (wardd_geo_snapshot_status(options->snapshot_root, &status, error, sizeof(error)) != 0 ||
        status.current[0] == '\0') {
        fprintf(
            stderr,
            "wardctl: cannot diff without a current snapshot%s%s\n",
            error[0] == '\0' ? "" : ": ",
            error
        );
        return EXIT_FAILURE;
    }
    if (wardd_geo_snapshot_diff(
            options->snapshot_root,
            status.current,
            new_id,
            &diff,
            error,
            sizeof(error)
        ) != 0) {
        fprintf(stderr, "wardctl: cannot diff snapshots: %s\n", error);
        return EXIT_FAILURE;
    }
    printf(
        "from=%s to=%s old=%zu new=%zu added=%zu removed=%zu change_ratio=%.6f\n",
        status.current,
        new_id,
        diff.old_prefixes,
        diff.new_prefixes,
        diff.added_prefixes,
        diff.removed_prefixes,
        diff.change_ratio
    );
    return EXIT_SUCCESS;
}

static int geo_approve_command(const char *id, const struct command_options *options)
{
    char error[512];

    if (wardd_geo_snapshot_approve(options->snapshot_root, id, error, sizeof(error)) != 0) {
        fprintf(stderr, "wardctl: cannot approve snapshot: %s\n", error);
        return EXIT_FAILURE;
    }
    printf("approved snapshot=%s\n", id);
    return EXIT_SUCCESS;
}

static int geo_activate_command(
    const char *id,
    const struct command_options *options,
    bool rollback,
    bool reload_live
)
{
    struct wardd_config config;
    char error[2048];
    const char *generated_directory;
    const char *nginx_binary;
    int result;

    if (load_config(options->config_path, &config) != 0) return EXIT_FAILURE;
    if (reload_live && !config.nginx.enabled) {
        fprintf(stderr, "wardctl: --reload requires enabled Nginx integration\n");
        return EXIT_FAILURE;
    }
    generated_directory = config.nginx.enabled ? config.nginx.generated_dir : NULL;
    nginx_binary = config.nginx.enabled ? options->nginx_binary : NULL;
    if (config.nginx.enabled &&
        wardd_nginx_render(
            config.nginx.generated_dir,
            config.nginx.limit_event_log,
            config.nginx.limit_zone,
            error,
            sizeof(error)
        ) != 0) {
        fprintf(stderr, "wardctl: cannot render Nginx integration: %s\n", error);
        return EXIT_FAILURE;
    }
    if (reload_live) {
        result = rollback ? wardd_geo_snapshot_rollback_live(
            options->snapshot_root,
            generated_directory,
            nginx_binary,
            error,
            sizeof(error)
        ) : wardd_geo_snapshot_activate_live(
            options->snapshot_root,
            generated_directory,
            id,
            nginx_binary,
            error,
            sizeof(error)
        );
    } else {
        result = rollback ? wardd_geo_snapshot_rollback(
            options->snapshot_root,
            generated_directory,
            nginx_binary,
            error,
            sizeof(error)
        ) : wardd_geo_snapshot_activate(
            options->snapshot_root,
            generated_directory,
            id,
            nginx_binary,
            error,
            sizeof(error)
        );
    }
    if (result != 0) {
        fprintf(stderr, "wardctl: cannot %s snapshot: %s\n", rollback ? "rollback" : "activate", error);
        return EXIT_FAILURE;
    }
    printf("%s snapshot%s%s", rollback ? "rolled back" : "activated", rollback ? "" : "=", rollback ? "" : id);
    if (reload_live) {
        printf("; live nginx -t and reload succeeded");
    } else if (config.nginx.enabled) {
        printf("; isolated nginx -t passed; live Nginx reload was not performed");
    }
    putchar('\n');
    return EXIT_SUCCESS;
}

static int nginx_render_command(const struct command_options *options)
{
    struct wardd_config config;
    char error[512];

    if (load_config(options->config_path, &config) != 0) return EXIT_FAILURE;
    if (!config.nginx.enabled) {
        fprintf(stderr, "wardctl: Nginx integration is disabled\n");
        return EXIT_FAILURE;
    }
    if (wardd_nginx_render(
            config.nginx.generated_dir,
            config.nginx.limit_event_log,
            config.nginx.limit_zone,
            error,
            sizeof(error)
        ) != 0) {
        fprintf(stderr, "wardctl: cannot render Nginx integration: %s\n", error);
        return EXIT_FAILURE;
    }
    char generated_include[WARDD_PATH_LEN + 64];
    if (snprintf(
            generated_include,
            sizeof(generated_include),
            "%s/wardd-geo.conf",
            config.nginx.generated_dir
        ) >= (int)sizeof(generated_include) ||
        wardd_nginx_check_http_include(
            options->nginx_binary, generated_include, error, sizeof(error)
        ) != 0) {
        fprintf(stderr, "wardctl: generated Nginx integration is invalid: %s\n", error);
        return EXIT_FAILURE;
    }
    printf(
        "rendered and isolated-tested wardd-owned Nginx includes in %s; live configuration unchanged\n",
        config.nginx.generated_dir
    );
    return EXIT_SUCCESS;
}

static int safe_snapshot_id(const char *id)
{
    if (id == NULL || id[0] == '\0' || strlen(id) >= WARDD_SNAPSHOT_ID_LEN || id[0] == '.') return 0;
    for (const unsigned char *cursor = (const unsigned char *)id; *cursor != '\0'; ++cursor) {
        if (!((*cursor >= 'a' && *cursor <= 'z') || (*cursor >= 'A' && *cursor <= 'Z') ||
              (*cursor >= '0' && *cursor <= '9') || *cursor == '-' || *cursor == '_' || *cursor == '.')) {
            return 0;
        }
    }
    return 1;
}

static int nginx_check_command(const char *id, const struct command_options *options)
{
    struct wardd_snapshot_status status;
    char include_path[2048];
    char error[2048];

    if (id == NULL) {
        if (wardd_geo_snapshot_status(options->snapshot_root, &status, error, sizeof(error)) != 0 ||
            status.current[0] == '\0') {
            fprintf(stderr, "wardctl: no current snapshot to check\n");
            return EXIT_FAILURE;
        }
        id = status.current;
    }
    if (!safe_snapshot_id(id) ||
        snprintf(
            include_path,
            sizeof(include_path),
            "%s/%s/nginx-cn.conf",
            options->snapshot_root,
            id
        ) >= (int)sizeof(include_path)) {
        fprintf(stderr, "wardctl: invalid snapshot ID\n");
        return EXIT_FAILURE;
    }
    if (wardd_nginx_check_include(options->nginx_binary, include_path, error, sizeof(error)) != 0) {
        fprintf(stderr, "wardctl: %s\n", error);
        return EXIT_FAILURE;
    }
    printf("isolated nginx -t passed for snapshot=%s; live configuration unchanged\n", id);
    return EXIT_SUCCESS;
}

static int xdp_status_command(const struct command_options *options)
{
    struct wardd_config config;
    struct wardd_xdp_status status;
    char error[1024];

    if (load_config(options->config_path, &config) != 0) return EXIT_FAILURE;
    if (wardd_xdp_get_status(config.xdp.interface, &status, error, sizeof(error)) != 0) {
        fprintf(stderr, "wardctl: cannot inspect XDP: %s\n", error);
        return EXIT_FAILURE;
    }
    printf(
        "interface=%s ifindex=%u attached=%s mode=%s programs=%u legacy=%s wardd=%s wardd_program_id=%u\n",
        config.xdp.interface,
        status.interface_index,
        status.attached ? "yes" : "no",
        status.attached ? status.mode : "none",
        status.program_count,
        status.legacy ? "yes" : "no",
        status.wardd_attached ? "yes" : "no",
        status.wardd_program_id
    );
    return EXIT_SUCCESS;
}

struct ban_sync_context {
    const char *interface_name;
    const char *pin_root;
    uint64_t now_realtime_seconds;
    size_t synced;
    char error[1024];
};

static int sync_stored_ban(const char *network, uint64_t expiry, void *opaque)
{
    struct ban_sync_context *context = opaque;
    uint64_t duration = 0;

    if (expiry != 0) {
        if (expiry <= context->now_realtime_seconds) return 0;
        duration = expiry - context->now_realtime_seconds;
    }
    if (wardd_xdp_ban_add(
            context->interface_name,
            context->pin_root,
            network,
            duration,
            context->error,
            sizeof(context->error)
        ) != 0) return -1;
    context->synced++;
    return 0;
}

static int sync_ban_state(
    const struct wardd_config *config,
    const struct command_options *options,
    size_t *synced,
    size_t *pruned,
    char *error,
    size_t error_size
)
{
    struct ban_sync_context context = {
        .interface_name = config->xdp.interface,
        .pin_root = options->bpf_pin_root,
    };
    const time_t now = time(NULL);
    size_t active;

    if (now < 0) {
        (void)snprintf(error, error_size, "cannot read realtime clock");
        return -1;
    }
    context.now_realtime_seconds = (uint64_t)now;
    if (wardd_ban_store_visit(
            options->ban_state,
            context.now_realtime_seconds,
            true,
            sync_stored_ban,
            &context,
            &active,
            pruned,
            error,
            error_size
        ) != 0) {
        if (context.error[0] != '\0') (void)snprintf(error, error_size, "%s", context.error);
        return -1;
    }
    if (synced != NULL) *synced = context.synced;
    return 0;
}

static int xdp_attach_command(const struct command_options *options)
{
    struct wardd_config config;
    struct wardd_xdp_attach_result result;
    size_t restored = 0;
    size_t pruned = 0;
    char error[2048];

    if (load_config(options->config_path, &config) != 0) return EXIT_FAILURE;
    if (wardd_xdp_attach_observe(
            options->bpf_object,
            options->bpf_pin_root,
            options->snapshot_root,
            &config,
            &result,
            error,
            sizeof(error)
        ) != 0) {
        fprintf(stderr, "wardctl: XDP attach failed safely: %s\n", error);
        return EXIT_FAILURE;
    }
    if (sync_ban_state(&config, options, &restored, &pruned, error, sizeof(error)) != 0) {
        char detach_error[1024];
        (void)wardd_xdp_detach(
            config.xdp.interface,
            options->bpf_pin_root,
            detach_error,
            sizeof(detach_error)
        );
        fprintf(stderr, "wardctl: XDP attach rolled back because durable bans could not be restored: %s\n", error);
        return EXIT_FAILURE;
    }
    printf(
        "attached wardd program_id=%u interface=%s ifindex=%u mode=%s "
        "geo_action=observe ban_action=observe ipv4=%zu ipv6=%zu restored_bans=%zu pruned_bans=%zu\n",
        result.program_id,
        config.xdp.interface,
        result.interface_index,
        result.mode,
        result.ipv4_prefixes,
        result.ipv6_prefixes,
        restored,
        pruned
    );
    return EXIT_SUCCESS;
}

static int xdp_detach_command(const struct command_options *options)
{
    struct wardd_config config;
    char error[1024];

    if (load_config(options->config_path, &config) != 0) return EXIT_FAILURE;
    if (wardd_xdp_detach(config.xdp.interface, options->bpf_pin_root, error, sizeof(error)) != 0) {
        fprintf(stderr, "wardctl: XDP detach refused or failed: %s\n", error);
        return EXIT_FAILURE;
    }
    printf("detached only the pinned wardd XDP program from interface=%s\n", config.xdp.interface);
    return EXIT_SUCCESS;
}

static int xdp_set_action_command(
    const char *policy,
    const char *action_name,
    const struct command_options *options
)
{
    struct wardd_config config;
    enum wardd_action action;
    char error[1024];

    if (strcmp(action_name, "observe") == 0) action = WARDD_ACTION_OBSERVE;
    else if (strcmp(action_name, "enforce") == 0) action = WARDD_ACTION_ENFORCE;
    else {
        fprintf(stderr, "wardctl: action must be observe or enforce\n");
        return EXIT_FAILURE;
    }
    if (strcmp(policy, "geo") != 0 && strcmp(policy, "ban") != 0) {
        fprintf(stderr, "wardctl: policy must be geo or ban\n");
        return EXIT_FAILURE;
    }
    if (load_config(options->config_path, &config) != 0) return EXIT_FAILURE;
    if (wardd_xdp_set_action(
            config.xdp.interface,
            options->bpf_pin_root,
            strcmp(policy, "geo") == 0,
            action,
            error,
            sizeof(error)
        ) != 0) {
        fprintf(stderr, "wardctl: cannot change XDP action: %s\n", error);
        return EXIT_FAILURE;
    }
    printf("updated XDP policy=%s action=%s interface=%s\n", policy, action_name, config.xdp.interface);
    return EXIT_SUCCESS;
}

static int xdp_metrics_command(const struct command_options *options)
{
    static const char *const names[WARDD_STAT_COUNT] = {
        "pass_cn",
        "pass_non_endpoint",
        "pass_parse_unsupported",
        "would_drop_geo",
        "drop_geo_non_cn",
        "would_drop_ban",
        "drop_ban_exact",
        "drop_ban_cidr",
        "parse_error",
    };
    uint64_t counters[WARDD_STAT_COUNT];
    char error[1024];

    if (wardd_xdp_read_metrics(options->bpf_pin_root, counters, error, sizeof(error)) != 0) {
        fprintf(stderr, "wardctl: cannot read XDP metrics: %s\n", error);
        return EXIT_FAILURE;
    }
    for (size_t index = 0; index < WARDD_STAT_COUNT; ++index) {
        printf("%s=%llu%s", names[index], (unsigned long long)counters[index],
            index + 1 == WARDD_STAT_COUNT ? "\n" : " ");
    }
    return EXIT_SUCCESS;
}

static int xdp_sync_geo_command(const struct command_options *options)
{
    struct wardd_config config;
    size_t ipv4_prefixes;
    size_t ipv6_prefixes;
    char error[1024];

    if (load_config(options->config_path, &config) != 0) return EXIT_FAILURE;
    if (wardd_xdp_sync_geo(
            config.xdp.interface,
            options->bpf_pin_root,
            options->snapshot_root,
            &ipv4_prefixes,
            &ipv6_prefixes,
            error,
            sizeof(error)
        ) != 0) {
        fprintf(stderr, "wardctl: cannot sync XDP GeoIP maps: %s\n", error);
        return EXIT_FAILURE;
    }
    printf(
        "atomically switched XDP GeoIP maps interface=%s ipv4=%zu ipv6=%zu\n",
        config.xdp.interface,
        ipv4_prefixes,
        ipv6_prefixes
    );
    return EXIT_SUCCESS;
}

static int parse_cli_duration(const char *text, uint64_t *seconds)
{
    char *end;
    unsigned long long value;
    uint64_t multiplier;

    if (text == NULL || text[0] == '\0') return -1;
    errno = 0;
    value = strtoull(text, &end, 10);
    if (errno != 0 || end == text || value == 0 || end[0] == '\0' || end[1] != '\0') return -1;
    if (*end == 's') multiplier = 1;
    else if (*end == 'm') multiplier = 60;
    else if (*end == 'h') multiplier = 60 * 60;
    else if (*end == 'd') multiplier = 24 * 60 * 60;
    else return -1;
    if (value > UINT64_MAX / multiplier) return -1;
    *seconds = (uint64_t)value * multiplier;
    return 0;
}

static int ban_add_command(
    const char *network,
    uint64_t duration_seconds,
    const struct command_options *options
)
{
    struct wardd_config config;
    struct wardd_xdp_status status;
    char normalized[WARDD_BAN_NETWORK_LEN];
    char error[1024];
    const time_t now = time(NULL);

    if (load_config(options->config_path, &config) != 0) return EXIT_FAILURE;
    if (now < 0 || wardd_ban_store_upsert(
            options->ban_state,
            network,
            duration_seconds,
            (uint64_t)now,
            normalized,
            error,
            sizeof(error)
        ) != 0) {
        fprintf(stderr, "wardctl: cannot persist ban: %s\n", now < 0 ? "cannot read realtime clock" : error);
        return EXIT_FAILURE;
    }
    if (wardd_xdp_get_status(config.xdp.interface, &status, error, sizeof(error)) != 0) {
        printf("added ban=%s%s durable=yes live=pending reason=xdp-unavailable\n",
            normalized, duration_seconds == 0 ? " permanent=yes" : "");
        return EXIT_SUCCESS;
    }
    if (status.wardd_attached && wardd_xdp_ban_add(
            config.xdp.interface,
            options->bpf_pin_root,
            normalized,
            duration_seconds,
            error,
            sizeof(error)
        ) != 0) {
        fprintf(stderr, "wardctl: persisted ban=%s but live XDP sync failed: %s\n", normalized, error);
        return EXIT_FAILURE;
    }
    if (duration_seconds == 0) printf("added permanent ban=%s", normalized);
    else printf("added ban=%s duration_seconds=%llu", normalized, (unsigned long long)duration_seconds);
    printf(" durable=yes live=%s\n", status.wardd_attached ? "applied" : "pending");
    return EXIT_SUCCESS;
}

static int ban_remove_command(const char *network, const struct command_options *options)
{
    struct wardd_config config;
    struct wardd_xdp_status status;
    char normalized[WARDD_BAN_NETWORK_LEN];
    char error[1024];

    if (load_config(options->config_path, &config) != 0) return EXIT_FAILURE;
    if (wardd_ban_store_remove(
            options->ban_state,
            network,
            normalized,
            error,
            sizeof(error)
        ) != 0) {
        fprintf(stderr, "wardctl: cannot remove durable ban: %s\n", error);
        return EXIT_FAILURE;
    }
    if (wardd_xdp_get_status(config.xdp.interface, &status, error, sizeof(error)) != 0) {
        printf("removed ban=%s durable=yes live=pending reason=xdp-unavailable\n", normalized);
        return EXIT_SUCCESS;
    }
    if (status.wardd_attached && wardd_xdp_ban_remove(
            config.xdp.interface,
            options->bpf_pin_root,
            normalized,
            error,
            sizeof(error)
        ) != 0) {
        fprintf(stderr, "wardctl: removed durable ban=%s but live XDP sync failed: %s\n", normalized, error);
        return EXIT_FAILURE;
    }
    printf("removed ban=%s durable=yes live=%s\n", normalized, status.wardd_attached ? "removed" : "not-attached");
    return EXIT_SUCCESS;
}

struct ban_list_context {
    uint64_t now_realtime_seconds;
    size_t count;
};

static int print_ban(const char *network, uint64_t expires_realtime_seconds, void *opaque)
{
    struct ban_list_context *context = opaque;

    printf("network=%s ", network);
    if (expires_realtime_seconds == 0) {
        printf("state=active expires=permanent\n");
    } else {
        printf(
            "state=active expires_epoch=%llu remaining_seconds=%llu\n",
            (unsigned long long)expires_realtime_seconds,
            (unsigned long long)(expires_realtime_seconds - context->now_realtime_seconds)
        );
    }
    context->count++;
    return 0;
}

static int ban_list_command(const struct command_options *options)
{
    struct ban_list_context context = {0};
    const time_t now = time(NULL);
    char error[1024];
    size_t pruned = 0;

    if (now < 0) {
        fprintf(stderr, "wardctl: cannot read realtime clock\n");
        return EXIT_FAILURE;
    }
    context.now_realtime_seconds = (uint64_t)now;
    if (wardd_ban_store_visit(
            options->ban_state,
            context.now_realtime_seconds,
            true,
            print_ban,
            &context,
            NULL,
            &pruned,
            error,
            sizeof(error)
        ) != 0) {
        fprintf(stderr, "wardctl: cannot list durable bans: %s\n", error);
        return EXIT_FAILURE;
    }
    printf("total=%zu pruned=%zu state=%s\n", context.count, pruned, options->ban_state);
    return EXIT_SUCCESS;
}

static int ban_sync_command(const struct command_options *options)
{
    struct wardd_config config;
    struct wardd_xdp_status status;
    size_t synced = 0;
    size_t pruned = 0;
    char error[1024];

    if (load_config(options->config_path, &config) != 0) return EXIT_FAILURE;
    if (wardd_xdp_get_status(config.xdp.interface, &status, error, sizeof(error)) != 0 ||
        !status.wardd_attached) {
        fprintf(stderr, "wardctl: cannot sync bans without an attached wardd XDP program%s%s\n",
            error[0] == '\0' ? "" : ": ", error);
        return EXIT_FAILURE;
    }
    if (sync_ban_state(&config, options, &synced, &pruned, error, sizeof(error)) != 0) {
        fprintf(stderr, "wardctl: cannot sync durable bans: %s\n", error);
        return EXIT_FAILURE;
    }
    printf("synced_bans=%zu pruned_bans=%zu interface=%s\n", synced, pruned, config.xdp.interface);
    return EXIT_SUCCESS;
}

static int parse_epoch(const char *text, uint64_t *epoch)
{
    char *end;
    unsigned long long value;
    if (text == NULL || text[0] == '\0') return -1;
    errno = 0;
    value = strtoull(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value == 0) return -1;
    *epoch = (uint64_t)value;
    return 0;
}

static int ban_event_command(
    const char *peer,
    const char *status_name,
    const char *server,
    const char *zone,
    const char *request_id,
    const char *epoch_text,
    const struct command_options *options
)
{
    struct wardd_config config;
    struct wardd_auto_ban_event event = {0};
    struct wardd_auto_ban_decision decision;
    struct wardd_runtime_paths runtime_paths;
    struct wardd_auto_apply_context apply_context;
    const time_t now = time(NULL);
    char error[1024];

    if (strcmp(status_name, "REJECTED") != 0 || parse_epoch(epoch_text, &event.event_realtime_seconds) != 0) {
        fprintf(stderr, "wardctl: automatic ban event requires status REJECTED and a positive epoch\n");
        return EXIT_FAILURE;
    }
    if (strlen(peer) >= sizeof(event.peer) || strlen(server) >= sizeof(event.server) ||
        strlen(zone) >= sizeof(event.zone) || strlen(request_id) >= sizeof(event.request_id) || now < 0) {
        fprintf(stderr, "wardctl: automatic ban event fields are too long or clock is unavailable\n");
        return EXIT_FAILURE;
    }
    (void)snprintf(event.peer, sizeof(event.peer), "%s", peer);
    (void)snprintf(event.server, sizeof(event.server), "%s", server);
    (void)snprintf(event.zone, sizeof(event.zone), "%s", zone);
    (void)snprintf(event.request_id, sizeof(event.request_id), "%s", request_id);
    event.limiter_rejected = true;
    event.confirmed_peer = true;
    if (load_config(options->config_path, &config) != 0) return EXIT_FAILURE;
    runtime_paths = (struct wardd_runtime_paths){
        .ban_state = options->ban_state,
        .bpf_pin_root = options->bpf_pin_root,
        .audit_log = options->audit_log,
    };
    apply_context = (struct wardd_auto_apply_context){.config = &config, .paths = &runtime_paths};
    if (wardd_auto_ban_process(
            &config.ban,
            options->auto_ban_state,
            &event,
            (uint64_t)now,
            wardd_runtime_apply_automatic_ban,
            &apply_context,
            &decision,
            error,
            sizeof(error)
        ) != 0) {
        fprintf(stderr, "wardctl: automatic ban event failed: %s\n", error);
        return EXIT_FAILURE;
    }
    printf(
        "auto_ban=%s peer=%s window_count=%llu strike=%llu duration_seconds=%llu%s%s\n",
        wardd_auto_ban_disposition_name(decision.disposition),
        decision.network[0] == '\0' ? peer : decision.network,
        (unsigned long long)decision.window_count,
        (unsigned long long)decision.strike,
        (unsigned long long)decision.duration_seconds,
        decision.disposition == WARDD_AUTO_BAN_TRIGGERED ? " outcome=" : "",
        decision.disposition == WARDD_AUTO_BAN_TRIGGERED ? apply_context.outcome : ""
    );
    return EXIT_SUCCESS;
}

int main(int argc, char **argv)
{
    const char *socket_path = DEFAULT_SOCKET_PATH;
    int index = 1;

    while (index < argc) {
        if (strcmp(argv[index], "--socket") == 0 && index + 1 < argc) {
            socket_path = argv[index + 1];
            index += 2;
        } else if (strcmp(argv[index], "--version") == 0) {
            printf("wardctl %s\n", WARDD_VERSION);
            return EXIT_SUCCESS;
        } else if (strcmp(argv[index], "--help") == 0) {
            usage(stdout);
            return EXIT_SUCCESS;
        } else {
            break;
        }
    }

    if (index >= argc) {
        usage(stderr);
        return EXIT_FAILURE;
    }
    if (strcmp(argv[index], "status") == 0) {
        const bool json = index + 1 < argc && strcmp(argv[index + 1], "--json") == 0;
        if (index + (json ? 2 : 1) != argc) {
            usage(stderr);
            return EXIT_FAILURE;
        }
        return send_command(socket_path, json ? "STATUS JSON" : "STATUS TEXT");
    }
    if (strcmp(argv[index], "shutdown") == 0) {
        if (index + 1 != argc) {
            usage(stderr);
            return EXIT_FAILURE;
        }
        return send_command(socket_path, "SHUTDOWN");
    }
    if (strcmp(argv[index], "config") == 0 && index + 1 < argc &&
        strcmp(argv[index + 1], "validate") == 0) {
        const char *path = index + 2 < argc ? argv[index + 2] : DEFAULT_CONFIG_PATH;
        if (index + (index + 2 < argc ? 3 : 2) != argc) {
            usage(stderr);
            return EXIT_FAILURE;
        }
        return validate_config_command(path);
    }
    if (strcmp(argv[index], "geo") == 0 && index + 3 < argc &&
        strcmp(argv[index + 1], "compile") == 0) {
        const char *country = "CN";
        if (index + 4 < argc) {
            if (strcmp(argv[index + 4], "--country") != 0 || index + 5 >= argc || index + 6 != argc) {
                usage(stderr);
                return EXIT_FAILURE;
            }
            country = argv[index + 5];
        } else if (index + 4 != argc) {
            usage(stderr);
            return EXIT_FAILURE;
        }
        return geo_compile_command(argv[index + 2], argv[index + 3], country);
    }
    if (strcmp(argv[index], "geo") == 0 && index + 1 < argc) {
        struct command_options options;
        const char *operation = argv[index + 1];

        if (strcmp(operation, "import") == 0 && index + 2 < argc) {
            if (parse_command_options(argc, argv, index + 3, &options) != 0) {
                usage(stderr);
                return EXIT_FAILURE;
            }
            return geo_import_command(argv[index + 2], &options);
        }
        if (strcmp(operation, "update") == 0) {
            if (parse_command_options(argc, argv, index + 2, &options) != 0) {
                usage(stderr);
                return EXIT_FAILURE;
            }
            return geo_update_command(&options);
        }
        if (strcmp(operation, "status") == 0) {
            if (parse_command_options(argc, argv, index + 2, &options) != 0) {
                usage(stderr);
                return EXIT_FAILURE;
            }
            return geo_status_command(&options);
        }
        if (strcmp(operation, "diff") == 0 && index + 2 < argc) {
            if (parse_command_options(argc, argv, index + 3, &options) != 0) {
                usage(stderr);
                return EXIT_FAILURE;
            }
            return geo_diff_command(argv[index + 2], &options);
        }
        if (strcmp(operation, "approve") == 0 && index + 2 < argc) {
            if (parse_command_options(argc, argv, index + 3, &options) != 0) {
                usage(stderr);
                return EXIT_FAILURE;
            }
            return geo_approve_command(argv[index + 2], &options);
        }
        if (strcmp(operation, "activate") == 0 && index + 2 < argc) {
            const bool reload_live = index + 3 < argc && strcmp(argv[index + 3], "--reload") == 0;
            if (parse_command_options(argc, argv, index + 3 + (reload_live ? 1 : 0), &options) != 0) {
                usage(stderr);
                return EXIT_FAILURE;
            }
            return geo_activate_command(argv[index + 2], &options, false, reload_live);
        }
        if (strcmp(operation, "rollback") == 0) {
            const bool reload_live = index + 2 < argc && strcmp(argv[index + 2], "--reload") == 0;
            if (parse_command_options(argc, argv, index + 2 + (reload_live ? 1 : 0), &options) != 0) {
                usage(stderr);
                return EXIT_FAILURE;
            }
            return geo_activate_command(NULL, &options, true, reload_live);
        }
    }
    if (strcmp(argv[index], "nginx") == 0 && index + 1 < argc) {
        struct command_options options;
        const char *operation = argv[index + 1];

        if (strcmp(operation, "render") == 0) {
            if (parse_command_options(argc, argv, index + 2, &options) != 0) {
                usage(stderr);
                return EXIT_FAILURE;
            }
            return nginx_render_command(&options);
        }
        if (strcmp(operation, "check") == 0) {
            const char *snapshot_id = NULL;
            int option_start = index + 2;
            if (option_start < argc && strncmp(argv[option_start], "--", 2) != 0) {
                snapshot_id = argv[option_start++];
            }
            if (parse_command_options(argc, argv, option_start, &options) != 0) {
                usage(stderr);
                return EXIT_FAILURE;
            }
            return nginx_check_command(snapshot_id, &options);
        }
    }
    if (strcmp(argv[index], "xdp") == 0 && index + 1 < argc) {
        struct command_options options;
        const char *operation = argv[index + 1];

        if (strcmp(operation, "status") == 0) {
            if (parse_command_options(argc, argv, index + 2, &options) != 0) {
                usage(stderr);
                return EXIT_FAILURE;
            }
            return xdp_status_command(&options);
        }
        if (strcmp(operation, "attach") == 0 && index + 2 < argc &&
            strcmp(argv[index + 2], "--observe") == 0) {
            if (parse_command_options(argc, argv, index + 3, &options) != 0) {
                usage(stderr);
                return EXIT_FAILURE;
            }
            return xdp_attach_command(&options);
        }
        if (strcmp(operation, "set-action") == 0 && index + 3 < argc) {
            if (parse_command_options(argc, argv, index + 4, &options) != 0) {
                usage(stderr);
                return EXIT_FAILURE;
            }
            return xdp_set_action_command(argv[index + 2], argv[index + 3], &options);
        }
        if (strcmp(operation, "metrics") == 0) {
            if (parse_command_options(argc, argv, index + 2, &options) != 0) {
                usage(stderr);
                return EXIT_FAILURE;
            }
            return xdp_metrics_command(&options);
        }
        if (strcmp(operation, "sync-geo") == 0) {
            if (parse_command_options(argc, argv, index + 2, &options) != 0) {
                usage(stderr);
                return EXIT_FAILURE;
            }
            return xdp_sync_geo_command(&options);
        }
        if (strcmp(operation, "detach") == 0) {
            if (parse_command_options(argc, argv, index + 2, &options) != 0) {
                usage(stderr);
                return EXIT_FAILURE;
            }
            return xdp_detach_command(&options);
        }
    }
    if (strcmp(argv[index], "ban") == 0 && index + 1 < argc) {
        struct command_options options;
        const char *operation = argv[index + 1];

        if (strcmp(operation, "add") == 0 && index + 3 < argc) {
            uint64_t duration_seconds = 0;
            int option_start;
            if (strcmp(argv[index + 3], "--permanent") == 0) {
                option_start = index + 4;
            } else if (strcmp(argv[index + 3], "--duration") == 0 && index + 4 < argc &&
                parse_cli_duration(argv[index + 4], &duration_seconds) == 0) {
                option_start = index + 5;
            } else {
                usage(stderr);
                return EXIT_FAILURE;
            }
            if (parse_command_options(argc, argv, option_start, &options) != 0) {
                usage(stderr);
                return EXIT_FAILURE;
            }
            return ban_add_command(argv[index + 2], duration_seconds, &options);
        }
        if (strcmp(operation, "remove") == 0 && index + 2 < argc) {
            if (parse_command_options(argc, argv, index + 3, &options) != 0) {
                usage(stderr);
                return EXIT_FAILURE;
            }
            return ban_remove_command(argv[index + 2], &options);
        }
        if (strcmp(operation, "list") == 0) {
            if (parse_command_options(argc, argv, index + 2, &options) != 0) {
                usage(stderr);
                return EXIT_FAILURE;
            }
            return ban_list_command(&options);
        }
        if (strcmp(operation, "sync") == 0) {
            if (parse_command_options(argc, argv, index + 2, &options) != 0) {
                usage(stderr);
                return EXIT_FAILURE;
            }
            return ban_sync_command(&options);
        }
        if (strcmp(operation, "event") == 0 && index + 8 < argc &&
            strcmp(argv[index + 8], "--confirmed-peer") == 0) {
            if (parse_command_options(argc, argv, index + 9, &options) != 0) {
                usage(stderr);
                return EXIT_FAILURE;
            }
            return ban_event_command(
                argv[index + 2], argv[index + 3], argv[index + 4], argv[index + 5],
                argv[index + 6], argv[index + 7], &options
            );
        }
    }
    if (strcmp(argv[index], "doctor") == 0) {
        const char *path = DEFAULT_CONFIG_PATH;
        if (index + 1 < argc) {
            if (strcmp(argv[index + 1], "--config") != 0 || index + 2 >= argc || index + 3 != argc) {
                usage(stderr);
                return EXIT_FAILURE;
            }
            path = argv[index + 2];
        }
        return doctor_command(path);
    }

    usage(stderr);
    return EXIT_FAILURE;
}
