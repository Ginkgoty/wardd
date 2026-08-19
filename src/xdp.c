#include "wardd/xdp.h"

#include "wardd/bpf_shared.h"
#include "wardd/snapshot.h"

#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <net/if.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <xdp/libxdp.h>

#define XDP_PATH_LEN 2048
#define XDP_PREFIX_LIMIT 131072U

static const char *const map_names[] = {
    "cn_v4_template", "cn_v6_template", "cn_v4_sets", "cn_v6_sets",
    "ban_v4", "ban_v6", "ban_cidr4", "ban_cidr6", "geo_ep_v4",
    "geo_ep_v6", "ban_ports", "runtime_cfg", "stats",
};

static void set_error(char *error, size_t error_size, const char *format, ...)
{
    va_list arguments;

    if (error == NULL || error_size == 0) return;
    va_start(arguments, format);
    (void)vsnprintf(error, error_size, format, arguments);
    va_end(arguments);
}

static const char *mode_name(enum xdp_attach_mode mode)
{
    if (mode == XDP_MODE_NATIVE) return "native";
    if (mode == XDP_MODE_SKB) return "generic";
    if (mode == XDP_MODE_HW) return "hardware";
    return "unknown";
}

static int ensure_directory(const char *path, char *error, size_t error_size)
{
    char copy[XDP_PATH_LEN];

    if (path == NULL || path[0] != '/' || strlen(path) >= sizeof(copy)) {
        set_error(error, error_size, "BPF pin root must be a bounded absolute path");
        return -1;
    }
    (void)snprintf(copy, sizeof(copy), "%s", path);
    for (char *cursor = copy + 1; ; ++cursor) {
        if (*cursor != '/' && *cursor != '\0') continue;
        const char saved = *cursor;
        struct stat status;
        *cursor = '\0';
        if (mkdir(copy, 0750) != 0 && errno != EEXIST) {
            set_error(error, error_size, "cannot create BPF pin directory %s: %s", copy, strerror(errno));
            return -1;
        }
        if (lstat(copy, &status) != 0 || !S_ISDIR(status.st_mode)) {
            set_error(error, error_size, "BPF pin component %s is not a real directory", copy);
            return -1;
        }
        *cursor = saved;
        if (saved == '\0') break;
    }
    return 0;
}

static int path_join(char *output, size_t output_size, const char *left, const char *right)
{
    const int length = snprintf(output, output_size, "%s/%s", left, right);
    return length < 0 || (size_t)length >= output_size ? -1 : 0;
}

static void describe_system_error(char *error, size_t error_size, const char *operation, int status)
{
    const int error_number = status < 0 ? -status : status;
    set_error(error, error_size, "%s: %s", operation, strerror(error_number));
}

int wardd_xdp_available(void)
{
    return 1;
}

int wardd_xdp_get_status(
    const char *interface_name,
    struct wardd_xdp_status *status,
    char *error,
    size_t error_size
)
{
    struct xdp_multiprog *multiprog;
    struct xdp_program *program = NULL;
    long xdp_error;

    if (error != NULL && error_size > 0) error[0] = '\0';
    if (interface_name == NULL || status == NULL) {
        set_error(error, error_size, "interface and status output are required");
        return -1;
    }
    memset(status, 0, sizeof(*status));
    status->interface_index = if_nametoindex(interface_name);
    if (status->interface_index == 0) {
        set_error(error, error_size, "interface %s does not exist", interface_name);
        return -1;
    }
    multiprog = xdp_multiprog__get_from_ifindex((int)status->interface_index);
    xdp_error = libxdp_get_error(multiprog);
    if (xdp_error != 0) {
        if (xdp_error == -ENOENT || xdp_error == -ENXIO) return 0;
        describe_system_error(error, error_size, "cannot inspect interface XDP state", (int)xdp_error);
        return -1;
    }
    status->attached = true;
    status->legacy = xdp_multiprog__is_legacy(multiprog);
    status->program_count = (unsigned int)xdp_multiprog__program_count(multiprog);
    (void)snprintf(status->mode, sizeof(status->mode), "%s", mode_name(xdp_multiprog__attach_mode(multiprog)));
    while ((program = xdp_multiprog__next_prog(program, multiprog)) != NULL) {
        const char *name = xdp_program__name(program);
        if (name != NULL && strcmp(name, "wardd_xdp") == 0) {
            status->wardd_attached = true;
            status->wardd_program_id = xdp_program__id(program);
        }
    }
    if (status->legacy) {
        program = xdp_multiprog__main_prog(multiprog);
        if (program != NULL) {
            const char *name = xdp_program__name(program);
            if (name != NULL && strcmp(name, "wardd_xdp") == 0) {
                status->wardd_attached = true;
                status->wardd_program_id = xdp_program__id(program);
            }
        }
    }
    xdp_multiprog__close(multiprog);
    return 0;
}

static int map_fd(struct bpf_object *object, const char *name, char *error, size_t error_size)
{
    struct bpf_map *map = bpf_object__find_map_by_name(object, name);
    int file_descriptor;

    if (map == NULL) {
        set_error(error, error_size, "BPF object is missing map %s", name);
        return -1;
    }
    file_descriptor = bpf_map__fd(map);
    if (file_descriptor < 0) {
        set_error(error, error_size, "BPF map %s is not loaded", name);
        return -1;
    }
    return file_descriptor;
}

static void mask_address(unsigned char *address, unsigned int bits, unsigned int width)
{
    const unsigned int full_bytes = bits / 8;
    const unsigned int remaining = bits % 8;

    if (remaining != 0 && full_bytes < width) {
        address[full_bytes] &= (unsigned char)(0xffU << (8U - remaining));
    }
    const unsigned int start = full_bytes + (remaining == 0 ? 0U : 1U);
    for (unsigned int index = start; index < width; ++index) address[index] = 0;
}

static int populate_prefix_map(
    int map,
    const char *path,
    int family,
    size_t *count,
    char *error,
    size_t error_size
)
{
    FILE *file;
    struct stat file_status;
    char line[256];
    size_t line_number = 0;
    const __u8 value = 1;

    if (lstat(path, &file_status) != 0 || !S_ISREG(file_status.st_mode)) {
        set_error(error, error_size, "prefix set %s is not a regular file", path);
        return -1;
    }
    file = fopen(path, "r");
    if (file == NULL) {
        set_error(error, error_size, "cannot open prefix set %s: %s", path, strerror(errno));
        return -1;
    }
    while (fgets(line, sizeof(line), file) != NULL) {
        char *slash;
        char *end;
        unsigned long prefix_length;
        size_t length;

        line_number++;
        length = strlen(line);
        if (length == 0 || (line[length - 1] != '\n' && !feof(file))) {
            set_error(error, error_size, "prefix line %zu is too long", line_number);
            (void)fclose(file);
            return -1;
        }
        while (length > 0 && (line[length - 1] == '\n' || line[length - 1] == '\r')) line[--length] = '\0';
        if (length == 0) continue;
        slash = strrchr(line, '/');
        if (slash == NULL || slash == line || slash[1] == '\0') {
            set_error(error, error_size, "invalid CIDR at line %zu", line_number);
            (void)fclose(file);
            return -1;
        }
        *slash = '\0';
        errno = 0;
        prefix_length = strtoul(slash + 1, &end, 10);
        if (errno != 0 || *end != '\0' || prefix_length == 0 ||
            (family == AF_INET && prefix_length > 32) ||
            (family == AF_INET6 && prefix_length > 128)) {
            set_error(error, error_size, "invalid prefix length at line %zu", line_number);
            (void)fclose(file);
            return -1;
        }
        if (*count >= XDP_PREFIX_LIMIT) {
            set_error(error, error_size, "prefix set exceeds BPF map capacity");
            (void)fclose(file);
            return -1;
        }
        if (family == AF_INET) {
            struct wardd_v4_lpm_key key = {.prefixlen = (__u32)prefix_length};
            if (inet_pton(AF_INET, line, &key.address) != 1) {
                set_error(error, error_size, "invalid IPv4 CIDR at line %zu", line_number);
                (void)fclose(file);
                return -1;
            }
            mask_address((unsigned char *)&key.address, (__u32)prefix_length, 4);
            if (bpf_map_update_elem(map, &key, &value, BPF_NOEXIST) != 0) {
                set_error(error, error_size, "cannot add IPv4 prefix at line %zu: %s", line_number, strerror(errno));
                (void)fclose(file);
                return -1;
            }
        } else {
            struct wardd_v6_lpm_key key = {.prefixlen = (__u32)prefix_length};
            if (inet_pton(AF_INET6, line, key.address) != 1) {
                set_error(error, error_size, "invalid IPv6 CIDR at line %zu", line_number);
                (void)fclose(file);
                return -1;
            }
            mask_address(key.address, (__u32)prefix_length, 16);
            if (bpf_map_update_elem(map, &key, &value, BPF_NOEXIST) != 0) {
                set_error(error, error_size, "cannot add IPv6 prefix at line %zu: %s", line_number, strerror(errno));
                (void)fclose(file);
                return -1;
            }
        }
        (*count)++;
    }
    if (ferror(file)) {
        set_error(error, error_size, "cannot read prefix set %s", path);
        (void)fclose(file);
        return -1;
    }
    (void)fclose(file);
    if (*count == 0) {
        set_error(error, error_size, "prefix set %s is empty", path);
        return -1;
    }
    return 0;
}

static int create_lpm_map(int family, char *error, size_t error_size)
{
    LIBBPF_OPTS(bpf_map_create_opts, options, .map_flags = BPF_F_NO_PREALLOC);
    int file_descriptor = bpf_map_create(
        BPF_MAP_TYPE_LPM_TRIE,
        family == AF_INET ? "wardd_cn4" : "wardd_cn6",
        family == AF_INET ? sizeof(struct wardd_v4_lpm_key) : sizeof(struct wardd_v6_lpm_key),
        sizeof(__u8),
        XDP_PREFIX_LIMIT,
        &options
    );

    if (file_descriptor < 0) {
        set_error(error, error_size, "cannot create CN LPM map: %s", strerror(errno));
    }
    return file_descriptor;
}

static int populate_endpoints(
    struct bpf_object *object,
    const struct wardd_config *config,
    char *error,
    size_t error_size
)
{
    const int ipv4_map = map_fd(object, "geo_ep_v4", error, error_size);
    const int ipv6_map = map_fd(object, "geo_ep_v6", error, error_size);
    const __u8 value = 1;

    if (ipv4_map < 0 || ipv6_map < 0) return -1;
    for (size_t index = 0; index < config->xdp.endpoint_count; ++index) {
        const struct wardd_geo_endpoint *endpoint = &config->xdp.endpoints[index];
        struct wardd_v4_endpoint_key ipv4_key = {
            .port = htons(endpoint->port),
            .protocol = IPPROTO_TCP,
        };
        struct wardd_v6_endpoint_key ipv6_key = {
            .port = htons(endpoint->port),
            .protocol = IPPROTO_TCP,
        };

        if (strcmp(endpoint->address, "*") == 0) {
            if (bpf_map_update_elem(ipv4_map, &ipv4_key, &value, BPF_ANY) != 0 ||
                bpf_map_update_elem(ipv6_map, &ipv6_key, &value, BPF_ANY) != 0) {
                set_error(error, error_size, "cannot add wildcard GeoIP endpoint: %s", strerror(errno));
                return -1;
            }
        } else if (inet_pton(AF_INET, endpoint->address, &ipv4_key.address) == 1) {
            if (bpf_map_update_elem(ipv4_map, &ipv4_key, &value, BPF_ANY) != 0) {
                set_error(error, error_size, "cannot add IPv4 GeoIP endpoint: %s", strerror(errno));
                return -1;
            }
        } else if (inet_pton(AF_INET6, endpoint->address, ipv6_key.address) == 1) {
            if (bpf_map_update_elem(ipv6_map, &ipv6_key, &value, BPF_ANY) != 0) {
                set_error(error, error_size, "cannot add IPv6 GeoIP endpoint: %s", strerror(errno));
                return -1;
            }
        } else {
            set_error(error, error_size, "invalid GeoIP endpoint %s", endpoint->address);
            return -1;
        }
    }
    return 0;
}

static int populate_runtime(
    struct bpf_object *object,
    const struct wardd_config *config,
    char *error,
    size_t error_size
)
{
    const int port_map = map_fd(object, "ban_ports", error, error_size);
    const int config_map = map_fd(object, "runtime_cfg", error, error_size);
    const __u8 value = 1;
    const __u32 zero = 0;
    const struct wardd_runtime_config runtime = {
        .geo_action = WARDD_RUNTIME_OBSERVE,
        .ban_action = WARDD_RUNTIME_OBSERVE,
    };

    if (port_map < 0 || config_map < 0) return -1;
    for (size_t index = 0; index < config->ban.protected_tcp_port_count; ++index) {
        const __be16 port = htons(config->ban.protected_tcp_ports[index]);
        if (bpf_map_update_elem(port_map, &port, &value, BPF_ANY) != 0) {
            set_error(error, error_size, "cannot add protected TCP port: %s", strerror(errno));
            return -1;
        }
    }
    if (bpf_map_update_elem(config_map, &zero, &runtime, BPF_ANY) != 0) {
        set_error(error, error_size, "cannot set observe-mode runtime policy: %s", strerror(errno));
        return -1;
    }
    return populate_endpoints(object, config, error, error_size);
}

static int build_country_maps(
    const char *snapshot_root,
    int *ipv4_inner,
    int *ipv6_inner,
    size_t *ipv4_count,
    size_t *ipv6_count,
    char *error,
    size_t error_size
)
{
    struct wardd_snapshot_status snapshot_status;
    char directory[XDP_PATH_LEN];
    char ipv4_path[XDP_PATH_LEN];
    char ipv6_path[XDP_PATH_LEN];
    char approval_path[XDP_PATH_LEN];
    struct stat approval_status;
    if (wardd_geo_snapshot_status(snapshot_root, &snapshot_status, error, error_size) != 0 ||
        snapshot_status.current[0] == '\0') {
        set_error(error, error_size, "an active GeoIP snapshot is required before XDP attach");
        return -1;
    }
    if (path_join(directory, sizeof(directory), snapshot_root, snapshot_status.current) != 0 ||
        path_join(ipv4_path, sizeof(ipv4_path), directory, "cn-v4.txt") != 0 ||
        path_join(ipv6_path, sizeof(ipv6_path), directory, "cn-v6.txt") != 0 ||
        path_join(approval_path, sizeof(approval_path), directory, ".approved") != 0 ||
        lstat(approval_path, &approval_status) != 0 || !S_ISREG(approval_status.st_mode)) {
        set_error(error, error_size, "active GeoIP snapshot is incomplete or unapproved");
        return -1;
    }
    *ipv4_inner = create_lpm_map(AF_INET, error, error_size);
    *ipv6_inner = create_lpm_map(AF_INET6, error, error_size);
    if (*ipv4_inner < 0 || *ipv6_inner < 0 ||
        populate_prefix_map(*ipv4_inner, ipv4_path, AF_INET, ipv4_count, error, error_size) != 0 ||
        populate_prefix_map(*ipv6_inner, ipv6_path, AF_INET6, ipv6_count, error, error_size) != 0) {
        return -1;
    }
    return 0;
}

static int switch_country_maps(
    int outer_v4,
    int outer_v6,
    int ipv4_inner,
    int ipv6_inner,
    char *error,
    size_t error_size
)
{
    const __u32 zero = 0;
    __u32 old_v4_id;
    __u32 old_v6_id;
    int old_v4 = -1;
    int old_v6 = -1;
    int return_value = -1;

    if (bpf_map_lookup_elem(outer_v4, &zero, &old_v4_id) != 0 ||
        bpf_map_lookup_elem(outer_v6, &zero, &old_v6_id) != 0) {
        set_error(error, error_size, "cannot read current CN map set: %s", strerror(errno));
        return -1;
    }
    old_v4 = bpf_map_get_fd_by_id(old_v4_id);
    old_v6 = bpf_map_get_fd_by_id(old_v6_id);
    if (old_v4 < 0 || old_v6 < 0) {
        set_error(error, error_size, "cannot retain current CN map set: %s", strerror(errno));
        goto done;
    }
    if (bpf_map_update_elem(outer_v4, &zero, &ipv4_inner, BPF_ANY) != 0) {
        set_error(error, error_size, "cannot switch IPv4 CN map: %s", strerror(errno));
        goto done;
    }
    if (bpf_map_update_elem(outer_v6, &zero, &ipv6_inner, BPF_ANY) != 0) {
        const int saved_errno = errno;
        if (bpf_map_update_elem(outer_v4, &zero, &old_v4, BPF_ANY) != 0) {
            set_error(error, error_size, "IPv6 CN switch failed and IPv4 rollback also failed");
        } else {
            set_error(error, error_size, "cannot switch IPv6 CN map: %s", strerror(saved_errno));
        }
        goto done;
    }
    return_value = 0;

done:
    if (old_v4 >= 0) (void)close(old_v4);
    if (old_v6 >= 0) (void)close(old_v6);
    return return_value;
}

static int populate_country_maps(
    struct bpf_object *object,
    const char *snapshot_root,
    size_t *ipv4_count,
    size_t *ipv6_count,
    char *error,
    size_t error_size
)
{
    int ipv4_inner = -1;
    int ipv6_inner = -1;
    int return_value = -1;

    if (build_country_maps(
            snapshot_root,
            &ipv4_inner,
            &ipv6_inner,
            ipv4_count,
            ipv6_count,
            error,
            error_size
        ) != 0) {
        goto done;
    }
    const int outer_v4 = map_fd(object, "cn_v4_sets", error, error_size);
    const int outer_v6 = map_fd(object, "cn_v6_sets", error, error_size);
    if (outer_v4 < 0 || outer_v6 < 0 || switch_country_maps(
            outer_v4,
            outer_v6,
            ipv4_inner,
            ipv6_inner,
            error,
            error_size
        ) != 0) {
        goto done;
    }
    return_value = 0;

done:
    if (ipv4_inner >= 0) (void)close(ipv4_inner);
    if (ipv6_inner >= 0) (void)close(ipv6_inner);
    return return_value;
}

static void cleanup_pins(const char *pin_root)
{
    char path[XDP_PATH_LEN];
    char map_directory[XDP_PATH_LEN];

    if (path_join(path, sizeof(path), pin_root, "program") == 0) (void)unlink(path);
    if (path_join(map_directory, sizeof(map_directory), pin_root, "maps") != 0) return;
    for (size_t index = 0; index < sizeof(map_names) / sizeof(map_names[0]); ++index) {
        if (path_join(path, sizeof(path), map_directory, map_names[index]) == 0) (void)unlink(path);
    }
    (void)rmdir(map_directory);
    (void)rmdir(pin_root);
}

static int pin_loaded_object(
    struct xdp_program *program,
    const char *pin_root,
    char *error,
    size_t error_size
)
{
    struct bpf_object *object = xdp_program__bpf_obj(program);
    char map_directory[XDP_PATH_LEN];
    char program_path[XDP_PATH_LEN];
    struct stat existing_status;
    int status;

    if (ensure_directory(pin_root, error, error_size) != 0 ||
        path_join(map_directory, sizeof(map_directory), pin_root, "maps") != 0 ||
        path_join(program_path, sizeof(program_path), pin_root, "program") != 0) {
        set_error(error, error_size, "cannot prepare wardd BPF pin paths");
        return -1;
    }
    if (lstat(program_path, &existing_status) == 0 || errno != ENOENT ||
        lstat(map_directory, &existing_status) == 0 || errno != ENOENT) {
        set_error(error, error_size, "wardd BPF pin root is already in use");
        return -1;
    }
    if (mkdir(map_directory, 0750) != 0) {
        set_error(error, error_size, "cannot prepare wardd BPF pins: %s", strerror(errno));
        return -1;
    }
    status = bpf_object__pin_maps(object, map_directory);
    if (status != 0) {
        describe_system_error(error, error_size, "cannot pin wardd BPF maps", status);
        cleanup_pins(pin_root);
        return -1;
    }
    status = xdp_program__pin(program, program_path);
    if (status != 0) {
        describe_system_error(error, error_size, "cannot pin wardd XDP program", status);
        cleanup_pins(pin_root);
        return -1;
    }
    return 0;
}

int wardd_xdp_attach_observe(
    const char *object_path,
    const char *pin_root,
    const char *snapshot_root,
    const struct wardd_config *config,
    struct wardd_xdp_attach_result *result,
    char *error,
    size_t error_size
)
{
    struct wardd_xdp_status existing;
    struct xdp_program *program = NULL;
    struct bpf_object *object;
    enum xdp_attach_mode mode;
    long xdp_error;
    int status;
    bool pinned = false;
    bool attached = false;
    bool ready = false;
    struct wardd_xdp_attach_result local_result = {0};
    char verifier_log[65536] = {0};
    LIBBPF_OPTS(
        bpf_object_open_opts,
        open_options,
        .kernel_log_buf = verifier_log,
        .kernel_log_size = sizeof(verifier_log),
        .kernel_log_level = 1
    );

    if (error != NULL && error_size > 0) error[0] = '\0';
    if (result != NULL) memset(result, 0, sizeof(*result));
    if (object_path == NULL || pin_root == NULL || snapshot_root == NULL || config == NULL ||
        !config->xdp.enabled) {
        set_error(error, error_size, "enabled XDP configuration and object/state paths are required");
        return -1;
    }
    if (config->xdp.attach_mode == WARDD_ATTACH_OFF) {
        set_error(error, error_size, "XDP attach mode is off");
        return -1;
    }
    if (wardd_xdp_get_status(config->xdp.interface, &existing, error, error_size) != 0) return -1;
    if (existing.wardd_attached) {
        set_error(error, error_size, "wardd is already attached to %s", config->xdp.interface);
        return -1;
    }
    if (existing.legacy) {
        set_error(error, error_size, "refusing to replace a legacy XDP program on %s", config->xdp.interface);
        return -1;
    }

    program = xdp_program__open_file(object_path, "xdp", &open_options);
    xdp_error = libxdp_get_error(program);
    if (xdp_error != 0) {
        describe_system_error(error, error_size, "cannot open wardd XDP object", (int)xdp_error);
        return -1;
    }
    status = xdp_program__set_run_prio(program, 50);
    if (status == 0) status = xdp_program__set_chain_call_enabled(program, XDP_PASS, true);
    if (status != 0) {
        describe_system_error(error, error_size, "cannot configure dispatcher metadata", status);
        goto done;
    }
    mode = config->xdp.attach_mode == WARDD_ATTACH_GENERIC ? XDP_MODE_SKB : XDP_MODE_NATIVE;
    status = xdp_program__attach(program, (int)existing.interface_index, mode, 0);
    if (status != 0 && config->xdp.attach_mode == WARDD_ATTACH_AUTO && config->xdp.generic_fallback) {
        mode = XDP_MODE_SKB;
        status = xdp_program__attach(program, (int)existing.interface_index, mode, 0);
    }
    if (status != 0) {
        set_error(
            error,
            error_size,
            "cannot attach wardd through libxdp: %s%s",
            verifier_log[0] == '\0' ? "" : verifier_log,
            verifier_log[0] == '\0' ? strerror(-status) : ""
        );
        goto done;
    }
    attached = true;
    if (xdp_program__fd(program) < 0) {
        set_error(error, error_size, "attached XDP program has no file descriptor");
        goto done;
    }
    object = xdp_program__bpf_obj(program);
    if (object == NULL) {
        set_error(error, error_size, "attached XDP program has no BPF object");
        goto done;
    }
    if (populate_country_maps(
            object,
            snapshot_root,
            &local_result.ipv4_prefixes,
            &local_result.ipv6_prefixes,
            error,
            error_size
        ) != 0 ||
        populate_runtime(object, config, error, error_size) != 0) {
        goto done;
    }
    if (pin_loaded_object(program, pin_root, error, error_size) != 0) goto done;
    pinned = true;
    local_result.interface_index = existing.interface_index;
    local_result.program_id = xdp_program__id(program);
    (void)snprintf(local_result.mode, sizeof(local_result.mode), "%s", mode_name(mode));
    if (result != NULL) *result = local_result;
    ready = true;

done:
    if (!ready && attached) {
        (void)xdp_program__detach(program, (int)existing.interface_index, mode, 0);
    }
    if (!ready && pinned) cleanup_pins(pin_root);
    xdp_program__close(program);
    return ready ? 0 : -1;
}

int wardd_xdp_detach(
    const char *interface_name,
    const char *pin_root,
    char *error,
    size_t error_size
)
{
    struct wardd_xdp_status status_info;
    struct xdp_program *program;
    char program_path[XDP_PATH_LEN];
    enum xdp_attach_mode mode;
    long xdp_error;
    int status;

    if (error != NULL && error_size > 0) error[0] = '\0';
    if (wardd_xdp_get_status(interface_name, &status_info, error, error_size) != 0) return -1;
    if (!status_info.wardd_attached || status_info.legacy) {
        set_error(error, error_size, "no safely detachable wardd dispatcher program is attached");
        return -1;
    }
    if (path_join(program_path, sizeof(program_path), pin_root, "program") != 0) {
        set_error(error, error_size, "BPF pin path is too long");
        return -1;
    }
    program = xdp_program__from_pin(program_path);
    xdp_error = libxdp_get_error(program);
    if (xdp_error != 0) {
        describe_system_error(error, error_size, "cannot open pinned wardd program", (int)xdp_error);
        return -1;
    }
    if (xdp_program__name(program) == NULL || strcmp(xdp_program__name(program), "wardd_xdp") != 0 ||
        xdp_program__id(program) != status_info.wardd_program_id) {
        set_error(error, error_size, "pinned program identity does not match attached wardd program");
        xdp_program__close(program);
        return -1;
    }
    mode = strcmp(status_info.mode, "generic") == 0 ? XDP_MODE_SKB : XDP_MODE_NATIVE;
    status = xdp_program__detach(program, (int)status_info.interface_index, mode, 0);
    if (status != 0) {
        describe_system_error(error, error_size, "cannot detach wardd XDP program", status);
        xdp_program__close(program);
        return -1;
    }
    xdp_program__close(program);
    cleanup_pins(pin_root);
    return 0;
}

static struct xdp_program *open_verified_program(
    const char *interface_name,
    const char *pin_root,
    struct wardd_xdp_status *status_info,
    char *error,
    size_t error_size
)
{
    struct xdp_program *program;
    char program_path[XDP_PATH_LEN];
    long xdp_error;

    if (wardd_xdp_get_status(interface_name, status_info, error, error_size) != 0) return NULL;
    if (!status_info->wardd_attached || status_info->legacy) {
        set_error(error, error_size, "no safely managed wardd dispatcher program is attached");
        return NULL;
    }
    if (path_join(program_path, sizeof(program_path), pin_root, "program") != 0) {
        set_error(error, error_size, "BPF pin path is too long");
        return NULL;
    }
    program = xdp_program__from_pin(program_path);
    xdp_error = libxdp_get_error(program);
    if (xdp_error != 0) {
        describe_system_error(error, error_size, "cannot open pinned wardd program", (int)xdp_error);
        return NULL;
    }
    if (xdp_program__name(program) == NULL || strcmp(xdp_program__name(program), "wardd_xdp") != 0 ||
        xdp_program__id(program) != status_info->wardd_program_id) {
        set_error(error, error_size, "pinned program identity does not match attached wardd program");
        xdp_program__close(program);
        return NULL;
    }
    return program;
}

int wardd_xdp_set_action(
    const char *interface_name,
    const char *pin_root,
    bool geo_action,
    enum wardd_action action,
    char *error,
    size_t error_size
)
{
    struct wardd_xdp_status status_info;
    struct xdp_program *program;
    struct wardd_runtime_config runtime;
    char map_path[XDP_PATH_LEN];
    const __u32 zero = 0;
    int map = -1;
    int return_value = -1;

    if (error != NULL && error_size > 0) error[0] = '\0';
    if (action != WARDD_ACTION_OBSERVE && action != WARDD_ACTION_ENFORCE) {
        set_error(error, error_size, "runtime action is invalid");
        return -1;
    }
    program = open_verified_program(interface_name, pin_root, &status_info, error, error_size);
    if (program == NULL) return -1;
    if (snprintf(map_path, sizeof(map_path), "%s/maps/runtime_cfg", pin_root) >= (int)sizeof(map_path)) {
        set_error(error, error_size, "runtime map path is too long");
        goto done;
    }
    map = bpf_obj_get(map_path);
    if (map < 0 || bpf_map_lookup_elem(map, &zero, &runtime) != 0) {
        set_error(error, error_size, "cannot read pinned runtime policy: %s", strerror(errno));
        goto done;
    }
    if (geo_action) runtime.geo_action = (__u8)action;
    else runtime.ban_action = (__u8)action;
    if (bpf_map_update_elem(map, &zero, &runtime, BPF_EXIST) != 0) {
        set_error(error, error_size, "cannot update runtime policy: %s", strerror(errno));
        goto done;
    }
    return_value = 0;

done:
    if (map >= 0) (void)close(map);
    xdp_program__close(program);
    return return_value;
}

int wardd_xdp_sync_geo(
    const char *interface_name,
    const char *pin_root,
    const char *snapshot_root,
    size_t *ipv4_prefixes,
    size_t *ipv6_prefixes,
    char *error,
    size_t error_size
)
{
    struct wardd_xdp_status status_info;
    struct xdp_program *program;
    char outer_v4_path[XDP_PATH_LEN];
    char outer_v6_path[XDP_PATH_LEN];
    int outer_v4 = -1;
    int outer_v6 = -1;
    int inner_v4 = -1;
    int inner_v6 = -1;
    int return_value = -1;

    if (error != NULL && error_size > 0) error[0] = '\0';
    if (ipv4_prefixes == NULL || ipv6_prefixes == NULL) {
        set_error(error, error_size, "GeoIP sync counters are required");
        return -1;
    }
    *ipv4_prefixes = 0;
    *ipv6_prefixes = 0;
    program = open_verified_program(interface_name, pin_root, &status_info, error, error_size);
    if (program == NULL) return -1;
    if (snprintf(outer_v4_path, sizeof(outer_v4_path), "%s/maps/cn_v4_sets", pin_root) >=
            (int)sizeof(outer_v4_path) ||
        snprintf(outer_v6_path, sizeof(outer_v6_path), "%s/maps/cn_v6_sets", pin_root) >=
            (int)sizeof(outer_v6_path)) {
        set_error(error, error_size, "CN outer map pin path is too long");
        goto done;
    }
    outer_v4 = bpf_obj_get(outer_v4_path);
    outer_v6 = bpf_obj_get(outer_v6_path);
    if (outer_v4 < 0 || outer_v6 < 0) {
        set_error(error, error_size, "cannot open pinned CN outer maps: %s", strerror(errno));
        goto done;
    }
    if (build_country_maps(
            snapshot_root,
            &inner_v4,
            &inner_v6,
            ipv4_prefixes,
            ipv6_prefixes,
            error,
            error_size
        ) != 0 ||
        switch_country_maps(outer_v4, outer_v6, inner_v4, inner_v6, error, error_size) != 0) {
        goto done;
    }
    return_value = 0;

done:
    if (outer_v4 >= 0) (void)close(outer_v4);
    if (outer_v6 >= 0) (void)close(outer_v6);
    if (inner_v4 >= 0) (void)close(inner_v4);
    if (inner_v6 >= 0) (void)close(inner_v6);
    xdp_program__close(program);
    return return_value;
}

int wardd_xdp_read_metrics(
    const char *pin_root,
    uint64_t counters[WARDD_STAT_COUNT],
    char *error,
    size_t error_size
)
{
    struct bpf_map_info info = {.key_size = 0};
    __u32 info_length = sizeof(info);
    char map_path[XDP_PATH_LEN];
    __u64 *per_cpu_values = NULL;
    int possible_cpus;
    int map = -1;
    int return_value = -1;

    if (error != NULL && error_size > 0) error[0] = '\0';
    if (pin_root == NULL || counters == NULL ||
        snprintf(map_path, sizeof(map_path), "%s/maps/stats", pin_root) >= (int)sizeof(map_path)) {
        set_error(error, error_size, "stats pin path and output are required");
        return -1;
    }
    memset(counters, 0, sizeof(uint64_t) * WARDD_STAT_COUNT);
    map = bpf_obj_get(map_path);
    if (map < 0 || bpf_obj_get_info_by_fd(map, &info, &info_length) != 0) {
        set_error(error, error_size, "cannot open pinned XDP stats: %s", strerror(errno));
        goto done;
    }
    if (info.type != BPF_MAP_TYPE_PERCPU_ARRAY || info.key_size != sizeof(__u32) ||
        info.value_size != sizeof(__u64) || info.max_entries != WARDD_STAT_COUNT) {
        set_error(error, error_size, "pinned stats map has an incompatible schema");
        goto done;
    }
    possible_cpus = libbpf_num_possible_cpus();
    if (possible_cpus <= 0) {
        set_error(error, error_size, "cannot determine possible CPU count");
        goto done;
    }
    per_cpu_values = calloc((size_t)possible_cpus, sizeof(*per_cpu_values));
    if (per_cpu_values == NULL) {
        set_error(error, error_size, "cannot allocate per-CPU stats buffer");
        goto done;
    }
    for (__u32 key = 0; key < WARDD_STAT_COUNT; ++key) {
        if (bpf_map_lookup_elem(map, &key, per_cpu_values) != 0) {
            set_error(error, error_size, "cannot read XDP counter %u: %s", key, strerror(errno));
            goto done;
        }
        for (int cpu = 0; cpu < possible_cpus; ++cpu) counters[key] += per_cpu_values[cpu];
    }
    return_value = 0;

done:
    free(per_cpu_values);
    if (map >= 0) (void)close(map);
    return return_value;
}

struct parsed_network {
    int family;
    bool cidr;
    unsigned int prefix_length;
    union {
        __be32 ipv4;
        struct wardd_v6_address ipv6;
    } address;
};

static int parse_network(
    const char *input,
    struct parsed_network *network,
    char *error,
    size_t error_size
)
{
    char copy[INET6_ADDRSTRLEN + 8];
    char *slash;
    char *end;
    unsigned long prefix_length = 0;

    if (input == NULL || strlen(input) >= sizeof(copy)) {
        set_error(error, error_size, "IP or CIDR is missing or too long");
        return -1;
    }
    memset(network, 0, sizeof(*network));
    (void)snprintf(copy, sizeof(copy), "%s", input);
    slash = strchr(copy, '/');
    if (slash != NULL) {
        if (slash == copy || slash[1] == '\0' || strchr(slash + 1, '/') != NULL) {
            set_error(error, error_size, "invalid CIDR %s", input);
            return -1;
        }
        *slash = '\0';
        errno = 0;
        prefix_length = strtoul(slash + 1, &end, 10);
        if (errno != 0 || *end != '\0' || prefix_length == 0) {
            set_error(error, error_size, "invalid or unsafe CIDR prefix in %s", input);
            return -1;
        }
        network->cidr = true;
    }
    if (inet_pton(AF_INET, copy, &network->address.ipv4) == 1) {
        network->family = AF_INET;
        network->prefix_length = slash == NULL ? 32U : (unsigned int)prefix_length;
        if (network->prefix_length > 32U) {
            set_error(error, error_size, "invalid IPv4 prefix in %s", input);
            return -1;
        }
        mask_address((unsigned char *)&network->address.ipv4, network->prefix_length, 4);
        return 0;
    }
    if (inet_pton(AF_INET6, copy, network->address.ipv6.address) == 1) {
        network->family = AF_INET6;
        network->prefix_length = slash == NULL ? 128U : (unsigned int)prefix_length;
        if (network->prefix_length > 128U) {
            set_error(error, error_size, "invalid IPv6 prefix in %s", input);
            return -1;
        }
        mask_address(network->address.ipv6.address, network->prefix_length, 16);
        return 0;
    }
    set_error(error, error_size, "invalid IP or CIDR %s", input);
    return -1;
}

static int ban_map_path(
    char *path,
    size_t path_size,
    const char *pin_root,
    const struct parsed_network *network
)
{
    const char *name;

    if (network->family == AF_INET) name = network->cidr ? "ban_cidr4" : "ban_v4";
    else name = network->cidr ? "ban_cidr6" : "ban_v6";
    return snprintf(path, path_size, "%s/maps/%s", pin_root, name) >= (int)path_size ? -1 : 0;
}

static int ban_update(
    const char *interface_name,
    const char *pin_root,
    const char *input,
    uint64_t duration_seconds,
    bool remove,
    char *error,
    size_t error_size
)
{
    struct wardd_xdp_status status_info;
    struct xdp_program *program;
    struct parsed_network network;
    struct wardd_ban_value value = {0};
    struct timespec now;
    char path[XDP_PATH_LEN];
    int map = -1;
    int operation_status;
    int return_value = -1;

    if (error != NULL && error_size > 0) error[0] = '\0';
    if (parse_network(input, &network, error, error_size) != 0) return -1;
    program = open_verified_program(interface_name, pin_root, &status_info, error, error_size);
    if (program == NULL) return -1;
    if (ban_map_path(path, sizeof(path), pin_root, &network) != 0) {
        set_error(error, error_size, "ban map path is too long");
        goto done;
    }
    map = bpf_obj_get(path);
    if (map < 0) {
        set_error(error, error_size, "cannot open pinned ban map: %s", strerror(errno));
        goto done;
    }
    if (!remove && duration_seconds != 0) {
        if (clock_gettime(CLOCK_MONOTONIC, &now) != 0 || now.tv_sec < 0 || now.tv_nsec < 0) {
            set_error(error, error_size, "ban duration cannot be represented safely");
            goto done;
        }
        const uint64_t max_seconds = (UINT64_MAX - (uint64_t)now.tv_nsec) / 1000000000ULL;
        if ((uint64_t)now.tv_sec > max_seconds ||
            duration_seconds > max_seconds - (uint64_t)now.tv_sec) {
            set_error(error, error_size, "ban duration cannot be represented safely");
            goto done;
        }
        value.expires_monotonic_ns = ((uint64_t)now.tv_sec + duration_seconds) * 1000000000ULL +
            (uint64_t)now.tv_nsec;
    }
    if (network.family == AF_INET && !network.cidr) {
        operation_status = remove ? bpf_map_delete_elem(map, &network.address.ipv4) :
            bpf_map_update_elem(map, &network.address.ipv4, &value, BPF_ANY);
    } else if (network.family == AF_INET) {
        const struct wardd_v4_lpm_key key = {
            .prefixlen = network.prefix_length,
            .address = network.address.ipv4,
        };
        operation_status = remove ? bpf_map_delete_elem(map, &key) :
            bpf_map_update_elem(map, &key, &value, BPF_ANY);
    } else if (!network.cidr) {
        operation_status = remove ? bpf_map_delete_elem(map, &network.address.ipv6) :
            bpf_map_update_elem(map, &network.address.ipv6, &value, BPF_ANY);
    } else {
        struct wardd_v6_lpm_key key = {.prefixlen = network.prefix_length};
        memcpy(key.address, network.address.ipv6.address, sizeof(key.address));
        operation_status = remove ? bpf_map_delete_elem(map, &key) :
            bpf_map_update_elem(map, &key, &value, BPF_ANY);
    }
    if (operation_status != 0) {
        set_error(error, error_size, "cannot %s ban %s: %s", remove ? "remove" : "add", input, strerror(errno));
        goto done;
    }
    return_value = 0;

done:
    if (map >= 0) (void)close(map);
    xdp_program__close(program);
    return return_value;
}

int wardd_xdp_ban_add(
    const char *interface_name,
    const char *pin_root,
    const char *network,
    uint64_t duration_seconds,
    char *error,
    size_t error_size
)
{
    return ban_update(
        interface_name,
        pin_root,
        network,
        duration_seconds,
        false,
        error,
        error_size
    );
}

int wardd_xdp_ban_remove(
    const char *interface_name,
    const char *pin_root,
    const char *network,
    char *error,
    size_t error_size
)
{
    return ban_update(interface_name, pin_root, network, 0, true, error, error_size);
}

static int visit_map(
    const char *path,
    int family,
    bool cidr,
    wardd_ban_visitor visitor,
    void *context,
    char *error,
    size_t error_size
)
{
    union {
        __be32 ipv4;
        struct wardd_v6_address ipv6;
        struct wardd_v4_lpm_key cidr4;
        struct wardd_v6_lpm_key cidr6;
    } current = {0}, next = {0};
    struct wardd_ban_value value;
    void *current_key = NULL;
    int map = bpf_obj_get(path);

    if (map < 0) {
        set_error(error, error_size, "cannot open pinned ban map %s: %s", path, strerror(errno));
        return -1;
    }
    for (;;) {
        if (bpf_map_get_next_key(map, current_key, &next) != 0) {
            if (errno == ENOENT) break;
            set_error(error, error_size, "cannot iterate ban map: %s", strerror(errno));
            (void)close(map);
            return -1;
        }
        if (bpf_map_lookup_elem(map, &next, &value) != 0) {
            set_error(error, error_size, "cannot read ban entry: %s", strerror(errno));
            (void)close(map);
            return -1;
        }
        char address[INET6_ADDRSTRLEN];
        char network[INET6_ADDRSTRLEN + 8];
        unsigned int prefix_length;
        const void *address_data;
        if (family == AF_INET && !cidr) {
            address_data = &next.ipv4;
            prefix_length = 32;
        } else if (family == AF_INET) {
            address_data = &next.cidr4.address;
            prefix_length = next.cidr4.prefixlen;
        } else if (!cidr) {
            address_data = next.ipv6.address;
            prefix_length = 128;
        } else {
            address_data = next.cidr6.address;
            prefix_length = next.cidr6.prefixlen;
        }
        if (inet_ntop(family, address_data, address, sizeof(address)) == NULL ||
            snprintf(network, sizeof(network), cidr ? "%s/%u" : "%s", address, prefix_length) >=
                (int)sizeof(network) ||
            visitor(network, value.expires_monotonic_ns, context) != 0) {
            set_error(error, error_size, "cannot format or visit ban entry");
            (void)close(map);
            return -1;
        }
        current = next;
        current_key = &current;
    }
    (void)close(map);
    return 0;
}

int wardd_xdp_ban_list(
    const char *pin_root,
    wardd_ban_visitor visitor,
    void *context,
    char *error,
    size_t error_size
)
{
    static const struct {
        const char *name;
        int family;
        bool cidr;
    } maps[] = {
        {"ban_v4", AF_INET, false},
        {"ban_v6", AF_INET6, false},
        {"ban_cidr4", AF_INET, true},
        {"ban_cidr6", AF_INET6, true},
    };

    if (error != NULL && error_size > 0) error[0] = '\0';
    if (pin_root == NULL || visitor == NULL) {
        set_error(error, error_size, "ban pin root and visitor are required");
        return -1;
    }
    for (size_t index = 0; index < sizeof(maps) / sizeof(maps[0]); ++index) {
        char path[XDP_PATH_LEN];
        if (snprintf(path, sizeof(path), "%s/maps/%s", pin_root, maps[index].name) >= (int)sizeof(path) ||
            visit_map(
                path,
                maps[index].family,
                maps[index].cidr,
                visitor,
                context,
                error,
                error_size
            ) != 0) {
            return -1;
        }
    }
    return 0;
}
