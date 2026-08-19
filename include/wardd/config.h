#ifndef WARDD_CONFIG_H
#define WARDD_CONFIG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define WARDD_COUNTRY_LEN 3
#define WARDD_NAME_LEN 32
#define WARDD_INTERFACE_LEN 64
#define WARDD_ADDRESS_LEN 64
#define WARDD_PATH_LEN 512
#define WARDD_URL_LEN 1024
#define WARDD_MAX_ENDPOINTS 16
#define WARDD_MAX_BAN_PORTS 64
#define WARDD_MAX_BAN_EXEMPT 64

enum wardd_action {
    WARDD_ACTION_OBSERVE = 0,
    WARDD_ACTION_ENFORCE = 1,
};

enum wardd_attach_mode {
    WARDD_ATTACH_AUTO = 0,
    WARDD_ATTACH_NATIVE,
    WARDD_ATTACH_GENERIC,
    WARDD_ATTACH_OFF,
};

enum wardd_firewall_ownership {
    WARDD_FIREWALL_EXTERNAL = 0,
    WARDD_FIREWALL_HOST,
    WARDD_FIREWALL_NONE,
};

struct wardd_geo_config {
    char country[WARDD_COUNTRY_LEN];
    char provider[WARDD_NAME_LEN];
    char url[WARDD_URL_LEN];
    char checksum_url[WARDD_URL_LEN];
    uint64_t update_interval_seconds;
    uint64_t max_age_seconds;
    uint64_t max_download_bytes;
    double max_change_ratio;
};

struct wardd_geo_endpoint {
    char address[WARDD_ADDRESS_LEN];
    char protocol[8];
    uint16_t port;
};

struct wardd_xdp_config {
    bool enabled;
    char interface[WARDD_INTERFACE_LEN];
    enum wardd_attach_mode attach_mode;
    bool generic_fallback;
    enum wardd_action geo_action;
    enum wardd_action ban_action;
    struct wardd_geo_endpoint endpoints[WARDD_MAX_ENDPOINTS];
    size_t endpoint_count;
};

struct wardd_auto_ban_config {
    bool enabled;
    char event_source[WARDD_NAME_LEN];
    uint64_t window_seconds;
    uint64_t rejections;
    uint64_t first_duration_seconds;
    uint64_t second_duration_seconds;
    uint64_t third_duration_seconds;
    uint64_t strike_retention_seconds;
};

struct wardd_ban_config {
    uint16_t protected_tcp_ports[WARDD_MAX_BAN_PORTS];
    size_t protected_tcp_port_count;
    char exempt[WARDD_MAX_BAN_EXEMPT][WARDD_ADDRESS_LEN];
    size_t exempt_count;
    struct wardd_auto_ban_config automatic;
};

struct wardd_nginx_config {
    bool enabled;
    char generated_dir[WARDD_PATH_LEN];
    char limit_event_log[WARDD_PATH_LEN];
    char limit_zone[WARDD_NAME_LEN];
};

struct wardd_firewall_config {
    enum wardd_firewall_ownership ownership;
    bool manage;
};

struct wardd_config {
    uint32_t version;
    struct wardd_geo_config geo;
    struct wardd_xdp_config xdp;
    struct wardd_ban_config ban;
    struct wardd_nginx_config nginx;
    struct wardd_firewall_config firewall;
};

void wardd_config_init(struct wardd_config *config);

int wardd_config_load(
    const char *path,
    struct wardd_config *config,
    char *error,
    size_t error_size
);

const char *wardd_action_name(enum wardd_action action);
const char *wardd_attach_mode_name(enum wardd_attach_mode mode);
const char *wardd_firewall_ownership_name(enum wardd_firewall_ownership ownership);

#endif
