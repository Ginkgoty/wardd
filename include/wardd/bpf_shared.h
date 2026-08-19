#ifndef WARDD_BPF_SHARED_H
#define WARDD_BPF_SHARED_H

#include <linux/types.h>

enum wardd_runtime_action {
    WARDD_RUNTIME_OBSERVE = 0,
    WARDD_RUNTIME_ENFORCE = 1,
};

enum wardd_stat_key {
    WARDD_STAT_PASS_CN = 0,
    WARDD_STAT_PASS_NON_ENDPOINT,
    WARDD_STAT_PASS_PARSE_UNSUPPORTED,
    WARDD_STAT_WOULD_DROP_GEO,
    WARDD_STAT_DROP_GEO_NON_CN,
    WARDD_STAT_WOULD_DROP_BAN,
    WARDD_STAT_DROP_BAN_EXACT,
    WARDD_STAT_DROP_BAN_CIDR,
    WARDD_STAT_PARSE_ERROR,
    WARDD_STAT_COUNT,
};

struct wardd_runtime_config {
    __u8 geo_action;
    __u8 ban_action;
    __u8 reserved[6];
};

struct wardd_ban_value {
    __u64 expires_monotonic_ns;
};

struct wardd_v4_lpm_key {
    __u32 prefixlen;
    __be32 address;
};

struct wardd_v6_lpm_key {
    __u32 prefixlen;
    __u8 address[16];
};

struct wardd_v6_address {
    __u8 address[16];
};

struct wardd_v4_endpoint_key {
    __be32 address;
    __be16 port;
    __u8 protocol;
    __u8 reserved;
};

struct wardd_v6_endpoint_key {
    __u8 address[16];
    __be16 port;
    __u8 protocol;
    __u8 reserved;
};

#endif
