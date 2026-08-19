#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>

#include <stdbool.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "wardd_shared.h"

struct wardd_vlan_header {
    __be16 tci;
    __be16 encapsulated_protocol;
};

struct cn_v4_inner {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 131072);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct wardd_v4_lpm_key);
    __type(value, __u8);
};

struct cn_v6_inner {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 131072);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct wardd_v6_lpm_key);
    __type(value, __u8);
};

struct cn_v4_inner cn_v4_template SEC(".maps");
struct cn_v6_inner cn_v6_template SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, 1);
    __type(key, __u32);
    __array(values, struct cn_v4_inner);
} cn_v4_sets SEC(".maps") = {
    .values = {[0] = &cn_v4_template},
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, 1);
    __type(key, __u32);
    __array(values, struct cn_v6_inner);
} cn_v6_sets SEC(".maps") = {
    .values = {[0] = &cn_v6_template},
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __be32);
    __type(value, struct wardd_ban_value);
} ban_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct wardd_v6_address);
    __type(value, struct wardd_ban_value);
} ban_v6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 16384);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct wardd_v4_lpm_key);
    __type(value, struct wardd_ban_value);
} ban_cidr4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 16384);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct wardd_v6_lpm_key);
    __type(value, struct wardd_ban_value);
} ban_cidr6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, struct wardd_v4_endpoint_key);
    __type(value, __u8);
} geo_ep_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, struct wardd_v6_endpoint_key);
    __type(value, __u8);
} geo_ep_v6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __be16);
    __type(value, __u8);
} ban_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct wardd_runtime_config);
} runtime_cfg SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, WARDD_STAT_COUNT);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

static __always_inline void count_stat(enum wardd_stat_key key)
{
    __u32 index = (__u32)key;
    __u64 *counter = bpf_map_lookup_elem(&stats, &index);

    if (counter != NULL) {
        (*counter)++;
    }
}

static __always_inline bool ban_is_active(const struct wardd_ban_value *value, __u64 now)
{
    return value != NULL &&
        (value->expires_monotonic_ns == 0 || now < value->expires_monotonic_ns);
}

static __always_inline int ban_result(
    const struct wardd_runtime_config *config,
    bool cidr
)
{
    if (config == NULL || config->ban_action == WARDD_RUNTIME_OBSERVE) {
        count_stat(WARDD_STAT_WOULD_DROP_BAN);
        return XDP_PASS;
    }
    count_stat(cidr ? WARDD_STAT_DROP_BAN_CIDR : WARDD_STAT_DROP_BAN_EXACT);
    return XDP_DROP;
}

static __always_inline int geo_miss_result(const struct wardd_runtime_config *config)
{
    if (config == NULL || config->geo_action == WARDD_RUNTIME_OBSERVE) {
        count_stat(WARDD_STAT_WOULD_DROP_GEO);
        return XDP_PASS;
    }
    count_stat(WARDD_STAT_DROP_GEO_NON_CN);
    return XDP_DROP;
}

static __always_inline int handle_ipv4(
    void *cursor,
    void *data_end,
    const struct wardd_runtime_config *config
)
{
    struct iphdr *ipv4 = cursor;
    struct tcphdr *tcp;
    __u32 config_key = 0;
    __u64 now;
    __u8 *enabled;
    __u8 *country_match;
    void *cn_map;

    if ((void *)(ipv4 + 1) > data_end || ipv4->ihl < 5) {
        count_stat(WARDD_STAT_PARSE_ERROR);
        return XDP_PASS;
    }
    if (ipv4->protocol != IPPROTO_TCP) {
        count_stat(WARDD_STAT_PASS_NON_ENDPOINT);
        return XDP_PASS;
    }
    if ((ipv4->frag_off & bpf_htons(0x1fff)) != 0) {
        count_stat(WARDD_STAT_PASS_PARSE_UNSUPPORTED);
        return XDP_PASS;
    }
    tcp = (void *)((unsigned char *)ipv4 + ((__u32)ipv4->ihl * 4));
    if ((void *)(tcp + 1) > data_end) {
        count_stat(WARDD_STAT_PARSE_ERROR);
        return XDP_PASS;
    }

    enabled = bpf_map_lookup_elem(&ban_ports, &tcp->dest);
    if (enabled != NULL) {
        struct wardd_ban_value *exact;
        struct wardd_ban_value *cidr;
        struct wardd_v4_lpm_key cidr_key = {
            .prefixlen = 32,
            .address = ipv4->saddr,
        };

        now = bpf_ktime_get_ns();
        exact = bpf_map_lookup_elem(&ban_v4, &ipv4->saddr);
        if (ban_is_active(exact, now)) {
            return ban_result(config, false);
        }
        cidr = bpf_map_lookup_elem(&ban_cidr4, &cidr_key);
        if (ban_is_active(cidr, now)) {
            return ban_result(config, true);
        }
    }

    struct wardd_v4_endpoint_key endpoint = {
        .address = ipv4->daddr,
        .port = tcp->dest,
        .protocol = IPPROTO_TCP,
    };
    enabled = bpf_map_lookup_elem(&geo_ep_v4, &endpoint);
    if (enabled == NULL) {
        endpoint.address = 0;
        enabled = bpf_map_lookup_elem(&geo_ep_v4, &endpoint);
    }
    if (enabled == NULL) {
        count_stat(WARDD_STAT_PASS_NON_ENDPOINT);
        return XDP_PASS;
    }

    cn_map = bpf_map_lookup_elem(&cn_v4_sets, &config_key);
    if (cn_map == NULL) {
        count_stat(WARDD_STAT_PASS_PARSE_UNSUPPORTED);
        return XDP_PASS;
    }
    struct wardd_v4_lpm_key country_key = {
        .prefixlen = 32,
        .address = ipv4->saddr,
    };
    country_match = bpf_map_lookup_elem(cn_map, &country_key);
    if (country_match == NULL) {
        return geo_miss_result(config);
    }
    count_stat(WARDD_STAT_PASS_CN);
    return XDP_PASS;
}

static __always_inline int handle_ipv6(
    void *cursor,
    void *data_end,
    const struct wardd_runtime_config *config
)
{
    struct ipv6hdr *ipv6 = cursor;
    struct tcphdr *tcp;
    struct wardd_v6_address source = {0};
    __u32 config_key = 0;
    __u64 now;
    __u8 *enabled;
    __u8 *country_match;
    void *cn_map;

    if ((void *)(ipv6 + 1) > data_end) {
        count_stat(WARDD_STAT_PARSE_ERROR);
        return XDP_PASS;
    }
    if (ipv6->nexthdr != IPPROTO_TCP) {
        count_stat(WARDD_STAT_PASS_PARSE_UNSUPPORTED);
        return XDP_PASS;
    }
    tcp = (void *)(ipv6 + 1);
    if ((void *)(tcp + 1) > data_end) {
        count_stat(WARDD_STAT_PARSE_ERROR);
        return XDP_PASS;
    }
    __builtin_memcpy(source.address, &ipv6->saddr, sizeof(source.address));

    enabled = bpf_map_lookup_elem(&ban_ports, &tcp->dest);
    if (enabled != NULL) {
        struct wardd_ban_value *exact;
        struct wardd_ban_value *cidr;
        struct wardd_v6_lpm_key cidr_key = {.prefixlen = 128};

        __builtin_memcpy(cidr_key.address, source.address, sizeof(cidr_key.address));
        now = bpf_ktime_get_ns();
        exact = bpf_map_lookup_elem(&ban_v6, &source);
        if (ban_is_active(exact, now)) {
            return ban_result(config, false);
        }
        cidr = bpf_map_lookup_elem(&ban_cidr6, &cidr_key);
        if (ban_is_active(cidr, now)) {
            return ban_result(config, true);
        }
    }

    struct wardd_v6_endpoint_key endpoint = {
        .port = tcp->dest,
        .protocol = IPPROTO_TCP,
    };
    __builtin_memcpy(endpoint.address, &ipv6->daddr, sizeof(endpoint.address));
    enabled = bpf_map_lookup_elem(&geo_ep_v6, &endpoint);
    if (enabled == NULL) {
        __builtin_memset(endpoint.address, 0, sizeof(endpoint.address));
        enabled = bpf_map_lookup_elem(&geo_ep_v6, &endpoint);
    }
    if (enabled == NULL) {
        count_stat(WARDD_STAT_PASS_NON_ENDPOINT);
        return XDP_PASS;
    }

    cn_map = bpf_map_lookup_elem(&cn_v6_sets, &config_key);
    if (cn_map == NULL) {
        count_stat(WARDD_STAT_PASS_PARSE_UNSUPPORTED);
        return XDP_PASS;
    }
    struct wardd_v6_lpm_key country_key = {.prefixlen = 128};
    __builtin_memcpy(country_key.address, source.address, sizeof(country_key.address));
    country_match = bpf_map_lookup_elem(cn_map, &country_key);
    if (country_match == NULL) {
        return geo_miss_result(config);
    }
    count_stat(WARDD_STAT_PASS_CN);
    return XDP_PASS;
}

SEC("xdp")
int wardd_xdp(struct xdp_md *context)
{
    void *data = (void *)(long)context->data;
    void *data_end = (void *)(long)context->data_end;
    struct ethhdr *ethernet = data;
    void *cursor;
    __be16 protocol;
    __u32 config_key = 0;
    struct wardd_runtime_config *config;

    if ((void *)(ethernet + 1) > data_end) {
        count_stat(WARDD_STAT_PARSE_ERROR);
        return XDP_PASS;
    }
    protocol = ethernet->h_proto;
    cursor = ethernet + 1;

#pragma unroll
    for (int index = 0; index < 2; index++) {
        if (protocol == bpf_htons(ETH_P_8021Q) || protocol == bpf_htons(ETH_P_8021AD)) {
            struct wardd_vlan_header *vlan = cursor;
            if ((void *)(vlan + 1) > data_end) {
                count_stat(WARDD_STAT_PARSE_ERROR);
                return XDP_PASS;
            }
            protocol = vlan->encapsulated_protocol;
            cursor = vlan + 1;
        }
    }

    config = bpf_map_lookup_elem(&runtime_cfg, &config_key);
    if (protocol == bpf_htons(ETH_P_IP)) {
        return handle_ipv4(cursor, data_end, config);
    }
    if (protocol == bpf_htons(ETH_P_IPV6)) {
        return handle_ipv6(cursor, data_end, config);
    }
    count_stat(WARDD_STAT_PASS_NON_ENDPOINT);
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
