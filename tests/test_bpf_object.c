#include <bpf/libbpf.h>

#include <stdio.h>

static int require_map(struct bpf_object *object, const char *name)
{
    if (bpf_object__find_map_by_name(object, name) == NULL) {
        fprintf(stderr, "BPF object is missing map: %s\n", name);
        return -1;
    }

    return 0;
}

int main(void)
{
    static const char *const required_maps[] = {
        "cn_v4_sets",
        "cn_v6_sets",
        "ban_v4",
        "ban_v6",
        "ban_cidr4",
        "ban_cidr6",
        "geo_ep_v4",
        "geo_ep_v6",
        "ban_ports",
        "runtime_cfg",
        "stats",
    };
    struct bpf_object *object;
    size_t index;
    int result = 0;

    object = bpf_object__open_file(WARDD_TEST_BPF_OBJECT, NULL);
    if (libbpf_get_error(object) != 0) {
        fprintf(stderr, "cannot open BPF object: %s\n", WARDD_TEST_BPF_OBJECT);
        return 1;
    }

    if (bpf_object__find_program_by_name(object, "wardd_xdp") == NULL) {
        fprintf(stderr, "BPF object is missing program: wardd_xdp\n");
        result = 1;
    }

    for (index = 0; index < sizeof(required_maps) / sizeof(required_maps[0]); ++index) {
        if (require_map(object, required_maps[index]) != 0) {
            result = 1;
        }
    }

    bpf_object__close(object);
    return result;
}
