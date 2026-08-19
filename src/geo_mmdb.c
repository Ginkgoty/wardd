#include "wardd/geo.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <maxminddb.h>

struct compiler {
    MMDB_s database;
    char country[3];
    FILE *ipv4_output;
    FILE *ipv6_output;
    FILE *nginx_output;
    uint64_t visited_nodes;
    uint64_t visit_limit;
    size_t ipv4_prefixes;
    size_t ipv6_prefixes;
    bool created_ipv4;
    bool created_ipv6;
    bool created_nginx;
    char *error;
    size_t error_size;
};

enum subtree_coverage {
    SUBTREE_EMPTY = 0,
    SUBTREE_FULL,
    SUBTREE_MIXED,
};

static void set_error(struct compiler *compiler, const char *format, ...)
{
    va_list arguments;

    if (compiler->error == NULL || compiler->error_size == 0) {
        return;
    }
    va_start(arguments, format);
    (void)vsnprintf(compiler->error, compiler->error_size, format, arguments);
    va_end(arguments);
}

static int entry_matches_country(
    struct compiler *compiler,
    MMDB_entry_s entry,
    bool *matches
)
{
    MMDB_entry_data_s data = {0};
    int status;

    *matches = false;
    status = MMDB_get_value(&entry, &data, "country", "iso_code", NULL);
    if (status == MMDB_LOOKUP_PATH_DOES_NOT_MATCH_DATA_ERROR) {
        return 0;
    }
    if (status != MMDB_SUCCESS) {
        set_error(compiler, "cannot read country.iso_code: %s", MMDB_strerror(status));
        return -1;
    }
    if (!data.has_data) {
        return 0;
    }
    if (data.type != MMDB_DATA_TYPE_UTF8_STRING) {
        set_error(compiler, "country.iso_code is not a UTF-8 string");
        return -1;
    }
    *matches = data.data_size == 2 &&
        memcmp(data.utf8_string, compiler->country, 2) == 0;
    return 0;
}

static int emit_prefix(
    struct compiler *compiler,
    int address_family,
    const unsigned char address[16],
    unsigned int prefix_length
)
{
    char address_text[INET6_ADDRSTRLEN];
    FILE *family_output;

    if (prefix_length == 0) {
        set_error(compiler, "compiled country unexpectedly covers a default route");
        return -1;
    }
    if (inet_ntop(address_family, address, address_text, sizeof(address_text)) == NULL) {
        set_error(compiler, "cannot format network address: %s", strerror(errno));
        return -1;
    }

    family_output = address_family == AF_INET ? compiler->ipv4_output : compiler->ipv6_output;
    if (fprintf(family_output, "%s/%u\n", address_text, prefix_length) < 0 ||
        fprintf(compiler->nginx_output, "%s/%u 1;\n", address_text, prefix_length) < 0) {
        set_error(compiler, "cannot write compiled prefix: %s", strerror(errno));
        return -1;
    }
    if (address_family == AF_INET) {
        compiler->ipv4_prefixes++;
    } else {
        compiler->ipv6_prefixes++;
    }
    return 0;
}

static int walk_node(
    struct compiler *compiler,
    int address_family,
    uint32_t node_number,
    unsigned int depth,
    const unsigned char parent_address[16],
    bool skip_ipv4_subtree,
    enum subtree_coverage *coverage
)
{
    MMDB_search_node_s node = {0};
    const unsigned int address_bits = address_family == AF_INET ? 32U : 128U;
    enum subtree_coverage branch_coverage[2] = {SUBTREE_EMPTY, SUBTREE_EMPTY};
    unsigned char branch_address[2][16];
    int status;

    if (depth >= address_bits) {
        set_error(compiler, "MMDB search node exceeds address width");
        return -1;
    }
    if (++compiler->visited_nodes > compiler->visit_limit) {
        set_error(compiler, "MMDB traversal exceeded the node safety limit");
        return -1;
    }
    if (skip_ipv4_subtree &&
        depth == compiler->database.ipv4_start_node.netmask &&
        node_number == compiler->database.ipv4_start_node.node_value) {
        *coverage = SUBTREE_EMPTY;
        return 0;
    }

    status = MMDB_read_node(&compiler->database, node_number, &node);
    if (status != MMDB_SUCCESS) {
        set_error(compiler, "cannot read MMDB node %u: %s", node_number, MMDB_strerror(status));
        return -1;
    }

    for (unsigned int branch = 0; branch < 2; branch++) {
        const uint8_t record_type = branch == 0 ? node.left_record_type : node.right_record_type;
        const uint64_t record = branch == 0 ? node.left_record : node.right_record;
        MMDB_entry_s entry = branch == 0 ? node.left_record_entry : node.right_record_entry;
        bool matches;

        memcpy(branch_address[branch], parent_address, sizeof(branch_address[branch]));
        if (branch != 0) {
            branch_address[branch][depth / 8] |= (unsigned char)(0x80U >> (depth % 8));
        }

        if (record_type == MMDB_RECORD_TYPE_EMPTY) {
            continue;
        }
        if (record_type == MMDB_RECORD_TYPE_DATA) {
            if (entry_matches_country(compiler, entry, &matches) != 0) return -1;
            branch_coverage[branch] = matches ? SUBTREE_FULL : SUBTREE_EMPTY;
            continue;
        }
        if (record_type != MMDB_RECORD_TYPE_SEARCH_NODE || record > UINT32_MAX) {
            set_error(compiler, "invalid MMDB record at node %u", node_number);
            return -1;
        }
        if (walk_node(
                compiler,
                address_family,
                (uint32_t)record,
                depth + 1,
                branch_address[branch],
                skip_ipv4_subtree,
                &branch_coverage[branch]
            ) != 0) {
            return -1;
        }
    }
    if (branch_coverage[0] == SUBTREE_FULL && branch_coverage[1] == SUBTREE_FULL) {
        *coverage = SUBTREE_FULL;
        return 0;
    }
    for (unsigned int branch = 0; branch < 2; ++branch) {
        if (branch_coverage[branch] == SUBTREE_FULL &&
            emit_prefix(compiler, address_family, branch_address[branch], depth + 1) != 0) {
            return -1;
        }
    }
    *coverage = branch_coverage[0] == SUBTREE_EMPTY && branch_coverage[1] == SUBTREE_EMPTY
        ? SUBTREE_EMPTY : SUBTREE_MIXED;
    return 0;
}

static int flush_output(struct compiler *compiler, FILE *output, const char *label)
{
    if (fflush(output) != 0 || fsync(fileno(output)) != 0) {
        set_error(compiler, "cannot flush %s output: %s", label, strerror(errno));
        return -1;
    }
    return 0;
}

static void close_output(FILE **output)
{
    if (*output != NULL) {
        (void)fclose(*output);
        *output = NULL;
    }
}

int wardd_geo_compile_mmdb(
    const char *mmdb_path,
    const char country[3],
    const char *ipv4_output_path,
    const char *ipv6_output_path,
    const char *nginx_output_path,
    struct wardd_geo_compile_result *result,
    char *error,
    size_t error_size
)
{
    struct compiler compiler = {.error = error, .error_size = error_size};
    unsigned char root_address[16] = {0};
    enum subtree_coverage coverage = SUBTREE_EMPTY;
    int status;
    int return_value = -1;

    if (error != NULL && error_size > 0) {
        error[0] = '\0';
    }
    if (result != NULL) {
        memset(result, 0, sizeof(*result));
    }
    if (mmdb_path == NULL || country == NULL || strlen(country) != 2 ||
        ipv4_output_path == NULL || ipv6_output_path == NULL || nginx_output_path == NULL) {
        set_error(&compiler, "MMDB input, two-letter country, and output paths are required");
        return -1;
    }
    compiler.country[0] = country[0];
    compiler.country[1] = country[1];
    compiler.country[2] = '\0';

    status = MMDB_open(mmdb_path, MMDB_MODE_MMAP, &compiler.database);
    if (status != MMDB_SUCCESS) {
        set_error(&compiler, "cannot open MMDB: %s", MMDB_strerror(status));
        return -1;
    }
    if (compiler.database.metadata.binary_format_major_version != 2 ||
        (compiler.database.metadata.ip_version != 4 && compiler.database.metadata.ip_version != 6) ||
        compiler.database.metadata.node_count == 0) {
        set_error(&compiler, "unsupported or empty MMDB metadata");
        goto done;
    }
    compiler.visit_limit = (uint64_t)compiler.database.metadata.node_count * 3ULL + 256ULL;

    compiler.ipv4_output = fopen(ipv4_output_path, "wx");
    if (compiler.ipv4_output == NULL) {
        set_error(&compiler, "cannot create staged GeoIP output: %s", strerror(errno));
        goto done;
    }
    compiler.created_ipv4 = true;
    compiler.ipv6_output = fopen(ipv6_output_path, "wx");
    if (compiler.ipv6_output == NULL) {
        set_error(&compiler, "cannot create staged GeoIP output: %s", strerror(errno));
        goto done;
    }
    compiler.created_ipv6 = true;
    compiler.nginx_output = fopen(nginx_output_path, "wx");
    if (compiler.nginx_output == NULL) {
        set_error(&compiler, "cannot create staged GeoIP output: %s", strerror(errno));
        goto done;
    }
    compiler.created_nginx = true;
    if (fchmod(fileno(compiler.ipv4_output), 0640) != 0 ||
        fchmod(fileno(compiler.ipv6_output), 0640) != 0 ||
        fchmod(fileno(compiler.nginx_output), 0640) != 0) {
        set_error(&compiler, "cannot set staged GeoIP output permissions: %s", strerror(errno));
        goto done;
    }
    if (fprintf(
            compiler.nginx_output,
            "# Generated by wardd from MMDB build epoch %llu; do not edit.\n",
            (unsigned long long)compiler.database.metadata.build_epoch
        ) < 0) {
        set_error(&compiler, "cannot write Nginx output header: %s", strerror(errno));
        goto done;
    }

    if (compiler.database.metadata.ip_version == 4) {
        if (walk_node(&compiler, AF_INET, 0, 0, root_address, false, &coverage) != 0 ||
            (coverage == SUBTREE_FULL && emit_prefix(&compiler, AF_INET, root_address, 0) != 0)) {
            goto done;
        }
    } else {
        const uint32_t ipv4_start = compiler.database.ipv4_start_node.node_value;
        uint64_t ipv4_visited = 0;

        if (ipv4_start < compiler.database.metadata.node_count &&
            (walk_node(&compiler, AF_INET, ipv4_start, 0, root_address, false, &coverage) != 0 ||
             (coverage == SUBTREE_FULL && emit_prefix(&compiler, AF_INET, root_address, 0) != 0))) {
            goto done;
        }
        ipv4_visited = compiler.visited_nodes;
        compiler.visited_nodes = 0;
        coverage = SUBTREE_EMPTY;
        if (walk_node(&compiler, AF_INET6, 0, 0, root_address, true, &coverage) != 0 ||
            (coverage == SUBTREE_FULL && emit_prefix(&compiler, AF_INET6, root_address, 0) != 0)) {
            goto done;
        }
        compiler.visited_nodes += ipv4_visited;
    }
    if (compiler.ipv4_prefixes == 0 || compiler.ipv6_prefixes == 0) {
        set_error(&compiler, "compiled country must contain both IPv4 and IPv6 prefixes");
        goto done;
    }
    if (flush_output(&compiler, compiler.ipv4_output, "IPv4") != 0 ||
        flush_output(&compiler, compiler.ipv6_output, "IPv6") != 0 ||
        flush_output(&compiler, compiler.nginx_output, "Nginx") != 0) {
        goto done;
    }

    if (result != NULL) {
        result->build_epoch = compiler.database.metadata.build_epoch;
        result->visited_nodes = compiler.visited_nodes;
        result->ipv4_prefixes = compiler.ipv4_prefixes;
        result->ipv6_prefixes = compiler.ipv6_prefixes;
        if (compiler.database.metadata.database_type != NULL) {
            (void)snprintf(
                result->database_type,
                sizeof(result->database_type),
                "%s",
                compiler.database.metadata.database_type
            );
        }
    }
    return_value = 0;

done:
    close_output(&compiler.ipv4_output);
    close_output(&compiler.ipv6_output);
    close_output(&compiler.nginx_output);
    MMDB_close(&compiler.database);
    if (return_value != 0) {
        if (compiler.created_ipv4) (void)unlink(ipv4_output_path);
        if (compiler.created_ipv6) (void)unlink(ipv6_output_path);
        if (compiler.created_nginx) (void)unlink(nginx_output_path);
    }
    return return_value;
}

int wardd_geo_mmdb_available(void)
{
    return 1;
}
