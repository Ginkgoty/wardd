#ifndef WARDD_FETCH_H
#define WARDD_FETCH_H

#include <stddef.h>
#include <stdint.h>

#define WARDD_SHA256_HEX_LEN 65
#define WARDD_ETAG_LEN 256

struct wardd_fetch_result {
    uint64_t bytes;
    long http_status;
    char etag[WARDD_ETAG_LEN];
};

int wardd_https_download(
    const char *url,
    const char *output_path,
    uint64_t max_bytes,
    struct wardd_fetch_result *result,
    char *error,
    size_t error_size
);

int wardd_sha256_file(
    const char *path,
    char digest[WARDD_SHA256_HEX_LEN],
    char *error,
    size_t error_size
);

int wardd_read_sha256_file(
    const char *path,
    char digest[WARDD_SHA256_HEX_LEN],
    char *error,
    size_t error_size
);

int wardd_verify_sha256(
    const char *data_path,
    const char *checksum_path,
    char digest[WARDD_SHA256_HEX_LEN],
    char *error,
    size_t error_size
);

#endif
