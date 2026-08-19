#include "wardd/fetch.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int failures;

#define CHECK(condition, message) \
    do { \
        if (!(condition)) { \
            fprintf(stderr, "FAIL: %s (line %d)\n", (message), __LINE__); \
            failures++; \
        } \
    } while (0)

static int write_file(const char *path, const char *contents)
{
    FILE *file = fopen(path, "wx");
    if (file == NULL) return -1;
    if (fputs(contents, file) == EOF) {
        (void)fclose(file);
        return -1;
    }
    return fclose(file) == 0 ? 0 : -1;
}

int main(void)
{
    static const char expected[] = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    char directory[] = "/tmp/wardd-fetch-test-XXXXXX";
    char data_path[256];
    char checksum_path[256];
    char rejected_path[256];
    char digest[WARDD_SHA256_HEX_LEN];
    char error[512];

    CHECK(mkdtemp(directory) != NULL, "create fetch test directory");
    (void)snprintf(data_path, sizeof(data_path), "%s/data", directory);
    (void)snprintf(checksum_path, sizeof(checksum_path), "%s/data.sha256sum", directory);
    (void)snprintf(rejected_path, sizeof(rejected_path), "%s/rejected", directory);
    CHECK(write_file(data_path, "abc") == 0, "write digest fixture");
    CHECK(
        write_file(
            checksum_path,
            "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD  data\n"
        ) == 0,
        "write checksum fixture"
    );
    CHECK(wardd_sha256_file(data_path, digest, error, sizeof(error)) == 0, error);
    CHECK(strcmp(digest, expected) == 0, "known SHA-256 digest");
    CHECK(
        wardd_verify_sha256(data_path, checksum_path, digest, error, sizeof(error)) == 0,
        error
    );
    CHECK(strcmp(digest, expected) == 0, "verified SHA-256 digest");
    CHECK(
        wardd_https_download(
            "http://example.invalid/data",
            rejected_path,
            1024,
            NULL,
            error,
            sizeof(error)
        ) != 0,
        "plain HTTP must be rejected"
    );
    CHECK(access(rejected_path, F_OK) != 0, "rejected download creates no output");

    (void)unlink(data_path);
    (void)unlink(checksum_path);
    (void)unlink(rejected_path);
    (void)rmdir(directory);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
