#include "wardd/fetch.h"

#include <ctype.h>
#include <curl/curl.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

struct download_context {
    FILE *output;
    uint64_t bytes;
    uint64_t max_bytes;
    bool size_exceeded;
};

static void set_error(char *error, size_t error_size, const char *format, ...)
{
    va_list arguments;

    if (error == NULL || error_size == 0) {
        return;
    }
    va_start(arguments, format);
    (void)vsnprintf(error, error_size, format, arguments);
    va_end(arguments);
}

static size_t write_download(void *data, size_t size, size_t count, void *opaque)
{
    struct download_context *context = opaque;
    size_t bytes;

    if (count != 0 && size > SIZE_MAX / count) {
        context->size_exceeded = true;
        return 0;
    }
    bytes = size * count;
    if ((uint64_t)bytes > context->max_bytes - context->bytes) {
        context->size_exceeded = true;
        return 0;
    }
    if (fwrite(data, 1, bytes, context->output) != bytes) {
        return 0;
    }
    context->bytes += (uint64_t)bytes;
    return bytes;
}

int wardd_https_download(
    const char *url,
    const char *output_path,
    uint64_t max_bytes,
    struct wardd_fetch_result *result,
    char *error,
    size_t error_size
)
{
    struct download_context context = {.max_bytes = max_bytes};
    CURL *curl = NULL;
    CURLcode curl_status;
    long http_status = 0;
    int return_value = -1;

    if (error != NULL && error_size > 0) error[0] = '\0';
    if (result != NULL) memset(result, 0, sizeof(*result));
    if (url == NULL || strncmp(url, "https://", 8) != 0 || output_path == NULL || max_bytes == 0) {
        set_error(error, error_size, "an HTTPS URL, output path, and positive size limit are required");
        return -1;
    }

    context.output = fopen(output_path, "wx");
    if (context.output == NULL) {
        set_error(error, error_size, "cannot create download output: %s", strerror(errno));
        return -1;
    }
    if (fchmod(fileno(context.output), 0600) != 0) {
        set_error(error, error_size, "cannot protect download output: %s", strerror(errno));
        goto done;
    }
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
        set_error(error, error_size, "cannot initialize HTTPS client");
        goto done;
    }
    curl = curl_easy_init();
    if (curl == NULL) {
        set_error(error, error_size, "cannot allocate HTTPS client");
        goto done_global;
    }

#define SETOPT(option, value) \
    do { \
        if (curl_easy_setopt(curl, (option), (value)) != CURLE_OK) { \
            set_error(error, error_size, "cannot configure HTTPS client"); \
            goto done_curl; \
        } \
    } while (0)

    SETOPT(CURLOPT_URL, url);
    SETOPT(CURLOPT_PROTOCOLS_STR, "https");
    SETOPT(CURLOPT_REDIR_PROTOCOLS_STR, "https");
    SETOPT(CURLOPT_FOLLOWLOCATION, 1L);
    SETOPT(CURLOPT_MAXREDIRS, 3L);
    SETOPT(CURLOPT_CONNECTTIMEOUT, 15L);
    SETOPT(CURLOPT_TIMEOUT, 120L);
    SETOPT(CURLOPT_FAILONERROR, 1L);
    SETOPT(CURLOPT_NOSIGNAL, 1L);
    SETOPT(CURLOPT_USERAGENT, "wardd/0.1");
    SETOPT(CURLOPT_WRITEFUNCTION, write_download);
    SETOPT(CURLOPT_WRITEDATA, &context);

#undef SETOPT

    curl_status = curl_easy_perform(curl);
    (void)curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_status);
    if (curl_status != CURLE_OK) {
        set_error(
            error,
            error_size,
            context.size_exceeded ? "download exceeded the configured size limit" :
                "HTTPS download failed: %s",
            context.size_exceeded ? "" : curl_easy_strerror(curl_status)
        );
        goto done_curl;
    }
    if (http_status != 200) {
        set_error(error, error_size, "HTTPS server returned status %ld", http_status);
        goto done_curl;
    }
    if (fflush(context.output) != 0 || fsync(fileno(context.output)) != 0) {
        set_error(error, error_size, "cannot flush download output: %s", strerror(errno));
        goto done_curl;
    }
    if (result != NULL) {
        result->bytes = context.bytes;
        result->http_status = http_status;
    }
    return_value = 0;

done_curl:
    curl_easy_cleanup(curl);
done_global:
    curl_global_cleanup();
done:
    if (fclose(context.output) != 0 && return_value == 0) {
        set_error(error, error_size, "cannot close download output: %s", strerror(errno));
        return_value = -1;
    }
    if (return_value != 0) (void)unlink(output_path);
    return return_value;
}

int wardd_sha256_file(
    const char *path,
    char digest[WARDD_SHA256_HEX_LEN],
    char *error,
    size_t error_size
)
{
    unsigned char buffer[32768];
    unsigned char raw_digest[EVP_MAX_MD_SIZE];
    unsigned int raw_length = 0;
    EVP_MD_CTX *context = NULL;
    FILE *file = NULL;
    int return_value = -1;

    if (error != NULL && error_size > 0) error[0] = '\0';
    if (path == NULL || digest == NULL) {
        set_error(error, error_size, "SHA-256 input and output are required");
        return -1;
    }
    file = fopen(path, "rb");
    if (file == NULL) {
        set_error(error, error_size, "cannot open SHA-256 input: %s", strerror(errno));
        return -1;
    }
    context = EVP_MD_CTX_new();
    if (context == NULL || EVP_DigestInit_ex(context, EVP_sha256(), NULL) != 1) {
        set_error(error, error_size, "cannot initialize SHA-256");
        goto done;
    }
    for (;;) {
        size_t bytes = fread(buffer, 1, sizeof(buffer), file);
        if (bytes > 0 && EVP_DigestUpdate(context, buffer, bytes) != 1) {
            set_error(error, error_size, "cannot update SHA-256");
            goto done;
        }
        if (bytes < sizeof(buffer)) {
            if (ferror(file)) {
                set_error(error, error_size, "cannot read SHA-256 input: %s", strerror(errno));
                goto done;
            }
            break;
        }
    }
    if (EVP_DigestFinal_ex(context, raw_digest, &raw_length) != 1 || raw_length != 32) {
        set_error(error, error_size, "cannot finish SHA-256");
        goto done;
    }
    for (size_t index = 0; index < 32; ++index) {
        (void)snprintf(digest + index * 2, 3, "%02x", raw_digest[index]);
    }
    digest[64] = '\0';
    return_value = 0;

done:
    EVP_MD_CTX_free(context);
    (void)fclose(file);
    return return_value;
}

int wardd_read_sha256_file(
    const char *path,
    char digest[WARDD_SHA256_HEX_LEN],
    char *error,
    size_t error_size
)
{
    char buffer[4096];
    FILE *file;
    size_t length;

    if (error != NULL && error_size > 0) error[0] = '\0';
    if (path == NULL || digest == NULL) {
        set_error(error, error_size, "checksum path and output are required");
        return -1;
    }
    file = fopen(path, "r");
    if (file == NULL) {
        set_error(error, error_size, "cannot open checksum file: %s", strerror(errno));
        return -1;
    }
    length = fread(buffer, 1, sizeof(buffer) - 1, file);
    if (ferror(file)) {
        set_error(error, error_size, "cannot read checksum file: %s", strerror(errno));
        (void)fclose(file);
        return -1;
    }
    if (!feof(file)) {
        set_error(error, error_size, "checksum file is too large");
        (void)fclose(file);
        return -1;
    }
    (void)fclose(file);
    buffer[length] = '\0';
    if (length < 64 || (length > 64 && !isspace((unsigned char)buffer[64]))) {
        set_error(error, error_size, "checksum file does not start with a SHA-256 digest");
        return -1;
    }
    for (size_t index = 0; index < 64; ++index) {
        if (!isxdigit((unsigned char)buffer[index])) {
            set_error(error, error_size, "checksum file contains an invalid SHA-256 digest");
            return -1;
        }
        digest[index] = (char)tolower((unsigned char)buffer[index]);
    }
    digest[64] = '\0';
    return 0;
}

int wardd_verify_sha256(
    const char *data_path,
    const char *checksum_path,
    char digest[WARDD_SHA256_HEX_LEN],
    char *error,
    size_t error_size
)
{
    char expected[WARDD_SHA256_HEX_LEN];
    char actual[WARDD_SHA256_HEX_LEN];

    if (wardd_read_sha256_file(checksum_path, expected, error, error_size) != 0 ||
        wardd_sha256_file(data_path, actual, error, error_size) != 0) {
        return -1;
    }
    if (strcmp(expected, actual) != 0) {
        set_error(error, error_size, "SHA-256 mismatch: expected %s, got %s", expected, actual);
        return -1;
    }
    if (digest != NULL) (void)snprintf(digest, WARDD_SHA256_HEX_LEN, "%s", actual);
    return 0;
}
