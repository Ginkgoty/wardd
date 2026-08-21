#include "wardd/snapshot.h"

#include "wardd/nginx.h"
#include "wardd/version.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/*
 * Bumped from 1 when geo.country became a list. The schema is part of the
 * snapshot identity so that directories written by an older wardd, which hold
 * differently named files, can never collide with new ones.
 */
#define SNAPSHOT_METADATA_SCHEMA 2u
#define SNAPSHOT_PATH_LEN 2048
#define PREFIX_LINE_LIMIT 2000000U

struct prefix_list {
    char **items;
    size_t count;
    size_t capacity;
};

static void set_error(char *error, size_t error_size, const char *format, ...)
{
    va_list arguments;

    if (error == NULL || error_size == 0) return;
    va_start(arguments, format);
    (void)vsnprintf(error, error_size, format, arguments);
    va_end(arguments);
}

static int path_join(char *output, size_t output_size, const char *left, const char *right)
{
    const int length = snprintf(output, output_size, "%s/%s", left, right);
    return length < 0 || (size_t)length >= output_size ? -1 : 0;
}

static int lock_snapshot_root(const char *root, char *error, size_t error_size)
{
    char path[SNAPSHOT_PATH_LEN];
    int file;

    if (path_join(path, sizeof(path), root, ".lock") != 0) {
        set_error(error, error_size, "snapshot lock path is too long");
        return -1;
    }
    file = open(path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (file < 0 || flock(file, LOCK_EX) != 0) {
        const int saved_errno = errno;
        if (file >= 0) (void)close(file);
        set_error(error, error_size, "cannot lock snapshot transactions: %s", strerror(saved_errno));
        return -1;
    }
    return file;
}

static int ensure_directory(const char *path, char *error, size_t error_size)
{
    char copy[SNAPSHOT_PATH_LEN];

    if (path == NULL || path[0] != '/' || strlen(path) >= sizeof(copy)) {
        set_error(error, error_size, "snapshot root must be a bounded absolute path");
        return -1;
    }
    (void)snprintf(copy, sizeof(copy), "%s", path);
    for (char *cursor = copy + 1; ; ++cursor) {
        if (*cursor != '/' && *cursor != '\0') continue;
        const char saved = *cursor;
        struct stat status;
        *cursor = '\0';
        if (mkdir(copy, 0750) != 0 && errno != EEXIST) {
            set_error(error, error_size, "cannot create %s: %s", copy, strerror(errno));
            return -1;
        }
        if (lstat(copy, &status) != 0 || !S_ISDIR(status.st_mode)) {
            set_error(error, error_size, "%s is not a real directory", copy);
            return -1;
        }
        *cursor = saved;
        if (saved == '\0') break;
    }
    return 0;
}

static bool valid_snapshot_id(const char *id)
{
    size_t length;

    if (id == NULL) return false;
    length = strlen(id);
    if (length == 0 || length >= WARDD_SNAPSHOT_ID_LEN || id[0] == '.') return false;
    for (size_t index = 0; index < length; ++index) {
        const unsigned char character = (unsigned char)id[index];
        if (!isalnum(character) && character != '-' && character != '_' && character != '.') return false;
    }
    return true;
}

static int require_regular(const char *path, char *error, size_t error_size)
{
    struct stat status;

    if (lstat(path, &status) != 0) {
        set_error(error, error_size, "required snapshot file %s is unavailable: %s", path, strerror(errno));
        return -1;
    }
    if (!S_ISREG(status.st_mode)) {
        set_error(error, error_size, "required snapshot path %s is not a regular file", path);
        return -1;
    }
    return 0;
}

static int validate_snapshot(
    const char *root,
    const char *id,
    char *directory,
    size_t directory_size,
    char *error,
    size_t error_size
)
{
    static const char *const files[] = {
        "source.mmdb", "geo-v4.txt", "geo-v6.txt", "nginx-geo.conf", "metadata.json", "sha256"
    };
    struct stat status;

    if (!valid_snapshot_id(id) || path_join(directory, directory_size, root, id) != 0) {
        set_error(error, error_size, "snapshot ID is invalid or too long");
        return -1;
    }
    if (lstat(directory, &status) != 0 || !S_ISDIR(status.st_mode)) {
        set_error(error, error_size, "snapshot %s is not available", id);
        return -1;
    }
    for (size_t index = 0; index < sizeof(files) / sizeof(files[0]); ++index) {
        char path[SNAPSHOT_PATH_LEN];
        if (path_join(path, sizeof(path), directory, files[index]) != 0 ||
            require_regular(path, error, error_size) != 0) {
            return -1;
        }
    }
    return 0;
}

static int copy_source(
    const char *source_path,
    const char *destination_path,
    uint64_t max_bytes,
    char *error,
    size_t error_size
)
{
    unsigned char buffer[32768];
    struct stat status;
    int source = -1;
    int destination = -1;
    int return_value = -1;

    source = open(source_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (source < 0 || fstat(source, &status) != 0 || !S_ISREG(status.st_mode)) {
        set_error(error, error_size, "MMDB source must be a readable regular file: %s", strerror(errno));
        goto done;
    }
    if (status.st_size < 0 || (uint64_t)status.st_size > max_bytes) {
        set_error(error, error_size, "MMDB source exceeds the configured size limit");
        goto done;
    }
    destination = open(
        destination_path,
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
        0640
    );
    if (destination < 0) {
        set_error(error, error_size, "cannot create snapshot source: %s", strerror(errno));
        goto done;
    }
    for (;;) {
        ssize_t bytes = read(source, buffer, sizeof(buffer));
        if (bytes < 0 && errno == EINTR) continue;
        if (bytes < 0) {
            set_error(error, error_size, "cannot read MMDB source: %s", strerror(errno));
            goto done;
        }
        if (bytes == 0) break;
        size_t written = 0;
        while (written < (size_t)bytes) {
            ssize_t amount = write(destination, buffer + written, (size_t)bytes - written);
            if (amount < 0 && errno == EINTR) continue;
            if (amount <= 0) {
                set_error(error, error_size, "cannot write snapshot source: %s", strerror(errno));
                goto done;
            }
            written += (size_t)amount;
        }
    }
    if (fsync(destination) != 0) {
        set_error(error, error_size, "cannot flush snapshot source: %s", strerror(errno));
        goto done;
    }
    return_value = 0;

done:
    if (source >= 0) (void)close(source);
    if (destination >= 0) (void)close(destination);
    if (return_value != 0) (void)unlink(destination_path);
    return return_value;
}

static void cleanup_staging(const char *directory)
{
    static const char *const files[] = {
        "source.mmdb", "geo-v4.txt", "geo-v6.txt", "nginx-geo.conf", "metadata.json", "sha256", ".approved"
    };

    if (directory == NULL || strstr(directory, "/.staging-") == NULL) return;
    for (size_t index = 0; index < sizeof(files) / sizeof(files[0]); ++index) {
        char path[SNAPSHOT_PATH_LEN];
        if (path_join(path, sizeof(path), directory, files[index]) == 0) (void)unlink(path);
    }
    (void)rmdir(directory);
}

static int write_text_file(
    const char *path,
    const char *contents,
    mode_t mode,
    char *error,
    size_t error_size
)
{
    int file = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, mode);
    size_t length = strlen(contents);
    size_t written = 0;

    if (file < 0) {
        set_error(error, error_size, "cannot create %s: %s", path, strerror(errno));
        return -1;
    }
    while (written < length) {
        ssize_t amount = write(file, contents + written, length - written);
        if (amount < 0 && errno == EINTR) continue;
        if (amount <= 0) {
            const int saved_errno = errno;
            (void)close(file);
            (void)unlink(path);
            set_error(error, error_size, "cannot write %s: %s", path, strerror(saved_errno));
            return -1;
        }
        written += (size_t)amount;
    }
    if (fsync(file) != 0) {
        const int saved_errno = errno;
        (void)close(file);
        (void)unlink(path);
        set_error(error, error_size, "cannot flush %s: %s", path, strerror(saved_errno));
        return -1;
    }
    if (close(file) != 0) {
        const int saved_errno = errno;
        (void)unlink(path);
        set_error(error, error_size, "cannot close %s: %s", path, strerror(saved_errno));
        return -1;
    }
    return 0;
}

static int compare_strings(const void *left, const void *right)
{
    const char *const *left_string = left;
    const char *const *right_string = right;
    return strcmp(*left_string, *right_string);
}

static void free_prefixes(struct prefix_list *list)
{
    for (size_t index = 0; index < list->count; ++index) free(list->items[index]);
    free(list->items);
    memset(list, 0, sizeof(*list));
}

static int read_prefixes(
    const char *path,
    struct prefix_list *list,
    char *error,
    size_t error_size
)
{
    FILE *file = fopen(path, "r");
    char *line = NULL;
    size_t capacity = 0;
    ssize_t length;

    if (file == NULL) {
        set_error(error, error_size, "cannot read prefix file %s: %s", path, strerror(errno));
        return -1;
    }
    while ((length = getline(&line, &capacity, file)) >= 0) {
        char *copy;
        while (length > 0 && (line[length - 1] == '\n' || line[length - 1] == '\r')) line[--length] = '\0';
        if (length == 0) continue;
        if (list->count >= PREFIX_LINE_LIMIT) {
            set_error(error, error_size, "prefix file exceeds the safety limit");
            free(line);
            (void)fclose(file);
            return -1;
        }
        if (list->count == list->capacity) {
            const size_t new_capacity = list->capacity == 0 ? 1024 : list->capacity * 2;
            char **new_items = realloc(list->items, new_capacity * sizeof(*new_items));
            if (new_items == NULL) {
                set_error(error, error_size, "cannot allocate prefix comparison");
                free(line);
                (void)fclose(file);
                return -1;
            }
            list->items = new_items;
            list->capacity = new_capacity;
        }
        copy = strdup(line);
        if (copy == NULL) {
            set_error(error, error_size, "cannot allocate prefix comparison");
            free(line);
            (void)fclose(file);
            return -1;
        }
        list->items[list->count++] = copy;
    }
    free(line);
    if (ferror(file)) {
        set_error(error, error_size, "cannot finish reading prefix file %s", path);
        (void)fclose(file);
        return -1;
    }
    (void)fclose(file);
    qsort(list->items, list->count, sizeof(*list->items), compare_strings);
    return 0;
}

static void compare_prefixes(
    const struct prefix_list *old_list,
    const struct prefix_list *new_list,
    size_t *added,
    size_t *removed
)
{
    size_t old_index = 0;
    size_t new_index = 0;

    while (old_index < old_list->count && new_index < new_list->count) {
        const int comparison = strcmp(old_list->items[old_index], new_list->items[new_index]);
        if (comparison == 0) {
            old_index++;
            new_index++;
        } else if (comparison < 0) {
            (*removed)++;
            old_index++;
        } else {
            (*added)++;
            new_index++;
        }
    }
    *removed += old_list->count - old_index;
    *added += new_list->count - new_index;
}

int wardd_geo_snapshot_diff(
    const char *snapshot_root,
    const char *old_id,
    const char *new_id,
    struct wardd_geo_diff *diff,
    char *error,
    size_t error_size
)
{
    struct prefix_list old_list = {0};
    struct prefix_list new_list = {0};
    char old_directory[SNAPSHOT_PATH_LEN];
    char new_directory[SNAPSHOT_PATH_LEN];
    int return_value = -1;

    if (error != NULL && error_size > 0) error[0] = '\0';
    if (diff == NULL) {
        set_error(error, error_size, "diff output is required");
        return -1;
    }
    memset(diff, 0, sizeof(*diff));
    if (validate_snapshot(snapshot_root, old_id, old_directory, sizeof(old_directory), error, error_size) != 0 ||
        validate_snapshot(snapshot_root, new_id, new_directory, sizeof(new_directory), error, error_size) != 0) {
        return -1;
    }
    for (size_t family = 0; family < 2; ++family) {
        const char *filename = family == 0 ? "geo-v4.txt" : "geo-v6.txt";
        char old_path[SNAPSHOT_PATH_LEN];
        char new_path[SNAPSHOT_PATH_LEN];
        if (path_join(old_path, sizeof(old_path), old_directory, filename) != 0 ||
            path_join(new_path, sizeof(new_path), new_directory, filename) != 0 ||
            read_prefixes(old_path, &old_list, error, error_size) != 0 ||
            read_prefixes(new_path, &new_list, error, error_size) != 0) {
            goto done;
        }
        diff->old_prefixes += old_list.count;
        diff->new_prefixes += new_list.count;
        compare_prefixes(&old_list, &new_list, &diff->added_prefixes, &diff->removed_prefixes);
        free_prefixes(&old_list);
        free_prefixes(&new_list);
    }
    diff->change_ratio = diff->old_prefixes == 0 ? 1.0 :
        (double)(diff->added_prefixes + diff->removed_prefixes) / (double)diff->old_prefixes;
    return_value = 0;

done:
    free_prefixes(&old_list);
    free_prefixes(&new_list);
    return return_value;
}

static int read_link_id(
    const char *root,
    const char *name,
    char output[WARDD_SNAPSHOT_ID_LEN],
    bool required,
    char *error,
    size_t error_size
)
{
    char path[SNAPSHOT_PATH_LEN];
    ssize_t length;

    output[0] = '\0';
    if (path_join(path, sizeof(path), root, name) != 0) {
        set_error(error, error_size, "snapshot link path is too long");
        return -1;
    }
    length = readlink(path, output, WARDD_SNAPSHOT_ID_LEN - 1);
    if (length < 0) {
        if (!required && errno == ENOENT) return 0;
        set_error(error, error_size, "cannot read snapshot %s link: %s", name, strerror(errno));
        return -1;
    }
    output[length] = '\0';
    if (!valid_snapshot_id(output)) {
        set_error(error, error_size, "snapshot %s link has an unsafe target", name);
        return -1;
    }
    return 0;
}

static int create_approval(
    const char *directory,
    char *error,
    size_t error_size
)
{
    char path[SNAPSHOT_PATH_LEN];

    if (path_join(path, sizeof(path), directory, ".approved") != 0) {
        set_error(error, error_size, "approval path is too long");
        return -1;
    }
    if (write_text_file(path, "approved\n", 0640, error, error_size) == 0) return 0;
    if (errno == EEXIST) {
        struct stat status;
        if (lstat(path, &status) == 0 && S_ISREG(status.st_mode)) {
            if (error != NULL && error_size > 0) error[0] = '\0';
            return 0;
        }
    }
    return -1;
}

static int approve_snapshot_unlocked(
    const char *snapshot_root,
    const char *snapshot_id,
    char *error,
    size_t error_size
)
{
    char directory[SNAPSHOT_PATH_LEN];

    if (error != NULL && error_size > 0) error[0] = '\0';
    if (validate_snapshot(snapshot_root, snapshot_id, directory, sizeof(directory), error, error_size) != 0) {
        return -1;
    }
    return create_approval(directory, error, error_size);
}

int wardd_geo_snapshot_approve(
    const char *snapshot_root,
    const char *snapshot_id,
    char *error,
    size_t error_size
)
{
    int lock;
    int result;

    if (error != NULL && error_size > 0) error[0] = '\0';
    if (ensure_directory(snapshot_root, error, error_size) != 0) return -1;
    lock = lock_snapshot_root(snapshot_root, error, error_size);
    if (lock < 0) return -1;
    result = approve_snapshot_unlocked(snapshot_root, snapshot_id, error, error_size);
    (void)flock(lock, LOCK_UN);
    (void)close(lock);
    return result;
}

static void safe_database_type(const char *input, char *output, size_t output_size)
{
    size_t index = 0;

    if (output_size == 0) return;
    if (input != NULL) {
        while (input[index] != '\0' && index + 1 < output_size) {
            const unsigned char character = (unsigned char)input[index];
            output[index] = (isalnum(character) || character == '-' || character == '_' || character == '.')
                ? (char)character : '_';
            index++;
        }
    }
    output[index] = '\0';
}

int wardd_geo_snapshot_create(
    const char *mmdb_path,
    const struct wardd_country_set *countries,
    const char *snapshot_root,
    uint64_t max_source_bytes,
    double max_change_ratio,
    struct wardd_snapshot_result *result,
    char *error,
    size_t error_size
)
{
    struct wardd_snapshot_result local_result = {0};
    char staging[SNAPSHOT_PATH_LEN] = {0};
    char final_directory[SNAPSHOT_PATH_LEN];
    char source_path[SNAPSHOT_PATH_LEN];
    char ipv4_path[SNAPSHOT_PATH_LEN];
    char ipv6_path[SNAPSHOT_PATH_LEN];
    char nginx_path[SNAPSHOT_PATH_LEN];
    char metadata_path[SNAPSHOT_PATH_LEN];
    char country_token[WARDD_COUNTRY_TOKEN_LEN];
    char country_json[WARDD_MAX_COUNTRIES * (WARDD_COUNTRY_LEN + 3)];
    char checksum_path[SNAPSHOT_PATH_LEN];
    char current[WARDD_SNAPSHOT_ID_LEN];
    char metadata[2048];
    char database_type[WARDD_MMDB_TYPE_LEN];
    struct stat status;
    struct stat source_status;
    int directory_fd = -1;
    int lock_fd = -1;
    int return_value = -1;

    if (error != NULL && error_size > 0) error[0] = '\0';
    if (result != NULL) memset(result, 0, sizeof(*result));
    if (mmdb_path == NULL || countries == NULL ||
        wardd_country_set_token(countries, country_token, sizeof(country_token)) != 0 ||
        max_source_bytes == 0 || !(max_change_ratio > 0.0 && max_change_ratio <= 1.0)) {
        set_error(error, error_size, "valid MMDB, country, size limit, and change ratio are required");
        return -1;
    }
    if (lstat(mmdb_path, &source_status) != 0 || !S_ISREG(source_status.st_mode) ||
        source_status.st_size < 0 || (uint64_t)source_status.st_size > max_source_bytes) {
        set_error(error, error_size, "MMDB source must be a bounded regular file");
        return -1;
    }
    if (wardd_sha256_file(mmdb_path, local_result.source_sha256, error, error_size) != 0 ||
        ensure_directory(snapshot_root, error, error_size) != 0) {
        return -1;
    }
    lock_fd = lock_snapshot_root(snapshot_root, error, error_size);
    if (lock_fd < 0) return -1;
    if (snprintf(
            local_result.id,
            sizeof(local_result.id),
            "%s-%s-s%u-v%s",
            local_result.source_sha256,
            country_token,
            SNAPSHOT_METADATA_SCHEMA,
            WARDD_VERSION
        ) >= (int)sizeof(local_result.id) ||
        path_join(final_directory, sizeof(final_directory), snapshot_root, local_result.id) != 0) {
        set_error(error, error_size, "snapshot identity is too long");
        goto done;
    }
    if (lstat(final_directory, &status) == 0) {
        char approval[SNAPSHOT_PATH_LEN];
        char existing_path[SNAPSHOT_PATH_LEN];
        struct prefix_list prefixes = {0};
        if (validate_snapshot(
                snapshot_root,
                local_result.id,
                final_directory,
                sizeof(final_directory),
                error,
                error_size
            ) != 0) {
            goto done;
        }
        local_result.existed = true;
        if (path_join(existing_path, sizeof(existing_path), final_directory, "geo-v4.txt") != 0 ||
            read_prefixes(existing_path, &prefixes, error, error_size) != 0) {
            free_prefixes(&prefixes);
            goto done;
        }
        local_result.compile.ipv4_prefixes = prefixes.count;
        free_prefixes(&prefixes);
        if (path_join(existing_path, sizeof(existing_path), final_directory, "geo-v6.txt") != 0 ||
            read_prefixes(existing_path, &prefixes, error, error_size) != 0) {
            free_prefixes(&prefixes);
            goto done;
        }
        local_result.compile.ipv6_prefixes = prefixes.count;
        free_prefixes(&prefixes);
        if (path_join(approval, sizeof(approval), final_directory, ".approved") != 0) {
            set_error(error, error_size, "snapshot approval path is too long");
            goto done;
        }
        local_result.pending_review = lstat(approval, &status) != 0 || !S_ISREG(status.st_mode);
        return_value = 0;
        goto done;
    }
    if (errno != ENOENT) {
        set_error(error, error_size, "cannot inspect snapshot target: %s", strerror(errno));
        goto done;
    }
    if (snprintf(staging, sizeof(staging), "%s/.staging-XXXXXX", snapshot_root) >= (int)sizeof(staging) ||
        mkdtemp(staging) == NULL) {
        set_error(error, error_size, "cannot create snapshot staging directory: %s", strerror(errno));
        goto done;
    }
    if (chmod(staging, 0750) != 0 ||
        path_join(source_path, sizeof(source_path), staging, "source.mmdb") != 0 ||
        path_join(ipv4_path, sizeof(ipv4_path), staging, "geo-v4.txt") != 0 ||
        path_join(ipv6_path, sizeof(ipv6_path), staging, "geo-v6.txt") != 0 ||
        path_join(nginx_path, sizeof(nginx_path), staging, "nginx-geo.conf") != 0 ||
        path_join(metadata_path, sizeof(metadata_path), staging, "metadata.json") != 0 ||
        path_join(checksum_path, sizeof(checksum_path), staging, "sha256") != 0) {
        set_error(error, error_size, "cannot prepare snapshot paths: %s", strerror(errno));
        goto done;
    }
    if (copy_source(mmdb_path, source_path, max_source_bytes, error, error_size) != 0 ||
        wardd_geo_compile_mmdb(
            source_path,
            countries,
            ipv4_path,
            ipv6_path,
            nginx_path,
            &local_result.compile,
            error,
            error_size
        ) != 0) {
        goto done;
    }
    safe_database_type(local_result.compile.database_type, database_type, sizeof(database_type));
    country_json[0] = '\0';
    for (size_t index = 0; index < countries->count; ++index) {
        const size_t used = strlen(country_json);
        if (snprintf(
                country_json + used,
                sizeof(country_json) - used,
                "%s\"%s\"",
                index == 0 ? "" : ", ",
                countries->codes[index]
            ) >= (int)(sizeof(country_json) - used)) {
            set_error(error, error_size, "snapshot country list is too long");
            goto done;
        }
    }
    if (snprintf(
            metadata,
            sizeof(metadata),
            "{\n"
            "  \"schema\": %u,\n"
            "  \"snapshot_id\": \"%s\",\n"
            "  \"source_sha256\": \"%s\",\n"
            "  \"countries\": [%s],\n"
            "  \"compiler_version\": \"%s\",\n"
            "  \"created_epoch\": %llu,\n"
            "  \"mmdb_build_epoch\": %llu,\n"
            "  \"database_type\": \"%s\",\n"
            "  \"ipv4_prefixes\": %zu,\n"
            "  \"ipv6_prefixes\": %zu\n"
            "}\n",
            SNAPSHOT_METADATA_SCHEMA,
            local_result.id,
            local_result.source_sha256,
            country_json,
            WARDD_VERSION,
            (unsigned long long)time(NULL),
            (unsigned long long)local_result.compile.build_epoch,
            database_type,
            local_result.compile.ipv4_prefixes,
            local_result.compile.ipv6_prefixes
        ) >= (int)sizeof(metadata) ||
        write_text_file(metadata_path, metadata, 0640, error, error_size) != 0) {
        goto done;
    }
    char checksum_contents[WARDD_SHA256_HEX_LEN + 32];
    (void)snprintf(checksum_contents, sizeof(checksum_contents), "%s  source.mmdb\n", local_result.source_sha256);
    if (write_text_file(checksum_path, checksum_contents, 0640, error, error_size) != 0) goto done;

    directory_fd = open(staging, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory_fd < 0 || fsync(directory_fd) != 0) {
        set_error(error, error_size, "cannot flush snapshot staging directory: %s", strerror(errno));
        goto done;
    }
    (void)close(directory_fd);
    directory_fd = -1;
    if (rename(staging, final_directory) != 0) {
        set_error(error, error_size, "cannot commit snapshot: %s", strerror(errno));
        goto done;
    }
    staging[0] = '\0';

    if (read_link_id(snapshot_root, "current", current, false, error, error_size) != 0) goto done;
    if (current[0] != '\0') {
        if (wardd_geo_snapshot_diff(
                snapshot_root,
                current,
                local_result.id,
                &local_result.diff,
                error,
                error_size
            ) != 0) {
            goto done;
        }
        local_result.pending_review = local_result.diff.change_ratio > max_change_ratio;
    }
    if (!local_result.pending_review &&
        approve_snapshot_unlocked(snapshot_root, local_result.id, error, error_size) != 0) {
        goto done;
    }
    return_value = 0;

done:
    if (directory_fd >= 0) (void)close(directory_fd);
    if (staging[0] != '\0') cleanup_staging(staging);
    if (lock_fd >= 0) {
        (void)flock(lock_fd, LOCK_UN);
        (void)close(lock_fd);
    }
    if (return_value == 0 && result != NULL) *result = local_result;
    return return_value;
}

static int atomic_symlink(
    const char *target,
    const char *link_path,
    char *error,
    size_t error_size
)
{
    char temporary[SNAPSHOT_PATH_LEN];
    struct stat status;

    if (snprintf(temporary, sizeof(temporary), "%s.new.%ld", link_path, (long)getpid()) >=
        (int)sizeof(temporary)) {
        set_error(error, error_size, "snapshot symlink path is too long");
        return -1;
    }
    if (lstat(link_path, &status) == 0) {
        if (!S_ISLNK(status.st_mode)) {
            set_error(error, error_size, "refusing to replace non-symlink %s", link_path);
            return -1;
        }
    } else if (errno != ENOENT) {
        set_error(error, error_size, "cannot inspect %s: %s", link_path, strerror(errno));
        return -1;
    }
    if (symlink(target, temporary) != 0) {
        set_error(error, error_size, "cannot create snapshot symlink: %s", strerror(errno));
        return -1;
    }
    if (rename(temporary, link_path) != 0) {
        const int saved_errno = errno;
        (void)unlink(temporary);
        set_error(error, error_size, "cannot activate snapshot symlink: %s", strerror(saved_errno));
        return -1;
    }
    return 0;
}

static int restore_symlink(
    const char *path,
    const char *target,
    char *error,
    size_t error_size
)
{
    struct stat status;

    if (target != NULL && target[0] != '\0') return atomic_symlink(target, path, error, error_size);
    if (lstat(path, &status) != 0) {
        if (errno == ENOENT) return 0;
        set_error(error, error_size, "cannot inspect rollback link %s: %s", path, strerror(errno));
        return -1;
    }
    if (!S_ISLNK(status.st_mode)) {
        set_error(error, error_size, "refusing to remove non-symlink rollback path %s", path);
        return -1;
    }
    if (unlink(path) != 0) {
        set_error(error, error_size, "cannot remove rollback link %s: %s", path, strerror(errno));
        return -1;
    }
    return 0;
}

static int activate_snapshot_unlocked(
    const char *snapshot_root,
    const char *generated_directory,
    const char *snapshot_id,
    const char *nginx_binary,
    char *error,
    size_t error_size
)
{
    char directory[SNAPSHOT_PATH_LEN];
    char approval[SNAPSHOT_PATH_LEN];
    char nginx_include[SNAPSHOT_PATH_LEN];
    char root_current_path[SNAPSHOT_PATH_LEN];
    char root_previous_path[SNAPSHOT_PATH_LEN];
    char generated_current_path[SNAPSHOT_PATH_LEN];
    char old_current[WARDD_SNAPSHOT_ID_LEN];
    char old_generated[SNAPSHOT_PATH_LEN] = {0};
    struct stat status;
    ssize_t old_generated_length = -1;
    bool generated_changed = false;

    if (error != NULL && error_size > 0) error[0] = '\0';
    if (validate_snapshot(snapshot_root, snapshot_id, directory, sizeof(directory), error, error_size) != 0 ||
        path_join(approval, sizeof(approval), directory, ".approved") != 0 ||
        lstat(approval, &status) != 0 || !S_ISREG(status.st_mode)) {
        set_error(error, error_size, "snapshot %s is not approved", snapshot_id == NULL ? "" : snapshot_id);
        return -1;
    }
    if (path_join(nginx_include, sizeof(nginx_include), directory, "nginx-geo.conf") != 0 ||
        (nginx_binary != NULL &&
         wardd_nginx_check_include(nginx_binary, nginx_include, error, error_size) != 0)) {
        return -1;
    }
    if (read_link_id(snapshot_root, "current", old_current, false, error, error_size) != 0 ||
        path_join(root_current_path, sizeof(root_current_path), snapshot_root, "current") != 0 ||
        path_join(root_previous_path, sizeof(root_previous_path), snapshot_root, "previous") != 0) {
        return -1;
    }

    if (generated_directory != NULL) {
        if (ensure_directory(generated_directory, error, error_size) != 0 ||
            path_join(generated_current_path, sizeof(generated_current_path), generated_directory, "current") != 0) {
            return -1;
        }
        old_generated_length = readlink(generated_current_path, old_generated, sizeof(old_generated) - 1);
        if (old_generated_length >= 0) old_generated[old_generated_length] = '\0';
        else if (errno != ENOENT) {
            set_error(error, error_size, "cannot inspect generated current link: %s", strerror(errno));
            return -1;
        }
        if (atomic_symlink(directory, generated_current_path, error, error_size) != 0) return -1;
        generated_changed = true;
    }
    if (atomic_symlink(snapshot_id, root_current_path, error, error_size) != 0) {
        if (generated_changed) {
            if (old_generated_length >= 0) {
                (void)atomic_symlink(old_generated, generated_current_path, NULL, 0);
            } else {
                (void)unlink(generated_current_path);
            }
        }
        return -1;
    }
    if (old_current[0] != '\0' && strcmp(old_current, snapshot_id) != 0 &&
        atomic_symlink(old_current, root_previous_path, error, error_size) != 0) {
        (void)atomic_symlink(old_current, root_current_path, NULL, 0);
        if (generated_changed) {
            if (old_generated_length >= 0) {
                (void)atomic_symlink(old_generated, generated_current_path, NULL, 0);
            } else {
                (void)unlink(generated_current_path);
            }
        }
        return -1;
    }
    return 0;
}

int wardd_geo_snapshot_activate(
    const char *snapshot_root,
    const char *generated_directory,
    const char *snapshot_id,
    const char *nginx_binary,
    char *error,
    size_t error_size
)
{
    int lock;
    int result;

    if (error != NULL && error_size > 0) error[0] = '\0';
    if (ensure_directory(snapshot_root, error, error_size) != 0) return -1;
    lock = lock_snapshot_root(snapshot_root, error, error_size);
    if (lock < 0) return -1;
    result = activate_snapshot_unlocked(
        snapshot_root,
        generated_directory,
        snapshot_id,
        nginx_binary,
        error,
        error_size
    );
    (void)flock(lock, LOCK_UN);
    (void)close(lock);
    return result;
}

int wardd_geo_snapshot_rollback(
    const char *snapshot_root,
    const char *generated_directory,
    const char *nginx_binary,
    char *error,
    size_t error_size
)
{
    char previous[WARDD_SNAPSHOT_ID_LEN];
    int lock;
    int result;

    if (error != NULL && error_size > 0) error[0] = '\0';
    if (ensure_directory(snapshot_root, error, error_size) != 0) return -1;
    lock = lock_snapshot_root(snapshot_root, error, error_size);
    if (lock < 0) return -1;
    if (read_link_id(snapshot_root, "previous", previous, true, error, error_size) != 0) {
        (void)flock(lock, LOCK_UN);
        (void)close(lock);
        return -1;
    }
    result = activate_snapshot_unlocked(
        snapshot_root,
        generated_directory,
        previous,
        nginx_binary,
        error,
        error_size
    );
    (void)flock(lock, LOCK_UN);
    (void)close(lock);
    return result;
}

static int activate_snapshot_live_unlocked(
    const char *snapshot_root,
    const char *generated_directory,
    const char *snapshot_id,
    const char *nginx_binary,
    char *error,
    size_t error_size
)
{
    char old_current[WARDD_SNAPSHOT_ID_LEN];
    char old_previous[WARDD_SNAPSHOT_ID_LEN];
    char old_generated[SNAPSHOT_PATH_LEN] = {0};
    char current_path[SNAPSHOT_PATH_LEN];
    char previous_path[SNAPSHOT_PATH_LEN];
    char generated_path[SNAPSHOT_PATH_LEN];
    char primary_error[2048];
    char recovery_error[2048] = {0};
    ssize_t generated_length = -1;
    bool reload_attempted = false;
    bool links_restored = true;
    bool runtime_recovered = true;

    if (generated_directory == NULL || nginx_binary == NULL || nginx_binary[0] == '\0') {
        set_error(error, error_size, "live activation requires Nginx integration and binary");
        return -1;
    }
    if (read_link_id(snapshot_root, "current", old_current, false, error, error_size) != 0 ||
        read_link_id(snapshot_root, "previous", old_previous, false, error, error_size) != 0 ||
        path_join(current_path, sizeof(current_path), snapshot_root, "current") != 0 ||
        path_join(previous_path, sizeof(previous_path), snapshot_root, "previous") != 0 ||
        path_join(generated_path, sizeof(generated_path), generated_directory, "current") != 0) {
        return -1;
    }
    generated_length = readlink(generated_path, old_generated, sizeof(old_generated) - 1);
    if (generated_length >= 0) old_generated[generated_length] = '\0';
    else if (errno != ENOENT) {
        set_error(error, error_size, "cannot capture generated Nginx link: %s", strerror(errno));
        return -1;
    }
    if (activate_snapshot_unlocked(
            snapshot_root,
            generated_directory,
            snapshot_id,
            nginx_binary,
            error,
            error_size
        ) != 0) return -1;
    if (wardd_nginx_test_live(nginx_binary, error, error_size) == 0) {
        reload_attempted = true;
        if (wardd_nginx_reload_live(nginx_binary, error, error_size) == 0) return 0;
    }
    (void)snprintf(primary_error, sizeof(primary_error), "%s", error == NULL ? "Nginx activation failed" : error);

    if (restore_symlink(current_path, old_current, recovery_error, sizeof(recovery_error)) != 0) {
        links_restored = false;
    }
    if (restore_symlink(previous_path, old_previous, recovery_error, sizeof(recovery_error)) != 0) {
        links_restored = false;
    }
    if (restore_symlink(
            generated_path,
            generated_length >= 0 ? old_generated : "",
            recovery_error,
            sizeof(recovery_error)
        ) != 0) {
        links_restored = false;
    }
    if (reload_attempted) {
        if (!links_restored ||
            wardd_nginx_test_live(nginx_binary, recovery_error, sizeof(recovery_error)) != 0 ||
            wardd_nginx_reload_live(nginx_binary, recovery_error, sizeof(recovery_error)) != 0) {
            runtime_recovered = false;
        }
    }
    set_error(
        error,
        error_size,
        "%s; wardd links restored=%s; previous live configuration recovered=%s%s%s",
        primary_error,
        links_restored ? "yes" : "no",
        runtime_recovered ? "yes" : "no",
        (!links_restored || !runtime_recovered) && recovery_error[0] != '\0' ? ": " : "",
        (!links_restored || !runtime_recovered) ? recovery_error : ""
    );
    return -1;
}

int wardd_geo_snapshot_activate_live(
    const char *snapshot_root,
    const char *generated_directory,
    const char *snapshot_id,
    const char *nginx_binary,
    char *error,
    size_t error_size
)
{
    int lock;
    int result;

    if (error != NULL && error_size > 0) error[0] = '\0';
    if (ensure_directory(snapshot_root, error, error_size) != 0) return -1;
    lock = lock_snapshot_root(snapshot_root, error, error_size);
    if (lock < 0) return -1;
    result = activate_snapshot_live_unlocked(
        snapshot_root, generated_directory, snapshot_id, nginx_binary, error, error_size
    );
    (void)flock(lock, LOCK_UN);
    (void)close(lock);
    return result;
}

int wardd_geo_snapshot_rollback_live(
    const char *snapshot_root,
    const char *generated_directory,
    const char *nginx_binary,
    char *error,
    size_t error_size
)
{
    char previous[WARDD_SNAPSHOT_ID_LEN];
    int lock;
    int result;

    if (error != NULL && error_size > 0) error[0] = '\0';
    if (ensure_directory(snapshot_root, error, error_size) != 0) return -1;
    lock = lock_snapshot_root(snapshot_root, error, error_size);
    if (lock < 0) return -1;
    if (read_link_id(snapshot_root, "previous", previous, true, error, error_size) != 0) {
        (void)flock(lock, LOCK_UN);
        (void)close(lock);
        return -1;
    }
    result = activate_snapshot_live_unlocked(
        snapshot_root, generated_directory, previous, nginx_binary, error, error_size
    );
    (void)flock(lock, LOCK_UN);
    (void)close(lock);
    return result;
}

int wardd_geo_snapshot_status(
    const char *snapshot_root,
    struct wardd_snapshot_status *status,
    char *error,
    size_t error_size
)
{
    DIR *directory;
    struct dirent *entry;

    if (error != NULL && error_size > 0) error[0] = '\0';
    if (status == NULL) {
        set_error(error, error_size, "snapshot status output is required");
        return -1;
    }
    memset(status, 0, sizeof(*status));
    if (read_link_id(snapshot_root, "current", status->current, false, error, error_size) != 0 ||
        read_link_id(snapshot_root, "previous", status->previous, false, error, error_size) != 0) {
        return -1;
    }
    directory = opendir(snapshot_root);
    if (directory == NULL) {
        if (errno == ENOENT) return 0;
        set_error(error, error_size, "cannot read snapshot root: %s", strerror(errno));
        return -1;
    }
    while ((entry = readdir(directory)) != NULL) {
        char path[SNAPSHOT_PATH_LEN];
        struct stat item_status;
        if (!valid_snapshot_id(entry->d_name) ||
            path_join(path, sizeof(path), snapshot_root, entry->d_name) != 0) continue;
        if (lstat(path, &item_status) == 0 && S_ISDIR(item_status.st_mode)) status->snapshot_count++;
    }
    (void)closedir(directory);
    if (status->current[0] != '\0') {
        char current_directory[SNAPSHOT_PATH_LEN];
        char approval[SNAPSHOT_PATH_LEN];
        struct stat approval_status;
        if (path_join(current_directory, sizeof(current_directory), snapshot_root, status->current) == 0 &&
            path_join(approval, sizeof(approval), current_directory, ".approved") == 0 &&
            lstat(approval, &approval_status) == 0 && S_ISREG(approval_status.st_mode)) {
            status->current_approved = true;
        }
    }
    return 0;
}
