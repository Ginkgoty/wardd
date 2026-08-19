#include "wardd/nginx_events.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CURSOR_HEADER "wardd-nginx-cursor-v1"

static void set_error(char *error, size_t error_size, const char *format, ...)
{
    va_list arguments;
    if (error == NULL || error_size == 0) return;
    va_start(arguments, format);
    (void)vsnprintf(error, error_size, format, arguments);
    va_end(arguments);
}

static int take_literal(const char **cursor, const char *literal)
{
    const size_t length = strlen(literal);
    if (strncmp(*cursor, literal, length) != 0) return -1;
    *cursor += length;
    return 0;
}

static int take_string(const char **cursor, char *output, size_t output_size)
{
    size_t used = 0;
    while (**cursor != '\0' && **cursor != '"') {
        const unsigned char character = (unsigned char)**cursor;
        if (character < 0x20 || character == '\\' || used + 1 >= output_size) return -1;
        output[used++] = (char)character;
        (*cursor)++;
    }
    if (**cursor != '"' || used == 0) return -1;
    output[used] = '\0';
    (*cursor)++;
    return 0;
}

int wardd_nginx_event_parse(
    const char *line,
    struct wardd_auto_ban_event *event,
    char *error,
    size_t error_size
)
{
    const char *cursor = line;
    char status[16];
    char epoch[32];
    char *end;
    unsigned long long seconds;

    if (error != NULL && error_size > 0) error[0] = '\0';
    if (line == NULL || event == NULL || strlen(line) >= WARDD_NGINX_EVENT_BUFFER_LEN) {
        set_error(error, error_size, "Nginx event line is missing or too large");
        return -1;
    }
    memset(event, 0, sizeof(*event));
    if (take_literal(&cursor, "{\"schema\":1,\"peer\":\"") != 0 ||
        take_string(&cursor, event->peer, sizeof(event->peer)) != 0 ||
        take_literal(&cursor, ",\"server\":\"") != 0 ||
        take_string(&cursor, event->server, sizeof(event->server)) != 0 ||
        take_literal(&cursor, ",\"zone\":\"") != 0 ||
        take_string(&cursor, event->zone, sizeof(event->zone)) != 0 ||
        take_literal(&cursor, ",\"status\":\"") != 0 ||
        take_string(&cursor, status, sizeof(status)) != 0 ||
        take_literal(&cursor, ",\"request_id\":\"") != 0 ||
        take_string(&cursor, event->request_id, sizeof(event->request_id)) != 0 ||
        take_literal(&cursor, ",\"epoch\":\"") != 0 ||
        take_string(&cursor, epoch, sizeof(epoch)) != 0 ||
        strcmp(cursor, "}") != 0) {
        set_error(error, error_size, "Nginx limit event does not match schema 1");
        return -1;
    }
    if (strcmp(status, "REJECTED") != 0) {
        set_error(error, error_size, "Nginx limit event status is not REJECTED");
        return -1;
    }
    char *fraction = strchr(epoch, '.');
    if (fraction != NULL) {
        *fraction++ = '\0';
        if (*fraction == '\0') {
            set_error(error, error_size, "Nginx event epoch fraction is empty");
            return -1;
        }
        for (const unsigned char *digit = (const unsigned char *)fraction; *digit != '\0'; ++digit) {
            if (*digit < '0' || *digit > '9') {
                set_error(error, error_size, "Nginx event epoch fraction is invalid");
                return -1;
            }
        }
    }
    errno = 0;
    seconds = strtoull(epoch, &end, 10);
    if (errno != 0 || end == epoch || *end != '\0' || seconds == 0) {
        set_error(error, error_size, "Nginx event epoch is invalid");
        return -1;
    }
    event->event_realtime_seconds = (uint64_t)seconds;
    event->limiter_rejected = true;
    event->confirmed_peer = true;
    return 0;
}

static int ensure_parent(const char *path, char parent[WARDD_NGINX_EVENT_PATH_LEN], char *error, size_t error_size)
{
    char *slash;
    struct stat status;

    if (path == NULL || path[0] != '/' || strlen(path) >= WARDD_NGINX_EVENT_PATH_LEN) {
        set_error(error, error_size, "Nginx event cursor path must be a bounded absolute path");
        return -1;
    }
    (void)snprintf(parent, WARDD_NGINX_EVENT_PATH_LEN, "%s", path);
    slash = strrchr(parent, '/');
    if (slash == parent) slash[1] = '\0';
    else *slash = '\0';
    for (char *cursor = parent + 1; ; ++cursor) {
        if (*cursor != '/' && *cursor != '\0') continue;
        const char saved = *cursor;
        *cursor = '\0';
        if (mkdir(parent, 0750) != 0 && errno != EEXIST) {
            set_error(error, error_size, "cannot create cursor directory %s: %s", parent, strerror(errno));
            return -1;
        }
        if (lstat(parent, &status) != 0 || !S_ISDIR(status.st_mode)) {
            set_error(error, error_size, "cursor parent %s is not a real directory", parent);
            return -1;
        }
        *cursor = saved;
        if (saved == '\0') break;
    }
    return 0;
}

static int load_cursor(struct wardd_nginx_event_reader *reader, char *error, size_t error_size)
{
    char text[256];
    struct stat status;
    int descriptor;
    ssize_t bytes;
    uintmax_t device;
    uintmax_t inode;
    uint64_t offset;
    char extra;

    descriptor = open(reader->cursor_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) {
        if (errno == ENOENT) {
            reader->cursor_loaded = true;
            reader->have_cursor = false;
            return 0;
        }
        set_error(error, error_size, "cannot open Nginx event cursor: %s", strerror(errno));
        return -1;
    }
    if (fstat(descriptor, &status) != 0 || !S_ISREG(status.st_mode)) {
        set_error(error, error_size, "Nginx event cursor is not a regular file");
        (void)close(descriptor);
        return -1;
    }
    bytes = read(descriptor, text, sizeof(text) - 1);
    (void)close(descriptor);
    if (bytes <= 0 || (size_t)bytes >= sizeof(text) - 1) {
        set_error(error, error_size, "Nginx event cursor is empty or too large");
        return -1;
    }
    text[bytes] = '\0';
    if (sscanf(text, CURSOR_HEADER "\t%ju\t%ju\t%" SCNu64 "\n%c", &device, &inode, &offset, &extra) != 3) {
        set_error(error, error_size, "Nginx event cursor has an invalid schema");
        return -1;
    }
    reader->cursor_loaded = true;
    reader->have_cursor = true;
    reader->cursor_device = (dev_t)device;
    reader->cursor_inode = (ino_t)inode;
    reader->cursor_offset = offset;
    return 0;
}

static int save_cursor_values(
    struct wardd_nginx_event_reader *reader,
    dev_t device,
    ino_t inode,
    uint64_t offset,
    char *error,
    size_t error_size
)
{
    char parent[WARDD_NGINX_EVENT_PATH_LEN];
    char temporary[WARDD_NGINX_EVENT_PATH_LEN];
    char text[256];
    struct stat status;
    FILE *file;
    int directory;

    if (ensure_parent(reader->cursor_path, parent, error, error_size) != 0 ||
        snprintf(temporary, sizeof(temporary), "%s.tmp.%ld", reader->cursor_path, (long)getpid()) >=
            (int)sizeof(temporary) ||
        snprintf(text, sizeof(text), CURSOR_HEADER "\t%ju\t%ju\t%" PRIu64 "\n",
            (uintmax_t)device, (uintmax_t)inode, offset) >= (int)sizeof(text)) {
        if (error != NULL && error[0] == '\0') set_error(error, error_size, "Nginx cursor path is too long");
        return -1;
    }
    errno = 0;
    const int inspect_status = lstat(reader->cursor_path, &status);
    if (inspect_status == 0 && !S_ISREG(status.st_mode)) {
        set_error(error, error_size, "refusing to replace non-regular Nginx event cursor");
        return -1;
    } else if (inspect_status != 0 && errno != ENOENT) {
        set_error(error, error_size, "cannot inspect Nginx event cursor: %s", strerror(errno));
        return -1;
    }
    file = fopen(temporary, "wxe");
    if (file == NULL) {
        set_error(error, error_size, "cannot create Nginx event cursor: %s", strerror(errno));
        return -1;
    }
    if (fchmod(fileno(file), 0640) != 0 || fputs(text, file) == EOF || fflush(file) != 0 ||
        fsync(fileno(file)) != 0) {
        const int saved_errno = errno;
        (void)fclose(file);
        (void)unlink(temporary);
        set_error(error, error_size, "cannot write Nginx event cursor: %s", strerror(saved_errno));
        return -1;
    }
    if (fclose(file) != 0 || rename(temporary, reader->cursor_path) != 0) {
        const int saved_errno = errno;
        (void)unlink(temporary);
        set_error(error, error_size, "cannot activate Nginx event cursor: %s", strerror(saved_errno));
        return -1;
    }
    directory = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory < 0 || fsync(directory) != 0) {
        set_error(error, error_size, "cannot flush Nginx event cursor directory: %s", strerror(errno));
        if (directory >= 0) (void)close(directory);
        return -1;
    }
    (void)close(directory);
    reader->have_cursor = true;
    reader->cursor_device = device;
    reader->cursor_inode = inode;
    reader->cursor_offset = offset;
    return 0;
}

static int open_log(struct wardd_nginx_event_reader *reader, bool rotated, char *error, size_t error_size)
{
    struct stat status;
    uint64_t offset;
    int descriptor = open(reader->log_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);

    if (descriptor < 0) {
        if (errno == ENOENT) reader->missing_log_seen = true;
        set_error(error, error_size, "cannot open Nginx limit event log: %s", strerror(errno));
        return -1;
    }
    if (fstat(descriptor, &status) != 0 || !S_ISREG(status.st_mode) || status.st_size < 0) {
        set_error(error, error_size, "Nginx limit event log is not a regular file");
        (void)close(descriptor);
        return -1;
    }
    if (!reader->cursor_loaded && load_cursor(reader, error, error_size) != 0) {
        (void)close(descriptor);
        return -1;
    }
    if (rotated) offset = 0;
    else if (reader->have_cursor && reader->cursor_device == status.st_dev &&
        reader->cursor_inode == status.st_ino && reader->cursor_offset <= (uint64_t)status.st_size) {
        offset = reader->cursor_offset;
    } else if (reader->have_cursor) {
        offset = 0;
    } else if (reader->missing_log_seen) {
        offset = 0;
    } else {
        offset = (uint64_t)status.st_size;
    }
    if (offset > (uint64_t)INT64_MAX || lseek(descriptor, (off_t)offset, SEEK_SET) < 0 ||
        save_cursor_values(reader, status.st_dev, status.st_ino, offset, error, error_size) != 0) {
        if (error != NULL && error[0] == '\0') set_error(error, error_size, "cannot seek Nginx limit event log");
        (void)close(descriptor);
        return -1;
    }
    reader->descriptor = descriptor;
    reader->device = status.st_dev;
    reader->inode = status.st_ino;
    reader->committed_offset = offset;
    reader->read_offset = offset;
    reader->buffered = 0;
    reader->rotation_pending = false;
    reader->missing_log_seen = false;
    return 0;
}

int wardd_nginx_event_reader_init(
    struct wardd_nginx_event_reader *reader,
    const char *log_path,
    const char *cursor_path,
    char *error,
    size_t error_size
)
{
    if (reader == NULL || log_path == NULL || cursor_path == NULL || log_path[0] != '/' ||
        cursor_path[0] != '/' || strlen(log_path) >= sizeof(reader->log_path) ||
        strlen(cursor_path) >= sizeof(reader->cursor_path)) {
        set_error(error, error_size, "bounded absolute Nginx log and cursor paths are required");
        return -1;
    }
    memset(reader, 0, sizeof(*reader));
    reader->descriptor = -1;
    (void)snprintf(reader->log_path, sizeof(reader->log_path), "%s", log_path);
    (void)snprintf(reader->cursor_path, sizeof(reader->cursor_path), "%s", cursor_path);
    return 0;
}

static int process_buffer(
    struct wardd_nginx_event_reader *reader,
    wardd_nginx_event_handler handler,
    void *context,
    size_t maximum_events,
    size_t *processed,
    char *error,
    size_t error_size
)
{
    while (*processed < maximum_events) {
        char *newline = memchr(reader->buffer, '\n', reader->buffered);
        struct wardd_auto_ban_event event;
        size_t line_length;
        uint64_t new_offset;
        char saved;

        if (newline == NULL) return 0;
        line_length = (size_t)(newline - reader->buffer);
        if (line_length == 0 || line_length >= WARDD_NGINX_EVENT_BUFFER_LEN ||
            reader->committed_offset > UINT64_MAX - line_length - 1U) {
            set_error(error, error_size, "Nginx limit event line is empty or unsafe");
            return -1;
        }
        saved = reader->buffer[line_length];
        reader->buffer[line_length] = '\0';
        if (wardd_nginx_event_parse(reader->buffer, &event, error, error_size) != 0 ||
            handler(&event, context, error, error_size) != 0) {
            reader->buffer[line_length] = saved;
            return -1;
        }
        reader->buffer[line_length] = saved;
        new_offset = reader->committed_offset + line_length + 1U;
        if (save_cursor_values(
                reader, reader->device, reader->inode, new_offset, error, error_size
            ) != 0) return -1;
        memmove(reader->buffer, reader->buffer + line_length + 1U, reader->buffered - line_length - 1U);
        reader->buffered -= line_length + 1U;
        reader->committed_offset = new_offset;
        (*processed)++;
    }
    return 0;
}

int wardd_nginx_event_reader_step(
    struct wardd_nginx_event_reader *reader,
    wardd_nginx_event_handler handler,
    void *context,
    size_t maximum_events,
    size_t *processed_events,
    char *error,
    size_t error_size
)
{
    struct stat descriptor_status;
    struct stat path_status;
    size_t processed = 0;
    bool read_any = false;

    if (error != NULL && error_size > 0) error[0] = '\0';
    if (reader == NULL || handler == NULL || maximum_events == 0) {
        set_error(error, error_size, "Nginx event reader, handler, and event limit are required");
        return -1;
    }
    if (processed_events != NULL) *processed_events = 0;
    if (reader->descriptor < 0 && open_log(reader, false, error, error_size) != 0) return -1;
    if (fstat(reader->descriptor, &descriptor_status) != 0 || descriptor_status.st_size < 0) {
        set_error(error, error_size, "cannot inspect open Nginx event log: %s", strerror(errno));
        return -1;
    }
    if ((uint64_t)descriptor_status.st_size < reader->read_offset) {
        if (lseek(reader->descriptor, 0, SEEK_SET) < 0 ||
            save_cursor_values(reader, reader->device, reader->inode, 0, error, error_size) != 0) {
            set_error(error, error_size, "cannot recover copy-truncated Nginx event log");
            return -1;
        }
        reader->buffered = 0;
        reader->committed_offset = 0;
        reader->read_offset = 0;
    }
    if (process_buffer(reader, handler, context, maximum_events, &processed, error, error_size) != 0) return -1;
    if (processed != 0) {
        read_any = true;
        reader->rotation_pending = false;
    }
    while (processed < maximum_events) {
        ssize_t bytes;
        if (reader->buffered == sizeof(reader->buffer)) {
            set_error(error, error_size, "Nginx limit event exceeds the line size limit");
            return -1;
        }
        bytes = read(
            reader->descriptor,
            reader->buffer + reader->buffered,
            sizeof(reader->buffer) - reader->buffered
        );
        if (bytes < 0 && errno == EINTR) continue;
        if (bytes < 0) {
            set_error(error, error_size, "cannot read Nginx limit event log: %s", strerror(errno));
            return -1;
        }
        if (bytes == 0) break;
        read_any = true;
        reader->rotation_pending = false;
        reader->buffered += (size_t)bytes;
        reader->read_offset += (uint64_t)bytes;
        if (process_buffer(reader, handler, context, maximum_events, &processed, error, error_size) != 0) return -1;
    }
    errno = 0;
    const int path_inspection = stat(reader->log_path, &path_status);
    if (processed < maximum_events && path_inspection == 0 &&
        (path_status.st_dev != reader->device || path_status.st_ino != reader->inode)) {
        if (reader->buffered != 0) {
            set_error(error, error_size, "rotated Nginx event log ended with a partial line");
            return -1;
        }
        if (!reader->rotation_pending || reader->pending_device != path_status.st_dev ||
            reader->pending_inode != path_status.st_ino || read_any) {
            reader->rotation_pending = true;
            reader->pending_device = path_status.st_dev;
            reader->pending_inode = path_status.st_ino;
            if (processed_events != NULL) *processed_events = processed;
            return 0;
        }
        (void)close(reader->descriptor);
        reader->descriptor = -1;
        if (open_log(reader, true, error, error_size) != 0) return -1;
        size_t additional = 0;
        const int next_result = wardd_nginx_event_reader_step(
            reader,
            handler,
            context,
            maximum_events - processed,
            &additional,
            error,
            error_size
        );
        if (processed_events != NULL) *processed_events = processed + additional;
        return next_result;
    }
    if (path_inspection != 0 && errno != ENOENT) {
        set_error(error, error_size, "cannot inspect Nginx limit event log path: %s", strerror(errno));
        return -1;
    }
    if (processed_events != NULL) *processed_events = processed;
    return 0;
}

void wardd_nginx_event_reader_close(struct wardd_nginx_event_reader *reader)
{
    if (reader == NULL) return;
    if (reader->descriptor >= 0) (void)close(reader->descriptor);
    reader->descriptor = -1;
}
