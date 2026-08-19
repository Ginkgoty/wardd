#include "wardd/audit.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define AUDIT_PATH_LEN 1024
#define AUDIT_LINE_LEN 2048

static void set_error(char *error, size_t error_size, const char *format, ...)
{
    va_list arguments;
    if (error == NULL || error_size == 0) return;
    va_start(arguments, format);
    (void)vsnprintf(error, error_size, format, arguments);
    va_end(arguments);
}

static int safe_token(const char *text)
{
    if (text == NULL || text[0] == '\0') return 0;
    for (const unsigned char *cursor = (const unsigned char *)text; *cursor != '\0'; ++cursor) {
        if (!( (*cursor >= 'a' && *cursor <= 'z') || (*cursor >= 'A' && *cursor <= 'Z') ||
               (*cursor >= '0' && *cursor <= '9') || *cursor == '.' || *cursor == '_' ||
               *cursor == '-' || *cursor == ':' )) return 0;
    }
    return 1;
}

static int ensure_parent(const char *path, char parent[AUDIT_PATH_LEN], char *error, size_t error_size)
{
    char *slash;
    struct stat status;

    if (path == NULL || path[0] != '/' || strlen(path) >= AUDIT_PATH_LEN) {
        set_error(error, error_size, "audit path must be a bounded absolute path");
        return -1;
    }
    (void)snprintf(parent, AUDIT_PATH_LEN, "%s", path);
    slash = strrchr(parent, '/');
    if (slash == parent) slash[1] = '\0';
    else *slash = '\0';
    for (char *cursor = parent + 1; ; ++cursor) {
        if (*cursor != '/' && *cursor != '\0') continue;
        const char saved = *cursor;
        *cursor = '\0';
        if (mkdir(parent, 0750) != 0 && errno != EEXIST) {
            set_error(error, error_size, "cannot create audit directory %s: %s", parent, strerror(errno));
            return -1;
        }
        if (lstat(parent, &status) != 0 || !S_ISDIR(status.st_mode)) {
            set_error(error, error_size, "audit parent %s is not a real directory", parent);
            return -1;
        }
        *cursor = saved;
        if (saved == '\0') break;
    }
    return 0;
}

int wardd_audit_auto_ban(
    const char *path,
    const struct wardd_auto_ban_event *event,
    const struct wardd_auto_ban_decision *decision,
    const char *outcome,
    char *error,
    size_t error_size
)
{
    char parent[AUDIT_PATH_LEN];
    char line[AUDIT_LINE_LEN];
    struct stat status;
    const time_t now = time(NULL);
    size_t length;
    size_t offset = 0;
    int file = -1;
    int result = -1;

    if (error != NULL && error_size > 0) error[0] = '\0';
    if (event == NULL || decision == NULL || !safe_token(event->peer) ||
        !safe_token(event->server) || !safe_token(event->zone) || !safe_token(event->request_id) ||
        !safe_token(outcome) || ensure_parent(path, parent, error, error_size) != 0) {
        if (error != NULL && error[0] == '\0') set_error(error, error_size, "audit event contains unsafe fields");
        return -1;
    }
    const int formatted = snprintf(
        line,
        sizeof(line),
        "{\"schema\":1,\"event\":\"automatic_ban\",\"recorded_epoch\":%llu,"
        "\"event_epoch\":%llu,\"uid\":%llu,\"pid\":%llu,\"peer\":\"%s\","
        "\"server\":\"%s\",\"zone\":\"%s\",\"request_id\":\"%s\","
        "\"window_count\":%llu,\"strike\":%llu,\"duration_seconds\":%llu,"
        "\"expires_epoch\":%llu,\"policy_version\":1,\"outcome\":\"%s\"}\n",
        (unsigned long long)(now < 0 ? 0 : now),
        (unsigned long long)event->event_realtime_seconds,
        (unsigned long long)geteuid(),
        (unsigned long long)getpid(),
        event->peer,
        event->server,
        event->zone,
        event->request_id,
        (unsigned long long)decision->window_count,
        (unsigned long long)decision->strike,
        (unsigned long long)decision->duration_seconds,
        (unsigned long long)decision->expires_realtime_seconds,
        outcome
    );
    if (formatted < 0 || (size_t)formatted >= sizeof(line)) {
        set_error(error, error_size, "audit event is too large");
        return -1;
    }
    length = (size_t)formatted;
    file = open(path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0640);
    if (file < 0 || fstat(file, &status) != 0 || !S_ISREG(status.st_mode) || flock(file, LOCK_EX) != 0) {
        const int saved_errno = errno;
        if (file >= 0) (void)close(file);
        set_error(error, error_size, "cannot safely open audit log: %s", strerror(saved_errno));
        return -1;
    }
    while (offset < length) {
        ssize_t written = write(file, line + offset, length - offset);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) {
            set_error(error, error_size, "cannot append complete audit event: %s", strerror(errno));
            goto done;
        }
        offset += (size_t)written;
    }
    if (fsync(file) != 0) {
        set_error(error, error_size, "cannot append audit event: %s", strerror(errno));
        goto done;
    }
    int directory = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory < 0 || fsync(directory) != 0) {
        set_error(error, error_size, "cannot flush audit directory: %s", strerror(errno));
        if (directory >= 0) (void)close(directory);
        goto done;
    }
    (void)close(directory);
    result = 0;

done:
    (void)flock(file, LOCK_UN);
    (void)close(file);
    return result;
}
