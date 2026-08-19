#ifndef WARDD_NGINX_EVENTS_H
#define WARDD_NGINX_EVENTS_H

#include "wardd/auto_ban.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define WARDD_NGINX_EVENT_PATH_LEN 1024
#define WARDD_NGINX_EVENT_BUFFER_LEN 8192

typedef int (*wardd_nginx_event_handler)(
    const struct wardd_auto_ban_event *event,
    void *context,
    char *error,
    size_t error_size
);

struct wardd_nginx_event_reader {
    char log_path[WARDD_NGINX_EVENT_PATH_LEN];
    char cursor_path[WARDD_NGINX_EVENT_PATH_LEN];
    int descriptor;
    dev_t device;
    ino_t inode;
    uint64_t committed_offset;
    uint64_t read_offset;
    char buffer[WARDD_NGINX_EVENT_BUFFER_LEN];
    size_t buffered;
    bool cursor_loaded;
    bool have_cursor;
    dev_t cursor_device;
    ino_t cursor_inode;
    uint64_t cursor_offset;
    bool rotation_pending;
    dev_t pending_device;
    ino_t pending_inode;
    bool missing_log_seen;
};

int wardd_nginx_event_parse(
    const char *line,
    struct wardd_auto_ban_event *event,
    char *error,
    size_t error_size
);

int wardd_nginx_event_reader_init(
    struct wardd_nginx_event_reader *reader,
    const char *log_path,
    const char *cursor_path,
    char *error,
    size_t error_size
);

int wardd_nginx_event_reader_step(
    struct wardd_nginx_event_reader *reader,
    wardd_nginx_event_handler handler,
    void *context,
    size_t maximum_events,
    size_t *processed_events,
    char *error,
    size_t error_size
);

void wardd_nginx_event_reader_close(struct wardd_nginx_event_reader *reader);

#endif
