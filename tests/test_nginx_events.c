#include "wardd/nginx_events.h"

#include <errno.h>
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

struct handler_context {
    size_t count;
    char last_request[WARDD_AUTO_EVENT_FIELD_LEN];
};

static int handle_event(
    const struct wardd_auto_ban_event *event,
    void *opaque,
    char *error,
    size_t error_size
)
{
    struct handler_context *context = opaque;
    (void)error;
    (void)error_size;
    context->count++;
    (void)snprintf(context->last_request, sizeof(context->last_request), "%s", event->request_id);
    return 0;
}

static int write_text(const char *path, const char *mode, const char *text)
{
    FILE *file = fopen(path, mode);
    if (file == NULL) return -1;
    if (fputs(text, file) == EOF || fflush(file) != 0) {
        (void)fclose(file);
        return -1;
    }
    return fclose(file);
}

static void make_line(char *output, size_t output_size, const char *request_id, unsigned long long epoch)
{
    (void)snprintf(
        output,
        output_size,
        "{\"schema\":1,\"peer\":\"8.8.4.4\",\"server\":\"service.example.com\","
        "\"zone\":\"api\",\"status\":\"REJECTED\",\"request_id\":\"%s\","
        "\"epoch\":\"%llu.123\"}\n",
        request_id,
        epoch
    );
}

int main(void)
{
    char directory[] = "/tmp/wardd-nginx-events-test-XXXXXX";
    char log_path[512];
    char old_path[512];
    char cursor_path[512];
    char cursor_lock[1024];
    char delayed_log[512];
    char delayed_cursor[512];
    char line[1024];
    char error[1024];
    struct wardd_nginx_event_reader reader;
    struct wardd_auto_ban_event parsed;
    struct handler_context handled = {0};
    size_t processed;

    CHECK(mkdtemp(directory) != NULL, "create Nginx event test directory");
    (void)snprintf(log_path, sizeof(log_path), "%s/events.log", directory);
    (void)snprintf(old_path, sizeof(old_path), "%s/events.log.1", directory);
    (void)snprintf(cursor_path, sizeof(cursor_path), "%s/state/cursor", directory);
    (void)snprintf(cursor_lock, sizeof(cursor_lock), "%s.lock", cursor_path);
    (void)snprintf(delayed_log, sizeof(delayed_log), "%s/delayed.log", directory);
    (void)snprintf(delayed_cursor, sizeof(delayed_cursor), "%s/state/delayed.cursor", directory);
    make_line(line, sizeof(line), "preexisting", 1000);
    CHECK(write_text(log_path, "wx", line) == 0, "write preexisting event");
    CHECK(wardd_nginx_event_reader_init(&reader, log_path, cursor_path, error, sizeof(error)) == 0, error);
    CHECK(wardd_nginx_event_reader_step(
        &reader, handle_event, &handled, 16, &processed, error, sizeof(error)) == 0, error);
    CHECK(processed == 0 && handled.count == 0, "first start tails without replaying old log");

    make_line(line, sizeof(line), "partial", 1001);
    const size_t split = strlen(line) / 2U;
    char saved = line[split];
    line[split] = '\0';
    CHECK(write_text(log_path, "a", line) == 0, "append partial event prefix");
    CHECK(wardd_nginx_event_reader_step(
        &reader, handle_event, &handled, 16, &processed, error, sizeof(error)) == 0 && processed == 0,
        "partial line is retained without processing");
    line[split] = saved;
    CHECK(write_text(log_path, "a", line + split) == 0, "append partial event suffix");
    CHECK(wardd_nginx_event_reader_step(
        &reader, handle_event, &handled, 16, &processed, error, sizeof(error)) == 0, error);
    CHECK(processed == 1 && strcmp(handled.last_request, "partial") == 0, "complete partial event once");

    wardd_nginx_event_reader_close(&reader);
    CHECK(wardd_nginx_event_reader_init(&reader, log_path, cursor_path, error, sizeof(error)) == 0, error);
    CHECK(wardd_nginx_event_reader_step(
        &reader, handle_event, &handled, 16, &processed, error, sizeof(error)) == 0 && processed == 0,
        "persistent cursor prevents restart replay");

    make_line(line, sizeof(line), "copytruncate", 1002);
    CHECK(write_text(log_path, "w", line) == 0, "copytruncate event log");
    CHECK(wardd_nginx_event_reader_step(
        &reader, handle_event, &handled, 16, &processed, error, sizeof(error)) == 0, error);
    CHECK(processed == 1 && strcmp(handled.last_request, "copytruncate") == 0,
        "copytruncate resets cursor safely");

    CHECK(rename(log_path, old_path) == 0, "rotate event log by rename");
    make_line(line, sizeof(line), "rotated", 1003);
    CHECK(write_text(log_path, "wx", line) == 0, "create rotated event log");
    CHECK(wardd_nginx_event_reader_step(
        &reader, handle_event, &handled, 16, &processed, error, sizeof(error)) == 0 && processed == 0,
        "rotation waits for a stable old-file EOF");
    CHECK(wardd_nginx_event_reader_step(
        &reader, handle_event, &handled, 16, &processed, error, sizeof(error)) == 0, error);
    CHECK(processed == 1 && strcmp(handled.last_request, "rotated") == 0, "rename rotation reopens new log");

    make_line(line, sizeof(line), "parse", 1004);
    line[strlen(line) - 1] = '\0';
    CHECK(wardd_nginx_event_parse(line, &parsed, error, sizeof(error)) == 0, error);
    CHECK(parsed.confirmed_peer && parsed.limiter_rejected && parsed.event_realtime_seconds == 1004,
        "strict schema parser extracts trusted fields");
    CHECK(wardd_nginx_event_parse("{\"schema\":2}", &parsed, error, sizeof(error)) != 0,
        "reject unknown event schema");

    /*
     * Regression: a malformed record must be skipped, not treated as fatal.
     * nginx renders an empty $server_name for any server block without a
     * server_name directive, so a routine configuration used to permanently
     * disable automatic banning after a single line.
     */
    {
        const uint64_t rejected_before = reader.rejected_events;
        static const char empty_server[] =
            "{\"schema\":1,\"peer\":\"8.8.4.4\",\"server\":\"\","
            "\"zone\":\"api\",\"status\":\"REJECTED\",\"request_id\":\"poison\","
            "\"epoch\":\"1006.123\"}\n";

        CHECK(write_text(log_path, "a", empty_server) == 0, "append empty-server_name event");
        CHECK(wardd_nginx_event_reader_step(
            &reader, handle_event, &handled, 16, &processed, error, sizeof(error)) == 0,
            "empty server_name is skipped rather than fatal");
        CHECK(processed == 0 && reader.rejected_events == rejected_before + 1,
            "malformed line is counted as rejected");

        CHECK(write_text(log_path, "a", "this is not a wardd event\n") == 0, "append garbage line");
        CHECK(write_text(log_path, "a", "\n") == 0, "append empty line");
        make_line(line, sizeof(line), "after-poison", 1007);
        CHECK(write_text(log_path, "a", line) == 0, "append a valid event after the bad ones");
        CHECK(wardd_nginx_event_reader_step(
            &reader, handle_event, &handled, 16, &processed, error, sizeof(error)) == 0, error);
        CHECK(processed == 1 && strcmp(handled.last_request, "after-poison") == 0,
            "ingestion continues past malformed lines");
        CHECK(reader.rejected_events == rejected_before + 3, "every malformed line is counted");
        CHECK(reader.last_reject_reason[0] != '\0', "last rejection reason is recorded");
    }

    /*
     * Regression: an oversized line fills the buffer with no newline in sight.
     * A corrupt or foreign log must be resynchronised past, not treated as a
     * reason to stop ingesting.
     */
    {
        const uint64_t rejected_before = reader.rejected_events;
        char oversized[WARDD_NGINX_EVENT_BUFFER_LEN * 2];

        memset(oversized, 'x', sizeof(oversized) - 2);
        oversized[sizeof(oversized) - 2] = '\n';
        oversized[sizeof(oversized) - 1] = '\0';
        CHECK(write_text(log_path, "a", oversized) == 0, "append an oversized line");
        CHECK(wardd_nginx_event_reader_step(
            &reader, handle_event, &handled, 16, &processed, error, sizeof(error)) == 0,
            "an oversized line is skipped rather than fatal");
        CHECK(reader.rejected_events > rejected_before, "the oversized line is counted");

        make_line(line, sizeof(line), "after-oversized", 1008);
        CHECK(write_text(log_path, "a", line) == 0, "append a valid event after the oversized line");
        CHECK(wardd_nginx_event_reader_step(
            &reader, handle_event, &handled, 16, &processed, error, sizeof(error)) == 0, error);
        CHECK(processed == 1 && strcmp(handled.last_request, "after-oversized") == 0,
            "ingestion resynchronises after an oversized line");
    }

    /*
     * Regression: logrotate renames the log while a partial line is buffered.
     * The tail is lost, but the new file must still be picked up.
     */
    {
        const uint64_t rejected_before = reader.rejected_events;
        size_t split;

        make_line(line, sizeof(line), "torn", 1009);
        split = strlen(line) / 2;
        CHECK(write_text(log_path, "a", "") == 0 || 1, "prepare torn-line rotation");
        {
            const char saved = line[split];
            line[split] = '\0';
            CHECK(write_text(log_path, "a", line) == 0, "append a partial event");
            line[split] = saved;
        }
        CHECK(wardd_nginx_event_reader_step(
            &reader, handle_event, &handled, 16, &processed, error, sizeof(error)) == 0 && processed == 0,
            "the partial line is buffered, not processed");
        (void)unlink(old_path);
        CHECK(rename(log_path, old_path) == 0, "rotate while a partial line is buffered");
        make_line(line, sizeof(line), "post-rotation", 1010);
        CHECK(write_text(log_path, "wx", line) == 0, "create the rotated log");
        for (int attempt = 0; attempt < 3 && processed == 0; ++attempt) {
            CHECK(wardd_nginx_event_reader_step(
                &reader, handle_event, &handled, 16, &processed, error, sizeof(error)) == 0,
                "a torn line at rotation is skipped rather than fatal");
        }
        CHECK(processed == 1 && strcmp(handled.last_request, "post-rotation") == 0,
            "ingestion continues into the rotated log");
        CHECK(reader.rejected_events > rejected_before, "the torn line is counted");
    }

    wardd_nginx_event_reader_close(&reader);
    CHECK(wardd_nginx_event_reader_init(&reader, delayed_log, delayed_cursor, error, sizeof(error)) == 0, error);
    errno = 0;
    CHECK(wardd_nginx_event_reader_step(
        &reader, handle_event, &handled, 16, &processed, error, sizeof(error)) != 0 && errno == ENOENT,
        "missing log is retryable");
    make_line(line, sizeof(line), "delayed", 1005);
    CHECK(write_text(delayed_log, "wx", line) == 0, "create delayed event log");
    CHECK(wardd_nginx_event_reader_step(
        &reader, handle_event, &handled, 16, &processed, error, sizeof(error)) == 0 && processed == 1 &&
        strcmp(handled.last_request, "delayed") == 0,
        "new log after startup is read from the beginning");
    wardd_nginx_event_reader_close(&reader);
    (void)unlink(log_path);
    (void)unlink(old_path);
    (void)unlink(delayed_log);
    (void)unlink(delayed_cursor);
    (void)unlink(cursor_path);
    (void)unlink(cursor_lock);
    (void)snprintf(log_path, sizeof(log_path), "%s/state", directory);
    (void)rmdir(log_path);
    (void)rmdir(directory);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
