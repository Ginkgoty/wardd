#include "wardd/auto_ban.h"
#include "wardd/ban.h"
#include "wardd/audit.h"

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

struct apply_context {
    size_t calls;
    uint64_t strike;
    uint64_t duration;
};

static int apply_ban(
    const struct wardd_auto_ban_event *event,
    const struct wardd_auto_ban_decision *decision,
    void *opaque,
    char *error,
    size_t error_size
)
{
    struct apply_context *context = opaque;
    (void)event;
    (void)error;
    (void)error_size;
    context->calls++;
    context->strike = decision->strike;
    context->duration = decision->duration_seconds;
    return 0;
}

static int process(
    const struct wardd_ban_config *config,
    const char *path,
    struct wardd_auto_ban_event *event,
    uint64_t now,
    struct apply_context *applied,
    struct wardd_auto_ban_decision *decision,
    char *error
)
{
    event->event_realtime_seconds = now;
    return wardd_auto_ban_process(
        config, path, event, now, apply_ban, applied, decision, error, 512
    );
}

int main(void)
{
    char directory[] = "/tmp/wardd-auto-ban-test-XXXXXX";
    char path[512];
    char lock_path[1024];
    char audit_path[512];
    char error[512];
    struct wardd_ban_config config = {0};
    struct wardd_auto_ban_event event = {
        .peer = "8.8.8.8",
        .server = "service.example.com",
        .zone = "api",
        .request_id = "req-1",
        .limiter_rejected = true,
        .confirmed_peer = true,
    };
    struct wardd_auto_ban_decision decision;
    struct apply_context applied = {0};

    config.automatic.enabled = true;
    (void)snprintf(config.automatic.event_source, sizeof(config.automatic.event_source), "nginx_limit_req");
    config.automatic.window_seconds = 60;
    config.automatic.rejections = 3;
    config.automatic.first_duration_seconds = 10;
    config.automatic.second_duration_seconds = 20;
    config.automatic.third_duration_seconds = 30;
    config.automatic.strike_retention_seconds = 100;
    (void)snprintf(config.exempt[0], sizeof(config.exempt[0]), "9.9.9.0/24");
    config.exempt_count = 1;

    CHECK(mkdtemp(directory) != NULL, "create auto-ban test directory");
    (void)snprintf(path, sizeof(path), "%s/state/auto.state", directory);
    (void)snprintf(lock_path, sizeof(lock_path), "%s.lock", path);
    (void)snprintf(audit_path, sizeof(audit_path), "%s/audit.jsonl", directory);

    config.automatic.rejections = 1;
    CHECK(process(&config, path, &event, 1000, &applied, &decision, error) != 0,
        "single-event threshold is rejected as unsafe");
    config.automatic.rejections = 3;
    event.limiter_rejected = false;
    CHECK(process(&config, path, &event, 1000, &applied, &decision, error) == 0, error);
    CHECK(decision.disposition == WARDD_AUTO_BAN_NOT_REJECTED, "ignore non-limiter response");
    event.limiter_rejected = true;
    event.confirmed_peer = false;
    CHECK(process(&config, path, &event, 1000, &applied, &decision, error) == 0, error);
    CHECK(decision.disposition == WARDD_AUTO_BAN_UNCONFIRMED, "reject unconfirmed peer");
    event.confirmed_peer = true;
    (void)snprintf(event.peer, sizeof(event.peer), "127.0.0.1");
    CHECK(process(&config, path, &event, 1000, &applied, &decision, error) == 0, error);
    CHECK(decision.disposition == WARDD_AUTO_BAN_NON_PUBLIC, "reject loopback peer");
    (void)snprintf(event.peer, sizeof(event.peer), "9.9.9.9");
    CHECK(process(&config, path, &event, 1000, &applied, &decision, error) == 0, error);
    CHECK(decision.disposition == WARDD_AUTO_BAN_EXEMPT, "honor automatic-ban exemption");

    (void)snprintf(event.peer, sizeof(event.peer), "8.8.8.8");
    CHECK(process(&config, path, &event, 1000, &applied, &decision, error) == 0, error);
    CHECK(decision.disposition == WARDD_AUTO_BAN_COUNTED && decision.window_count == 1,
        "one rejection is counted but not banned");
    CHECK(process(&config, path, &event, 1001, &applied, &decision, error) == 0, error);
    CHECK(decision.disposition == WARDD_AUTO_BAN_DUPLICATE && decision.window_count == 1,
        "duplicate request ID is not counted");
    (void)snprintf(event.request_id, sizeof(event.request_id), "req-2");
    CHECK(process(&config, path, &event, 1002, &applied, &decision, error) == 0, error);
    CHECK(decision.disposition == WARDD_AUTO_BAN_COUNTED && applied.calls == 0, "threshold not reached");
    (void)snprintf(event.request_id, sizeof(event.request_id), "req-3");
    CHECK(process(&config, path, &event, 1003, &applied, &decision, error) == 0, error);
    CHECK(decision.disposition == WARDD_AUTO_BAN_TRIGGERED && applied.calls == 1 &&
        applied.strike == 1 && applied.duration == 10, "first strike triggers first duration");
    CHECK(wardd_audit_auto_ban(audit_path, &event, &decision, "durable_pending", error, sizeof(error)) == 0,
        error);
    FILE *audit = fopen(audit_path, "r");
    char audit_line[2048] = {0};
    CHECK(audit != NULL && fgets(audit_line, sizeof(audit_line), audit) != NULL,
        "read structured automatic-ban audit");
    if (audit != NULL) (void)fclose(audit);
    CHECK(strstr(audit_line, "\"event\":\"automatic_ban\"") != NULL &&
        strstr(audit_line, "\"zone\":\"api\"") != NULL,
        "audit contains bounded policy metadata");

    for (int index = 4; index <= 6; ++index) {
        (void)snprintf(event.request_id, sizeof(event.request_id), "req-%d", index);
        CHECK(process(&config, path, &event, 1000U + (uint64_t)index, &applied, &decision, error) == 0, error);
    }
    CHECK(applied.calls == 2 && applied.strike == 2 && applied.duration == 20,
        "second window escalates strike duration");

    for (int index = 7; index <= 9; ++index) {
        (void)snprintf(event.request_id, sizeof(event.request_id), "req-%d", index);
        CHECK(process(&config, path, &event, 1200U + (uint64_t)index, &applied, &decision, error) == 0, error);
    }
    CHECK(applied.calls == 3 && applied.strike == 1 && applied.duration == 10,
        "expired strike retention resets escalation");

    /* Nginx stamps the event, wardd reads its own clock, so an event can arrive
       a second or two ahead of the daemon. Such events are accepted, and must
       therefore also survive pruning: dropping them again discards the previous
       rejection on every new one, so the threshold is never reached and
       automatic banning silently stops working under clock skew. */
    for (int index = 10; index <= 12; ++index) {
        (void)snprintf(event.request_id, sizeof(event.request_id), "req-%d", index);
        event.event_realtime_seconds = 2002;
        CHECK(wardd_auto_ban_process(
                &config, path, &event, 2000, apply_ban, &applied, &decision, error, sizeof(error)) == 0,
            error);
    }
    CHECK(applied.calls == 4 && decision.disposition == WARDD_AUTO_BAN_TRIGGERED,
        "events stamped slightly ahead of the daemon clock still accumulate");

    (void)snprintf(event.request_id, sizeof(event.request_id), "req-13");
    event.event_realtime_seconds = 2010;
    CHECK(wardd_auto_ban_process(
            &config, path, &event, 2000, apply_ban, &applied, &decision, error, sizeof(error)) == 0,
        error);
    CHECK(decision.disposition == WARDD_AUTO_BAN_STALE,
        "an event far ahead of the daemon clock is still rejected");

    /*
     * The manual-ban warning and the automatic-ban peer test answer different
     * questions and are implemented separately. They must not disagree about
     * whether an address is ordinary public space, or an operator would be
     * warned about a network wardd is happy to ban itself, or worse the other
     * way round.
     */
    static const struct {
        const char *peer;
        bool public_space;
    } classification_cases[] = {
        {"10.1.2.3", false},
        {"172.20.3.4", false},
        {"192.168.1.5", false},
        {"127.0.0.1", false},
        {"169.254.1.1", false},
        {"100.100.1.1", false},
        {"fe80::1", false},
        {"fc00::1", false},
        {"8.8.8.8", true},
        {"1.1.1.1", true},
        {"2001:4860:4860::8888", true},
    };
    for (size_t index = 0; index < sizeof(classification_cases) / sizeof(classification_cases[0]); ++index) {
        char summary[WARDD_BAN_RESERVED_SUMMARY_LEN];
        const bool warned =
            wardd_ban_reserved_overlap(classification_cases[index].peer, summary, sizeof(summary)) != 0;
        (void)snprintf(event.peer, sizeof(event.peer), "%s", classification_cases[index].peer);
        (void)snprintf(event.request_id, sizeof(event.request_id), "class-%zu", index);
        event.event_realtime_seconds = 3000;
        CHECK(wardd_auto_ban_process(
                &config, path, &event, 3000, apply_ban, &applied, &decision, error, sizeof(error)) == 0,
            error);
        const bool auto_rejected = decision.disposition == WARDD_AUTO_BAN_NON_PUBLIC;
        CHECK(warned == auto_rejected && warned != classification_cases[index].public_space,
            classification_cases[index].peer);
    }

    (void)unlink(path);
    (void)unlink(lock_path);
    (void)unlink(audit_path);
    (void)snprintf(path, sizeof(path), "%s/state", directory);
    (void)rmdir(path);
    (void)rmdir(directory);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
