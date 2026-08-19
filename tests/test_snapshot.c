#include "wardd/snapshot.h"

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

static void remove_snapshot(const char *root, const char *id)
{
    static const char *const files[] = {
        "source.mmdb", "cn-v4.txt", "cn-v6.txt", "nginx-cn.conf",
        "metadata.json", "sha256", ".approved"
    };
    char directory[768];
    char path[1024];

    if (id[0] == '\0') return;
    (void)snprintf(directory, sizeof(directory), "%s/%s", root, id);
    for (size_t index = 0; index < sizeof(files) / sizeof(files[0]); ++index) {
        (void)snprintf(path, sizeof(path), "%s/%s", directory, files[index]);
        (void)unlink(path);
    }
    (void)rmdir(directory);
}

int main(void)
{
    char parent[] = "/tmp/wardd-snapshot-test-XXXXXX";
    char root[512];
    char generated[512];
    char path[1024];
    char fail_live[1024];
    char fail_reload[1024];
    char error[2048];
    struct wardd_snapshot_result cn = {0};
    struct wardd_snapshot_result jp = {0};
    struct wardd_snapshot_result duplicate = {0};
    struct wardd_snapshot_status status;
    struct wardd_geo_diff diff;

    CHECK(mkdtemp(parent) != NULL, "create snapshot test directory");
    (void)snprintf(root, sizeof(root), "%s/snapshots", parent);
    (void)snprintf(generated, sizeof(generated), "%s/generated", parent);
    (void)snprintf(fail_live, sizeof(fail_live), "%s/nginx-fail-live-test", parent);
    (void)snprintf(fail_reload, sizeof(fail_reload), "%s/nginx-fail-reload", parent);
    CHECK(symlink(WARDD_TEST_NGINX_COMMAND, fail_live) == 0, "create live-test failure helper");
    CHECK(symlink(WARDD_TEST_NGINX_COMMAND, fail_reload) == 0, "create reload failure helper");
    CHECK(
        wardd_geo_snapshot_create(
            WARDD_TEST_MMDB_PATH,
            "CN",
            root,
            32U * 1024U * 1024U,
            0.20,
            &cn,
            error,
            sizeof(error)
        ) == 0,
        error
    );
    CHECK(!cn.pending_review && !cn.existed, "first snapshot is auto-approved");
    CHECK(
        wardd_geo_snapshot_activate(root, generated, cn.id, WARDD_TEST_NGINX, error, sizeof(error)) == 0,
        error
    );
    CHECK(wardd_geo_snapshot_status(root, &status, error, sizeof(error)) == 0, error);
    CHECK(strcmp(status.current, cn.id) == 0, "CN snapshot is current");
    CHECK(status.current_approved, "current snapshot is approved");

    CHECK(
        wardd_geo_snapshot_create(
            WARDD_TEST_MMDB_PATH,
            "CN",
            root,
            32U * 1024U * 1024U,
            0.20,
            &duplicate,
            error,
            sizeof(error)
        ) == 0,
        error
    );
    CHECK(duplicate.existed && strcmp(duplicate.id, cn.id) == 0, "duplicate import is idempotent");

    CHECK(
        wardd_geo_snapshot_create(
            WARDD_TEST_MMDB_PATH,
            "JP",
            root,
            32U * 1024U * 1024U,
            0.01,
            &jp,
            error,
            sizeof(error)
        ) == 0,
        error
    );
    CHECK(jp.pending_review, "large country-set change requires review");
    CHECK(
        wardd_geo_snapshot_activate(root, generated, jp.id, WARDD_TEST_NGINX, error, sizeof(error)) != 0,
        "pending snapshot cannot activate"
    );
    CHECK(wardd_geo_snapshot_diff(root, cn.id, jp.id, &diff, error, sizeof(error)) == 0, error);
    CHECK(diff.added_prefixes > 0 && diff.removed_prefixes > 0, "snapshot diff detects changes");
    CHECK(wardd_geo_snapshot_approve(root, jp.id, error, sizeof(error)) == 0, error);
    CHECK(
        wardd_geo_snapshot_activate_live(root, generated, jp.id, fail_live, error, sizeof(error)) != 0,
        "live test failure rejects activation"
    );
    CHECK(wardd_geo_snapshot_status(root, &status, error, sizeof(error)) == 0, error);
    CHECK(strcmp(status.current, cn.id) == 0, "live test failure restores current snapshot");
    CHECK(
        wardd_geo_snapshot_activate_live(root, generated, jp.id, fail_reload, error, sizeof(error)) != 0,
        "reload failure rejects activation"
    );
    CHECK(wardd_geo_snapshot_status(root, &status, error, sizeof(error)) == 0, error);
    CHECK(strcmp(status.current, cn.id) == 0, "reload failure restores current snapshot");
    CHECK(
        wardd_geo_snapshot_activate_live(root, generated, jp.id, "/bin/true", error, sizeof(error)) == 0,
        error
    );
    CHECK(wardd_geo_snapshot_status(root, &status, error, sizeof(error)) == 0, error);
    CHECK(strcmp(status.current, jp.id) == 0 && strcmp(status.previous, cn.id) == 0, "activation records previous");
    CHECK(
        wardd_geo_snapshot_rollback_live(root, generated, "/bin/true", error, sizeof(error)) == 0,
        error
    );
    CHECK(wardd_geo_snapshot_status(root, &status, error, sizeof(error)) == 0, error);
    CHECK(strcmp(status.current, cn.id) == 0, "rollback restores CN snapshot");

    (void)snprintf(path, sizeof(path), "%s/current", generated);
    (void)unlink(path);
    (void)snprintf(path, sizeof(path), "%s/current", root);
    (void)unlink(path);
    (void)snprintf(path, sizeof(path), "%s/previous", root);
    (void)unlink(path);
    (void)snprintf(path, sizeof(path), "%s/.lock", root);
    (void)unlink(path);
    remove_snapshot(root, cn.id);
    remove_snapshot(root, jp.id);
    (void)unlink(fail_live);
    (void)unlink(fail_reload);
    (void)rmdir(generated);
    (void)rmdir(root);
    (void)rmdir(parent);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
