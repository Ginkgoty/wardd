#ifndef WARDD_NGINX_H
#define WARDD_NGINX_H

#include <stddef.h>

/*
 * Enough for a dumped configuration from an ordinary deployment. A dump that
 * does not fit is reported as such rather than silently searched in part,
 * because a truncated dump would make "not wired" indistinguishable from
 * "wired past the truncation point".
 */
#define WARDD_NGINX_DUMP_LEN (512U * 1024U)

int wardd_nginx_render(
    const char *generated_directory,
    const char *limit_event_log,
    const char *limit_zone,
    char *error,
    size_t error_size
);

int wardd_nginx_check_http_include(
    const char *nginx_binary,
    const char *include_path,
    char *error,
    size_t error_size
);

int wardd_nginx_check_include(
    const char *nginx_binary,
    const char *include_path,
    char *error,
    size_t error_size
);

int wardd_nginx_test_live(
    const char *nginx_binary,
    char *error,
    size_t error_size
);

int wardd_nginx_reload_live(
    const char *nginx_binary,
    char *error,
    size_t error_size
);

/* Capture `nginx -T`, the fully resolved live configuration. */
int wardd_nginx_dump_config(
    const char *nginx_binary,
    char *output,
    size_t output_size,
    char *error,
    size_t error_size
);

/* Path of wardd's own drop-in inside the Nginx configuration directory. */
int wardd_nginx_dropin_path(
    const char *conf_dir,
    char *output,
    size_t output_size,
    char *error,
    size_t error_size
);

/*
 * Install wardd's http-block drop-in, then verify that the live configuration
 * still loads. wardd writes only this one file: it never edits a file the
 * administrator wrote. If the check fails the previous state is restored, so a
 * failed enable leaves Nginx exactly as it was.
 *
 * The server-block include cannot be placed automatically -- it must go inside
 * the specific server the administrator wants protected -- so it stays a
 * documented manual step that wardd_nginx_dump_config can verify afterwards.
 */
int wardd_nginx_enable(
    const char *nginx_binary,
    const char *conf_dir,
    const char *generated_directory,
    char *error,
    size_t error_size
);

/* Remove the drop-in, then verify the live configuration still loads.
   Returns 1 if a drop-in was removed, 0 if there was none, -1 on failure. */
int wardd_nginx_disable(
    const char *nginx_binary,
    const char *conf_dir,
    char *error,
    size_t error_size
);

#endif
