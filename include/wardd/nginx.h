#ifndef WARDD_NGINX_H
#define WARDD_NGINX_H

#include <stddef.h>

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

#endif
