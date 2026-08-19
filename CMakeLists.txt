cmake_minimum_required(VERSION 3.20)

project(
    wardd
    VERSION 0.1.0
    DESCRIPTION "A lightweight Linux edge firewall control plane"
    LANGUAGES C
)

include(GNUInstallDirs)
include(CTest)

find_package(OpenSSL REQUIRED COMPONENTS Crypto)
find_package(CURL REQUIRED)
find_path(LIBBPF_INCLUDE_DIR bpf/bpf_helpers.h REQUIRED)
find_library(LIBBPF_LIBRARY bpf REQUIRED)
find_path(LIBXDP_INCLUDE_DIR xdp/libxdp.h REQUIRED)
find_library(LIBXDP_LIBRARY xdp REQUIRED)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(WARDD_BUILD_BPF "Build the XDP BPF object (requires clang and libbpf headers)" OFF)
option(WARDD_ENABLE_RUNTIME_TESTS "Enable tests requiring local Unix socket operations" OFF)
set(WARDD_TEST_MMDB_PATH "" CACHE FILEPATH "Optional MMDB file used by the integration test")
set(WARDD_MAXMINDDB_ROOT "" CACHE PATH "Optional root containing a local libmaxminddb installation")

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/include/wardd/version.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/generated/wardd/version.h
    @ONLY
)

if(WARDD_MAXMINDDB_ROOT)
    find_path(MAXMINDDB_INCLUDE_DIR
        maxminddb.h
        PATHS
            ${WARDD_MAXMINDDB_ROOT}/usr/include/${CMAKE_LIBRARY_ARCHITECTURE}
            ${WARDD_MAXMINDDB_ROOT}/usr/include
        NO_DEFAULT_PATH
    )
    find_library(MAXMINDDB_LIBRARY
        maxminddb
        PATHS
            ${WARDD_MAXMINDDB_ROOT}/usr/lib/${CMAKE_LIBRARY_ARCHITECTURE}
            ${WARDD_MAXMINDDB_ROOT}/usr/lib
        NO_DEFAULT_PATH
    )
else()
    find_path(MAXMINDDB_INCLUDE_DIR maxminddb.h)
    find_library(MAXMINDDB_LIBRARY maxminddb)
endif()

add_library(wardd_core STATIC
    src/audit.c
    src/auto_ban.c
    src/ban.c
    src/config.c
    src/fetch.c
    src/nginx.c
    src/nginx_events.c
    src/runtime.c
    src/snapshot.c
    src/xdp.c
)
target_include_directories(wardd_core SYSTEM PRIVATE ${LIBBPF_INCLUDE_DIR} ${LIBXDP_INCLUDE_DIR})
target_link_libraries(wardd_core PUBLIC
    OpenSSL::Crypto
    CURL::libcurl
    ${LIBBPF_LIBRARY}
    ${LIBXDP_LIBRARY}
)
if(MAXMINDDB_INCLUDE_DIR AND MAXMINDDB_LIBRARY)
    target_sources(wardd_core PRIVATE src/geo_mmdb.c)
    target_include_directories(wardd_core SYSTEM PRIVATE ${MAXMINDDB_INCLUDE_DIR})
    target_link_libraries(wardd_core PUBLIC ${MAXMINDDB_LIBRARY})
    target_compile_definitions(wardd_core PUBLIC WARDD_HAVE_MAXMINDDB=1)
    set(WARDD_HAVE_MAXMINDDB ON)
else()
    target_sources(wardd_core PRIVATE src/geo_unavailable.c)
    target_compile_definitions(wardd_core PUBLIC WARDD_HAVE_MAXMINDDB=0)
    set(WARDD_HAVE_MAXMINDDB OFF)
endif()

target_include_directories(wardd_core
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_BINARY_DIR}/generated
)

target_compile_definitions(wardd_core PRIVATE _POSIX_C_SOURCE=200809L)
target_compile_options(wardd_core PRIVATE -Wall -Wextra -Wpedantic -Werror)

add_executable(wardd src/wardd.c)
target_link_libraries(wardd PRIVATE wardd_core)
target_compile_definitions(wardd PRIVATE _POSIX_C_SOURCE=200809L)
target_compile_options(wardd PRIVATE -Wall -Wextra -Wpedantic -Werror)

add_executable(wardctl src/wardctl.c)
target_link_libraries(wardctl PRIVATE wardd_core)
target_compile_definitions(wardctl PRIVATE
    _POSIX_C_SOURCE=200809L
    WARDD_DEFAULT_BPF_OBJECT="${CMAKE_INSTALL_FULL_LIBDIR}/wardd/wardd.bpf.o"
)
target_compile_options(wardctl PRIVATE -Wall -Wextra -Wpedantic -Werror)

if(WARDD_BUILD_BPF)
    find_program(CLANG_EXECUTABLE clang REQUIRED)

    if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|amd64)$")
        set(WARDD_BPF_ARCH x86)
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|arm64)$")
        set(WARDD_BPF_ARCH arm64)
    else()
        message(FATAL_ERROR "Unsupported BPF target architecture: ${CMAKE_SYSTEM_PROCESSOR}")
    endif()

    set(WARDD_BPF_OBJECT ${CMAKE_CURRENT_BINARY_DIR}/wardd.bpf.o)
    add_custom_command(
        OUTPUT ${WARDD_BPF_OBJECT}
        COMMAND ${CLANG_EXECUTABLE}
            -g -O2 -target bpf
            -D__TARGET_ARCH_${WARDD_BPF_ARCH}
            -I${LIBBPF_INCLUDE_DIR}
            -I/usr/include/${CMAKE_LIBRARY_ARCHITECTURE}
            -I${CMAKE_CURRENT_SOURCE_DIR}/bpf
            -I${CMAKE_CURRENT_SOURCE_DIR}/include
            -c ${CMAKE_CURRENT_SOURCE_DIR}/bpf/wardd.bpf.c
            -o ${WARDD_BPF_OBJECT}
        DEPENDS
            bpf/wardd.bpf.c
            bpf/wardd_shared.h
        VERBATIM
    )
    add_custom_target(wardd_bpf ALL DEPENDS ${WARDD_BPF_OBJECT})
    install(FILES ${WARDD_BPF_OBJECT} DESTINATION ${CMAKE_INSTALL_LIBDIR}/wardd)

    if(BUILD_TESTING)
        add_executable(test_bpf_object tests/test_bpf_object.c)
        target_include_directories(test_bpf_object SYSTEM PRIVATE ${LIBBPF_INCLUDE_DIR})
        target_link_libraries(test_bpf_object PRIVATE ${LIBBPF_LIBRARY})
        target_compile_definitions(test_bpf_object PRIVATE
            WARDD_TEST_BPF_OBJECT="${WARDD_BPF_OBJECT}"
        )
        target_compile_options(test_bpf_object PRIVATE -Wall -Wextra -Wpedantic -Werror)
        add_dependencies(test_bpf_object wardd_bpf)
        add_test(NAME bpf_object COMMAND test_bpf_object)
    endif()
endif()

if(BUILD_TESTING)
    add_executable(test_nginx_events tests/test_nginx_events.c)
    target_link_libraries(test_nginx_events PRIVATE wardd_core)
    target_compile_definitions(test_nginx_events PRIVATE _POSIX_C_SOURCE=200809L)
    target_compile_options(test_nginx_events PRIVATE -Wall -Wextra -Wpedantic -Werror)
    add_test(NAME nginx_events COMMAND test_nginx_events)

    add_executable(test_daemon_events tests/test_daemon_events.c)
    target_compile_definitions(test_daemon_events PRIVATE
        _POSIX_C_SOURCE=200809L
        WARDD_TEST_DAEMON="$<TARGET_FILE:wardd>"
    )
    target_compile_options(test_daemon_events PRIVATE -Wall -Wextra -Wpedantic -Werror)
    add_dependencies(test_daemon_events wardd)
    if(WARDD_ENABLE_RUNTIME_TESTS)
        add_test(NAME daemon_events COMMAND test_daemon_events)
    endif()

    add_executable(test_auto_ban tests/test_auto_ban.c)
    target_link_libraries(test_auto_ban PRIVATE wardd_core)
    target_compile_definitions(test_auto_ban PRIVATE _POSIX_C_SOURCE=200809L)
    target_compile_options(test_auto_ban PRIVATE -Wall -Wextra -Wpedantic -Werror)
    add_test(NAME auto_ban COMMAND test_auto_ban)

    add_executable(test_ban tests/test_ban.c)
    target_link_libraries(test_ban PRIVATE wardd_core)
    target_compile_definitions(test_ban PRIVATE _POSIX_C_SOURCE=200809L)
    target_compile_options(test_ban PRIVATE -Wall -Wextra -Wpedantic -Werror)
    add_test(NAME ban COMMAND test_ban)

    add_executable(test_fetch tests/test_fetch.c)
    target_link_libraries(test_fetch PRIVATE wardd_core)
    target_compile_definitions(test_fetch PRIVATE _POSIX_C_SOURCE=200809L)
    target_compile_options(test_fetch PRIVATE -Wall -Wextra -Wpedantic -Werror)
    add_test(NAME fetch COMMAND test_fetch)

    add_executable(test_config tests/test_config.c)
    target_link_libraries(test_config PRIVATE wardd_core)
    target_compile_definitions(test_config PRIVATE
        _POSIX_C_SOURCE=200809L
        WARDD_TEST_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}"
    )
    target_compile_options(test_config PRIVATE -Wall -Wextra -Wpedantic -Werror)
    add_test(NAME config COMMAND test_config)

    if(WARDD_HAVE_MAXMINDDB AND WARDD_TEST_MMDB_PATH)
        add_executable(test_geo_mmdb tests/test_geo_mmdb.c)
        target_link_libraries(test_geo_mmdb PRIVATE wardd_core)
        target_compile_definitions(test_geo_mmdb PRIVATE
            _POSIX_C_SOURCE=200809L
            WARDD_TEST_MMDB_PATH="${WARDD_TEST_MMDB_PATH}"
        )
        target_compile_options(test_geo_mmdb PRIVATE -Wall -Wextra -Wpedantic -Werror)
        add_test(NAME geo_mmdb COMMAND test_geo_mmdb)

        find_program(NGINX_EXECUTABLE nginx)
        if(NGINX_EXECUTABLE)
            add_executable(test_nginx_command tests/nginx_command.c)
            target_compile_options(test_nginx_command PRIVATE -Wall -Wextra -Wpedantic -Werror)

            add_executable(test_nginx tests/test_nginx.c)
            target_link_libraries(test_nginx PRIVATE wardd_core)
            target_compile_definitions(test_nginx PRIVATE
                _POSIX_C_SOURCE=200809L
                WARDD_TEST_NGINX="${NGINX_EXECUTABLE}"
            )
            target_compile_options(test_nginx PRIVATE -Wall -Wextra -Wpedantic -Werror)
            add_test(NAME nginx COMMAND test_nginx)

            add_executable(test_nginx_live_events tests/test_nginx_live_events.c)
            target_link_libraries(test_nginx_live_events PRIVATE wardd_core)
            target_compile_definitions(test_nginx_live_events PRIVATE
                _POSIX_C_SOURCE=200809L
                WARDD_TEST_NGINX="${NGINX_EXECUTABLE}"
            )
            target_compile_options(test_nginx_live_events PRIVATE -Wall -Wextra -Wpedantic -Werror)
            if(WARDD_ENABLE_RUNTIME_TESTS)
                add_test(NAME nginx_live_events COMMAND test_nginx_live_events)
            endif()

            add_executable(test_snapshot tests/test_snapshot.c)
            target_link_libraries(test_snapshot PRIVATE wardd_core)
            target_compile_definitions(test_snapshot PRIVATE
                _POSIX_C_SOURCE=200809L
                WARDD_TEST_MMDB_PATH="${WARDD_TEST_MMDB_PATH}"
                WARDD_TEST_NGINX="${NGINX_EXECUTABLE}"
                WARDD_TEST_NGINX_COMMAND="$<TARGET_FILE:test_nginx_command>"
            )
            target_compile_options(test_snapshot PRIVATE -Wall -Wextra -Wpedantic -Werror)
            add_dependencies(test_snapshot test_nginx_command)
            add_test(NAME snapshot COMMAND test_snapshot)
        endif()
    endif()
endif()

install(TARGETS wardd wardctl
    RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR}
)
install(FILES config/wardd.toml.example
    DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/wardd
)
install(FILES
    packaging/systemd/wardd.service
    packaging/systemd/wardd-geo-update.service
    packaging/systemd/wardd-geo-update.timer
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/systemd/system
)
install(FILES packaging/tmpfiles/wardd.conf
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/tmpfiles.d
)
