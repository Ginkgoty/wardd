cmake_minimum_required(VERSION 3.20)

project(
    wardd
    VERSION 0.1.0
    DESCRIPTION "A lightweight Linux edge firewall control plane"
    HOMEPAGE_URL "https://github.com/Ginkgoty/wardd"
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

set(WARDD_PACKAGE_CHANNEL "stable" CACHE STRING "Package channel: stable or nightly")
set_property(CACHE WARDD_PACKAGE_CHANNEL PROPERTY STRINGS stable nightly)
set(WARDD_PACKAGE_BUILD_ID "" CACHE STRING "Nightly build identifier (UTC timestamp.commit)")

if(WARDD_PACKAGE_CHANNEL STREQUAL "stable")
    if(WARDD_PACKAGE_BUILD_ID)
        message(FATAL_ERROR "WARDD_PACKAGE_BUILD_ID must be empty for stable builds")
    endif()
    set(WARDD_BUILD_VERSION "${PROJECT_VERSION}")
elseif(WARDD_PACKAGE_CHANNEL STREQUAL "nightly")
    if(NOT WARDD_PACKAGE_BUILD_ID MATCHES "^[0-9]+[.][0-9a-f]+$")
        message(FATAL_ERROR
            "Nightly builds require WARDD_PACKAGE_BUILD_ID=<UTC timestamp>.<commit>"
        )
    endif()
    set(WARDD_BUILD_VERSION "${PROJECT_VERSION}-nightly.${WARDD_PACKAGE_BUILD_ID}")
else()
    message(FATAL_ERROR "WARDD_PACKAGE_CHANNEL must be stable or nightly")
endif()

# Hardening for a root-privileged network daemon shipped as DEB/RPM.
# _FORTIFY_SOURCE needs optimization and some toolchains predefine it, so it is
# undefined first and applied only to optimized configurations.
include(CheckPIESupported)
check_pie_supported()
set(WARDD_HARDENING_COMPILE_OPTIONS
    -fstack-protector-strong
    -fno-common
    $<$<NOT:$<CONFIG:Debug>>:-U_FORTIFY_SOURCE>
    $<$<NOT:$<CONFIG:Debug>>:-D_FORTIFY_SOURCE=2>
)
set(WARDD_HARDENING_LINK_OPTIONS
    -Wl,-z,relro
    -Wl,-z,now
    -Wl,-z,noexecstack
)

option(WARDD_BUILD_BPF "Build the XDP BPF object (requires clang and libbpf headers)" OFF)
option(WARDD_ENABLE_RUNTIME_TESTS "Enable tests requiring local Unix socket operations" OFF)
option(WARDD_ENABLE_PRIVILEGED_TESTS
    "Enable tests that need root, a network namespace and bpffs" OFF
)
set(WARDD_TEST_MMDB_PATH "" CACHE FILEPATH "Optional MMDB file used by the integration test")

# The GeoIP, Nginx, snapshot and XDP tests all need a real MMDB. Without one
# they are silently not registered at all, which made a green test run look far
# broader than it was. Generate a small synthetic database so those tests run
# everywhere by default; WARDD_TEST_MMDB_PATH still overrides it with a real one.
if(BUILD_TESTING AND NOT WARDD_TEST_MMDB_PATH)
    find_package(Python3 COMPONENTS Interpreter QUIET)
    if(Python3_Interpreter_FOUND)
        set(WARDD_GENERATED_MMDB "${CMAKE_CURRENT_BINARY_DIR}/wardd-test.mmdb")
        execute_process(
            COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/make_test_mmdb.py
                ${WARDD_GENERATED_MMDB}
            RESULT_VARIABLE WARDD_MMDB_STATUS
            OUTPUT_QUIET
        )
        if(WARDD_MMDB_STATUS EQUAL 0)
            set(WARDD_TEST_MMDB_PATH "${WARDD_GENERATED_MMDB}")
            message(STATUS "wardd: generated a synthetic MMDB test fixture")
        else()
            message(WARNING "wardd: could not generate the MMDB test fixture; GeoIP tests are disabled")
        endif()
    else()
        message(WARNING "wardd: python3 not found; GeoIP tests are disabled")
    endif()
endif()
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
target_compile_options(wardd_core PRIVATE -Wall -Wextra -Wpedantic -Werror ${WARDD_HARDENING_COMPILE_OPTIONS})
set_property(TARGET wardd_core PROPERTY POSITION_INDEPENDENT_CODE TRUE)

add_executable(wardd src/wardd.c)
target_link_libraries(wardd PRIVATE wardd_core)
# _GNU_SOURCE exposes struct ucred for the SO_PEERCRED check on the control socket.
target_compile_definitions(wardd PRIVATE _POSIX_C_SOURCE=200809L _GNU_SOURCE)
target_compile_options(wardd PRIVATE -Wall -Wextra -Wpedantic -Werror ${WARDD_HARDENING_COMPILE_OPTIONS})
target_link_options(wardd PRIVATE ${WARDD_HARDENING_LINK_OPTIONS})
set_property(TARGET wardd PROPERTY POSITION_INDEPENDENT_CODE TRUE)

add_executable(wardctl src/wardctl.c)
target_link_libraries(wardctl PRIVATE wardd_core)
target_compile_definitions(wardctl PRIVATE
    _POSIX_C_SOURCE=200809L
    WARDD_DEFAULT_BPF_OBJECT="${CMAKE_INSTALL_FULL_LIBDIR}/wardd/wardd.bpf.o"
)
target_compile_options(wardctl PRIVATE -Wall -Wextra -Wpedantic -Werror ${WARDD_HARDENING_COMPILE_OPTIONS})
target_link_options(wardctl PRIVATE ${WARDD_HARDENING_LINK_OPTIONS})
set_property(TARGET wardctl PROPERTY POSITION_INDEPENDENT_CODE TRUE)

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

if(BUILD_TESTING AND WARDD_ENABLE_PRIVILEGED_TESTS AND WARDD_BUILD_BPF AND WARDD_TEST_MMDB_PATH)
    # Drives the real BPF program over a veth pair inside a throwaway network
    # namespace. Never touches a real interface. Reports 77 (skip) when the
    # host cannot provide root or bpffs.
    add_test(NAME xdp_netns
        COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/xdp_netns.sh
            $<TARGET_FILE:wardctl>
            $<TARGET_FILE:wardd>
            ${WARDD_BPF_OBJECT}
            ${WARDD_TEST_MMDB_PATH}
    )
    set_property(TEST xdp_netns PROPERTY SKIP_RETURN_CODE 77)
    set_property(TEST xdp_netns PROPERTY TIMEOUT 300)
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
# Debian Policy requires /usr/share/doc/<pkg>/copyright; RPM marks LICENSE with
# %license via CPACK_RPM_USER_FILELIST in cmake/Packaging.cmake.
install(FILES LICENSE packaging/debian/copyright
    DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/doc/wardd
)

include(cmake/Packaging.cmake)
