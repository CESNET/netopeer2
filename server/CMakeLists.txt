cmake_minimum_required(VERSION 2.8.9)

# include custom Modules
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/../CMakeModules/")

project(netopeer2-server C)
include(GNUInstallDirs)
include(CheckFunctionExists)

# check the supported platform
if(NOT UNIX)
    message(FATAL_ERROR "Only *nix like systems are supported.")
endif()

# set version
set(NP2SRV_VERSION 0.6.16)

# set default build type if not specified by user
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE debug)
endif()

set(CMAKE_C_FLAGS         "${CMAKE_C_FLAGS} -Wall -Wextra -std=gnu11")
set(CMAKE_C_FLAGS_RELEASE "-O2 -DNDEBUG")
set(CMAKE_C_FLAGS_DEBUG   "-g -O0 -DDEBUG")

# build options
if(CMAKE_BUILD_TYPE STREQUAL debug)
    option(ENABLE_BUILD_TESTS "Build tests" ON)
    option(ENABLE_VALGRIND_TESTS "Build tests with valgrind" ON)
else()
    option(ENABLE_BUILD_TESTS "Build tests" OFF)
    option(ENABLE_VALGRIND_TESTS "Build tests with valgrind" OFF)
endif()
option(ENABLE_CONFIGURATION "Enable server configuration" ON)
set(THREAD_COUNT 5 CACHE STRING "Number of threads accepting new sessions and handling requests")
set(DEFAULT_HOST_KEY "/etc/ssh/ssh_host_rsa_key" CACHE STRING "Default server host key (used only if configuration is disabled)")

option(ENABLE_LY_CTX_INFO_CACHE "Enable caching the ly_ctx_info() result; reduces processing at the cost of increased memory usage." ON)
if(ENABLE_LY_CTX_INFO_CACHE)
    set(NP2SRV_ENABLED_LY_CTX_INFO_CACHE 1)
endif()

# set prefix for the PID file
if (NOT PIDFILE_PREFIX)
    set(PIDFILE_PREFIX "/var/run")
endif()

# get keystored keys directory
find_package(PkgConfig)
if (ENABLE_CONFIGURATION)
    if (NOT KEYSTORED_KEYS_DIR AND PKG_CONFIG_FOUND)
        execute_process(COMMAND ${PKG_CONFIG_EXECUTABLE} "--variable=KEYSTORED_KEYS_DIR" "keystored" OUTPUT_VARIABLE KEYSTORED_KEYS_DIR)
        if (KEYSTORED_KEYS_DIR)
            string(STRIP ${KEYSTORED_KEYS_DIR} KEYSTORED_KEYS_DIR)
        endif()
    endif()
    if (NOT KEYSTORED_KEYS_DIR)
        message(STATUS "Failed to learn keystored keys directory, rerun cmake and set KEYSTORED_KEYS_DIR manually or the server configuration will not work.")
        set(KEYSTORED_KEYS_DIR "none")
    else()
        message(STATUS "keystored keys directory is \"${KEYSTORED_KEYS_DIR}\".")
    endif()
else()
    if (NOT KEYSTORED_KEYS_DIR)
        set(KEYSTORED_KEYS_DIR "none")
    endif()
endif()

# set default SSH key
if (KEYSTORED_KEYS_DIR STREQUAL "none")
    message(STATUS "Server configuration off, default SSH host key will be used: \"${DEFAULT_HOST_KEY}\".")
endif()

# check that lnc2 supports np2srv thread count
if (PKG_CONFIG_FOUND)
    execute_process(COMMAND ${PKG_CONFIG_EXECUTABLE} "--variable=LNC2_MAX_THREAD_COUNT" "libnetconf2" OUTPUT_VARIABLE LNC2_THREAD_COUNT)
    if (LNC2_THREAD_COUNT)
        string(STRIP ${LNC2_THREAD_COUNT} LNC2_THREAD_COUNT)
        if (LNC2_THREAD_COUNT LESS THREAD_COUNT)
            message(FATAL_ERROR "libnetconf2 was compiled with support up to ${LNC2_THREAD_COUNT} threads, server is configured with ${THREAD_COUNT}.")
        else()
            message(STATUS "libnetconf2 was compiled with support of up to ${LNC2_THREAD_COUNT} threads")
        endif()
    else()
        message(STATUS "Unable to learn libnetconf2 thread support, check skipped")
    endif()
else()
    message(STATUS "pkg-config not found, so it was not possible to check if libnetconf2 supports ${THREAD_COUNT} threads")
endif()

# source files
set(srcs
    ietf_netconf_server.c
    ietf_system.c
    ietf_keystore.c
    netconf_monitoring.c
    operations.c
    op_get_config.c
    op_editconfig.c
    op_copyconfig.c
    op_deleteconfig.c
    op_candidate.c
    op_validate.c
    op_un_lock.c
    op_generic.c
    op_notifications.c
    op_kill.c
    log.c)

# object library to build source codes only once for the main binary
add_library(serverobj OBJECT ${srcs})

# netopeer2-server target
add_executable(netopeer2-server $<TARGET_OBJECTS:serverobj> main.c)

# dependencies - pthread
set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
find_package(Threads REQUIRED)
target_link_libraries(netopeer2-server ${CMAKE_THREAD_LIBS_INIT})

set(CMAKE_REQUIRED_FLAGS ${CMAKE_THREAD_LIBS_INIT})
check_function_exists(pthread_rwlockattr_setkind_np HAVE_PTHREAD_RWLOCKATTR_SETKIND_NP)

# dependencies - libyang
find_package(LibYANG REQUIRED)
target_link_libraries(netopeer2-server ${LIBYANG_LIBRARIES})
include_directories(${LIBYANG_INCLUDE_DIRS})

# dependencies - libnetconf2
find_package(LibNETCONF2 REQUIRED)
if (NOT LIBNETCONF2_ENABLED_SSH)
    message(FATAL_ERROR "Missing SSH support in libnetconf2, server requires SSH to be supported.")
endif()
target_link_libraries(netopeer2-server ${LIBNETCONF2_LIBRARIES})
include_directories(${LIBNETCONF2_INCLUDE_DIRS})

# dependencies - libssl
#if(LIBNETCONF2_ENABLED_TLS)
#    find_package(OpenSSL REQUIRED)
#    target_link_libraries(netopeer2-server ${OPENSSL_LIBRARIES})
#    include_directories(${OPENSSL_INCLUDE_DIR})
#endif()

# dependencies - sysrepo
find_package(SYSREPO REQUIRED)
target_link_libraries(netopeer2-server ${SYSREPO_LIBRARIES})
include_directories(${SYSREPO_INCLUDE_DIRS})

# install binary
install(TARGETS netopeer2-server DESTINATION ${CMAKE_INSTALL_BINDIR})

# only for configuration
if (ENABLE_CONFIGURATION)
    # find sysrepoctl
    if (NOT SYSREPOCTL_EXECUTABLE)
        find_program(SYSREPOCTL_EXECUTABLE sysrepoctl)
    endif()
    if (NOT SYSREPOCTL_EXECUTABLE)
        message(FATAL_ERROR "Unable to find sysrepoctl, set SYSREPOCTL_EXECUTABLE manually.")
    endif()

    # find sysrepocfg
    if (NOT SYSREPOCFG_EXECUTABLE)
        find_program(SYSREPOCFG_EXECUTABLE sysrepocfg)
    endif()
    if (NOT SYSREPOCFG_EXECUTABLE)
        message(FATAL_ERROR "Unable to find sysrepocfg, set SYSREPOCFG_EXECUTABLE manually.")
    endif()

    # Command line options to be passed to `sysrepoctl` when working with modules
    # which should only be accessible by an administrator
    if (NOT SYSREPOCTL_ROOT_PERMS)
        set(SYSREPOCTL_ROOT_PERMS "-o root:root -p 600")
    endif()

    install(CODE "
        set(ENV{SYSREPOCTL} ${SYSREPOCTL_EXECUTABLE})
        set(ENV{SYSREPOCFG} ${SYSREPOCFG_EXECUTABLE})
        set(ENV{SYSREPOCTL_ROOT_PERMS} SYSREPOCTL_ROOT_PERMS)
        execute_process(COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/scripts/model-install.sh)")
endif()

add_custom_target(install-scripts-ide
    scripts/model-install.sh
)

configure_file("${PROJECT_SOURCE_DIR}/config.h.in" "${PROJECT_BINARY_DIR}/config.h" ESCAPE_QUOTES @ONLY)
include_directories(${PROJECT_BINARY_DIR})

# clean cmake cache
add_custom_target(cleancache
                  COMMAND make clean
                  COMMAND find . -iname '*cmake*' -not -name CMakeLists.txt -exec rm -rf {} +
                  COMMAND rm -rf Makefile Doxyfile
                  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

if(ENABLE_VALGRIND_TESTS)
    set(ENABLE_BUILD_TESTS ON)
endif()

if(ENABLE_BUILD_TESTS)
    find_package(CMocka 1.0.0)
    if(CMOCKA_FOUND)
        enable_testing()
        add_subdirectory(tests)
    endif(CMOCKA_FOUND)
endif(ENABLE_BUILD_TESTS)
