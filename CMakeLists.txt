cmake_minimum_required(VERSION 2.8.12)

project(netopeer2 C)
set(NETOPEER2_DESC "NETCONF tools suite including a server and command-line client")

# include custom Modules
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/CMakeModules/")

if(POLICY CMP0075)
    cmake_policy(SET CMP0075 NEW)
endif()
include(GNUInstallDirs)
include(CheckFunctionExists)
include(CheckIncludeFile)
include(UseCompat)

# check the supported platform
if(NOT UNIX)
    message(FATAL_ERROR "Only *nix like systems are supported.")
endif()

# set default build type if not specified by user
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE debug)
endif()

add_compile_options(-Wall -Wextra -std=gnu99)
set(CMAKE_C_FLAGS_RELEASE "-O2 -DNDEBUG")
set(CMAKE_C_FLAGS_PACKAGE "-g -O2 -DNDEBUG")
set(CMAKE_C_FLAGS_DEBUG   "-g -O0 -DDEBUG")

# Version of the project
# Generic version of not only the library. Major version is reserved for really big changes of the project,
# minor version changes with added functionality (new tool, functionality of the tool or library, ...) and
# micro version is changed with a set of small changes or bugfixes anywhere in the project.
set(NP2SRV_VERSION 1.1.74)

# libyang required SO version
set(LIBYANG_DEP_SOVERSION_MAJOR 1)

# build options
if(CMAKE_BUILD_TYPE STREQUAL debug)
    option(BUILD_TESTS "Build tests" ON)
    option(VALGRIND_TESTS "Build tests with valgrind" ON)
else()
    option(BUILD_TESTS "Build tests" OFF)
    option(VALGRIND_TESTS "Build tests with valgrind" OFF)
endif()
option(BUILD_CLI "Build and install neotpeer2-cli" ON)
option(ENABLE_URL "Enable URL capability" ON)
set(THREAD_COUNT 5 CACHE STRING "Number of threads accepting new sessions and handling requests")
set(NACM_RECOVERY_UID 0 CACHE STRING "NACM recovery session UID that has unrestricted access")
set(POLL_IO_TIMEOUT 10 CACHE STRING "Timeout in milliseconds of polling sessions for new data. It is also used for synchronization of low level IO such as sending a reply while a notification is being sent")
set(YANG_MODULE_DIR "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_DATADIR}/yang/modules/netopeer2" CACHE STRING "Directory where to copy the YANG modules to")

# script options
option(INSTALL_MODULES "Install required modules into sysrepo" ON)
option(GENERATE_HOSTKEY "Generate a new RSA host key in the keystore named \"genkey\"" ON)
option(MERGE_LISTEN_CONFIG "Merge default server configuration for listening on all IPv4 interfaces" ON)
set(MODULES_PERMS 600 CACHE STRING "File access permissions set for all the server modules")
if(NOT MODULES_OWNER)
    execute_process(COMMAND id -un RESULT_VARIABLE RET
    OUTPUT_VARIABLE MODULES_OWNER OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_VARIABLE ERROR_STR OUTPUT_STRIP_TRAILING_WHITESPACE)
    if(RET)
        message(WARNING "Learning server module user failed (${ERROR_STR}), the current user will be used.")
    endif()
endif()
set(MODULES_OWNER "${MODULES_OWNER}" CACHE STRING "System user that will become the owner of server modules, empty means the current user")
if(NOT MODULES_GROUP AND MODULES_OWNER)
    execute_process(COMMAND id -gn ${MODULES_OWNER} RESULT_VARIABLE RET
    OUTPUT_VARIABLE MODULES_GROUP OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_VARIABLE ERROR_STR OUTPUT_STRIP_TRAILING_WHITESPACE)
    if(RET)
        message(WARNING "Learning server module group failed (${ERROR_STR}), the current user group will be used.")
    endif()
endif()
set(MODULES_GROUP "${MODULES_GROUP}" CACHE STRING "System group that the server modules will belong to, empty means the current user group")

# set prefix for the PID file
if(NOT PIDFILE_PREFIX)
    set(PIDFILE_PREFIX "/var/run")
endif()

set(NP2SRV_SSH_AUTHORIZED_KEYS_PATTERN "%s/.ssh/authorized_keys" CACHE STRING "printf-like pattern for determining path to users' SSH authorized_keys file. Must contain exactly one '%s'.")
set(NP2SRV_SSH_AUTHORIZED_KEYS_ARG_IS_USERNAME 0 CACHE STRING "If true, replace '%s' by username. If not set, replace '%s' by home directory. By default, unset.")
if(NOT NP2SRV_SSH_AUTHORIZED_KEYS_PATTERN MATCHES "^[^%]*%s[^%]*$")
    message(FATAL_ERROR "Wrong format string given for NP2SRV_SSH_AUTHORIZED_KEYS_PATTERN: exactly one '%s' expected.")
endif()

# check that lnc2 supports np2srv thread count
find_package(PkgConfig)
if(PKG_CONFIG_FOUND)
    execute_process(COMMAND ${PKG_CONFIG_EXECUTABLE} "--variable=LNC2_MAX_THREAD_COUNT" "libnetconf2" OUTPUT_VARIABLE LNC2_THREAD_COUNT)
    if(LNC2_THREAD_COUNT)
        string(STRIP ${LNC2_THREAD_COUNT} LNC2_THREAD_COUNT)
        if(LNC2_THREAD_COUNT LESS THREAD_COUNT)
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

# put all binaries into one directory (even from subprojects)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR})

# dependencies - OpenSSL (required by later libnetconf2 checks and not really the server itself)
find_package(OpenSSL)
if(OPENSSL_FOUND)
    list(APPEND CMAKE_REQUIRED_INCLUDES ${OPENSSL_INCLUDE_DIRS})
    list(APPEND CMAKE_REQUIRED_LIBRARIES ${OPENSSL_LIBRARIES})
endif()

# dependencies - libssh (also required by libnetconf2 checks)
find_package(LibSSH 0.7.1)
if(LIBSSH_FOUND)
    list(APPEND CMAKE_REQUIRED_INCLUDES ${LIBSSH_INCLUDE_DIRS})
    list(APPEND CMAKE_REQUIRED_LIBRARIES ${LIBSSH_LIBRARIES})
endif()

# dependencies - libnetconf2 (now, because we need to configure outselves based on it)
find_package(LibNETCONF2 REQUIRED)
include_directories(${LIBNETCONF2_INCLUDE_DIRS})
list(APPEND CMAKE_REQUIRED_INCLUDES ${LIBNETCONF2_INCLUDE_DIRS})
list(APPEND CMAKE_REQUIRED_LIBRARIES ${LIBNETCONF2_LIBRARIES})

# source files
set(SERVER_SRC
    src/common.c
    src/netconf.c
    src/netconf_monitoring.c
    src/netconf_acm.c
    src/netconf_nmda.c
    src/log.c)

# at least some remote transport is enabled
if(LIBNETCONF2_ENABLED_SSH OR LIBNETCONF2_ENABLED_TLS)
    list(APPEND SERVER_SRC src/netconf_server.c)
endif()

# SSH is enabled
if(LIBNETCONF2_ENABLED_SSH)
    list(APPEND SERVER_SRC src/netconf_server_ssh.c)
endif()

# TLS is enabled
if(LIBNETCONF2_ENABLED_TLS)
    list(APPEND SERVER_SRC src/netconf_server_tls.c)
endif()

# link compat
use_compat()

# netopeer2-server
add_library(serverobj OBJECT ${SERVER_SRC})
add_executable(netopeer2-server $<TARGET_OBJECTS:serverobj> src/main.c $<TARGET_OBJECTS:compat>)

# dependencies - libnetconf2 (was already found)
target_link_libraries(netopeer2-server ${LIBNETCONF2_LIBRARIES})

# dependencies - libssh (was already found, if exists)
if(LIBSSH_FOUND AND LIBNETCONF2_ENABLED_SSH)
    target_link_libraries(netopeer2-server ${LIBSSH_LIBRARIES})
    include_directories(${LIBSSH_INCLUDE_DIRS})
endif()

# dependencies - libcurl
if(ENABLE_URL)
    find_package(CURL)
    if(CURL_FOUND)
        include_directories(${CURL_INCLUDE_DIRS})
        target_link_libraries(netopeer2-server ${CURL_LIBRARIES})
        set(NP2SRV_URL_CAPAB 1)
    else()
        message(STATUS "libcurl not found, url capability will not be supported")
        unset(NP2SRV_URL_CAPAB)
    endif()
endif()

# dependencies - pthread
set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
find_package(Threads REQUIRED)
target_link_libraries(netopeer2-server ${CMAKE_THREAD_LIBS_INIT})
list(APPEND CMAKE_REQUIRED_FLAGS ${CMAKE_THREAD_LIBS_INIT})

# dependencies - stdatomic
check_include_file(stdatomic.h HAVE_STDATOMIC)

# dependencies - libyang
find_package(LibYANG REQUIRED)
target_link_libraries(netopeer2-server ${LIBYANG_LIBRARIES})
include_directories(${LIBYANG_INCLUDE_DIRS})
list(APPEND CMAKE_REQUIRED_INCLUDES ${LIBYANG_INCLUDE_DIRS})
list(APPEND CMAKE_REQUIRED_LIBRARIES ${LIBYANG_LIBRARIES})

# dependencies - sysrepo
find_package(Sysrepo REQUIRED)
target_link_libraries(netopeer2-server ${SYSREPO_LIBRARIES})
include_directories(${SYSREPO_INCLUDE_DIRS})
list(APPEND CMAKE_REQUIRED_INCLUDES ${SYSREPO_INCLUDE_DIRS})
list(APPEND CMAKE_REQUIRED_LIBRARIES ${SYSREPO_LIBRARIES})

# generate files
configure_file("${PROJECT_SOURCE_DIR}/src/config.h.in" "${PROJECT_BINARY_DIR}/config.h" ESCAPE_QUOTES @ONLY)
include_directories(${PROJECT_BINARY_DIR})

# set script dir
set(SCRIPT_DIR "${PROJECT_SOURCE_DIR}/scripts/")

# packages
add_subdirectory(packages)

# install the module files
install(DIRECTORY "${PROJECT_SOURCE_DIR}/modules/" DESTINATION ${YANG_MODULE_DIR})

# install the binary, required modules, and default configuration
install(TARGETS netopeer2-server DESTINATION ${CMAKE_INSTALL_BINDIR})
if(INSTALL_MODULES)
    install(CODE "
        message(STATUS \"Installing missing sysrepo modules...\")
        set(ENV{NP2_MODULE_DIR} \"${YANG_MODULE_DIR}\")
        set(ENV{NP2_MODULE_PERMS} \"${MODULES_PERMS}\")
        set(ENV{NP2_MODULE_OWNER} \"${MODULES_OWNER}\")
        set(ENV{NP2_MODULE_GROUP} \"${MODULES_GROUP}\")
        execute_process(COMMAND \"${SCRIPT_DIR}/setup.sh\" RESULT_VARIABLE SETUP_RES)
        if(NOT SETUP_RES EQUAL \"0\")
            message(FATAL_ERROR \" scripts/setup.sh failed: \${SETUP_RES}\")
        endif()
    ")
else()
    message(WARNING "Server will refuse to start if the modules are not installed!")
endif()
if(GENERATE_HOSTKEY)
    install(CODE "
        message(STATUS \"Generating a new RSA host key \\\"genkey\\\" if not already added...\")
        execute_process(COMMAND ${SCRIPT_DIR}/merge_hostkey.sh RESULT_VARIABLE MERGE_HOSTKEY_RES)
        if(NOT MERGE_HOSTKEY_RES EQUAL \"0\")
            message(FATAL_ERROR \" scripts/merge_hostkey.sh failed: \${MERGE_HOSTKEY_RES}\")
        endif()
    ")
endif()
if(MERGE_LISTEN_CONFIG)
    install(CODE "
        message(STATUS \"Merging default server listen configuration if there is none...\")
        execute_process(COMMAND ${SCRIPT_DIR}/merge_config.sh RESULT_VARIABLE MERGE_CONFIG_RES)
        if(NOT MERGE_CONFIG_RES EQUAL \"0\")
            message(FATAL_ERROR \" scripts/merge_config.sh failed: \${MERGE_CONFIG_RES}\")
        endif()
    ")
endif()

# cli
if(BUILD_CLI)
    add_subdirectory(cli)
endif()

# clean cmake cache
add_custom_target(cleancache
    COMMAND make clean
    COMMAND find . -iname '*cmake*' -not -name CMakeLists.txt -exec rm -rf {} +
    COMMAND rm -rf Makefile Doxyfile
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

# uninstall
add_custom_target(uninstall "${CMAKE_COMMAND}" -P "${CMAKE_MODULE_PATH}/uninstall.cmake")
