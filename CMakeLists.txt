cmake_minimum_required(VERSION 3.5)

project(netopeer2 C)
set(NETOPEER2_DESC "NETCONF tools suite including a server and command-line client")

# include custom Modules
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/CMakeModules/")

include(GNUInstallDirs)
include(CheckFunctionExists)
include(CheckIncludeFile)
include(UseCompat)
include(SourceFormat)
include(GenCoverage)
if(POLICY CMP0028)
    cmake_policy(SET CMP0028 NEW)
endif()
if(POLICY CMP0075)
    cmake_policy(SET CMP0075 NEW)
endif()

# set default build type if not specified by user and normalize it
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()
string(TOUPPER "${CMAKE_BUILD_TYPE}" BUILD_TYPE_UPPER)
# see https://github.com/CESNET/libyang/pull/1692 for why CMAKE_C_FLAGS_<type> are not used directly
if("${BUILD_TYPE_UPPER}" STREQUAL "RELEASE")
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build Type" FORCE)
    set(CMAKE_C_FLAGS "-DNDEBUG -O2 ${CMAKE_C_FLAGS}")
elseif("${BUILD_TYPE_UPPER}" STREQUAL "DEBUG")
    set(CMAKE_BUILD_TYPE "Debug" CACHE STRING "Build Type" FORCE)
    set(CMAKE_C_FLAGS "-g -O0 ${CMAKE_C_FLAGS}")
elseif("${BUILD_TYPE_UPPER}" STREQUAL "RELWITHDEBINFO")
    set(CMAKE_BUILD_TYPE "RelWithDebInfo" CACHE STRING "Build Type" FORCE)
elseif("${BUILD_TYPE_UPPER}" STREQUAL "RELWITHDEBUG")
    set(CMAKE_BUILD_TYPE "RelWithDebug" CACHE STRING "Build Type" FORCE)
endif()

# check the supported platform
if(NOT UNIX)
    message(FATAL_ERROR "Only *nix like systems are supported.")
endif()

# Version of the project
# Generic version of not only the library. Major version is reserved for really big changes of the project,
# minor version changes with added functionality (new tool, functionality of the tool or library, ...) and
# micro version is changed with a set of small changes or bugfixes anywhere in the project.
set(NP2SRV_VERSION 2.2.8)

# libyang required version
set(LIBYANG_DEP_VERSION 2.1.142)
set(LIBYANG_DEP_SOVERSION 2.45.6)
set(LIBYANG_DEP_SOVERSION_MAJOR 2)

# libnetconf2 required version
set(LIBNETCONF2_DEP_VERSION 3.0.6)
set(LIBNETCONF2_DEP_SOVERSION 4.1.3)
set(LIBNETCONF2_DEP_SOVERSION_MAJOR 4)

# sysrepo required version
set(SYSREPO_DEP_VERSION 2.2.111)
set(SYSREPO_DEP_SOVERSION 7.19.7)
set(SYSREPO_DEP_SOVERSION_MAJOR 7)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -std=c99")

#
# options
#
option(ENABLE_TESTS "Build tests" ON)
if(("${BUILD_TYPE_UPPER}" STREQUAL "DEBUG") OR ("${BUILD_TYPE_UPPER}" STREQUAL "RELWITHDEBINFO"))
    option(ENABLE_VALGRIND_TESTS "Build tests with valgrind" ON)
else()
    option(ENABLE_VALGRIND_TESTS "Build tests with valgrind" OFF)
endif()
option(ENABLE_COVERAGE "Build code coverage report from tests" OFF)
option(BUILD_CLI "Build and install neotpeer2-cli" ON)
option(ENABLE_URL "Enable URL capability" ON)
set(THREAD_COUNT 3 CACHE STRING "Number of threads accepting new sessions and handling requests")
set(POLL_IO_TIMEOUT 10 CACHE STRING "Timeout in milliseconds of polling sessions for new data. It is also used for synchronization of low level IO such as sending a reply while a notification is being sent")
set(YANG_MODULE_DIR "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_DATADIR}/yang/modules/netopeer2" CACHE STRING "Directory where to copy the YANG modules to")
set(DATA_DIR "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_DATADIR}/netopeer2" CACHE STRING "Directory with shared netopeer2 data")

# script options
option(SYSREPO_SETUP "Install required modules with their default configuration into sysrepo" ON)
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

if(NOT SERVER_DIR)
    if("${BUILD_TYPE_UPPER}" STREQUAL "DEBUG")
        set(SERVER_DIR "$ENV{HOME}/.netopeer2-server")
    else()
        set(SERVER_DIR "/var/netopeer2")
    endif()
endif()

#
# sources
#
set(SERVER_SRC
    src/common.c
    src/netconf.c
    src/netconf_monitoring.c
    src/netconf_nmda.c
    src/netconf_subscribed_notifications.c
    src/netconf_confirmed_commit.c
    src/subscribed_notifications.c
    src/yang_push.c
    src/log.c
    src/err_netconf.c)

# source files to be covered by the 'format' target
set(FORMAT_SRC
    compat/*.c
    compat/*.h*
    src/*.c
    src/*.h
    cli/*.c
    cli/*.h
    tests/*.c
    tests/*.h)

#
# checks
#

# PKGCONFIG {

find_package(PkgConfig REQUIRED)

# find libnetconf2 pkg
pkg_check_modules(PKG_LN2 REQUIRED libnetconf2)

# libnetconf2 thread count check
pkg_get_variable(LN2_THREAD_COUNT libnetconf2 "LN2_MAX_THREAD_COUNT")
if(LN2_THREAD_COUNT)
    if(LN2_THREAD_COUNT LESS THREAD_COUNT)
        message(FATAL_ERROR "libnetconf2 was compiled with support up to ${LN2_THREAD_COUNT} threads, server is configured with ${THREAD_COUNT}.")
    else()
        message(STATUS "libnetconf2 was compiled with support of up to ${LN2_THREAD_COUNT} threads")
    endif()
else()
    message(STATUS "Unable to learn libnetconf2 thread support, check skipped")
endif()

# get libnetconf2 module directory, use it later when installing modules
pkg_get_variable(LN2_YANG_MODULE_DIR libnetconf2 "LN2_SCHEMAS_DIR")
if(NOT LN2_YANG_MODULE_DIR)
    message(FATAL_ERROR "Unable to learn libnetconf2 module search directory.")
endif()

# find sysrepo pkg and get sysrepo group
pkg_check_modules(PKG_SR REQUIRED sysrepo)
pkg_get_variable(SR_GROUP sysrepo "SR_GROUP")

# } PKGCONFIG

if(ENABLE_VALGRIND_TESTS)
    find_program(VALGRIND_FOUND valgrind)
    if(NOT VALGRIND_FOUND)
        message(WARNING "valgrind executable not found! Disabling memory leaks tests.")
        set(ENABLE_VALGRIND_TESTS OFF)
    else()
        set(ENABLE_TESTS ON)
    endif()
endif()

if(ENABLE_TESTS)
    find_package(CMocka 1.0.1)
    if(NOT CMOCKA_FOUND)
        message(STATUS "Disabling tests because of missing CMocka")
        set(ENABLE_TESTS OFF)
    endif()
endif()

if(ENABLE_COVERAGE)
    gen_coverage_enable(${ENABLE_TESTS})
endif()

if ("${BUILD_TYPE_UPPER}" STREQUAL "DEBUG")
    source_format_enable(0.77)
endif()

#
# targets
#

# put all binaries into one directory (even from subprojects)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR})

# dependencies - OpenSSL (required by later libnetconf2 checks and not really the server itself)
find_package(OpenSSL 3.0.0)
if(OPENSSL_FOUND)
    list(APPEND CMAKE_REQUIRED_INCLUDES ${OPENSSL_INCLUDE_DIR})
    list(APPEND CMAKE_REQUIRED_LIBRARIES ${OPENSSL_LIBRARIES})
endif()

# dependencies - libssh (also required by libnetconf2 checks)
find_package(LibSSH 0.9.5)
if(LIBSSH_FOUND)
    list(APPEND CMAKE_REQUIRED_INCLUDES ${LIBSSH_INCLUDE_DIRS})
    list(APPEND CMAKE_REQUIRED_LIBRARIES ${LIBSSH_LIBRARIES})
endif()

# dependencies - libnetconf2 (now, because we need to configure outselves based on it)
find_package(LibNETCONF2 ${LIBNETCONF2_DEP_SOVERSION} REQUIRED)
include_directories(${LIBNETCONF2_INCLUDE_DIRS})
list(APPEND CMAKE_REQUIRED_INCLUDES ${LIBNETCONF2_INCLUDE_DIRS})
list(APPEND CMAKE_REQUIRED_LIBRARIES ${LIBNETCONF2_LIBRARIES})

# link compat
use_compat()

# netopeer2-server
add_library(serverobj OBJECT ${SERVER_SRC})
add_executable(netopeer2-server $<TARGET_OBJECTS:serverobj> src/main.c ${compatsrc})

#
# dependencies
#

# librt (not required on OSX or QNX)
find_library(LIBRT rt)
if(LIBRT)
    target_link_libraries(netopeer2-server ${LIBRT})
endif()

# libnetconf2 (was already found)
target_link_libraries(netopeer2-server ${LIBNETCONF2_LIBRARIES})

# libssh (was already found, if exists)
if(LIBSSH_FOUND AND LIBNETCONF2_ENABLED_SSH_TLS)
    target_link_libraries(netopeer2-server ${LIBSSH_LIBRARIES})
    include_directories(${LIBSSH_INCLUDE_DIRS})
endif()

# libcurl
if(ENABLE_URL)
    find_package(CURL)
    if(CURL_FOUND)
        include_directories(${CURL_INCLUDE_DIRS})
        if(TARGET CURL::libcurl)
            target_link_libraries(netopeer2-server CURL::libcurl)
        else()
            target_link_libraries(netopeer2-server ${CURL_LIBRARIES})
        endif()
        set(NP2SRV_URL_CAPAB 1)
    else()
        message(STATUS "libcurl not found, url capability will not be supported")
        unset(NP2SRV_URL_CAPAB)
    endif()
endif()

# libsystemd
if(NOT PKG_CONFIG_FOUND AND NOT SYSTEMD_UNIT_DIR)
    set(SYSTEMD_UNIT_DIR "/usr/lib/systemd/system")
endif()
find_package(LibSystemd)
if(LIBSYSTEMD_FOUND)
    set(NP2SRV_HAVE_SYSTEMD 1)
    target_link_libraries(netopeer2-server ${LIBSYSTEMD_LIBRARIES})
    include_directories(${LIBSYSTEMD_INCLUDE_DIRS})
    message(STATUS "systemd system service unit path: ${SYSTEMD_UNIT_DIR}")
else()
    message(WARNING "Disabling netopeer2-server systemd support because libsystemd was not found.")
endif()

# pthread
set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
find_package(Threads REQUIRED)
target_link_libraries(netopeer2-server ${CMAKE_THREAD_LIBS_INIT})
list(APPEND CMAKE_REQUIRED_FLAGS ${CMAKE_THREAD_LIBS_INIT})

# libyang
find_package(LibYANG ${LIBYANG_DEP_SOVERSION} REQUIRED)
target_link_libraries(netopeer2-server ${LIBYANG_LIBRARIES})
include_directories(${LIBYANG_INCLUDE_DIRS})
list(APPEND CMAKE_REQUIRED_INCLUDES ${LIBYANG_INCLUDE_DIRS})
list(APPEND CMAKE_REQUIRED_LIBRARIES ${LIBYANG_LIBRARIES})

# sysrepo
find_package(Sysrepo ${SYSREPO_DEP_SOVERSION} REQUIRED)
target_link_libraries(netopeer2-server ${SYSREPO_LIBRARIES})
include_directories(${SYSREPO_INCLUDE_DIRS})
list(APPEND CMAKE_REQUIRED_INCLUDES ${SYSREPO_INCLUDE_DIRS})
list(APPEND CMAKE_REQUIRED_LIBRARIES ${SYSREPO_LIBRARIES})

if(SYSREPO_SETUP)
    # find sysrepoctl to be used for installation and tests
    if (NOT SYSREPOCTL_EXECUTABLE)
        find_program(SYSREPOCTL_EXECUTABLE sysrepoctl)
    endif()
    if (NOT SYSREPOCTL_EXECUTABLE)
        message(FATAL_ERROR "Unable to find sysrepoctl, set SYSREPOCTL_EXECUTABLE manually.")
    endif()

    # find sysrepocfg to be used for installation and tests
    if (NOT SYSREPOCFG_EXECUTABLE)
        find_program(SYSREPOCFG_EXECUTABLE sysrepocfg)
    endif()
    if (NOT SYSREPOCFG_EXECUTABLE)
        message(FATAL_ERROR "Unable to find sysrepocfg, set SYSREPOCFG_EXECUTABLE manually.")
    endif()
endif()

# generate files
configure_file("${PROJECT_SOURCE_DIR}/src/config.h.in" "${PROJECT_BINARY_DIR}/config.h" ESCAPE_QUOTES @ONLY)
configure_file("${PROJECT_SOURCE_DIR}/service/netopeer2-server.service.in" "${PROJECT_BINARY_DIR}/netopeer2-server.service" @ONLY)
include_directories(${PROJECT_BINARY_DIR})

# install the modules and scripts
install(DIRECTORY "${PROJECT_SOURCE_DIR}/modules/" DESTINATION ${YANG_MODULE_DIR})
install(DIRECTORY "${PROJECT_SOURCE_DIR}/scripts/" DESTINATION ${DATA_DIR}/scripts USE_SOURCE_PERMISSIONS)

# install the binary, required modules, and default configuration
install(TARGETS netopeer2-server DESTINATION ${CMAKE_INSTALL_SBINDIR})
install(FILES ${PROJECT_SOURCE_DIR}/doc/netopeer2-server.8 DESTINATION ${CMAKE_INSTALL_MANDIR}/man8)
if(NP2SRV_HAVE_SYSTEMD)
    install(FILES ${PROJECT_BINARY_DIR}/netopeer2-server.service DESTINATION ${SYSTEMD_UNIT_DIR})
endif()

# copy pam service to /etc/pam.d
if(EXISTS "/etc/pam.d")
    install(FILES "${CMAKE_SOURCE_DIR}/pam/netopeer2.conf" DESTINATION "/etc/pam.d")
endif()

if(SYSREPO_SETUP)
    install(CODE "
        message(STATUS \"Installing missing sysrepo modules...\")
        set(ENV{NP2_MODULE_DIR} \"${YANG_MODULE_DIR}\")
        set(ENV{NP2_MODULE_PERMS} \"${MODULES_PERMS}\")
        set(ENV{NP2_MODULE_OWNER} \"${MODULES_OWNER}\")
        set(ENV{NP2_MODULE_GROUP} \"${MODULES_GROUP}\")
        set(ENV{LN2_MODULE_DIR} \"${LN2_YANG_MODULE_DIR}\")
        set(ENV{SYSREPOCTL_EXECUTABLE} \"${SYSREPOCTL_EXECUTABLE}\")
        set(ENV{SYSREPOCFG_EXECUTABLE} \"${SYSREPOCFG_EXECUTABLE}\")
        execute_process(COMMAND \"\$ENV{DESTDIR}${DATA_DIR}/scripts/setup.sh\" RESULT_VARIABLE SETUP_RES)
        if(NOT SETUP_RES EQUAL \"0\")
            message(FATAL_ERROR \" scripts/setup.sh failed: \${SETUP_RES}\")
        endif()
    ")

    # generate hostkey
    install(CODE "
        message(STATUS \"Generating a new RSA host key \\\"genkey\\\" if not already added...\")
        set(ENV{SYSREPOCTL_EXECUTABLE} \"${SYSREPOCTL_EXECUTABLE}\")
        set(ENV{SYSREPOCFG_EXECUTABLE} \"${SYSREPOCFG_EXECUTABLE}\")
        execute_process(COMMAND \"\$ENV{DESTDIR}${DATA_DIR}/scripts/merge_hostkey.sh\" RESULT_VARIABLE MERGE_HOSTKEY_RES)
        if(NOT MERGE_HOSTKEY_RES EQUAL \"0\")
            message(FATAL_ERROR \" scripts/merge_hostkey.sh failed: \${MERGE_HOSTKEY_RES}\")
        endif()
    ")

    # merge listen config
    install(CODE "
        message(STATUS \"Merging default server listen configuration if there is none...\")
        set(ENV{SYSREPOCTL_EXECUTABLE} \"${SYSREPOCTL_EXECUTABLE}\")
        set(ENV{SYSREPOCFG_EXECUTABLE} \"${SYSREPOCFG_EXECUTABLE}\")
        execute_process(COMMAND \"\$ENV{DESTDIR}${DATA_DIR}/scripts/merge_config.sh\" RESULT_VARIABLE MERGE_CONFIG_RES)
        if(NOT MERGE_CONFIG_RES EQUAL \"0\")
            message(FATAL_ERROR \" scripts/merge_config.sh failed: \${MERGE_CONFIG_RES}\")
        endif()
    ")
else()
    message(WARNING "Server will refuse to start if the modules are not installed!")
endif()

# tests
if(ENABLE_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# create coverage target for generating coverage reports
gen_coverage("test_.*" "test_.*_valgrind")

# cli
if(BUILD_CLI)
    add_subdirectory(cli)
endif()

# source files to be covered by the 'format' target and a test with 'format-check' target
source_format(${FORMAT_SRC})

# clean cmake cache
add_custom_target(cleancache
    COMMAND make clean
    COMMAND find . -iname '*cmake*' -not -name CMakeLists.txt -exec rm -rf {} +
    COMMAND rm -rf Makefile Doxyfile
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

# uninstall
add_custom_target(uninstall ${DATA_DIR}/scripts/remove.sh
    COMMAND "${CMAKE_COMMAND}" -P "${CMAKE_MODULE_PATH}/uninstall.cmake"
    COMMENT "Removing netopeer2 modules from sysrepo..."
)
