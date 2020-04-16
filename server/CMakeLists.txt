cmake_minimum_required(VERSION 2.8.9)

# include custom Modules
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/../CMakeModules/")

project(netopeer2-server C)
include(GNUInstallDirs)
include(CheckFunctionExists)
include(CheckIncludeFile)

# check the supported platform
if(NOT UNIX)
    message(FATAL_ERROR "Only *nix like systems are supported.")
endif()

# set default build type if not specified by user
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE debug)
endif()

set(CMAKE_C_FLAGS         "${CMAKE_C_FLAGS} -Wall -Wextra -std=gnu11")
set(CMAKE_C_FLAGS_RELEASE "-O2 -DNDEBUG")
set(CMAKE_C_FLAGS_DEBUG   "-g -O0 -DDEBUG")

# Version of the project
# Generic version of not only the library. Major version is reserved for really big changes of the project,
# minor version changes with added functionality (new tool, functionality of the tool or library, ...) and
# micro version is changed with a set of small changes or bugfixes anywhere in the project.
set(NP2SRV_VERSION 1.1.22)

# build options
if(CMAKE_BUILD_TYPE STREQUAL debug)
    option(ENABLE_BUILD_TESTS "Build tests" ON)
    option(ENABLE_VALGRIND_TESTS "Build tests with valgrind" ON)
else()
    option(ENABLE_BUILD_TESTS "Build tests" OFF)
    option(ENABLE_VALGRIND_TESTS "Build tests with valgrind" OFF)
endif()
option(ENABLE_URL "Enable URL capability" ON)
option(INSTALL_MODULES "Install required modules into sysrepo" ON)
option(GENERATE_HOSTKEY "Generate a new RSA host key in the keystore named \"genkey\"" ON)
option(MERGE_LISTEN_CONFIG "Merge default server configuration for listening on all IPv4 interfaces" ON)
set(DEFAULT_HOSTKEY "genkey" CACHE STRING "Name of the hostkey from the keystore used in default listen configuration")
set(THREAD_COUNT 5 CACHE STRING "Number of threads accepting new sessions and handling requests")
set(MODULES_OWNER "$ENV{USER}" CACHE STRING "User that will become the owner of server modules")
set(NACM_RECOVERY_UID 0 CACHE STRING "NACM recovery session UID that has unrestricted access")
set(DATA_CHANGE_TIMEOUT 5 CACHE STRING "Timeout in seconds of any (sysrepo) data changes, 0 is the default sysrepo timeout")
set(RPC_TIMEOUT 6 CACHE STRING "Timeout in seconds of the global RPC callback, that calls all the other specific RPC callbacks. This timeout should always be higher than that of other RPCs")
option(DATA_CHANGE_WAIT "Whether to wait for all events on any (sysrepo) data changes" OFF)
if(DATA_CHANGE_WAIT)
    set(DATA_CHANGE_WAIT_BOOL 1)
else()
    set(DATA_CHANGE_WAIT_BOOL 0)
endif()
if(NOT RPC_TIMEOUT GREATER DATA_CHANGE_TIMEOUT)
    message(FATAL_ERROR "RPC timeout must be longer than data change timeout.")
endif()

# set prefix for the PID file
if(NOT PIDFILE_PREFIX)
    set(PIDFILE_PREFIX "/var/run")
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

# source files
set(srcs
    common.c
    netconf.c
    netconf_monitoring.c
    netconf_server.c
    netconf_server_ssh.c
    netconf_server_tls.c
    netconf_acm.c
    netconf_nmda.c
    log.c)

# object library to build source codes only once for the main binary
add_library(serverobj OBJECT ${srcs})

# netopeer2-server target
add_executable(netopeer2-server $<TARGET_OBJECTS:serverobj> main.c)

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

# dependencies - libssh
find_package(LibSSH 0.7.0 REQUIRED)
if(LibSSH_VERSION VERSION_LESS 0.8.0)
    target_link_libraries(netopeer2-server "-L${LIBSSH_LIBRARY_DIR}" -lssh -lssh_threads -lcrypt)
    list(APPEND CMAKE_REQUIRED_FLAGS "-L${LIBSSH_LIBRARY_DIR}")
    list(APPEND CMAKE_REQUIRED_LIBRARIES ssh crypt)
else()
    target_link_libraries(netopeer2-server ${LIBSSH_LIBRARIES} -lcrypt)
    list(APPEND CMAKE_REQUIRED_LIBRARIES ${LIBSSH_LIBRARIES} crypt)
endif()
include_directories(${LIBSSH_INCLUDE_DIRS})
list(APPEND CMAKE_REQUIRED_INCLUDES ${LIBSSH_INCLUDE_DIRS})

# dependencies - libyang
find_package(LibYANG REQUIRED)
target_link_libraries(netopeer2-server ${LIBYANG_LIBRARIES})
include_directories(${LIBYANG_INCLUDE_DIRS})
list(APPEND CMAKE_REQUIRED_INCLUDES ${LIBYANG_INCLUDE_DIRS})
list(APPEND CMAKE_REQUIRED_LIBRARIES ${LIBYANG_LIBRARIES})

# dependencies - libnetconf2
find_package(LibNETCONF2 REQUIRED)
if(NOT LIBNETCONF2_ENABLED_SSH)
    message(FATAL_ERROR "Missing SSH support in libnetconf2, server requires SSH to be supported.")
endif()
target_link_libraries(netopeer2-server ${LIBNETCONF2_LIBRARIES})
include_directories(${LIBNETCONF2_INCLUDE_DIRS})
list(APPEND CMAKE_REQUIRED_INCLUDES ${LIBNETCONF2_INCLUDE_DIRS})
list(APPEND CMAKE_REQUIRED_LIBRARIES ${LIBNETCONF2_LIBRARIES})

# dependencies - sysrepo
find_package(SYSREPO REQUIRED)
target_link_libraries(netopeer2-server ${SYSREPO_LIBRARIES})
include_directories(${SYSREPO_INCLUDE_DIRS})
find_program(SYSREPOCTL "sysrepoctl")
if(SYSREPOCTL-NOTFOUND)
    message(FATAL_ERROR "sysrepoctl utility not found.")
endif()
find_program(SYSREPOCFG "sysrepocfg")
if(SYSREPOCFG-NOTFOUND)
    message(FATAL_ERROR "sysrepocfg utility not found.")
endif()

# dependencies - openssl utility
if(GENERATE_HOSTKEY)
    find_program(OPENSSL "openssl")
    if(OPENSSL-NOTFOUND)
        message(FATAL_ERROR "openssl utility not found.")
    endif()
endif()

# install the binary, required modules, and default configuration
install(TARGETS netopeer2-server DESTINATION ${CMAKE_INSTALL_BINDIR})
if(INSTALL_MODULES)
    install(CODE "
        message(STATUS \"Installing sysrepo modules...\")
        execute_process(COMMAND ${PROJECT_SOURCE_DIR}/setup.sh ${SYSREPOCTL} ${PROJECT_SOURCE_DIR}/../modules ${MODULES_OWNER})
        execute_process(COMMAND ${SYSREPOCTL} -C RESULT_VARIABLE RET OUTPUT_VARIABLE OUT ERROR_VARIABLE ERR
                OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_STRIP_TRAILING_WHITESPACE)
        if(\${RET})
            message(FATAL_ERROR \"sysrepoctl failed: \${ERR}\")
        elseif(\${OUT} GREATER \"0\")
            message(WARNING \"There are some sysrepo connections, module changes could not be applied now!\")
        endif()
    ")
else()
    message(WARNING "Server will refuse to start if the modules are not installed!")
endif()
if(GENERATE_HOSTKEY)
    install(CODE "
        message(STATUS \"Generating a new RSA host key \\\"genkey\\\"...\")
        execute_process(COMMAND ${PROJECT_SOURCE_DIR}/merge_hostkey.sh ${SYSREPOCFG} ${OPENSSL})
    ")
endif()
if(MERGE_LISTEN_CONFIG)
    install(CODE "
        message(STATUS \"Merging default server listen configuration...\")
        execute_process(COMMAND ${PROJECT_SOURCE_DIR}/merge_config.sh ${SYSREPOCFG} ${DEFAULT_HOSTKEY})
    ")
endif()

configure_file("${PROJECT_SOURCE_DIR}/config.h.in" "${PROJECT_BINARY_DIR}/config.h" ESCAPE_QUOTES @ONLY)
include_directories(${PROJECT_BINARY_DIR})

# clean cmake cache
add_custom_target(cleancache
    COMMAND make clean
    COMMAND find . -iname '*cmake*' -not -name CMakeLists.txt -exec rm -rf {} +
    COMMAND rm -rf Makefile Doxyfile
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

# uninstall
add_custom_target(uninstall "${CMAKE_COMMAND}" -P "${CMAKE_MODULE_PATH}/uninstall.cmake")
