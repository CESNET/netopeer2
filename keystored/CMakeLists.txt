cmake_minimum_required(VERSION 2.6)

# include custom Modules
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/../CMakeModules/")

project(keystored C)
include(GNUInstallDirs)

# check the supported platform
if(NOT UNIX)
    message(FATAL_ERROR "Only *nix like systems are supported.")
endif()

# set default build type if not specified by user
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE debug)
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra")
set(CMAKE_C_FLAGS_RELEASE "-O2 -DNDEBUG")
set(CMAKE_C_FLAGS_DEBUG   "-g -O0 -DDEBUG")

# set version
set(KEYSTORED_VERSION 0.1.1)

# config variables
if (NOT KEYSTORED_KEYS_DIR)
    set(KEYSTORED_KEYS_DIR "${CMAKE_INSTALL_FULL_SYSCONFDIR}/keystored/keys")
endif()
if (NOT OPENSSL_EXECUTABLE)
    find_program(OPENSSL_EXECUTABLE openssl)
    if (NOT OPENSSL_EXECUTABLE)
        message(FATAL_ERROR "openssl utility not found.")
    endif()
endif()

configure_file("${PROJECT_SOURCE_DIR}/config.h.in" "${PROJECT_BINARY_DIR}/config.h" ESCAPE_QUOTES @ONLY)
include_directories(${PROJECT_BINARY_DIR})

# keystored plugin
add_library(keystored SHARED keystored.c)

# pkgconfig keys directory
find_package(PkgConfig)
if (PKG_CONFIG_FOUND)
    # generate and install pkg-config file
    configure_file("keystored.pc.in" "keystored.pc" @ONLY)
    install(FILES "${CMAKE_CURRENT_BINARY_DIR}/keystored.pc" DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig")
    execute_process(COMMAND ${PKG_CONFIG_EXECUTABLE} "--variable=pc_path" "pkg-config" RESULT_VARIABLE RET OUTPUT_VARIABLE OUT)
    if (RET)
        message(WARNING "Failed to check pkg-config search directories.")
        message(WARNING "For netopeer2-server configuration to work, pkg-config search path must include \"${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}/pkgconfig\" or you keystored keys directory will have to be set manually to \"${KEYSTORED_KEYS_DIR}\".")
    else()
        string(REGEX MATCH "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}/pkgconfig" MATCHED "${OUT}")
        if (MATCHED)
            message(STATUS "pkg-config check successful, netopeer2-server configuration should work after installation")
        else()
            message(WARNING "keystored pkg-config file copied into a directory not searched by pkg-config.")
            message(WARNING "For netopeer2-server configuration to work, pkg-config search path must include \"${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}/pkgconfig\" or keystored keys directory will have to be set manually to \"${KEYSTORED_KEYS_DIR}\".")
        endif()
    endif()
else()
    message(WARNING "pkg-config not detected.")
    message(WARNING "For netopeer2-server configuration to work, keystored keys directory will have to be set manually to \"${KEYSTORED_KEYS_DIR}\".")
endif()

# dependencies - sysrepo
find_package(SYSREPO REQUIRED)
target_link_libraries(keystored ${SYSREPO_LIBRARIES})
include_directories(${SYSREPO_INCLUDE_DIRS})

# get sysrepo plugins directory
if (NOT SR_PLUGINS_DIR)
    if (PKG_CONFIG_FOUND)
        execute_process(COMMAND ${PKG_CONFIG_EXECUTABLE} "--variable=SR_PLUGINS_DIR" "libsysrepo" OUTPUT_VARIABLE SR_PLUGINS_DIR)
        string(STRIP ${SR_PLUGINS_DIR} SR_PLUGINS_DIR)
    endif()
endif()
if (NOT SR_PLUGINS_DIR)
    message(FATAL_ERROR "Cannot get sysrepo plugins directory due to missing pkg-config, set SR_PLUGINS_DIR manually.")
endif()

# find programs
if (NOT SYSREPOCTL_EXECUTABLE)
    find_program(SYSREPOCTL_EXECUTABLE sysrepoctl)
endif()
if (NOT SYSREPOCTL_EXECUTABLE)
    message(FATAL_ERROR "Unable to find sysrepoctl, set SYSREPOCTL_EXECUTABLE manually.")
endif()

if (NOT SYSREPOCFG_EXECUTABLE)
    find_program(SYSREPOCFG_EXECUTABLE sysrepocfg)
endif()
if (NOT SYSREPOCFG_EXECUTABLE)
    message(FATAL_ERROR "Unable to find sysrepocfg, set SYSREPOCFG_EXECUTABLE manually.")
endif()

if (NOT CHMOD_EXECUTABLE)
    find_program(CHMOD_EXECUTABLE chmod)
endif()
if (NOT CHMOD_EXECUTABLE)
    message(FATAL_ERROR "Unable to find chmod, set CHMOD_EXECUTABLE manually.")
endif()

# Command line options to be passed to `sysrepoctl` when working with modules
# which should only be accessible by an administrator
if (NOT SYSREPOCTL_ROOT_PERMS)
    set(SYSREPOCTL_ROOT_PERMS "-o root:root -p 600")
endif()

# create the keys directory with correct permissions
install(DIRECTORY DESTINATION ${KEYSTORED_KEYS_DIR}
        DIRECTORY_PERMISSIONS OWNER_WRITE OWNER_READ OWNER_EXECUTE)

option(MODEL_INSTALL "Enable yang model installation" ON)
if (MODEL_INSTALL)
    install(CODE "
        set(ENV{SYSREPOCTL} ${SYSREPOCTL_EXECUTABLE})
        set(ENV{SYSREPOCTL_ROOT_PERMS} SYSREPOCTL_ROOT_PERMS)
        execute_process(COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/scripts/model-install.sh)")
endif()

option(SSH_KEY_INSTALL "Enable ssh key import" ON)
if (SSH_KEY_INSTALL)
    install(CODE "
        set(ENV{SYSREPOCFG} ${SYSREPOCFG_EXECUTABLE})
        set(ENV{CHMOD} ${CHMOD_EXECUTABLE})
        set(ENV{OPENSSL} ${OPENSSL_EXECUTABLE})
        set(ENV{KEYSTORED_KEYS_DIR} ${KEYSTORED_KEYS_DIR})
        execute_process(COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/scripts/ssh-key-import.sh)")
endif()

# plugins should be installed into sysrepo plugins dir
install(TARGETS keystored DESTINATION ${SR_PLUGINS_DIR})
