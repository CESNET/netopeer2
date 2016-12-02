cmake_minimum_required(VERSION 2.6)

# include custom Modules
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/../CMakeModules/")

project(keystored C)
include(GNUInstallDirs)

# check the supported platform
if(NOT UNIX)
    message(FATAL_ERROR "Only *nix like systems are supported.")
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O0 -DDEBUG -Wall -Wextra")

# config variables
if (NOT KEYSTORED_KEYS_DIR)
    set(KEYSTORED_KEYS_DIR "${CMAKE_INSTALL_PREFIX}/etc/keystored/keys")
endif()
if (NOT OPENSSL_EXECUTABLE)
    find_program(OPENSSL_EXECUTABLE openssl)
    if (NOT OPENSSL_EXECUTABLE)
        message(FATAL_ERROR "openssl utility not found.")
    endif()
endif()

configure_file("${PROJECT_SOURCE_DIR}/config.h.in" "${PROJECT_SOURCE_DIR}/config.h" ESCAPE_QUOTES @ONLY)

# keystored plugin
add_library(keystored SHARED keystored.c)

# pkgconfig keys directory
find_package(PkgConfig)
if (PKG_CONFIG_FOUND)
    # generate and install pkg-config file
    configure_file("keystored.pc.in" "keystored.pc" @ONLY)
    install(FILES "${CMAKE_CURRENT_BINARY_DIR}/keystored.pc" DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig")
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

# create the keys directory with correct permissions
install(DIRECTORY DESTINATION ${KEYSTORED_KEYS_DIR}
        DIRECTORY_PERMISSIONS OWNER_WRITE OWNER_READ OWNER_EXECUTE)

# install all the required modules and enable features
install(CODE "
    execute_process(COMMAND ${SYSREPOCTL_EXECUTABLE} -l RESULT_VARIABLE RET OUTPUT_VARIABLE INSTALLED_MODULES ERROR_VARIABLE OUT)
    if (RET)
        string(REPLACE \"\n\" \"\n  \" OUT \${OUT})
        message(FATAL_ERROR \"  Command sysrepoctl list failed:\n  \${OUT}\")
    endif()

    string(REGEX MATCH \"ietf-keystore [^\n]*\" INSTALLED_MODULE_LINE \"\${INSTALLED_MODULES}\")
    if (NOT INSTALLED_MODULE_LINE)
        message(STATUS \"Importing module ietf-keystore into sysrepo...\")
        execute_process(COMMAND ${SYSREPOCTL_EXECUTABLE} -i -g ${CMAKE_SOURCE_DIR}/../modules/ietf-keystore.yang -o root:root -p 600 RESULT_VARIABLE RET OUTPUT_VARIABLE OUT ERROR_VARIABLE OUT)
        if (RET)
            string(REPLACE \"\n\" \"\n  \" OUT \${OUT})
            message(FATAL_ERROR \"  Command sysrepoctl install failed:\n  \${OUT}\")
        endif()

        execute_process(COMMAND ${SYSREPOCTL_EXECUTABLE} -m ietf-keystore -t RESULT_VARIABLE RET OUTPUT_VARIABLE OUT ERROR_VARIABLE OUT)
        if (RET)
            string(REPLACE \"\n\" \"\n  \" OUT \${OUT})
            message(FATAL_ERROR \"  Command sysrepoctl init failed:\n  \${OUT}\")
        endif()

    else()
        message(STATUS \"Module ietf-keystore already in sysrepo.\")
    endif()")

# import stock OpenSSH RSA key
install(CODE "
    execute_process(COMMAND ${SYSREPOCFG_EXECUTABLE} -d startup --export ietf-keystore RESULT_VARIABLE RET OUTPUT_VARIABLE OUT ERROR_VARIABLE OUT)
    if (RET)
        string(REPLACE \"\n\" \"\n  \" OUT \${OUT})
        message(FATAL_ERROR \"  Command sysrepocfg export failed:\n  \${OUT}\")
    endif()

    if (OUT)
        message(STATUS \"Some ietf-keystore configuration set, no keys will be imported.\")
    else()
        message(STATUS \"Importing stock OpenSSH RSA key.\")
        file(READ /etc/ssh/ssh_host_rsa_key RSA_KEY)
        file(WRITE ${KEYSTORED_KEYS_DIR}/ssh_host_rsa_key.pem \${RSA_KEY})
        execute_process(COMMAND ${CHMOD_EXECUTABLE} go-rw ${KEYSTORED_KEYS_DIR}/ssh_host_rsa_key.pem)
        execute_process(COMMAND ${OPENSSL_EXECUTABLE} rsa -pubout -in ${KEYSTORED_KEYS_DIR}/ssh_host_rsa_key.pem -out ${KEYSTORED_KEYS_DIR}/ssh_host_rsa_key.pub.pem RESULT_VARIABLE RET OUTPUT_VARIABLE OUT ERROR_VARIABLE OUT)
        if (RET)
            string(REPLACE \"\n\" \"\n  \" OUT \${OUT})
            message(FATAL_ERROR \"  Command openssl generate public key failed:\n  \${OUT}\")
        endif()
        execute_process(COMMAND ${SYSREPOCFG_EXECUTABLE} -d startup -i ${CMAKE_SOURCE_DIR}/stock_key_config.xml ietf-keystore RESULT_VARIABLE RET OUTPUT_VARIABLE OUT ERROR_VARIABLE OUT)
        if (RET)
            string(REPLACE \"\n\" \"\n  \" OUT \${OUT})
            message(FATAL_ERROR \"  Command sysrepocfg import failed:\n  \${OUT}\")
        endif()
    endif()")

# plugins should be installed into sysrepo plugins dir
install(TARGETS keystored DESTINATION ${SR_PLUGINS_DIR})
