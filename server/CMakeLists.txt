cmake_minimum_required(VERSION 2.6)

# include custom Modules
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/../CMakeModules/")

project(netopeer2-server C)

# check the supported platform
if(NOT UNIX)
	message(FATAL_ERROR "Only *nix like systems are supported.")
endif()

# set default build type if not specified by user
if(NOT CMAKE_BUILD_TYPE)
	set(CMAKE_BUILD_TYPE debug)
endif()

set(CMAKE_C_FLAGS         "${CMAKE_C_FLAGS} -Wall -Wextra")
set(CMAKE_C_FLAGS_RELEASE "-O2")
set(CMAKE_C_FLAGS_DEBUG   "-g -O0")

# set version
set(NP2SRV_VERSION 0.1.5)

# set prefix for the PID file
if (NOT PIDFILE_PREFIX)
	set(PIDFILE_PREFIX "/var/run")
endif()

configure_file("${PROJECT_SOURCE_DIR}/config.h.in" "${PROJECT_SOURCE_DIR}/config.h" ESCAPE_QUOTES @ONLY)

# source files
set(srcs
	main.c
	operations.c
	log.c)

# netopeer2-server target
add_executable(netopeer2-server ${srcs})

# dependencies - pthread
set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
find_package(Threads REQUIRED)
target_link_libraries(netopeer2-server ${CMAKE_THREAD_LIBS_INIT})

# dependencies - libyang
find_package(LibYANG REQUIRED)
target_link_libraries(netopeer2-server ${LIBYANG_LIBRARIES})
include_directories(${LIBYANG_INCLUDE_DIRS})

# dependencies - libnetconf2
find_package(LibNETCONF2 REQUIRED)
if (NOT LIBNETCONF2_ENABLED_SSH)
	message(SEND_ERROR "Missing SSH support in libnetconf2, server requires SSH to be supported.")
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

if(NOT BIN_INSTALL_DIR)
	set(BIN_INSTALL_DIR ${CMAKE_INSTALL_PREFIX}/bin)
endif()

# install binary
install(TARGETS netopeer2-server DESTINATION ${BIN_INSTALL_DIR})

# clean cmake cache
add_custom_target(cleancache
                  COMMAND make clean
                  COMMAND find . -iname '*cmake*' -not -name CMakeLists.txt -exec rm -rf {} +
                  COMMAND rm -rf Makefile Doxyfile
                  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
