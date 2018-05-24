cmake_minimum_required(VERSION 2.6)

# include custom Modules
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/../CMakeModules/")

project(netopeer2-cli C)
include(GNUInstallDirs)

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
set(NP2CLI_VERSION 2.0.46)
configure_file("${PROJECT_SOURCE_DIR}/version.h.in" "${PROJECT_BINARY_DIR}/version.h" ESCAPE_QUOTES @ONLY)
include_directories(${PROJECT_BINARY_DIR})

# source files
set(srcs
    main.c
    commands.c
    completion.c
    configuration.c
    linenoise/linenoise.c)

# netopeer2-cli target
add_executable(netopeer2-cli ${srcs})

# dependencies - pthread
set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
find_package(Threads REQUIRED)
target_link_libraries(netopeer2-cli ${CMAKE_THREAD_LIBS_INIT})

# dependencies - libyang
find_package(LibYANG REQUIRED)
target_link_libraries(netopeer2-cli ${LIBYANG_LIBRARIES})
include_directories(${LIBYANG_INCLUDE_DIRS})

# dependencies - libnetconf2
find_package(LibNETCONF2 REQUIRED)
if (NOT LIBNETCONF2_ENABLED_SSH AND NOT LIBNETCONF2_ENABLED_TLS)
    message(SEND_ERROR "Missing SSH and TLS support in libnetconf2, CLI requires at least one them to be supported.")
endif()
target_link_libraries(netopeer2-cli ${LIBNETCONF2_LIBRARIES})
include_directories(${LIBNETCONF2_INCLUDE_DIRS})

# dependencies - libssl
if(LIBNETCONF2_ENABLED_TLS)
    find_package(OpenSSL REQUIRED)
    target_link_libraries(netopeer2-cli ${OPENSSL_LIBRARIES})
    include_directories(${OPENSSL_INCLUDE_DIR})
endif()

include(CheckFunctionExists)
check_function_exists(eaccess HAVE_EACCESS)
check_function_exists(mkstemps HAVE_MKSTEMPS)
if(HAVE_MKSTEMPS)
    set(CMAKE_C_FLAGS         "${CMAKE_C_FLAGS} -DHAVE_MKSTEMPS")
endif(HAVE_MKSTEMPS)

# install binary
install(TARGETS netopeer2-cli DESTINATION ${CMAKE_INSTALL_BINDIR})

# man -> html
find_program(ROFF2HTML roff2html)
if("${ROFF2HTML}" STREQUAL "ROFF2HTML-NOTFOUND")
    message("roff2html not found, html version of man pages cannot be generated!")
else()
    add_custom_target(doc ${ROFF2HTML} "${PROJECT_SOURCE_DIR}/doc/${PROJECT_NAME}.1" > "${PROJECT_SOURCE_DIR}/doc/${PROJECT_NAME}.1.html"
                      DEPENDS ${PROJECT_SOURCE_DIR}/doc/${PROJECT_NAME}.1)
endif()

# install doc (man)
install(FILES ${PROJECT_SOURCE_DIR}/doc/${PROJECT_NAME}.1 DESTINATION ${CMAKE_INSTALL_MANDIR}/man1)

# clean cmake cache
add_custom_target(cleancache
                  COMMAND make clean
                  COMMAND find . -iname '*cmake*' -not -name CMakeLists.txt -exec rm -rf {} +
                  COMMAND rm -rf Makefile Doxyfile
                  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
