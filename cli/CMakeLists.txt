if(NOT NP2SRV_VERSION)
    message(FATAL_ERROR "Please use the root CMakeLists file instead.")
endif()

include(CheckFunctionExists)

project(netopeer2-cli C)

# set version
set(NP2CLI_VERSION 2.0.77)
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/cli_version.h.in" "${PROJECT_BINARY_DIR}/cli_version.h" ESCAPE_QUOTES @ONLY)
include_directories(${PROJECT_BINARY_DIR})

# source files
set(CLI_SRC
    main.c
    commands.c
    completion.c
    configuration.c
    linenoise/linenoise.c)

# netopeer2-cli target
add_executable(netopeer2-cli ${CLI_SRC} ${compatsrc})

# reuse server variables
target_link_libraries(netopeer2-cli ${CMAKE_THREAD_LIBS_INIT})
target_link_libraries(netopeer2-cli ${LIBYANG_LIBRARIES})
target_link_libraries(netopeer2-cli ${LIBNETCONF2_LIBRARIES})

# dependencies
if(LIBNETCONF2_ENABLED_SSH_TLS)
    # - libssh
    if(NOT LIBSSH_FOUND)
        message(FATAL_ERROR "libnetconf2 supports SSH but libssh was not found, CLI compilation failed!")
    endif()
    target_link_libraries(netopeer2-cli ${LIBSSH_LIBRARIES})
    include_directories(${LIBSSH_INCLUDE_DIRS})

    # - openssl
    if(NOT OPENSSL_FOUND)
        message(FATAL_ERROR "libnetconf2 supports TLS but OpenSSL was not found, CLI compilation failed!")
    endif()
    target_link_libraries(netopeer2-cli ${OPENSSL_LIBRARIES})
    include_directories(${OPENSSL_INCLUDE_DIR})
endif()

# compat checks
check_function_exists(eaccess HAVE_EACCESS)
check_function_exists(mkstemps HAVE_MKSTEMPS)
if(HAVE_MKSTEMPS)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DHAVE_MKSTEMPS")
endif(HAVE_MKSTEMPS)

# install
install(TARGETS netopeer2-cli DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/doc/netopeer2-cli.1 DESTINATION ${CMAKE_INSTALL_MANDIR}/man1)
