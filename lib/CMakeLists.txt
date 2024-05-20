if(NOT NP2SRV_VERSION)
    message(FATAL_ERROR "Please use the root CMakeLists file instead.")
endif()

project(libnetopeer2 C)

include(GNUInstallDirs)

# source files
set(LIB_SRC
    np2_sr_setup.c
    ${compatsrc})

if(NETOPEER2_LIB_SERVER)
    # include server main function as a library function
    add_library(netopeer2_lib_server OBJECT $<TARGET_OBJECTS:serverobj> ${PROJECT_SOURCE_DIR}/../src/main.c)
    target_compile_definitions(netopeer2_lib_server PRIVATE main=np2_server)
    set(NETOPEER2_SERVER_FUNC "\
/**
 * @brief netopeer2-server main function.
 *
 * @param[in] argc Argument count.
 * @param[in] argv Argument list, should always be at least the path to the binary.
 * @return EXIT_SUCCESS on success.
 * @return EXIT_FAILURE on error.
 */
int np2_server(int argc, char *argv[]);")
endif()

if(NETOPEER2_LIB_TESTS)
    # include every test as a library function
    foreach(TEST IN LISTS TESTS)
        add_library(netopeer2_lib_${TEST} OBJECT "${TEST_SRC_DIR}/${TEST}.c")
        target_compile_definitions(netopeer2_lib_${TEST} PRIVATE main=np2_${TEST})
        set(NETOPEER2_TESTS_FUNC ${NETOPEER2_TESTS_FUNC} "

/**
 * @brief netopeer2-server ${TEST}
 *
 * @param[in] argc Argument count, should be 0.
 * @param[in] argv Argument list, should be NULL.
 * @return EXIT_SUCCESS on success.
 * @return EXIT_FAILURE on error.
 */
int np2_${TEST}(int argc, char *argv[]);")
    endforeach()

    add_library(netopeer2_lib_test OBJECT "${TEST_SRC_DIR}/${TEST_SRC}")
    include_directories(${TEST_BIN_DIR})
    include_directories(${TEST_SRC_DIR})
endif()

configure_file(${PROJECT_SOURCE_DIR}/netopeer2.h.in ${PROJECT_BINARY_DIR}/include/netopeer2.h ESCAPE_QUOTES @ONLY)

# generate YANG header files
add_custom_command(OUTPUT np2_sr_yang.h
        COMMAND ${CMAKE_COMMAND} -E env
            NP2_MODULE_DIR=${PROJECT_SOURCE_DIR}/../modules
            LN2_MODULE_DIR=${LN2_YANG_MODULE_DIR}
            NP2_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}
            ${PROJECT_SOURCE_DIR}/generate.sh
        COMMENT "Generating YANG header files (generate.sh)..."
)

include_directories(${CMAKE_CURRENT_BINARY_DIR})

# lib target
add_library(netopeer2 ${LIB_SRC} np2_sr_yang.h)

# add dependencies
target_link_libraries(netopeer2 ${serverlibs})
if(TARGET CURL::libcurl)
    target_link_libraries(netopeer2 CURL::libcurl)
endif()
if(NETOPEER2_LIB_SERVER)
    target_link_libraries(netopeer2 netopeer2_lib_server)
endif()
if(NETOPEER2_LIB_TESTS)
    foreach(TEST IN LISTS TESTS)
        target_link_libraries(netopeer2 netopeer2_lib_${TEST})
    endforeach()
    target_link_libraries(netopeer2 netopeer2_lib_test)
endif()

# install
install(TARGETS netopeer2 DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES ${PROJECT_BINARY_DIR}/include/netopeer2.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
