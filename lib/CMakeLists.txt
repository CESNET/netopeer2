if(NOT NP2SRV_VERSION)
    message(FATAL_ERROR "Please use the root CMakeLists file instead.")
endif()

project(libnetopeer2 C)

include(GNUInstallDirs)

# source files
set(LIB_SRC
    np2_sr_setup.c)

if(NETOPEER2_LIB STREQUAL "server")
    # build server main function as a library function
    set(LIB_SRC ${LIB_SRC} ${serverobj} ${PROJECT_SOURCE_DIR}/../src/main.c ${compatsrc})
    add_definitions(-Dmain=np2_server)
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

# install
install(TARGETS netopeer2 DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES ${PROJECT_BINARY_DIR}/include/netopeer2.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
