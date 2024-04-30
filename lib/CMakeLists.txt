if(NOT NP2SRV_VERSION)
    message(FATAL_ERROR "Please use the root CMakeLists file instead.")
endif()

project(np2_sr_setup C)

# source files
set(LIB_SRC
    np2_sr_setup.c)

# generate YANG header files
add_custom_command(OUTPUT np2_sr_yang.h
        COMMAND ${CMAKE_COMMAND} -E env
            NP2_MODULE_DIR=${CMAKE_CURRENT_SOURCE_DIR}/../modules
            LN2_MODULE_DIR=${LN2_YANG_MODULE_DIR}
            NP2_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}
            ${CMAKE_CURRENT_SOURCE_DIR}/generate.sh
        COMMENT "Generating YANG header files (generate.sh)..."
)

include_directories(${CMAKE_CURRENT_BINARY_DIR})

# lib target
add_library(np2_sr_setup ${LIB_SRC} np2_sr_yang.h)

# reuse server variables
target_link_libraries(np2_sr_setup ${LIBYANG_LIBRARIES})
target_link_libraries(np2_sr_setup ${SYSREPO_LIBRARIES})
