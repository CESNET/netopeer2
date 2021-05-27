# correct RPATH usage on OS X
set(CMAKE_MACOSX_RPATH TRUE)

# update binary dir
set(CMAKE_CURRENT_BINARY_DIR "${CMAKE_BINARY_DIR}/tests")

# set ROOT_DIR to realpath
get_filename_component(ROOT_DIR "${CMAKE_SOURCE_DIR}" REALPATH)

# generate config
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/np_test_config.h.in" "${CMAKE_CURRENT_BINARY_DIR}/np_test_config.h" ESCAPE_QUOTES @ONLY)

# compat header include
add_test(NAME headers
    COMMAND ${CMAKE_SOURCE_DIR}/compat/check_includes.sh ${CMAKE_SOURCE_DIR}/src/ ${CMAKE_SOURCE_DIR}/cli/)

# format
if (${SOURCE_FORMAT_ENABLED})
    add_test(NAME format WORKING_DIRECTORY ${CMAKE_BINARY_DIR} COMMAND make format-check)
endif()

# include dirs
include_directories(SYSTEM ${CMOCKA_INCLUDE_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_BINARY_DIR})

# base test source
set(test_sources "np_test.c")

# list of all the tests
set(tests test_rpc)

# build the executables
foreach(test_name IN LISTS tests)
    add_executable(${test_name} ${test_sources} ${test_name}.c)
    target_link_libraries(${test_name} ${CMOCKA_LIBRARIES} ${LIBNETCONF2_LIBRARIES} ${LIBYANG_LIBRARIES})
    set_property(TARGET ${test_name} PROPERTY RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
endforeach(test_name)

# add tests with their attributes
foreach(test_name IN LISTS tests)
    add_test(NAME ${test_name} COMMAND $<TARGET_FILE:${test_name}>)
    set_property(TEST ${test_name} APPEND PROPERTY ENVIRONMENT
        "MALLOC_CHECK_=3"
    )
endforeach(test_name)

# valgrind tests
if(ENABLE_VALGRIND_TESTS)
    find_program(VALGRIND_FOUND valgrind)
    if(VALGRIND_FOUND)
        foreach(test_name IN LISTS tests)
            add_test(NAME ${test_name}_valgrind COMMAND valgrind --leak-check=full --show-leak-kinds=all --error-exitcode=1 ${CMAKE_CURRENT_BINARY_DIR}/${test_name})
        endforeach(test_name)
    else()
        message(WARNING "valgrind executable not found! Disabling memory leak tests.")
    endif()
endif()

# phony target for clearing all sysrepo test data
add_custom_target(test_clean
    COMMAND rm -rf ${CMAKE_CURRENT_BINARY_DIR}/repositories
    COMMAND rm -rf /dev/shm/_tests_np_*
)
