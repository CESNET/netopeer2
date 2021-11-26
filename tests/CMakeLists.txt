if(NOT NP2SRV_VERSION)
    message(FATAL_ERROR "Please use the root CMakeLists file instead.")
endif()

# correct RPATH usage on OS X
set(CMAKE_MACOSX_RPATH TRUE)

# update binary dir
set(CMAKE_CURRENT_BINARY_DIR "${CMAKE_BINARY_DIR}/tests")

# set ROOT_DIR to realpath
get_filename_component(ROOT_DIR "${CMAKE_SOURCE_DIR}" REALPATH)

# generate config
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/np_test_config.h.in" "${CMAKE_CURRENT_BINARY_DIR}/np_test_config.h" ESCAPE_QUOTES @ONLY)

# generate config
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/scripts/kill_np_server.sh.in"
    "${CMAKE_CURRENT_BINARY_DIR}/scripts/kill_np_server.sh" ESCAPE_QUOTES @ONLY)

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
set(tests test_rpc test_edit test_filter test_subscribe_filter test_subscribe_param test_parallel_sessions
    test_candidate test_with_defaults test_nacm test_sub_ntf test_sub_ntf_advanced test_sub_ntf_filter test_yang_push
    test_yang_push_advanced test_confirmed_commit)

# append url if supported
if(NP2SRV_URL_CAPAB)
    list(APPEND tests test_url)
endif()

# build the executables
foreach(test_name IN LISTS tests)
    add_executable(${test_name} ${test_sources} ${test_name}.c)
    target_link_libraries(${test_name} ${CMOCKA_LIBRARIES} ${LIBNETCONF2_LIBRARIES} ${LIBYANG_LIBRARIES} ${SYSREPO_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})
    set_property(TARGET ${test_name} PROPERTY RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
endforeach(test_name)

if(${CMAKE_VERSION} VERSION_GREATER "3.7")
    # tests cleanup fixture, keep repos with server log files
    add_test(NAME tests_done COMMAND make test_clean_keep_repos)
    set_tests_properties(tests_done PROPERTIES FIXTURES_CLEANUP tests_cleanup)
endif()

# add tests with their attributes
foreach(test_name IN LISTS tests)
    add_test(NAME ${test_name} COMMAND $<TARGET_FILE:${test_name}> WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
    set_property(TEST ${test_name} APPEND PROPERTY ENVIRONMENT "MALLOC_CHECK_=3")
    set_property(TEST ${test_name} APPEND PROPERTY ENVIRONMENT "TEST_NAME=${test_name}")
    if(${CMAKE_VERSION} VERSION_GREATER "3.7")
        set_tests_properties(${test_name} PROPERTIES FIXTURES_REQUIRED tests_cleanup)
    endif()
endforeach()

# valgrind tests
if(ENABLE_VALGRIND_TESTS)
    foreach(test_name IN LISTS tests)
        add_test(NAME ${test_name}_valgrind COMMAND valgrind --leak-check=full --show-leak-kinds=all --error-exitcode=1 ${CMAKE_CURRENT_BINARY_DIR}/${test_name} WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
        set(test_name "${test_name}_valgrind")
        set_property(TEST ${test_name} APPEND PROPERTY ENVIRONMENT "TEST_NAME=${test_name}")
        if(${CMAKE_VERSION} VERSION_GREATER "3.7")
            set_tests_properties(${test_name} PROPERTIES FIXTURES_REQUIRED tests_cleanup)
        endif()
    endforeach()
endif()

# phony target for clearing all sysrepo test data
add_custom_target(test_clean_keep_repos
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/scripts/kill_np_server.sh
    COMMAND rm -rf /dev/shm/_tests_np_*
)
add_custom_target(test_clean
    DEPENDS test_clean_keep_repos
    COMMAND rm -rf ${CMAKE_CURRENT_BINARY_DIR}/repositories
)
