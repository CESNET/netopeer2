if(NOT NP2SRV_VERSION)
    message(FATAL_ERROR "Please use the root CMakeLists file instead.")
endif()

# correct RPATH usage on OS X
set(CMAKE_MACOSX_RPATH TRUE)

# set ROOT_DIR to realpath
get_filename_component(ROOT_DIR "${CMAKE_SOURCE_DIR}" REALPATH)

# test directories that can be adjusted
if(NOT NP2_TEST_ROOT_DIR)
    set(NP2_TEST_ROOT_DIR ${PROJECT_BINARY_DIR}/repos)
endif()
if(NOT NP2_TEST_MODULE_DIR)
    set(NP2_TEST_MODULE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/modules)
endif()

# generate config
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/np2_test_config.h.in" "${CMAKE_CURRENT_BINARY_DIR}/np2_test_config.h" ESCAPE_QUOTES @ONLY)

# generate config
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/scripts/kill_np_server.sh.in"
    "${CMAKE_CURRENT_BINARY_DIR}/scripts/kill_np_server.sh" ESCAPE_QUOTES @ONLY)

# compat header include
add_test(NAME headers
    COMMAND ${CMAKE_SOURCE_DIR}/compat/check_includes.sh ${CMAKE_SOURCE_DIR}/src/ ${CMAKE_SOURCE_DIR}/cli/)

# format
if (${SOURCE_FORMAT_ENABLED})
    add_test(NAME format WORKING_DIRECTORY ${CMAKE_BINARY_DIR} COMMAND cmake --build ${CMAKE_BINARY_DIR} --target format-check)
endif()

# include dirs
include_directories(SYSTEM ${CMOCKA_INCLUDE_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_BINARY_DIR})

# base test source
set(TEST_SRC "np2_test.c" "np2_other_client.c")

# list of all the tests
set(TESTS test_rpc test_edit test_filter test_subscribe_filter test_subscribe_param test_parallel_sessions
    test_candidate test_with_defaults test_nacm test_sub_ntf test_sub_ntf_advanced test_sub_ntf_filter test_error test_other_client)

if(CMAKE_C_FLAGS MATCHES "-fsanitize=thread")
    message(WARNING "Features which use SIGEV_THREAD are known to be broken under TSAN, disabling tests for YANG-push and confirmed commit")
else()
    # On TSAN, SIGEV_THREAD is known to not work: https://github.com/google/sanitizers/issues/1612
    list(APPEND TESTS test_yang_push test_yang_push_advanced test_confirmed_commit)
endif()

# append url if supported
if(NP2SRV_URL_CAPAB)
    list(APPEND TESTS test_url)
endif()

if(ENABLE_TESTS)
    # build the executables
    foreach(test_name IN LISTS TESTS)
        add_executable(${test_name} ${TEST_SRC} ${test_name}.c)
        target_link_libraries(${test_name} ${CMOCKA_LIBRARIES} ${LIBNETCONF2_LIBRARIES} ${LIBYANG_LIBRARIES} ${SYSREPO_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})
        set_property(TARGET ${test_name} PROPERTY RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
    endforeach(test_name)

    set(TEST_KILL_SERVER_COMMAND ${CMAKE_CURRENT_BINARY_DIR}/scripts/kill_np_server.sh)
    set(TEST_CLEAR_STATE_COMMAND rm -rf /dev/shm/_tests_np_*)
    if(${CMAKE_VERSION} VERSION_GREATER "3.7")
        # tests cleanup fixtures, keep repos with server log files
        add_test(NAME tests_kill_server COMMAND ${TEST_KILL_SERVER_COMMAND})
        add_test(NAME tests_clear_state COMMAND ${TEST_CLEAR_STATE_COMMAND})
        set_tests_properties(tests_kill_server PROPERTIES FIXTURES_CLEANUP tests_cleanup)
        set_tests_properties(tests_clear_state PROPERTIES FIXTURES_CLEANUP tests_cleanup DEPENDS tests_kill_server)
    endif()

    # add tests with their attributes
    foreach(test_name IN LISTS TESTS)
        add_test(NAME ${test_name} COMMAND $<TARGET_FILE:${test_name}> WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
        set_property(TEST ${test_name} APPEND PROPERTY ENVIRONMENT "MALLOC_CHECK_=3")
        set_property(TEST ${test_name} APPEND PROPERTY ENVIRONMENT "TEST_NAME=${test_name}")
        set_property(TEST ${test_name} APPEND PROPERTY ENVIRONMENT "SYSREPOCTL_EXECUTABLE=${SYSREPOCTL_EXECUTABLE}")
        if(${CMAKE_VERSION} VERSION_GREATER "3.7")
            set_tests_properties(${test_name} PROPERTIES FIXTURES_REQUIRED tests_cleanup)
        endif()
    endforeach()

    # valgrind tests
    if(ENABLE_VALGRIND_TESTS)
        foreach(test_name IN LISTS TESTS)
            add_test(NAME ${test_name}_valgrind COMMAND valgrind --leak-check=full --show-leak-kinds=all --error-exitcode=1 ${CMAKE_CURRENT_BINARY_DIR}/${test_name} WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
            set(test_name "${test_name}_valgrind")
            set_property(TEST ${test_name} APPEND PROPERTY ENVIRONMENT "TEST_NAME=${test_name}")
            set_property(TEST ${test_name} APPEND PROPERTY ENVIRONMENT "SYSREPOCTL_EXECUTABLE=${SYSREPOCTL_EXECUTABLE}")
            if(${CMAKE_VERSION} VERSION_GREATER "3.7")
                set_tests_properties(${test_name} PROPERTIES FIXTURES_REQUIRED tests_cleanup)
            endif()
        endforeach()
    endif()

    # phony target for clearing all sysrepo test data
    add_custom_target(test_clean
        COMMAND ${TEST_KILL_SERVER_COMMAND}
        COMMAND ${TEST_CLEAR_STATE_COMMAND}
        COMMAND rm -rf ${NP2_TEST_ROOT_DIR}
    )
endif()

# propagate vars to parent
set(TESTS ${TESTS} PARENT_SCOPE)
set(TEST_SRC ${TEST_SRC} PARENT_SCOPE)
set(TEST_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR} PARENT_SCOPE)
set(TEST_BIN_DIR ${CMAKE_CURRENT_BINARY_DIR} PARENT_SCOPE)
set(TEST_MODULE_DIR ${NP2_TEST_MODULE_DIR} PARENT_SCOPE)
