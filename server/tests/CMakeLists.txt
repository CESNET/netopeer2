cmake_minimum_required(VERSION 2.6)

set(tests test_start)
set(sysrepo_wrap_link_flags "-Wl,--wrap=sr_connect,--wrap=sr_session_start,--wrap=sr_list_schemas,--wrap=sr_get_schema,--wrap=sr_free_schemas,--wrap=sr_session_start_user,--wrap=sr_session_stop,--wrap=sr_disconnect")
set(libnetconf2_wrap_link_flags "-Wl,--wrap=nc_server_ssh_add_endpt_listen,--wrap=nc_server_ssh_endpt_set_hostkey")

foreach(test_name IN LISTS tests)
    add_executable(${test_name} ${test_name}.c ../netconf_monitoring.c ../operations.c ../op_get_config.c ../op_editconfig.c ../op_copyconfig.c ../op_deleteconfig.c ../op_candidate.c ../op_validate.c ../op_un_lock.c ../op_generic.c ../log.c)
    target_link_libraries(${test_name} ${CMOCKA_LIBRARIES} pthread yang netconf2 sysrepo)
    set_target_properties(${test_name} PROPERTIES LINK_FLAGS "${sysrepo_wrap_link_flags} ${libnetconf2_wrap_link_flags}")
    add_test(NAME ${test_name} COMMAND $<TARGET_FILE:${test_name}>)
endforeach(test_name)

configure_file("${PROJECT_SOURCE_DIR}/tests/config.h.in" "${PROJECT_SOURCE_DIR}/tests/config.h" ESCAPE_QUOTES @ONLY)

if(ENABLE_VALGRIND_TESTS)
    find_program(valgrind_FOUND valgrind)
    if(valgrind_FOUND)
        foreach(test_name IN LISTS tests)
            add_test(${test_name}_valgrind valgrind --leak-check=full --show-leak-kinds=all
                 ${CMAKE_BINARY_DIR}/tests/${test_name})
        endforeach(test_name)
    else(valgrind_FOUND)
        Message("-- valgrind executable not found! Disabling memory leaks tests")
    endif(valgrind_FOUND)
endif()
