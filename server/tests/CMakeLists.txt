cmake_minimum_required(VERSION 2.6)

set(tests test_close_session test_get test_generic test_copy_config test_edit_get_config test_un_lock test_notif test_kill)

set(test test_close_session)
set(${test}_mock_funcs sr_connect sr_session_start sr_list_schemas sr_get_schema sr_module_install_subscribe sr_feature_enable_subscribe sr_module_change_subscribe sr_session_start_user sr_session_stop sr_disconnect sr_event_notif_send nc_accept nc_session_free nc_server_endpt_count)
set(${test}_wrap_link_flags "-Wl")
foreach(mock_func IN LISTS ${test}_mock_funcs)
    set(${test}_wrap_link_flags "${${test}_wrap_link_flags},--wrap=${mock_func}")
endforeach()

set(test test_get)
set(${test}_mock_funcs sr_session_refresh sr_check_exec_permission)
set(${test}_wrap_link_flags "-Wl")
foreach(mock_func IN LISTS test_close_session_mock_funcs ${test}_mock_funcs)
    set(${test}_wrap_link_flags "${${test}_wrap_link_flags},--wrap=${mock_func}")
endforeach()

set(test test_generic)
set(${test}_mock_funcs sr_rpc_send sr_action_send)
set(${test}_wrap_link_flags "-Wl")
foreach(mock_func IN LISTS test_close_session_mock_funcs test_get_mock_funcs ${test}_mock_funcs)
    set(${test}_wrap_link_flags "${${test}_wrap_link_flags},--wrap=${mock_func}")
endforeach()

set(test test_copy_config)
set(${test}_mock_funcs sr_session_switch_ds sr_set_item sr_delete_item sr_commit)
set(${test}_wrap_link_flags "-Wl")
foreach(mock_func IN LISTS test_close_session_mock_funcs test_get_mock_funcs ${test}_mock_funcs)
    set(${test}_wrap_link_flags "${${test}_wrap_link_flags},--wrap=${mock_func}")
endforeach()

set(test test_edit_get_config)
set(${test}_mock_funcs sr_get_items_iter sr_get_item_next sr_free_val_iter sr_move_item sr_session_set_options)
set(${test}_wrap_link_flags "-Wl")
foreach(mock_func IN LISTS test_close_session_mock_funcs test_get_mock_funcs test_copy_config_mock_funcs ${test}_mock_funcs)
    set(${test}_wrap_link_flags "${${test}_wrap_link_flags},--wrap=${mock_func}")
endforeach()

set(test test_un_lock)
set(${test}_mock_funcs sr_session_switch_ds sr_discard_changes sr_lock_datastore sr_unlock_datastore)
set(${test}_wrap_link_flags "-Wl")
foreach(mock_func IN LISTS test_close_session_mock_funcs test_get_mock_funcs ${test}_mock_funcs)
    set(${test}_wrap_link_flags "${${test}_wrap_link_flags},--wrap=${mock_func}")
endforeach()

set(test test_notif)
set(${test}_mock_funcs sr_event_notif_subscribe sr_event_notif_replay sr_check_exec_permission)
set(${test}_wrap_link_flags "-Wl")
foreach(mock_func IN LISTS test_close_session_mock_funcs ${test}_mock_funcs)
    set(${test}_wrap_link_flags "${${test}_wrap_link_flags},--wrap=${mock_func}")
endforeach()

set(test test_kill)
set(${test}_mock_funcs sr_check_exec_permission)
set(${test}_wrap_link_flags "-Wl")
foreach(mock_func IN LISTS test_close_session_mock_funcs ${test}_mock_funcs)
    set(${test}_wrap_link_flags "${${test}_wrap_link_flags},--wrap=${mock_func}")
endforeach()

foreach(src IN LISTS srcs)
    list(APPEND test_srcs "../${src}")
endforeach()

set(CMAKE_C_FLAGS         "${CMAKE_C_FLAGS} -DNP2SRV_THREAD_COUNT=1 -DNP2SRV_KEYSTORED_DIR=\\\"${CMAKE_SOURCE_DIR}/tests/files\\\"")

# object library to build source codes only once for all the tests
add_library(testobj OBJECT ${test_srcs})

foreach(test_name IN LISTS tests)
    add_executable(${test_name} $<TARGET_OBJECTS:testobj> ${test_name}.c)
    target_link_libraries(${test_name} ${CMOCKA_LIBRARIES} pthread ${LIBYANG_LIBRARIES} ${LIBNETCONF2_LIBRARIES} ${SYSREPO_LIBRARIES})
    set_target_properties(${test_name} PROPERTIES LINK_FLAGS "${${test_name}_wrap_link_flags}")
    add_test(NAME ${test_name} COMMAND $<TARGET_FILE:${test_name}>)
endforeach(test_name)

configure_file("${PROJECT_SOURCE_DIR}/tests/config.h.in" "${PROJECT_SOURCE_DIR}/tests/config.h" ESCAPE_QUOTES @ONLY)

if(ENABLE_VALGRIND_TESTS)
    find_program(valgrind_FOUND valgrind)
    if(valgrind_FOUND)
        foreach(test_name IN LISTS tests)
            add_test(${test_name}_valgrind valgrind --leak-check=full --show-leak-kinds=all --error-exitcode=1
                 ${CMAKE_BINARY_DIR}/tests/${test_name})
        endforeach(test_name)
    else(valgrind_FOUND)
        Message("-- valgrind executable not found! Disabling memory leaks tests")
    endif(valgrind_FOUND)
endif()
