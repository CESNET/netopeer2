cmake_minimum_required(VERSION 3.0)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/CMakeModules/")

add_executable(test-service main.cpp SysrepoListener.cpp SysrepoListener.hpp
                            RequestHandler.cpp RequestHandler.hpp)

find_package(Threads REQUIRED)
target_link_libraries(test-service ${CMAKE_THREAD_LIBS_INIT})

find_package(Sysrepo REQUIRED)
target_link_libraries(test-service ${SYSREPO_LIBRARY})

find_package(Pistache REQUIRED)
target_link_libraries(test-service pistache)

install(TARGETS test-service RUNTIME DESTINATION bin)
