cmake_minimum_required(VERSION 2.8.9)
add_subdirectory(server)
add_subdirectory(cli)

# clean cmake cache
add_custom_target(cleancache
                  COMMAND make clean
                  COMMAND find . -iname '*cmake*' -not -name CMakeLists.txt -exec rm -rf {} +
                  COMMAND rm -f Makefile Doxyfile cli/Makefile cli/Doxyfile server/Makefile server/Doxyfile
                  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

