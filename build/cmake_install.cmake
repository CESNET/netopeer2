# Install script for directory: /home/netconf/netopeer2-1

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/usr/local")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "Debug")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Install shared libraries without execute permission?
if(NOT DEFINED CMAKE_INSTALL_SO_NO_EXE)
  set(CMAKE_INSTALL_SO_NO_EXE "1")
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "FALSE")
endif()

# Set default install directory permissions.
if(NOT DEFINED CMAKE_OBJDUMP)
  set(CMAKE_OBJDUMP "/usr/bin/objdump")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  list(APPEND CMAKE_ABSOLUTE_DESTINATION_FILES
   "/usr/local/share/yang/modules/netopeer2/")
  if(CMAKE_WARN_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(WARNING "ABSOLUTE path INSTALL DESTINATION : ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  if(CMAKE_ERROR_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(FATAL_ERROR "ABSOLUTE path INSTALL DESTINATION forbidden (by caller): ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  file(INSTALL DESTINATION "/usr/local/share/yang/modules/netopeer2" TYPE DIRECTORY FILES "/home/netconf/netopeer2-1/modules/")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  list(APPEND CMAKE_ABSOLUTE_DESTINATION_FILES
   "/usr/local/share/netopeer2/scripts/")
  if(CMAKE_WARN_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(WARNING "ABSOLUTE path INSTALL DESTINATION : ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  if(CMAKE_ERROR_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(FATAL_ERROR "ABSOLUTE path INSTALL DESTINATION forbidden (by caller): ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  file(INSTALL DESTINATION "/usr/local/share/netopeer2/scripts" TYPE DIRECTORY FILES "/home/netconf/netopeer2-1/scripts/" USE_SOURCE_PERMISSIONS)
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/sbin/netopeer2-server" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/sbin/netopeer2-server")
    file(RPATH_CHECK
         FILE "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/sbin/netopeer2-server"
         RPATH "")
  endif()
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/sbin" TYPE EXECUTABLE FILES "/home/netconf/netopeer2-1/build/netopeer2-server")
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/sbin/netopeer2-server" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/sbin/netopeer2-server")
    file(RPATH_CHANGE
         FILE "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/sbin/netopeer2-server"
         OLD_RPATH "/usr/local/lib:"
         NEW_RPATH "")
    if(CMAKE_INSTALL_DO_STRIP)
      execute_process(COMMAND "/usr/bin/strip" "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/sbin/netopeer2-server")
    endif()
  endif()
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/share/man/man8" TYPE FILE FILES "/home/netconf/netopeer2-1/doc/netopeer2-server.8")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  list(APPEND CMAKE_ABSOLUTE_DESTINATION_FILES
   "/usr/lib/systemd/system/netopeer2-server.service")
  if(CMAKE_WARN_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(WARNING "ABSOLUTE path INSTALL DESTINATION : ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  if(CMAKE_ERROR_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(FATAL_ERROR "ABSOLUTE path INSTALL DESTINATION forbidden (by caller): ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  file(INSTALL DESTINATION "/usr/lib/systemd/system" TYPE FILE FILES "/home/netconf/netopeer2-1/build/netopeer2-server.service")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/etc/pam.d" TYPE FILE FILES "/home/netconf/netopeer2-1/pam/netopeer2.conf")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  
        message(STATUS "Installing missing sysrepo modules (setup.sh)...")
        set(ENV{NP2_MODULE_DIR} "/usr/local/share/yang/modules/netopeer2")
        set(ENV{NP2_MODULE_PERMS} "600")
        set(ENV{NP2_MODULE_OWNER} "netconf")
        set(ENV{NP2_MODULE_GROUP} "netconf")
        set(ENV{LN2_MODULE_DIR} "/usr/local/share/yang/modules/libnetconf2")
        set(ENV{SYSREPOCTL_EXECUTABLE} "/usr/local/bin/sysrepoctl")
        set(ENV{SYSREPOCFG_EXECUTABLE} "/usr/local/bin/sysrepocfg")
        execute_process(COMMAND "$ENV{DESTDIR}/usr/local/share/netopeer2/scripts/setup.sh"
                RESULT_VARIABLE CMD_RES
                OUTPUT_VARIABLE CMD_OUT
                ERROR_VARIABLE CMD_ERR
                OUTPUT_STRIP_TRAILING_WHITESPACE
                ERROR_STRIP_TRAILING_WHITESPACE)
        if(NOT CMD_RES EQUAL 0)
            string(REPLACE "\n" "\n " CMD_OUT_F "${CMD_OUT}")
            string(REPLACE "\n" "\n " CMD_ERR_F "${CMD_ERR}")
            message(FATAL_ERROR " OUTPUT:\n ${CMD_OUT_F}\n ERROR:\n ${CMD_ERR_F}")
        endif()
    
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  
        message(STATUS "Generating a new RSA host key \"genkey\" if not already added (merge_hostkey.sh)...")
        set(ENV{SYSREPOCTL_EXECUTABLE} "/usr/local/bin/sysrepoctl")
        set(ENV{SYSREPOCFG_EXECUTABLE} "/usr/local/bin/sysrepocfg")
        execute_process(COMMAND "$ENV{DESTDIR}/usr/local/share/netopeer2/scripts/merge_hostkey.sh"
                RESULT_VARIABLE CMD_RES
                OUTPUT_VARIABLE CMD_OUT
                ERROR_VARIABLE CMD_ERR
                OUTPUT_STRIP_TRAILING_WHITESPACE
                ERROR_STRIP_TRAILING_WHITESPACE)
        if(NOT CMD_RES EQUAL 0)
            string(REPLACE "\n" "\n " CMD_OUT_F "${CMD_OUT}")
            string(REPLACE "\n" "\n " CMD_ERR_F "${CMD_ERR}")
            message(FATAL_ERROR " OUTPUT:\n ${CMD_OUT_F}\n ERROR:\n ${CMD_ERR_F}")
        endif()
    
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  
        message(STATUS "Merging default server listen configuration if there is none (merge_config.sh)...")
        set(ENV{SYSREPOCTL_EXECUTABLE} "/usr/local/bin/sysrepoctl")
        set(ENV{SYSREPOCFG_EXECUTABLE} "/usr/local/bin/sysrepocfg")
        execute_process(COMMAND "$ENV{DESTDIR}/usr/local/share/netopeer2/scripts/merge_config.sh"
                RESULT_VARIABLE CMD_RES
                OUTPUT_VARIABLE CMD_OUT
                ERROR_VARIABLE CMD_ERR
                OUTPUT_STRIP_TRAILING_WHITESPACE
                ERROR_STRIP_TRAILING_WHITESPACE)
        if(NOT CMD_RES EQUAL 0)
            string(REPLACE "\n" "\n " CMD_OUT_F "${CMD_OUT}")
            string(REPLACE "\n" "\n " CMD_ERR_F "${CMD_ERR}")
            message(FATAL_ERROR " OUTPUT:\n ${CMD_OUT_F}\n ERROR:\n ${CMD_ERR_F}")
        endif()
    
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/netconf/netopeer2-1/build/tests/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/netconf/netopeer2-1/build/cli/cmake_install.cmake")
endif()

if(CMAKE_INSTALL_COMPONENT)
  set(CMAKE_INSTALL_MANIFEST "install_manifest_${CMAKE_INSTALL_COMPONENT}.txt")
else()
  set(CMAKE_INSTALL_MANIFEST "install_manifest.txt")
endif()

string(REPLACE ";" "\n" CMAKE_INSTALL_MANIFEST_CONTENT
       "${CMAKE_INSTALL_MANIFEST_FILES}")
file(WRITE "/home/netconf/netopeer2-1/build/${CMAKE_INSTALL_MANIFEST}"
     "${CMAKE_INSTALL_MANIFEST_CONTENT}")
