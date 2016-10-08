# - Try to find LibNETCONF2
# Once done this will define
#
#  LIBNETCONF2_FOUND - system has LibNETCONF2
#  LIBNETCONF2_INCLUDE_DIRS - the LibNETCONF2 include directory
#  LIBNETCONF2_LIBRARIES - Link these to use LibNETCONF2
#  LIBNETCONF2_ENABLED_SSH - LibNETCONF2 was compiled with SSH support
#  LIBNETCONF2_ENABLED_TLS - LibNETCONF2 was compiled with TLS support
#
#  Author Michal Vasko <mvasko@cesnet.cz>
#  Copyright (c) 2015 CESNET, z.s.p.o.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions
#  are met:
#
#  1. Redistributions of source code must retain the copyright
#     notice, this list of conditions and the following disclaimer.
#  2. Redistributions in binary form must reproduce the copyright
#     notice, this list of conditions and the following disclaimer in the
#     documentation and/or other materials provided with the distribution.
#  3. The name of the author may not be used to endorse or promote products
#     derived from this software without specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
#  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
#  OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
#  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
#  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
#  NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
#  THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

INCLUDE(CheckSymbolExists)

if (LIBNETCONF2_LIBRARIES AND LIBNETCONF2_INCLUDE_DIRS)
  # in cache already
  set(LIBNETCONF2_FOUND TRUE)
else (LIBNETCONF2_LIBRARIES AND LIBNETCONF2_INCLUDE_DIRS)

  find_path(LIBNETCONF2_INCLUDE_DIR
    NAMES
      nc_client.h
      nc_server.h
    PATHS
      /usr/include
      /usr/local/include
      /opt/local/include
      /sw/include
      ${CMAKE_INCLUDE_PATH}
      ${CMAKE_INSTALL_PREFIX}/include
  )

  find_library(LIBNETCONF2_LIBRARY
    NAMES
      netconf2
      libnetconf2
    PATHS
      /usr/lib
      /usr/lib64
      /usr/local/lib
      /usr/local/lib64
      /opt/local/lib
      /sw/lib
      ${CMAKE_LIBRARY_PATH}
      ${CMAKE_INSTALL_PREFIX}/lib
  )

  if (LIBNETCONF2_INCLUDE_DIR AND LIBNETCONF2_LIBRARY)
    set(LIBNETCONF2_FOUND TRUE)
    # check the configured options and make them available through cmake
    list(INSERT CMAKE_REQUIRED_INCLUDES 0 "${LIBNETCONF2_INCLUDE_DIR}")
    check_symbol_exists("NC_ENABLED_SSH" "nc_client.h" LIBNETCONF2_ENABLED_SSH)
    check_symbol_exists("NC_ENABLED_TLS" "nc_client.h" LIBNETCONF2_ENABLED_TLS)
    list(REMOVE_AT CMAKE_REQUIRED_INCLUDES 0)
  else (LIBNETCONF2_INCLUDE_DIR AND LIBNETCONF2_LIBRARY)
    set(LIBNETCONF2_FOUND FALSE)
  endif (LIBNETCONF2_INCLUDE_DIR AND LIBNETCONF2_LIBRARY)

  set(LIBNETCONF2_INCLUDE_DIRS ${LIBNETCONF2_INCLUDE_DIR})
  set(LIBNETCONF2_LIBRARIES ${LIBNETCONF2_LIBRARY})

  # show the LIBNETCONF2_INCLUDE_DIRS and LIBNETCONF2_LIBRARIES variables only in the advanced view
  mark_as_advanced(LIBNETCONF2_INCLUDE_DIRS LIBNETCONF2_LIBRARIES)

endif (LIBNETCONF2_LIBRARIES AND LIBNETCONF2_INCLUDE_DIRS)

