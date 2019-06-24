# - Try to find LibSSH
# Once done this will define
#
#  LIBSSH_FOUND - system has LibSSH
#  LIBSSH_INCLUDE_DIRS - the LibSSH include directory
#  LIBSSH_LIBRARY_DIR - the LibSSH library directory
#
#  Copyright (c) 2009 Andreas Schneider <asn@cryptomilk.org>
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

if (LIBSSH_LIBRARY_DIR AND LIBSSH_INCLUDE_DIRS)
  # in cache already
  set(LIBSSH_FOUND TRUE)
else (LIBSSH_LIBRARY_DIR AND LIBSSH_INCLUDE_DIRS)

  find_path(LIBSSH_INCLUDE_DIR
    NAMES
      libssh/libssh.h
    PATHS
      /usr/include
      /usr/local/include
      /opt/local/include
      /sw/include
      ${CMAKE_INCLUDE_PATH}
      ${CMAKE_INSTALL_PREFIX}/include
  )

  find_library(SSH_LIBRARY
    NAMES
      ssh.so
      libssh.so
    PATHS
      /usr/lib
      /usr/local/lib
      /opt/local/lib
      /sw/lib
      ${CMAKE_LIBRARY_PATH}
      ${CMAKE_INSTALL_PREFIX}/lib
  )

  if (LIBSSH_INCLUDE_DIR AND SSH_LIBRARY)
    set(SSH_FOUND TRUE)
  endif (LIBSSH_INCLUDE_DIR AND SSH_LIBRARY)

  set(LIBSSH_INCLUDE_DIRS
    ${LIBSSH_INCLUDE_DIR}
  )

  if (SSH_FOUND)
    string(REPLACE "libssh.so" ""
      LIBSSH_LIBRARY_DIR
      ${SSH_LIBRARY}
    )
    string(REPLACE "ssh.so" ""
      LIBSSH_LIBRARY_DIR
      ${LIBSSH_LIBRARY_DIR}
    )

    if (LibSSH_FIND_VERSION)
      file(STRINGS ${LIBSSH_INCLUDE_DIR}/libssh/libssh.h LIBSSH_VERSION_MAJOR
        REGEX "#define[ ]+LIBSSH_VERSION_MAJOR[ ]+[0-9]+")
      # Older versions of libssh like libssh-0.2 have LIBSSH_VERSION but not LIBSSH_VERSION_MAJOR
      if (LIBSSH_VERSION_MAJOR)
        string(REGEX MATCH "[0-9]+" LIBSSH_VERSION_MAJOR ${LIBSSH_VERSION_MAJOR})
	file(STRINGS ${LIBSSH_INCLUDE_DIR}/libssh/libssh.h LIBSSH_VERSION_MINOR
          REGEX "#define[ ]+LIBSSH_VERSION_MINOR[ ]+[0-9]+")
	string(REGEX MATCH "[0-9]+" LIBSSH_VERSION_MINOR ${LIBSSH_VERSION_MINOR})
	file(STRINGS ${LIBSSH_INCLUDE_DIR}/libssh/libssh.h LIBSSH_VERSION_PATCH
          REGEX "#define[ ]+LIBSSH_VERSION_MICRO[ ]+[0-9]+")
	string(REGEX MATCH "[0-9]+" LIBSSH_VERSION_PATCH ${LIBSSH_VERSION_PATCH})

	set(LibSSH_VERSION ${LIBSSH_VERSION_MAJOR}.${LIBSSH_VERSION_MINOR}.${LIBSSH_VERSION_PATCH})

	include(FindPackageVersionCheck)
	find_package_version_check(LibSSH DEFAULT_MSG)
      else (LIBSSH_VERSION_MAJOR)
        message(STATUS "LIBSSH_VERSION_MAJOR not found in ${LIBSSH_INCLUDE_DIR}/libssh/libssh.h, assuming libssh is too old")
        set(LIBSSH_FOUND FALSE)
      endif (LIBSSH_VERSION_MAJOR)
    endif (LibSSH_FIND_VERSION)
  endif (SSH_FOUND)

  # If the version is too old, but libs and includes are set,
  # find_package_handle_standard_args will set LIBSSH_FOUND to TRUE again,
  # so we need this if() here.
  if (LIBSSH_FOUND)
    include(FindPackageHandleStandardArgs)
    find_package_handle_standard_args(LibSSH DEFAULT_MSG LIBSSH_LIBRARY_DIR LIBSSH_INCLUDE_DIRS)
  endif (LIBSSH_FOUND)

  # show the LIBSSH_INCLUDE_DIRS and LIBSSH_LIBRARY_DIR variables only in the advanced view
  mark_as_advanced(LIBSSH_INCLUDE_DIRS LIBSSH_LIBRARY_DIR)

endif (LIBSSH_LIBRARY_DIR AND LIBSSH_INCLUDE_DIRS)

