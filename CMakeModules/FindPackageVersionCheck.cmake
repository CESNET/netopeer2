# FIND_PACKAGE_VERSION_CHECK(NAME (DEFAULT_MSG|"Custom failure message"))
#    This function is intended to be used in FindXXX.cmake modules files.
#    It handles NAME_FIND_VERSION and NAME_VERSION variables in a Module.
#
#    Example:
#    find_package(LibSSH 0.3.2)
#
#    # check for the version and set it
#    set(LibSSH_VERSION 0.3.0)
#    find_package_version_check(LibSSH DEFAULT_MSG)
#
#
# Copyright (c) 2009 Andreas Schneider <mail@cynapses.org>
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

function(FIND_PACKAGE_VERSION_CHECK _NAME _FAIL_MSG)
  string(TOUPPER ${_NAME} _NAME_UPPER)
  set(_AGE "old")

  if(${_NAME}_FIND_VERSION_EXACT)
    if (${_NAME}_FIND_VERSION VERSION_EQUAL ${_NAME}_VERSION)
      # exact version found
      set(${_NAME_UPPER}_FOUND TRUE)
    else (${_NAME}_FIND_VERSION VERSION_EQUAL ${_NAME}_VERSION)
      # exect version not found
      set(${_NAME_UPPER}_FOUND FALSE)
      # check if newer or older
      if (${_NAME}_FIND_VERSION VERSION_LESS ${_NAME}_VERSION)
        set(_AGE "new")
      else (${_NAME}_FIND_VERSION VERSION_LESS ${_NAME}_VERSION)
        set(_AGE "old")
      endif (${_NAME}_FIND_VERSION VERSION_LESS ${_NAME}_VERSION)
    endif (${_NAME}_FIND_VERSION VERSION_EQUAL ${_NAME}_VERSION)
  else (${_NAME}_FIND_VERSION_EXACT)
    if (${_NAME}_FIND_VERSION)
      if (${_NAME}_VERSION VERSION_LESS ${_NAME}_FIND_VERSION)
        set(${_NAME_UPPER}_FOUND FALSE)
        set(_AGE "old")
      else (${_NAME}_VERSION VERSION_LESS ${_NAME}_FIND_VERSION)
        set(${_NAME_UPPER}_FOUND TRUE)
     endif (${_NAME}_VERSION VERSION_LESS ${_NAME}_FIND_VERSION)
    endif (${_NAME}_FIND_VERSION)
  endif(${_NAME}_FIND_VERSION_EXACT)

  if ("${_FAIL_MSG}" STREQUAL "DEFAULT_MSG")
    if (${_NAME}_FIND_VERSION_EXACT)
      set(_FAIL_MESSAGE "The installed ${_NAME} version ${${_NAME}_VERSION} is too ${_AGE}, version ${${_NAME}_FIND_VERSION} is required.")
    else (${_NAME}_FIND_VERSION_EXACT)
      set(_FAIL_MESSAGE "The installed ${_NAME} version ${${_NAME}_VERSION} is too ${_AGE}, at least version ${${_NAME}_FIND_VERSION} is required.")
    endif (${_NAME}_FIND_VERSION_EXACT)
  else ("${_FAIL_MSG}" STREQUAL "DEFAULT_MSG")
    set(_FAIL_MESSAGE "${_FAIL_MSG}")
  endif ("${_FAIL_MSG}" STREQUAL "DEFAULT_MSG")

  if (NOT ${_NAME_UPPER}_FOUND)
    if (${_NAME}_FIND_REQUIRED)
      message(FATAL_ERROR "${_FAIL_MESSAGE}")
    else (${_NAME}_FIND_REQUIRED)
      if (NOT ${_NAME}_FIND_QUIETLY)
        message(STATUS "${_FAIL_MESSAGE}")
      endif (NOT ${_NAME}_FIND_QUIETLY)
    endif (${_NAME}_FIND_REQUIRED)
  endif (NOT ${_NAME_UPPER}_FOUND)

  set(${_NAME_UPPER}_FOUND ${${_NAME_UPPER}_FOUND} PARENT_SCOPE)
endfunction(FIND_PACKAGE_VERSION_CHECK)
