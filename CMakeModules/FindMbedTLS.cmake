# - Try to find MbedTLS
# Once done this will define
#
#  MBEDTLS_FOUND - MbedTLS was found
#  MBEDTLS_INCLUDE_DIRS - MbedTLS include directories
#  MBEDTLS_LIBRARIES - link these to use MbedTLS
#  MBEDTLS_VERSION - version of MbedTLS
#
#  Author Roman Janota <janota@cesnet.cz>
#  Copyright (c) 2025 CESNET, z.s.p.o.
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
include(FindPackageHandleStandardArgs)

if(MBEDTLS_LIBRARIES AND MBEDTLS_INCLUDE_DIRS)
    # in cache already
    set(MBEDTLS_FOUND TRUE)
else()
    find_path(MBEDTLS_INCLUDE_DIR
        NAMES
            mbedtls/ssl.h
        PATHS
            /opt/local/include
            /sw/include
            ${CMAKE_INCLUDE_PATH}
            ${CMAKE_INSTALL_PREFIX}/include
    )

    find_library(MBEDTLS_LIBRARY
        NAMES
            libmbedtls.so
        PATHS
            /usr/lib
            /usr/lib64
            /opt/local/lib
            /sw/lib
            ${CMAKE_LIBRARY_PATH}
            ${CMAKE_INSTALL_PREFIX}/lib
    )

    find_library(MBEDX509_LIBRARY
        NAMES
            libmbedx509.so
        PATHS
            /usr/lib
            /usr/lib64
            /opt/local/lib
            /sw/lib
            ${CMAKE_LIBRARY_PATH}
            ${CMAKE_INSTALL_PREFIX}/lib
    )

    find_library(MBEDCRYPTO_LIBRARY
        NAMES
            libmbedcrypto.so
        PATHS
            /usr/lib
            /usr/lib64
            /opt/local/lib
            /sw/lib
            ${CMAKE_LIBRARY_PATH}
            ${CMAKE_INSTALL_PREFIX}/lib
    )

    if(MBEDTLS_INCLUDE_DIR AND MBEDTLS_LIBRARY AND MBEDX509_LIBRARY AND MBEDCRYPTO_LIBRARY)
        # learn MbedTLS version
        if(EXISTS "${MBEDTLS_INCLUDE_DIR}/mbedtls/build_info.h")
            file(STRINGS "${MBEDTLS_INCLUDE_DIR}/mbedtls/build_info.h" MBEDTLS_VERSION
                REGEX "#define[ \t]+MBEDTLS_VERSION_STRING[ \t]+\"([0-9]+\.[0-9]+\.[0-9]+)\"")
            string(REGEX MATCH "[0-9]+\\.[0-9]+\\.[0-9]+" MBEDTLS_VERSION ${MBEDTLS_VERSION})
        endif()
        if(NOT MBEDTLS_VERSION)
            message(STATUS "MBEDTLS_VERSION not found, assuming MbedTLS is too old and cannot be used!")
            set(MBEDTLS_INCLUDE_DIR "MBEDTLS_INCLUDE_DIR-NOTFOUND")
            set(MBEDTLS_LIBRARY "MBEDTLS_LIBRARY-NOTFOUND")
        endif()
    endif()

    set(MBEDTLS_INCLUDE_DIRS ${MBEDTLS_INCLUDE_DIR})
    set(MBEDTLS_LIBRARIES ${MBEDTLS_LIBRARY} ${MBEDX509_LIBRARY} ${MBEDCRYPTO_LIBRARY})

    find_package_handle_standard_args(MbedTLS FOUND_VAR MBEDTLS_FOUND
        REQUIRED_VARS MBEDTLS_INCLUDE_DIRS MBEDTLS_LIBRARIES
        VERSION_VAR MBEDTLS_VERSION)

    # show the MBEDTLS_INCLUDE_DIR and MBEDTLS_LIBRARIES variables only in the advanced view
    mark_as_advanced(MBEDTLS_INCLUDE_DIRS MBEDTLS_LIBRARIES)
endif()
