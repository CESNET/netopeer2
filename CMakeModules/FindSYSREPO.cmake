#  SYSREPO_FOUND - System has SYSREPO
#  SYSREPO_INCLUDE_DIRS - The SYSREPO include directories
#  SYSREPO_LIBRARIES - The libraries needed to use SYSREPO
#  SYSREPO_DEFINITIONS - Compiler switches required for using SYSREPO

find_package(PkgConfig)
if (SYSREPO_FIND_REQUIRED)
    set(find_sysrepo_options REQUIRED)
elseif (SYSREPO_FIND_QUIETLY)
    set(find_sysrepo_options QUIET)
else()
    set(find_sysrepo_options)
endif()
mark_as_advanced(find_sysrepo_options)
pkg_check_modules(PC_SYSREPO libsysrepo ${find_sysrepo_options})
set(SYSREPO_INCLUDE_DIRS "${PC_SYSREPO_INCLUDE_DIRS}")
set(SYSREPO_DEFINITIONS "${PC_SYSREPO_DEFINITIONS}")
foreach(sysrepo_lib ${PC_SYSREPO_LIBRARIES})
    find_library(sysrepo_lib_${sysrepo_lib} NAMES ${sysrepo_lib} PATHS ${PC_SYSREPO_LIBDIR} ${find_sysrepo_options})
    mark_as_advanced(sysrepo_lib_${sysrepo_lib})
    list(APPEND SYSREPO_LIBRARIES ${sysrepo_lib_${sysrepo_lib}})
endforeach()

include(FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set SYSREPO_FOUND to TRUE
# if all listed variables are TRUE
find_package_handle_standard_args(sysrepo DEFAULT_MSG
                                  SYSREPO_LIBRARIES SYSREPO_INCLUDE_DIRS)
