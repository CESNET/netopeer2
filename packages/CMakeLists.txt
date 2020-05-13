set(PACKAGE "netopeer2")
set(PACKAGE_BRIEF "NETCONF tools")
set(PACKAGE_DESC ${NETOPEER2_DESC})
set(PACKAGE_DBG_DESC "Debug symbols for the server and client.")

set(GITHUB_URL "https://github.com/cesnet/netopeer2")

# read install scripts into variables
file(READ "${SCRIPT_DIR}/setup.sh" SETUP_SH)
file(READ "${SCRIPT_DIR}/merge_hostkey.sh" MERGE_HOSTKEY_SH)
file(READ "${SCRIPT_DIR}/merge_config.sh" MERGE_CONFIG_SH)

# prepend required environment variables for setup
set(SETUP_SH "NP2_MODULE_DIR=/usr/share/yang/modules/netopeer2 NP2_MODULE_PERMS=660 NP2_MODULE_OWNER=root NP2_MODULE_GROUP=netconf\n${SETUP_SH}")

set(POSTINST_CMD1 "groupadd -f netconf")
set(POSTINST_CMD2 ${SETUP_SH})
set(POSTINST_CMD3 ${MERGE_HOSTKEY_SH})
set(POSTINST_CMD4 ${MERGE_CONFIG_SH})

find_program(DEB_BUILDER NAMES debuild)
find_program(RPM_BUILDER NAMES rpmbuild)

# setup package build
configure_file(${PROJECT_SOURCE_DIR}/packages/${PACKAGE}.spec.in ${PROJECT_BINARY_DIR}/build-packages/${PACKAGE}.spec)
configure_file(${PROJECT_SOURCE_DIR}/packages/${PACKAGE}.dsc.in ${PROJECT_BINARY_DIR}/build-packages/${PACKAGE}.dsc)
configure_file(${PROJECT_SOURCE_DIR}/packages/debian.control.in ${PROJECT_BINARY_DIR}/build-packages/debian.control @ONLY)
configure_file(${PROJECT_SOURCE_DIR}/packages/debian.rules.in ${PROJECT_BINARY_DIR}/build-packages/debian.rules)
configure_file(${PROJECT_SOURCE_DIR}/packages/debian.compat ${PROJECT_BINARY_DIR}/build-packages/debian.compat COPYONLY)
configure_file(${PROJECT_SOURCE_DIR}/packages/debian.copyright ${PROJECT_BINARY_DIR}/build-packages/debian.copyright COPYONLY)
configure_file(${PROJECT_SOURCE_DIR}/packages/debian.${PACKAGE}.install
               ${PROJECT_BINARY_DIR}/build-packages/debian.${PACKAGE}.install COPYONLY)
configure_file(${PROJECT_SOURCE_DIR}/packages/debian.postinst.in ${PROJECT_BINARY_DIR}/build-packages/debian.postinst @ONLY)

if(NOT DEB_BUILDER)
    message(STATUS "Missing tools (devscripts, debhelper package) for building DEB package.")
else()
    # target for local build deb package
    message(STATUS "To build local DEB package, use \"build-deb\" target.")
    add_custom_target(build-deb
                      WORKING_DIRECTORY ${PROJECT_BINARY_DIR}
                      COMMAND build-packages/local-deb.sh
    )
    configure_file(${PROJECT_SOURCE_DIR}/packages/local-deb.sh.in ${PROJECT_BINARY_DIR}/build-packages/local-deb.sh @ONLY)
endif()

if(NOT RPM_BUILDER)
    message(STATUS "Missing tools (rpm package) for building RPM package.")
else()
    # target for local build rpm package
    message(STATUS "To build local RPM package, use \"build-rpm\" target.")
    string(REPLACE ${PROJECT_SOURCE_DIR} "." EXCLUDE_BUILD_DIR ${PROJECT_BINARY_DIR})
    add_custom_target(build-rpm
                      WORKING_DIRECTORY ${PROJECT_BINARY_DIR}
                      COMMAND build-packages/local-rpm.sh
    )
    configure_file(${PROJECT_SOURCE_DIR}/packages/local-rpm.sh.in ${PROJECT_BINARY_DIR}/build-packages/local-rpm.sh @ONLY)
endif()
