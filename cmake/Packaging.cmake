set(CPACK_PACKAGE_NAME "wardd")
set(CPACK_PACKAGE_VENDOR "Ginkgoty")
set(CPACK_PACKAGE_CONTACT "Ginkgoty <60060922+Ginkgoty@users.noreply.github.com>")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Lightweight Linux edge firewall control plane")
set(CPACK_PACKAGE_HOMEPAGE_URL "${PROJECT_HOMEPAGE_URL}")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_PACKAGE_DIRECTORY "${CMAKE_BINARY_DIR}/packages")
set(CPACK_PACKAGE_INSTALL_DIRECTORY "wardd")
set(CPACK_PACKAGE_RELOCATABLE OFF)
set(CPACK_STRIP_FILES ON)

set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "${CPACK_PACKAGE_CONTACT}")
set(CPACK_DEBIAN_PACKAGE_SECTION "net")
set(CPACK_DEBIAN_PACKAGE_PRIORITY "optional")
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
set(CPACK_DEBIAN_PACKAGE_DEPENDS "ca-certificates")
set(CPACK_DEBIAN_PACKAGE_RECOMMENDS "nginx")
set(CPACK_DEBIAN_PACKAGE_CONTROL_STRICT_PERMISSION ON)
set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA
    "${CMAKE_SOURCE_DIR}/packaging/debian/postinst"
    "${CMAKE_SOURCE_DIR}/packaging/debian/prerm"
    "${CMAKE_SOURCE_DIR}/packaging/debian/postrm"
)

set(CPACK_RPM_FILE_NAME RPM-DEFAULT)
set(CPACK_RPM_PACKAGE_GROUP "System Environment/Daemons")
set(CPACK_RPM_PACKAGE_DESCRIPTION
    "wardd compiles reviewed GeoIP policy for XDP and Nginx and maintains durable IP bans. It does not modify host or cloud firewall rules."
)
set(CPACK_RPM_PACKAGE_RELOCATABLE OFF)
# No repository-wide software license has been declared yet. Keep the package
# metadata explicit without choosing a license on the owner's behalf.
set(CPACK_RPM_PACKAGE_LICENSE "Unspecified")
set(CPACK_RPM_PACKAGE_AUTOREQPROV ON)
set(CPACK_RPM_PACKAGE_REQUIRES "ca-certificates")
set(CPACK_RPM_PACKAGE_RELEASE_DIST ON)
set(CPACK_RPM_POST_INSTALL_SCRIPT_FILE
    "${CMAKE_SOURCE_DIR}/packaging/rpm/post-install.sh"
)
set(CPACK_RPM_PRE_UNINSTALL_SCRIPT_FILE
    "${CMAKE_SOURCE_DIR}/packaging/rpm/pre-uninstall.sh"
)
set(CPACK_RPM_POST_UNINSTALL_SCRIPT_FILE
    "${CMAKE_SOURCE_DIR}/packaging/rpm/post-uninstall.sh"
)

if(WARDD_PACKAGE_CHANNEL STREQUAL "nightly")
    set(CPACK_DEBIAN_PACKAGE_VERSION
        "${PROJECT_VERSION}~nightly.${WARDD_PACKAGE_BUILD_ID}"
    )
    set(CPACK_DEBIAN_PACKAGE_RELEASE "1")
    set(CPACK_RPM_PACKAGE_RELEASE "0.nightly.${WARDD_PACKAGE_BUILD_ID}")
else()
    set(CPACK_DEBIAN_PACKAGE_VERSION "${PROJECT_VERSION}")
    set(CPACK_DEBIAN_PACKAGE_RELEASE "1")
    set(CPACK_RPM_PACKAGE_RELEASE "1")
endif()

include(CPack)
