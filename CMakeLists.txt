OPTION(COMPILE_AS_CXX "Forces compilation of the code with the CXX compiler (use for type-safe checking)")

CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
PROJECT(pronghorn)
SET(PRONGHORN_VERSION_MAJOR 0)
SET(PRONGHORN_VERSION_MINOR 9)


SET(CMAKE_BUILD_TYPE "DEBUG" CACHE STRING "Sets the build type")
STRING(TOUPPER "${CMAKE_BUILD_TYPE}" CMAKE_BUILD_TYPE)

IF(NOT CMAKE_BUILD_TYPE)
  SET(CMAKE_BUILD_TYPE "RELEASE")
ENDIF()

ADD_DEFINITIONS(-D_POSIX_C_SOURCE=200809L -D_FILE_OFFSET_BITS=64)

IF("${CMAKE_BUILD_TYPE}" STREQUAL DEBUG)
  MESSAGE(STATUS "Build type: DEBUG mode")
  ADD_DEFINITIONS(-DDEBUG)
ELSE()
  MESSAGE(STATUS "Build type: RELEASE mode")
  ADD_DEFINITIONS(-DNDEBUG)
ENDIF()

IF(CMAKE_COMPILER_IS_GNUCXX)
  IF("${CMAKE_BUILD_TYPE}" STREQUAL DEBUG)
    SET(CMAKE_C_FLAGS_${CMAKE_BUILD_TYPE} "-g -Wall -std=c99 -pedantic")
    SET(CMAKE_CXX_FLAGS_${CMAKE_BUILD_TYPE} "-g -Wall -std=c++0x -pedantic")
  ELSE()
    SET(CMAKE_C_FLAGS_${CMAKE_BUILD_TYPE} "-O2 -g -Wall -std=c99 -pedantic")
    SET(CMAKE_CXX_FLAGS_${CMAKE_BUILD_TYPE} "-O2 -g -Wall -std=c++0x -pedantic")
  ENDIF()
ENDIF()

SET(PRONGHORN_CONFIG_DIRECTORY "/etc/pronghorn" CACHE STRING "Where the configuration file will be installed")

# Can be redefined with cmake -DCMAKE_INSTALL_PREFIX=/foo
# NOTE if you set it then it will remain set until CMakeCache.txt is deleted (or edited)
MESSAGE(STATUS "***********************************************************************************")
MESSAGE(STATUS "* If you wish to change these values run cmake -i and change CMAKE_INSTALL_PREFIX *")
MESSAGE(STATUS "***********************************************************************************")
MESSAGE(STATUS "Installation prefix is ${CMAKE_INSTALL_PREFIX}")
MESSAGE(STATUS "Binaries and scripts will be installed into ${CMAKE_INSTALL_PREFIX}/pronghorn")
MESSAGE(STATUS "Subcontractors will be installed into ${CMAKE_INSTALL_PREFIX}/pronghorn/subcontractors")
MESSAGE(STATUS "The startup script will be installed into ${CMAKE_INSTALL_PREFIX}/bin")
MESSAGE(STATUS "The configuration file will be installed into ${PRONGHORN_CONFIG_DIRECTORY}")

# Global Dependency checking
MESSAGE(STATUS "Checking Basic Dependencies...")
INCLUDE(FindPkgConfig)

# Checking for glib
PKG_CHECK_MODULES(glib REQUIRED glib-2.0>=2.31.14)

if (NOT glib_FOUND)
 MESSAGE(STATUS "Couldn't find glib-2.0>=2.31.14. You could try apt-get install libglib2.0-dev (or as appropriate for your distribution).")
ENDIF()

SET(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR})

#Fuse
FIND_PACKAGE(FUSE)
IF(NOT FUSE_FOUND)
  MESSAGE(FATAL_ERROR "Could not find FUSE library! Install libfuse-dev")
ENDIF()

# Protobuf-c
FIND_PACKAGE(PROTOBUF-C)
IF(NOT PROTOBUF_FOUND)
    MESSAGE(FATAL_ERROR "Could not find PROTOBUF library! Install libprotobuf-c0-dev")
ENDIF()

# TSK
FIND_PACKAGE(TSK)
IF(NOT TSK_FOUND)
    MESSAGE(FATAL_ERROR "Could not find TSK library! Install libtsk-dev")
ENDIF()

# Adding all submodules
ADD_SUBDIRECTORY(config)
ADD_SUBDIRECTORY(src)

SET(CPACK_PACKAGING_INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX})

OPTION(DISABLE_DOC "Disables support for automatic docmentation")
IF(NOT DISABLE_DOC)
  ADD_SUBDIRECTORY(doc/source_doc)
ELSE()
  MESSAGE("Documentation support has been disabled")
ENDIF()

# uninstall target
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake_uninstall.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
    IMMEDIATE @ONLY)

add_custom_target(uninstall
    COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)

# Generate a debian package. invoke shlibdeps to automatically determine the dependencies.
SET(CPACK_GENERATOR "DEB")
SET(CPACK_PACKAGE_CONTACT "Department of Defence Australia")
SET(CPACK_PACKAGE_VERSION "${PRONGHORN_VERSION_MAJOR}.${PRONGHORN_VERSION_MINOR}")
SET(CPACK_PACKAGE_DESCRIPTION_SUMMARY "2012 DRFWS Forensic Challenge Submission by DSD Australia")
SET(CPACK_PACKAGE_DESCRIPTION "A submission for the 2012 DRFWS Forensic Challenge by the Defence Signals Directorate (DSD) Australia")

SET(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
SET(CPACK_DEBIAN_PACKAGE_VERSION "1:${CPACK_PACKAGE_VERSION}-ubuntu1")
SET(CPACK_DEBIAN_PACKAGE_SECTION "devel")
SET(CPACK_DEBIAN_PACKAGE_DESCRIPTION "${CPACK_PACKAGE_DESCRIPTION}")
SET(CPACK_DEBIAN_PACKAGE_DEPENDS "libprotobuf-c0, libglib2.0-0 (>=2.31.14), libfuse2, libzmq1 (>=2.2.0), libtsk3-3 (>=3.2.1), libarchive12, libexif12, libmagickcore4, libmagickwand4, libjbig2dec0, libcairo2, libgsl0ldbl, libavcodec53, libavformat53, libavutil51")
INCLUDE(CPack)

