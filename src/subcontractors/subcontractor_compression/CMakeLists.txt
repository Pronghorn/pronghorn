CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
PROJECT(subcontractor_compression)

INCLUDE(FindPkgConfig)
PKG_CHECK_MODULES(libarchive REQUIRED libarchive>=3.0.3) 

INCLUDE_DIRECTORIES(../../../include)
INCLUDE_DIRECTORIES(..)

INCLUDE_DIRECTORIES(${glib_INCLUDE_DIRS})
LINK_DIRECTORIES(${glib_LIBRARY_DIRS})

INCLUDE_DIRECTORIES(${libarchive_INCLUDE_DIRS})
LINK_DIRECTORIES(${libarchive_LIBRARY_DIRS})

SET(src_files subcontractor_compression.c ../subcontractor_helper.c)

IF(COMPILE_AS_CXX)
  SET_SOURCE_FILES_PROPERTIES(${src_files} PROPERTIES LANGUAGE CXX)
ENDIF()

ADD_EXECUTABLE(subcontractor_compression ${src_files})
TARGET_LINK_LIBRARIES(subcontractor_compression glib-2.0)
TARGET_LINK_LIBRARIES(subcontractor_compression libpronghorn)
TARGET_LINK_LIBRARIES(subcontractor_compression archive)

INSTALL(TARGETS subcontractor_compression DESTINATION pronghorn/subcontractors PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

