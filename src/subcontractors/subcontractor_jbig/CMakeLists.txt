CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
PROJECT(subcontractor_jbig)

INCLUDE(FindPkgConfig)

INCLUDE_DIRECTORIES(../../../include)
INCLUDE_DIRECTORIES(..)
INCLUDE_DIRECTORIES(${glib_INCLUDE_DIRS})

LINK_DIRECTORIES(${glib_LIBRARY_DIRS})

SET(src_files subcontractor_jbig.c ../subcontractor_helper.c)

IF(COMPILE_AS_CXX)
  SET_SOURCE_FILES_PROPERTIES(${src_files} PROPERTIES LANGUAGE CXX)
ENDIF()

ADD_EXECUTABLE(subcontractor_jbig ${src_files})
TARGET_LINK_LIBRARIES(subcontractor_jbig glib-2.0)
TARGET_LINK_LIBRARIES(subcontractor_jbig libjbig)
TARGET_LINK_LIBRARIES(subcontractor_jbig libpronghorn)

INSTALL(TARGETS subcontractor_jbig DESTINATION pronghorn/subcontractors PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

