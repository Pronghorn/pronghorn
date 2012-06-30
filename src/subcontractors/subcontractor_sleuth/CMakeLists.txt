CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
PROJECT(subcontractor_sleuth)

INCLUDE_DIRECTORIES(..)
INCLUDE_DIRECTORIES(../../../include)

# tsk doesn't register with pkg-config. We can't seem to do this yet
#PKG_CHECK_MODULES(tsk REQUIRED libtsk>=3.2.1)

INCLUDE_DIRECTORIES(${glib_INCLUDE_DIRS})
LINK_DIRECTORIES(${glib_LIBRARY_DIRS})

SET(src_files subcontractor_sleuth.c ../subcontractor_helper.c)

IF(COMPILE_AS_CXX)
  SET_SOURCE_FILES_PROPERTIES(${src_files} PROPERTIES LANGUAGE CXX)
ENDIF()

ADD_EXECUTABLE(subcontractor_sleuth ${src_files})
TARGET_LINK_LIBRARIES(subcontractor_sleuth glib-2.0)
TARGET_LINK_LIBRARIES(subcontractor_sleuth libpronghorn)
TARGET_LINK_LIBRARIES(subcontractor_sleuth tsk3)
TARGET_LINK_LIBRARIES(subcontractor_sleuth stdc++)

INSTALL(TARGETS subcontractor_sleuth DESTINATION pronghorn/subcontractors PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

