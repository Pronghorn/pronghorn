CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
PROJECT(logserver)

INCLUDE_DIRECTORIES(../../include)
INCLUDE_DIRECTORIES(${glib_INCLUDE_DIRS})

LINK_DIRECTORIES(${glib_LIBRARY_DIRS})

SET(src_files logserver.c)

IF(COMPILE_AS_CXX)
  SET_SOURCE_FILES_PROPERTIES(${src_files} PROPERTIES LANGUAGE CXX)
ENDIF()

ADD_EXECUTABLE(logserver ${src_files})
TARGET_LINK_LIBRARIES(logserver glib-2.0)
TARGET_LINK_LIBRARIES(logserver libpronghorn)

INSTALL(TARGETS logserver DESTINATION pronghorn PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

