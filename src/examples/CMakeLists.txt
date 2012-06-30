CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
PROJECT(examples)

INCLUDE_DIRECTORIES(../../include)
INCLUDE_DIRECTORIES(${glib_INCLUDE_DIRS})

LINK_DIRECTORIES(${glib_LIBRARY_DIRS})

IF(COMPILE_AS_CXX)
  SET_SOURCE_FILES_PROPERTIES(configexample.c lightmagic_test.c transport_test.c configserver_test.c PROPERTIES LANGUAGE CXX)
ENDIF()

ADD_EXECUTABLE(configexample configexample.c)
TARGET_LINK_LIBRARIES(configexample glib-2.0)

ADD_EXECUTABLE(lightmagic_test lightmagic_test.c)
TARGET_LINK_LIBRARIES(lightmagic_test glib-2.0)
TARGET_LINK_LIBRARIES(lightmagic_test libpronghorn)

ADD_EXECUTABLE(transport_test transport_test.c)
TARGET_LINK_LIBRARIES(transport_test glib-2.0)
TARGET_LINK_LIBRARIES(transport_test libpronghorn)

ADD_EXECUTABLE(configserver_test configserver_test.c)
TARGET_LINK_LIBRARIES(configserver_test glib-2.0)
TARGET_LINK_LIBRARIES(configserver_test libpronghorn)

