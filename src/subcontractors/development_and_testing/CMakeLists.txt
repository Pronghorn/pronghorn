CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
PROJECT(subcontractor_dev_testing)

INCLUDE_DIRECTORIES(../../../include)
INCLUDE_DIRECTORIES(..)
INCLUDE_DIRECTORIES(${glib_INCLUDE_DIRS})
LINK_DIRECTORIES(${glib_LIBRARY_DIRS})

IF(COMPILE_AS_CXX)
  SET_SOURCE_FILES_PROPERTIES(test_harness.c subcontractor_template.c ../subcontractor_helper.c subcontractor_test_invalid_contracts.c subcontractor_test_crash.c subcontractor_test_hang.c subcontractor_confidence_25.c subcontractor_confidence_50.c subcontractor_confidence_75.c ${src_files} PROPERTIES LANGUAGE CXX)
ENDIF()

ADD_EXECUTABLE(test_harness test_harness.c)
TARGET_LINK_LIBRARIES(test_harness glib-2.0)
TARGET_LINK_LIBRARIES(test_harness libpronghorn)

# The "do nothing" sub contractor

ADD_EXECUTABLE(subcontractor_template subcontractor_template.c ../subcontractor_helper.c)
TARGET_LINK_LIBRARIES(subcontractor_template glib-2.0)
TARGET_LINK_LIBRARIES(subcontractor_template libpronghorn)

# Intentionally misbehaving sub contractors

ADD_EXECUTABLE(subcontractor_test_invalid_contracts subcontractor_test_invalid_contracts.c ../subcontractor_helper.c)
TARGET_LINK_LIBRARIES(subcontractor_test_invalid_contracts glib-2.0)
TARGET_LINK_LIBRARIES(subcontractor_test_invalid_contracts libpronghorn)

ADD_EXECUTABLE(subcontractor_test_crash subcontractor_test_crash.c ../subcontractor_helper.c)
TARGET_LINK_LIBRARIES(subcontractor_test_crash glib-2.0)
TARGET_LINK_LIBRARIES(subcontractor_test_crash libpronghorn)

ADD_EXECUTABLE(subcontractor_test_hang subcontractor_test_hang.c ../subcontractor_helper.c)
TARGET_LINK_LIBRARIES(subcontractor_test_hang glib-2.0)
TARGET_LINK_LIBRARIES(subcontractor_test_hang libpronghorn)

