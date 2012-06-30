CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
PROJECT(docs)

# add a target to generate API documentation with Doxygen
FIND_PACKAGE(Doxygen QUIET)
IF(DOXYGEN_FOUND)
  CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile.in ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile @ONLY)
  ADD_CUSTOM_TARGET(doc ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR} COMMENT "Generating API documentation with Doxygen" VERBATIM)
ELSE()
  MESSAGE(STATUS "Doxygen not found - documentation support disabled")
ENDIF()



