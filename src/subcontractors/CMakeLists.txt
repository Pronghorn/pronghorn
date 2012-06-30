CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
PROJECT(subcontractors)

# Add the development and testing directory
IF("${CMAKE_BUILD_TYPE}" STREQUAL DEBUG)
  ADD_SUBDIRECTORY(development_and_testing)
ENDIF()

FILE(GLOB sub-dir ${CMAKE_CURRENT_SOURCE_DIR}/subcontractor_*)

LIST(REMOVE_ITEM sub-dir ${CMAKE_CURRENT_SOURCE_DIR}/subcontractor_helper.h ${CMAKE_CURRENT_SOURCE_DIR}/subcontractor_helper.c)

MESSAGE(STATUS "Scanning for modules to include into build system")
MESSAGE(STATUS "To disable a module use cmake -i")
MESSAGE(STATUS "")

FOREACH(dir ${sub-dir})
  GET_FILENAME_COMPONENT(basename ${dir} NAME)
  STRING(TOUPPER "DISABLE_${basename}" disable-subcontractor-option)

  OPTION(${disable-subcontractor-option} "Disables support for module ${basename}")

  IF(NOT ${disable-subcontractor-option})
    MESSAGE(STATUS "Adding module ${basename}")
    ADD_SUBDIRECTORY(${dir})
  ELSE()
    MESSAGE(STATUS " *** Disabling support for module ${basename} ***")
  ENDIF()
ENDFOREACH()

MESSAGE(STATUS "")
MESSAGE(STATUS "Finished module scan")
MESSAGE(STATUS "")

