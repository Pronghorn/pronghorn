CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
PROJECT(libpronghorn)

SET(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ../../libs)
SET(CMAKE_LIBRARY_OUTPUT_DIRECTORY ../../libs)

INCLUDE(FindPkgConfig)

PKG_CHECK_MODULES(zmq REQUIRED libzmq>=2.2.0)

if (NOT zmq_FOUND)
 MESSAGE(STATUS "Couldn't find libzmq>=2.2.0. You could try apt-get installing them (or similar for your distribution) but at time of writing they were only available via source download from http://www.zeromq.org/area:download")
ENDIF()

# This is required as the header files expect to find other libpronghorn
# header files in the include path and not local.
INCLUDE_DIRECTORIES(.)
INCLUDE_DIRECTORIES(../../include)
INCLUDE_DIRECTORIES(${glib_INCLUDE_DIRS})

LINK_DIRECTORIES(${glib_LIBRARY_DIRS})

SET(src_files logger.c lprocess.c transport.c lightmagic.c base_fuse.c config.c blocks.c sanity.c basename_safe.c prong_assert.c log.c contract.c block_range.c result.c report.c structures.pb-c.c)

IF(COMPILE_AS_CXX)
  SET_SOURCE_FILES_PROPERTIES(${src_files} PROPERTIES LANGUAGE CXX)
ENDIF()

ADD_LIBRARY(libpronghorn STATIC ${src_files})

TARGET_LINK_LIBRARIES(libpronghorn protobuf-c)
TARGET_LINK_LIBRARIES(libpronghorn zmq)
TARGET_LINK_LIBRARIES(libpronghorn glib-2.0)
TARGET_LINK_LIBRARIES(libpronghorn fuse)

SET_TARGET_PROPERTIES(libpronghorn PROPERTIES OUTPUT_NAME pronghorn)

FILE(MAKE_DIRECTORY ../../include)
FILE(GLOB headers *.h)
FOREACH(header ${headers})
  GET_FILENAME_COMPONENT(basename ${header} NAME)
  ADD_CUSTOM_COMMAND(TARGET libpronghorn POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy ${header} ../../include COMMENT "Copying libpronghorn header file '${basename}' to local include directory")
ENDFOREACH()

