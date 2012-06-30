CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
PROJECT(subcontractors)

INCLUDE(FindPkgConfig)
PKG_CHECK_MODULES(cairo REQUIRED cairo) # Required for subcontractor_pdf
PKG_CHECK_MODULES(poppler-glib REQUIRED poppler-glib) # Required for subcontractor_pdf

INCLUDE_DIRECTORIES(../../../include)
INCLUDE_DIRECTORIES(..)

INCLUDE_DIRECTORIES(${glib_INCLUDE_DIRS})
LINK_DIRECTORIES(${glib_LIBRARY_DIRS})

INCLUDE_DIRECTORIES(${cairo_INCLUDE_DIRS})
INCLUDE_DIRECTORIES(${poppler-glib_INCLUDE_DIRS})

SET(src_files subcontractor_pdf.c ../subcontractor_helper.c)

IF(COMPILE_AS_CXX)
  SET_SOURCE_FILES_PROPERTIES(${src_files} PROPERTIES LANGUAGE CXX)
ENDIF()

ADD_EXECUTABLE(subcontractor_pdf ${src_files})
TARGET_LINK_LIBRARIES(subcontractor_pdf glib-2.0)
TARGET_LINK_LIBRARIES(subcontractor_pdf libpronghorn)
TARGET_LINK_LIBRARIES(subcontractor_pdf cairo)
TARGET_LINK_LIBRARIES(subcontractor_pdf poppler-glib)

INSTALL(TARGETS subcontractor_pdf DESTINATION pronghorn/subcontractors PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

