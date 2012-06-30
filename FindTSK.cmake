#------------------------------------------------------------------------------
#
#  Copyright (C) 2010  Artem Rodygin
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#------------------------------------------------------------------------------
#
#  This module finds if C API of TSK library is installed and determines where required
#  include files and libraries are. The module sets the following variables:
#
#    TSK_FOUND         - system has TSK
#    TSK_INCLUDE_DIR   - the TSK include directory
#    TSK_LIBRARIES     - the libraries needed to use TSK
#    TSK_DEFINITIONS   - the compiler definitions, required for building with TSK
#    TSK_VERSION_MAJOR - the major version of the TSK release
#    TSK_VERSION_MINOR - the minor version of the TSK release
#
#  You can help the module to find TSK by specifying its root path
#  in environment variable named "TSK_ROOTDIR". If this variable is not set
#  then module will search for files in "/usr/local" and "/usr" by default.
#
#------------------------------------------------------------------------------

set(TSK_FOUND TRUE)

# search for header

find_path(TSK_INCLUDE_DIR
          NAMES "tsk3/libtsk.h"
                "tsk3/base/tsk_base.h"
          PATHS "/usr/local"
                "/usr"
          ENV TSK_ROOTDIR
          PATH_SUFFIXES "include")

# header is found

if (TSK_INCLUDE_DIR)

    set(TSK_INCLUDE_DIR "${TSK_INCLUDE_DIR}/tsk3")

    # retrieve version information from the header

    file(READ "${TSK_INCLUDE_DIR}/base/tsk_base.h" TSK_BASE_H_FILE)

    string(REGEX REPLACE ".*#define[ \t]+TSK_VERSION_STR[ \t]+\"([0-9]+).*" "\\1" TSK_VERSION_MAJOR "${TSK_BASE_H_FILE}")
    string(REGEX REPLACE ".*#define[ \t]+TSK_VERSION_STR[ \t]+\"[0-9]+.([0-9]+).*" "\\1" TSK_VERSION_MINOR "${TSK_BASE_H_FILE}")

    # search for library

    find_library(TSK_LIBRARIES
                 NAMES "libtsk3.so"
                 PATHS "/usr/local"
                       "/usr"
                 ENV TSK_ROOTDIR
                 PATH_SUFFIXES "lib")

endif (TSK_INCLUDE_DIR)

# header is not found

if (NOT TSK_INCLUDE_DIR)
    set(TSK_FOUND FALSE)
endif (NOT TSK_INCLUDE_DIR)

# library is not found

if (NOT TSK_LIBRARIES)
    set(TSK_FOUND FALSE)
endif (NOT TSK_LIBRARIES)

# set default error message

if (TSK_FIND_VERSION)
    set(TSK_ERROR_MESSAGE "Unable to find TSK library v${TSK_FIND_VERSION}")
else (TSK_FIND_VERSION)
    set(TSK_ERROR_MESSAGE "Unable to find TSK library")
endif (TSK_FIND_VERSION)

# check found version

if (TSK_FIND_VERSION AND TSK_FOUND)

    set(TSK_FOUND_VERSION "${TSK_VERSION_MAJOR}.${TSK_VERSION_MINOR}")

    if (TSK_FIND_VERSION_EXACT)
        if (NOT ${TSK_FOUND_VERSION} VERSION_EQUAL ${TSK_FIND_VERSION})
            set(TSK_FOUND FALSE)
        endif (NOT ${TSK_FOUND_VERSION} VERSION_EQUAL ${TSK_FIND_VERSION})
    else (TSK_FIND_VERSION_EXACT)
        if (${TSK_FOUND_VERSION} VERSION_LESS ${TSK_FIND_VERSION})
            set(TSK_FOUND FALSE)
        endif (${TSK_FOUND_VERSION} VERSION_LESS ${TSK_FIND_VERSION})
    endif (TSK_FIND_VERSION_EXACT)

    if (NOT TSK_FOUND)
        set(TSK_ERROR_MESSAGE "Unable to find TSK library v${TSK_FIND_VERSION} (${TSK_FOUND_VERSION} was found)")
    endif (NOT TSK_FOUND)

endif (TSK_FIND_VERSION AND TSK_FOUND)

# add definitions

if (TSK_FOUND)

    if (CMAKE_SYSTEM_PROCESSOR MATCHES ia64)
        set(TSK_DEFINITIONS "-D_REENTRANT -D_FILE_OFFSET_BITS=64")
    elseif (CMAKE_SYSTEM_PROCESSOR MATCHES amd64)
        set(TSK_DEFINITIONS "-D_REENTRANT -D_FILE_OFFSET_BITS=64")
    elseif (CMAKE_SYSTEM_PROCESSOR MATCHES x86_64)
        set(TSK_DEFINITIONS "-D_REENTRANT -D_FILE_OFFSET_BITS=64")
    else (CMAKE_SYSTEM_PROCESSOR MATCHES ia64)
        set(TSK_DEFINITIONS "-D_REENTRANT")
    endif (CMAKE_SYSTEM_PROCESSOR MATCHES ia64)

endif (TSK_FOUND)

# final status messages

if (TSK_FOUND)

    if (NOT TSK_FIND_QUIETLY)
        message(STATUS "TSK ${TSK_VERSION_MAJOR}.${TSK_VERSION_MINOR}")
    endif (NOT TSK_FIND_QUIETLY)

    mark_as_advanced(TSK_INCLUDE_DIR
                     TSK_LIBRARIES
                     TSK_DEFINITIONS)

else (TSK_FOUND)

    if (TSK_FIND_REQUIRED)
        message(SEND_ERROR "${TSK_ERROR_MESSAGE}")
    endif (TSK_FIND_REQUIRED)

endif (TSK_FOUND)
