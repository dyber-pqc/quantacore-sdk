#===============================================================================
# FindQuac100.cmake
# CMake Find Module for QuantaCore SDK (QUAC 100)
#
# This module finds the QuantaCore SDK installation and defines the following:
#
#   QUAC100_FOUND        - True if SDK was found
#   QUAC100_INCLUDE_DIRS - Include directories
#   QUAC100_LIBRARIES    - Libraries to link against
#   QUAC100_VERSION      - SDK version string
#   QUAC100_SIMULATOR    - Path to simulator library (if available)
#
# Imported Targets:
#   Quac100::quac100     - Main SDK library
#   Quac100::simulator   - Simulator library (if available)
#
# Hints:
#   QUAC100_ROOT         - Root directory of SDK installation
#   QUAC100_DIR          - Directory containing this file or SDK
#   ENV{QUAC100_HOME}    - Environment variable pointing to SDK
#
# Usage:
#   find_package(Quac100 REQUIRED)
#   target_link_libraries(myapp PRIVATE Quac100::quac100)
#
# Copyright (c) 2025 Dyber, Inc. All Rights Reserved.
#===============================================================================

# Prevent re-entry
if(QUAC100_FOUND)
    return()
endif()

#-------------------------------------------------------------------------------
# Search Paths
#-------------------------------------------------------------------------------

# Build search hints from various sources
set(_QUAC100_SEARCH_HINTS
    ${QUAC100_ROOT}
    ${QUAC100_DIR}
    $ENV{QUAC100_HOME}
    $ENV{QUAC100_ROOT}
)

# Platform-specific default paths
if(WIN32)
    list(APPEND _QUAC100_SEARCH_PATHS
        "C:/Program Files/Dyber/QuantaCore SDK"
        "C:/Program Files (x86)/Dyber/QuantaCore SDK"
        "$ENV{ProgramFiles}/Dyber/QuantaCore SDK"
        "$ENV{LOCALAPPDATA}/Dyber/QuantaCore SDK"
    )
else()
    list(APPEND _QUAC100_SEARCH_PATHS
        /usr/local
        /usr
        /opt/dyber/quantacore-sdk
        /opt/quantacore-sdk
        $ENV{HOME}/.local
    )
endif()

#-------------------------------------------------------------------------------
# Find Include Directory
#-------------------------------------------------------------------------------

find_path(QUAC100_INCLUDE_DIR
    NAMES quac100.h
    HINTS ${_QUAC100_SEARCH_HINTS}
    PATHS ${_QUAC100_SEARCH_PATHS}
    PATH_SUFFIXES include
    DOC "QuantaCore SDK include directory"
)

#-------------------------------------------------------------------------------
# Find Libraries
#-------------------------------------------------------------------------------

# Determine library names based on platform
if(WIN32)
    set(_QUAC100_LIB_NAMES quac100 libquac100)
    set(_QUAC100_SIM_NAMES quac100_sim libquac100_sim)
else()
    set(_QUAC100_LIB_NAMES quac100)
    set(_QUAC100_SIM_NAMES quac100_sim)
endif()

# Find main library
find_library(QUAC100_LIBRARY
    NAMES ${_QUAC100_LIB_NAMES}
    HINTS ${_QUAC100_SEARCH_HINTS}
    PATHS ${_QUAC100_SEARCH_PATHS}
    PATH_SUFFIXES lib lib64 lib/x86_64 lib/aarch64
    DOC "QuantaCore SDK main library"
)

# Find simulator library (optional)
find_library(QUAC100_SIMULATOR_LIBRARY
    NAMES ${_QUAC100_SIM_NAMES}
    HINTS ${_QUAC100_SEARCH_HINTS}
    PATHS ${_QUAC100_SEARCH_PATHS}
    PATH_SUFFIXES lib lib64 lib/x86_64 lib/aarch64
    DOC "QuantaCore SDK simulator library"
)

#-------------------------------------------------------------------------------
# Extract Version
#-------------------------------------------------------------------------------

if(QUAC100_INCLUDE_DIR)
    # Try to find version from quac100_version.h
    set(_QUAC100_VERSION_HEADER "${QUAC100_INCLUDE_DIR}/quac100_version.h")
    
    if(EXISTS "${_QUAC100_VERSION_HEADER}")
        file(STRINGS "${_QUAC100_VERSION_HEADER}" _QUAC100_VERSION_MAJOR_LINE
            REGEX "^#define[ \t]+QUAC100_VERSION_MAJOR[ \t]+[0-9]+")
        file(STRINGS "${_QUAC100_VERSION_HEADER}" _QUAC100_VERSION_MINOR_LINE
            REGEX "^#define[ \t]+QUAC100_VERSION_MINOR[ \t]+[0-9]+")
        file(STRINGS "${_QUAC100_VERSION_HEADER}" _QUAC100_VERSION_PATCH_LINE
            REGEX "^#define[ \t]+QUAC100_VERSION_PATCH[ \t]+[0-9]+")
        
        if(_QUAC100_VERSION_MAJOR_LINE)
            string(REGEX REPLACE "^#define[ \t]+QUAC100_VERSION_MAJOR[ \t]+([0-9]+).*" "\\1"
                QUAC100_VERSION_MAJOR "${_QUAC100_VERSION_MAJOR_LINE}")
        endif()
        if(_QUAC100_VERSION_MINOR_LINE)
            string(REGEX REPLACE "^#define[ \t]+QUAC100_VERSION_MINOR[ \t]+([0-9]+).*" "\\1"
                QUAC100_VERSION_MINOR "${_QUAC100_VERSION_MINOR_LINE}")
        endif()
        if(_QUAC100_VERSION_PATCH_LINE)
            string(REGEX REPLACE "^#define[ \t]+QUAC100_VERSION_PATCH[ \t]+([0-9]+).*" "\\1"
                QUAC100_VERSION_PATCH "${_QUAC100_VERSION_PATCH_LINE}")
        endif()
        
        if(DEFINED QUAC100_VERSION_MAJOR AND DEFINED QUAC100_VERSION_MINOR AND DEFINED QUAC100_VERSION_PATCH)
            set(QUAC100_VERSION "${QUAC100_VERSION_MAJOR}.${QUAC100_VERSION_MINOR}.${QUAC100_VERSION_PATCH}")
        endif()
        
        unset(_QUAC100_VERSION_MAJOR_LINE)
        unset(_QUAC100_VERSION_MINOR_LINE)
        unset(_QUAC100_VERSION_PATCH_LINE)
    endif()
    
    # Fallback: try VERSION file
    if(NOT DEFINED QUAC100_VERSION)
        get_filename_component(_QUAC100_ROOT "${QUAC100_INCLUDE_DIR}" DIRECTORY)
        set(_QUAC100_VERSION_FILE "${_QUAC100_ROOT}/VERSION")
        
        if(EXISTS "${_QUAC100_VERSION_FILE}")
            file(READ "${_QUAC100_VERSION_FILE}" QUAC100_VERSION)
            string(STRIP "${QUAC100_VERSION}" QUAC100_VERSION)
        endif()
        
        unset(_QUAC100_ROOT)
        unset(_QUAC100_VERSION_FILE)
    endif()
endif()

# Default version if not found
if(NOT DEFINED QUAC100_VERSION)
    set(QUAC100_VERSION "0.0.0")
endif()

#-------------------------------------------------------------------------------
# Handle Standard Args
#-------------------------------------------------------------------------------

include(FindPackageHandleStandardArgs)

find_package_handle_standard_args(Quac100
    REQUIRED_VARS
        QUAC100_LIBRARY
        QUAC100_INCLUDE_DIR
    VERSION_VAR
        QUAC100_VERSION
    HANDLE_COMPONENTS
)

#-------------------------------------------------------------------------------
# Set Output Variables
#-------------------------------------------------------------------------------

if(QUAC100_FOUND)
    set(QUAC100_INCLUDE_DIRS ${QUAC100_INCLUDE_DIR})
    set(QUAC100_LIBRARIES ${QUAC100_LIBRARY})
    
    if(QUAC100_SIMULATOR_LIBRARY)
        set(QUAC100_SIMULATOR ${QUAC100_SIMULATOR_LIBRARY})
        set(QUAC100_SIMULATOR_FOUND TRUE)
    else()
        set(QUAC100_SIMULATOR_FOUND FALSE)
    endif()
    
    #---------------------------------------------------------------------------
    # Create Imported Targets
    #---------------------------------------------------------------------------
    
    # Main library target
    if(NOT TARGET Quac100::quac100)
        add_library(Quac100::quac100 UNKNOWN IMPORTED)
        
        set_target_properties(Quac100::quac100 PROPERTIES
            IMPORTED_LOCATION "${QUAC100_LIBRARY}"
            INTERFACE_INCLUDE_DIRECTORIES "${QUAC100_INCLUDE_DIR}"
        )
        
        # Platform-specific dependencies
        if(WIN32)
            set_property(TARGET Quac100::quac100 APPEND PROPERTY
                INTERFACE_LINK_LIBRARIES setupapi cfgmgr32)
        elseif(UNIX)
            find_package(Threads QUIET)
            if(Threads_FOUND)
                set_property(TARGET Quac100::quac100 APPEND PROPERTY
                    INTERFACE_LINK_LIBRARIES Threads::Threads dl)
            endif()
        endif()
    endif()
    
    # Simulator library target (optional)
    if(QUAC100_SIMULATOR_FOUND AND NOT TARGET Quac100::simulator)
        add_library(Quac100::simulator UNKNOWN IMPORTED)
        
        set_target_properties(Quac100::simulator PROPERTIES
            IMPORTED_LOCATION "${QUAC100_SIMULATOR_LIBRARY}"
            INTERFACE_INCLUDE_DIRECTORIES "${QUAC100_INCLUDE_DIR}"
            INTERFACE_LINK_LIBRARIES Quac100::quac100
        )
    endif()
endif()

#-------------------------------------------------------------------------------
# Cleanup
#-------------------------------------------------------------------------------

unset(_QUAC100_SEARCH_HINTS)
unset(_QUAC100_SEARCH_PATHS)
unset(_QUAC100_LIB_NAMES)
unset(_QUAC100_SIM_NAMES)
unset(_QUAC100_VERSION_HEADER)

# Mark advanced variables
mark_as_advanced(
    QUAC100_INCLUDE_DIR
    QUAC100_LIBRARY
    QUAC100_SIMULATOR_LIBRARY
)