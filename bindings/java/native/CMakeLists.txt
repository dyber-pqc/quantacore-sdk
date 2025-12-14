# QUAC 100 Java JNI Library - Cross-Platform Build
# Copyright © 2025 Dyber, Inc. All Rights Reserved.

cmake_minimum_required(VERSION 3.16)
project(quac100_jni C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# =============================================================================
# Platform Detection
# =============================================================================
if(WIN32)
    set(QUAC_PLATFORM "windows")
    set(QUAC_LIB_PREFIX "")
    set(QUAC_LIB_SUFFIX ".dll")
    set(QUAC_STATIC_SUFFIX ".lib")
elseif(APPLE)
    set(QUAC_PLATFORM "macos")
    set(QUAC_LIB_PREFIX "lib")
    set(QUAC_LIB_SUFFIX ".dylib")
    set(QUAC_STATIC_SUFFIX ".a")
else()
    set(QUAC_PLATFORM "linux")
    set(QUAC_LIB_PREFIX "lib")
    set(QUAC_LIB_SUFFIX ".so")
    set(QUAC_STATIC_SUFFIX ".a")
endif()

# Architecture detection
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(QUAC_ARCH "x64")
else()
    set(QUAC_ARCH "x86")
endif()

set(QUAC_PLATFORM_ARCH "${QUAC_PLATFORM}-${QUAC_ARCH}")

# =============================================================================
# Find JNI
# =============================================================================
find_package(JNI REQUIRED)

if(NOT JNI_FOUND)
    message(FATAL_ERROR "JNI not found. Please set JAVA_HOME.")
endif()

message(STATUS "JNI Include: ${JNI_INCLUDE_DIRS}")

# =============================================================================
# Find QUAC 100 C Library
# =============================================================================
# Allow user to specify QUAC100_ROOT
if(NOT DEFINED QUAC100_ROOT)
    # Default search paths
    if(WIN32)
        set(QUAC100_ROOT_SEARCH_PATHS
            "${CMAKE_CURRENT_SOURCE_DIR}/../../c"
            "C:/Program Files/QUAC100"
            "$ENV{QUAC100_ROOT}"
        )
    else()
        set(QUAC100_ROOT_SEARCH_PATHS
            "${CMAKE_CURRENT_SOURCE_DIR}/../../c"
            "/usr/local"
            "/opt/quac100"
            "$ENV{QUAC100_ROOT}"
        )
    endif()
    
    foreach(path ${QUAC100_ROOT_SEARCH_PATHS})
        if(EXISTS "${path}/include/quac100/quac100.h")
            set(QUAC100_ROOT "${path}")
            break()
        endif()
    endforeach()
endif()

if(NOT DEFINED QUAC100_ROOT OR NOT EXISTS "${QUAC100_ROOT}/include/quac100/quac100.h")
    message(FATAL_ERROR 
        "QUAC 100 C library not found. Please set QUAC100_ROOT to the C library location.\n"
        "Example: cmake .. -DQUAC100_ROOT=/path/to/quac100-c-sdk"
    )
endif()

message(STATUS "QUAC 100 Root: ${QUAC100_ROOT}")

# Find library file
set(QUAC100_INCLUDE_DIR "${QUAC100_ROOT}/include")

# Search for library in common locations
set(QUAC100_LIB_SEARCH_PATHS
    "${QUAC100_ROOT}/build/Release"
    "${QUAC100_ROOT}/build/Debug"
    "${QUAC100_ROOT}/build"
    "${QUAC100_ROOT}/lib"
    "${QUAC100_ROOT}/lib64"
    "${QUAC100_ROOT}"
)

# Find dynamic library
find_library(QUAC100_LIBRARY
    NAMES quac100 libquac100
    PATHS ${QUAC100_LIB_SEARCH_PATHS}
    NO_DEFAULT_PATH
)

# Also find import library on Windows
if(WIN32)
    find_library(QUAC100_IMPLIB
        NAMES quac100.lib
        PATHS ${QUAC100_LIB_SEARCH_PATHS}
        NO_DEFAULT_PATH
    )
endif()

if(NOT QUAC100_LIBRARY)
    message(FATAL_ERROR 
        "QUAC 100 library not found in ${QUAC100_ROOT}.\n"
        "Please build the C library first:\n"
        "  cd ${QUAC100_ROOT} && mkdir build && cd build && cmake .. && cmake --build ."
    )
endif()

message(STATUS "Found QUAC 100 C library: ${QUAC100_LIBRARY}")

# =============================================================================
# Build JNI Library
# =============================================================================
add_library(quac100_jni SHARED
    quac100_jni.c
)

target_include_directories(quac100_jni PRIVATE
    ${JNI_INCLUDE_DIRS}
    ${QUAC100_INCLUDE_DIR}
)

# Link against QUAC 100 C library
if(WIN32 AND QUAC100_IMPLIB)
    target_link_libraries(quac100_jni PRIVATE ${QUAC100_IMPLIB})
else()
    target_link_libraries(quac100_jni PRIVATE ${QUAC100_LIBRARY})
endif()

# Platform-specific settings
if(WIN32)
    target_compile_definitions(quac100_jni PRIVATE
        _CRT_SECURE_NO_WARNINGS
        QUAC_USE_DLL
    )
    # Set output name without lib prefix on Windows
    set_target_properties(quac100_jni PROPERTIES
        PREFIX ""
        OUTPUT_NAME "quac100_jni"
    )
elseif(APPLE)
    set_target_properties(quac100_jni PROPERTIES
        INSTALL_RPATH "@loader_path"
        BUILD_WITH_INSTALL_RPATH TRUE
    )
else()
    # Linux
    target_compile_options(quac100_jni PRIVATE -fPIC)
    set_target_properties(quac100_jni PROPERTIES
        INSTALL_RPATH "$ORIGIN"
        BUILD_WITH_INSTALL_RPATH TRUE
    )
endif()

# =============================================================================
# Copy Dependencies (Post-Build)
# =============================================================================
# Copy the QUAC 100 C library DLL/SO to the build directory
get_filename_component(QUAC100_LIB_DIR "${QUAC100_LIBRARY}" DIRECTORY)
get_filename_component(QUAC100_LIB_NAME "${QUAC100_LIBRARY}" NAME)

if(WIN32)
    # On Windows, find the DLL (might be different from .lib)
    find_file(QUAC100_DLL
        NAMES quac100.dll
        PATHS ${QUAC100_LIB_SEARCH_PATHS}
        NO_DEFAULT_PATH
    )
    if(QUAC100_DLL)
        add_custom_command(TARGET quac100_jni POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${QUAC100_DLL}"
                "$<TARGET_FILE_DIR:quac100_jni>"
            COMMENT "Copying QUAC 100 DLL to output directory"
        )
    endif()
else()
    # On Linux/macOS, copy the shared library
    add_custom_command(TARGET quac100_jni POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${QUAC100_LIBRARY}"
            "$<TARGET_FILE_DIR:quac100_jni>"
        COMMENT "Copying QUAC 100 shared library to output directory"
    )
endif()

# =============================================================================
# Installation
# =============================================================================
install(TARGETS quac100_jni
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION lib
)

# =============================================================================
# Summary
# =============================================================================
message(STATUS "")
message(STATUS "QUAC 100 Java JNI Library Configuration:")
message(STATUS "  JNI Include: ${JNI_INCLUDE_DIRS}")
message(STATUS "  QUAC 100 Root: ${QUAC100_ROOT}")
message(STATUS "  QUAC 100 Library: ${QUAC100_LIBRARY}")
message(STATUS "  Platform: ${QUAC_PLATFORM_ARCH}")
message(STATUS "")