# =============================================================================
# QUAC 100 PKCS#11 Module - CMake Build Configuration
# =============================================================================
#
# Build system for the QUAC 100 PKCS#11 cryptographic token interface.
#
# Usage:
#   mkdir build && cd build
#   cmake ..
#   cmake --build .
#
# Options:
#   -DQUAC_SDK_PATH=/path/to/sdk    Enable hardware acceleration
#   -DBUILD_TESTS=ON                Build test suite
#   -DBUILD_EXAMPLES=ON             Build example programs
#   -DCMAKE_BUILD_TYPE=Release      Build type (Release/Debug)
#
# Copyright 2025 Dyber, Inc. All Rights Reserved.
# =============================================================================

cmake_minimum_required(VERSION 3.16)
project(quac100_pkcs11 VERSION 1.0.0 LANGUAGES C)

# =============================================================================
# Options
# =============================================================================

option(BUILD_TESTS "Build test suite" ON)
option(BUILD_EXAMPLES "Build example programs" ON)
option(QUAC_SDK_PATH "Path to QUAC 100 SDK for hardware acceleration" "")

# =============================================================================
# Compiler Settings
# =============================================================================

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Warning flags
if(MSVC)
    add_compile_options(/W4 /WX-)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        add_compile_options(-O3)
    endif()
endif()

# =============================================================================
# Dependencies
# =============================================================================

# OpenSSL (required for software simulation)
find_package(OpenSSL REQUIRED)
message(STATUS "Found OpenSSL: ${OPENSSL_VERSION}")

# pthreads (Unix)
if(NOT WIN32)
    find_package(Threads REQUIRED)
endif()

# QUAC SDK (optional, for hardware acceleration)
if(QUAC_SDK_PATH AND EXISTS "${QUAC_SDK_PATH}")
    message(STATUS "QUAC SDK found at: ${QUAC_SDK_PATH}")
    set(QUAC_HAS_HARDWARE ON)
    include_directories(${QUAC_SDK_PATH}/include)
    link_directories(${QUAC_SDK_PATH}/lib)
else()
    message(STATUS "QUAC SDK not found - using software simulation")
    set(QUAC_HAS_HARDWARE OFF)
endif()

# =============================================================================
# Source Files
# =============================================================================

set(PKCS11_SOURCES
    quac100_pkcs11.c
    quac100_pkcs11_slot.c
    quac100_pkcs11_session.c
    quac100_pkcs11_object.c
    quac100_pkcs11_crypto.c
)

set(PKCS11_HEADERS
    quac100_pkcs11.h
    quac100_pkcs11_internal.h
)

# =============================================================================
# PKCS#11 Shared Library
# =============================================================================

add_library(quac100_pkcs11 SHARED ${PKCS11_SOURCES} ${PKCS11_HEADERS})

target_include_directories(quac100_pkcs11 PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(quac100_pkcs11 PRIVATE
    OpenSSL::Crypto
)

if(NOT WIN32)
    target_link_libraries(quac100_pkcs11 PRIVATE
        Threads::Threads
    )
endif()

# Windows-specific settings
if(WIN32)
    target_sources(quac100_pkcs11 PRIVATE quac100_pkcs11.def)
    target_compile_definitions(quac100_pkcs11 PRIVATE
        QUAC_PKCS11_EXPORTS
        _WIN32_WINNT=0x0601
    )
endif()

# Hardware acceleration
if(QUAC_HAS_HARDWARE)
    target_compile_definitions(quac100_pkcs11 PRIVATE QUAC_HAS_HARDWARE)
    target_link_libraries(quac100_pkcs11 PRIVATE quac100)
endif()

# Set library properties
set_target_properties(quac100_pkcs11 PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION 1
    PUBLIC_HEADER "quac100_pkcs11.h"
    OUTPUT_NAME "quac100_pkcs11"
)

# =============================================================================
# Static Library (optional)
# =============================================================================

add_library(quac100_pkcs11_static STATIC ${PKCS11_SOURCES} ${PKCS11_HEADERS})

target_include_directories(quac100_pkcs11_static PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(quac100_pkcs11_static PRIVATE
    OpenSSL::Crypto
)

if(NOT WIN32)
    target_link_libraries(quac100_pkcs11_static PRIVATE
        Threads::Threads
    )
endif()

if(QUAC_HAS_HARDWARE)
    target_compile_definitions(quac100_pkcs11_static PRIVATE QUAC_HAS_HARDWARE)
endif()

# =============================================================================
# Test Suite
# =============================================================================

if(BUILD_TESTS)
    enable_testing()
    
    add_executable(test_quac100_pkcs11 test_quac100_pkcs11.c)
    
    target_include_directories(test_quac100_pkcs11 PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
    )
    
    target_link_libraries(test_quac100_pkcs11 PRIVATE
        quac100_pkcs11
        OpenSSL::Crypto
    )
    
    if(NOT WIN32)
        target_link_libraries(test_quac100_pkcs11 PRIVATE
            Threads::Threads
            dl
        )
    endif()
    
    add_test(NAME pkcs11_tests COMMAND test_quac100_pkcs11)
endif()

# =============================================================================
# Example Programs
# =============================================================================

if(BUILD_EXAMPLES)
    # Basic example
    add_executable(example_pkcs11 example_pkcs11.c)
    
    target_include_directories(example_pkcs11 PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
    )
    
    target_link_libraries(example_pkcs11 PRIVATE
        quac100_pkcs11
    )
    
    if(NOT WIN32)
        target_link_libraries(example_pkcs11 PRIVATE dl)
    endif()
    
    # Benchmark
    add_executable(bench_pkcs11 bench_pkcs11.c)
    
    target_include_directories(bench_pkcs11 PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
    )
    
    target_link_libraries(bench_pkcs11 PRIVATE
        quac100_pkcs11
    )
    
    if(NOT WIN32)
        target_link_libraries(bench_pkcs11 PRIVATE dl)
    endif()
endif()

# =============================================================================
# Installation
# =============================================================================

include(GNUInstallDirs)

install(TARGETS quac100_pkcs11
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(FILES
    quac100_pkcs11.h
    quac100_pkcs11_internal.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

# =============================================================================
# Package Configuration
# =============================================================================

include(CMakePackageConfigHelpers)

configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/quac100_pkcs11-config.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/quac100_pkcs11-config.cmake"
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/quac100_pkcs11
)

write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/quac100_pkcs11-config-version.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/quac100_pkcs11-config.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/quac100_pkcs11-config-version.cmake"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/quac100_pkcs11
)

# =============================================================================
# Summary
# =============================================================================

message(STATUS "")
message(STATUS "QUAC 100 PKCS#11 Module Configuration Summary")
message(STATUS "=============================================")
message(STATUS "  Version:            ${PROJECT_VERSION}")
message(STATUS "  Build type:         ${CMAKE_BUILD_TYPE}")
message(STATUS "  Hardware support:   ${QUAC_HAS_HARDWARE}")
message(STATUS "  OpenSSL version:    ${OPENSSL_VERSION}")
message(STATUS "  Build tests:        ${BUILD_TESTS}")
message(STATUS "  Build examples:     ${BUILD_EXAMPLES}")
message(STATUS "")