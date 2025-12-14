# =============================================================================
# QUAC 100 BoringSSL Integration - CMake Build
# =============================================================================
#
# Build Options:
#   -DQUAC_SDK_PATH=/path/to/sdk    Path to QuantaCore SDK (optional)
#   -DBORINGSSL_PATH=/path/to/bssl  Path to BoringSSL (required)
#   -DBUILD_SHARED_LIBS=ON          Build shared library (default: ON)
#   -DBUILD_TESTS=ON                Build test program (default: ON)
#   -DENABLE_HARDWARE=ON            Enable hardware support (default: ON)
#
# Usage:
#   mkdir build && cd build
#   cmake -DBORINGSSL_PATH=/opt/boringssl ..
#   make
#   sudo make install
#
# Copyright 2025 Dyber, Inc. All Rights Reserved.
# =============================================================================

cmake_minimum_required(VERSION 3.16)

project(quac100_boringssl
    VERSION 1.0.0
    DESCRIPTION "QUAC 100 Post-Quantum Cryptography Integration for BoringSSL"
    LANGUAGES C
)

# =============================================================================
# Options
# =============================================================================

option(BUILD_SHARED_LIBS "Build shared library" ON)
option(BUILD_TESTS "Build test programs" ON)
option(ENABLE_HARDWARE "Enable QUAC 100 hardware support" ON)

set(QUAC_SDK_PATH "" CACHE PATH "Path to QuantaCore SDK")
set(BORINGSSL_PATH "" CACHE PATH "Path to BoringSSL installation")

# =============================================================================
# Find BoringSSL
# =============================================================================

if(BORINGSSL_PATH)
    set(BORINGSSL_INCLUDE_DIR "${BORINGSSL_PATH}/include")
    set(BORINGSSL_CRYPTO_LIB "${BORINGSSL_PATH}/lib/libcrypto.a")
    set(BORINGSSL_SSL_LIB "${BORINGSSL_PATH}/lib/libssl.a")
    
    if(NOT EXISTS "${BORINGSSL_INCLUDE_DIR}/openssl/ssl.h")
        message(FATAL_ERROR "BoringSSL headers not found at ${BORINGSSL_INCLUDE_DIR}")
    endif()
    
    if(NOT EXISTS "${BORINGSSL_CRYPTO_LIB}")
        # Try shared library
        set(BORINGSSL_CRYPTO_LIB "${BORINGSSL_PATH}/lib/libcrypto.so")
        if(NOT EXISTS "${BORINGSSL_CRYPTO_LIB}")
            message(FATAL_ERROR "BoringSSL crypto library not found")
        endif()
    endif()
else()
    # Try to find BoringSSL in standard locations
    find_path(BORINGSSL_INCLUDE_DIR
        NAMES openssl/ssl.h
        PATHS
            /usr/local/include
            /usr/include
            /opt/boringssl/include
    )
    
    find_library(BORINGSSL_CRYPTO_LIB
        NAMES crypto
        PATHS
            /usr/local/lib
            /usr/lib
            /opt/boringssl/lib
    )
    
    find_library(BORINGSSL_SSL_LIB
        NAMES ssl
        PATHS
            /usr/local/lib
            /usr/lib
            /opt/boringssl/lib
    )
    
    if(NOT BORINGSSL_INCLUDE_DIR OR NOT BORINGSSL_CRYPTO_LIB)
        message(FATAL_ERROR "BoringSSL not found. Set -DBORINGSSL_PATH=/path/to/boringssl")
    endif()
endif()

message(STATUS "BoringSSL include: ${BORINGSSL_INCLUDE_DIR}")
message(STATUS "BoringSSL crypto:  ${BORINGSSL_CRYPTO_LIB}")

# =============================================================================
# Find QUAC SDK (optional)
# =============================================================================

if(QUAC_SDK_PATH AND ENABLE_HARDWARE)
    set(QUAC_INCLUDE_DIR "${QUAC_SDK_PATH}/include")
    set(QUAC_LIB_DIR "${QUAC_SDK_PATH}/lib")
    
    if(EXISTS "${QUAC_INCLUDE_DIR}/quac100/quac.h")
        message(STATUS "QUAC SDK found at ${QUAC_SDK_PATH}")
        set(HAVE_QUAC_HARDWARE TRUE)
        
        find_library(QUAC_LIBRARY
            NAMES quac100 quac
            PATHS ${QUAC_LIB_DIR}
            NO_DEFAULT_PATH
        )
    else()
        message(STATUS "QUAC SDK headers not found, hardware support disabled")
        set(HAVE_QUAC_HARDWARE FALSE)
    endif()
else()
    set(HAVE_QUAC_HARDWARE FALSE)
endif()

# =============================================================================
# Source Files
# =============================================================================

set(QUAC_SOURCES
    quac100_boringssl.c
    quac100_kem.c
    quac100_sig.c
    quac100_rand.c
    quac100_evp.c
    quac100_tls.c
    quac100_asn1.c
)

set(QUAC_HEADERS
    quac100_boringssl.h
)

# =============================================================================
# Library Target
# =============================================================================

add_library(quac100_boringssl ${QUAC_SOURCES})

target_include_directories(quac100_boringssl
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${BORINGSSL_INCLUDE_DIR}
)

target_link_libraries(quac100_boringssl
    PRIVATE
        ${BORINGSSL_CRYPTO_LIB}
        ${BORINGSSL_SSL_LIB}
        pthread
)

if(HAVE_QUAC_HARDWARE)
    target_compile_definitions(quac100_boringssl PRIVATE QUAC_HAS_HARDWARE)
    target_include_directories(quac100_boringssl PRIVATE ${QUAC_INCLUDE_DIR})
    target_link_libraries(quac100_boringssl PRIVATE ${QUAC_LIBRARY})
endif()

# Compiler settings
target_compile_features(quac100_boringssl PRIVATE c_std_11)

target_compile_options(quac100_boringssl PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -Wno-unused-parameter
    $<$<CONFIG:Release>:-O3>
    $<$<CONFIG:Debug>:-g -O0>
)

if(BUILD_SHARED_LIBS)
    set_target_properties(quac100_boringssl PROPERTIES
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
        POSITION_INDEPENDENT_CODE ON
    )
    
    if(APPLE)
        set_target_properties(quac100_boringssl PROPERTIES
            INSTALL_RPATH "@loader_path"
        )
    elseif(UNIX)
        set_target_properties(quac100_boringssl PROPERTIES
            INSTALL_RPATH "$ORIGIN"
        )
    endif()
endif()

# =============================================================================
# Test Target
# =============================================================================

if(BUILD_TESTS)
    add_executable(test_quac100_boringssl test_quac100_boringssl.c)
    
    target_link_libraries(test_quac100_boringssl
        PRIVATE
            quac100_boringssl
            ${BORINGSSL_CRYPTO_LIB}
            ${BORINGSSL_SSL_LIB}
            pthread
    )
    
    target_include_directories(test_quac100_boringssl
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}
            ${BORINGSSL_INCLUDE_DIR}
    )
    
    # CTest integration
    enable_testing()
    add_test(NAME quac100_boringssl_tests COMMAND test_quac100_boringssl)
endif()

# =============================================================================
# Benchmark Target
# =============================================================================

add_executable(bench_quac100_boringssl bench_quac100_boringssl.c)

target_link_libraries(bench_quac100_boringssl
    PRIVATE
        quac100_boringssl
        ${BORINGSSL_CRYPTO_LIB}
        pthread
)

target_include_directories(bench_quac100_boringssl
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${BORINGSSL_INCLUDE_DIR}
)

# =============================================================================
# Installation
# =============================================================================

include(GNUInstallDirs)

install(TARGETS quac100_boringssl
    EXPORT quac100_boringssl-targets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(FILES ${QUAC_HEADERS}
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/quac100
)

install(FILES README.md
    DESTINATION ${CMAKE_INSTALL_DOCDIR}
)

# Export targets
install(EXPORT quac100_boringssl-targets
    FILE quac100_boringssl-targets.cmake
    NAMESPACE QUAC::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/quac100_boringssl
)

# Package configuration
include(CMakePackageConfigHelpers)

configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/quac100_boringssl-config.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/quac100_boringssl-config.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/quac100_boringssl
)

write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/quac100_boringssl-config-version.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/quac100_boringssl-config.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/quac100_boringssl-config-version.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/quac100_boringssl
)

# =============================================================================
# Summary
# =============================================================================

message(STATUS "")
message(STATUS "=== QUAC 100 BoringSSL Integration Configuration ===")
message(STATUS "Version:          ${PROJECT_VERSION}")
message(STATUS "Build type:       ${CMAKE_BUILD_TYPE}")
message(STATUS "Shared library:   ${BUILD_SHARED_LIBS}")
message(STATUS "Hardware support: ${HAVE_QUAC_HARDWARE}")
message(STATUS "Build tests:      ${BUILD_TESTS}")
message(STATUS "Install prefix:   ${CMAKE_INSTALL_PREFIX}")
message(STATUS "")