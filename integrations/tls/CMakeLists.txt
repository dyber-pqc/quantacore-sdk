# ==============================================================================
# QUAC 100 TLS Integration - CMake Build Configuration
# ==============================================================================
#
# CMake build system for QUAC TLS library with post-quantum cryptography.
#
# Options:
#   -DBUILD_TESTS=ON        Build test suite (default: ON)
#   -DBUILD_EXAMPLES=ON     Build example programs (default: ON)
#   -DBUILD_TOOLS=ON        Build utility tools (default: ON)
#   -DBUILD_SHARED_LIBS=ON  Build shared library (default: ON)
#   -DQUAC_SDK_PATH=path    Path to QUAC 100 SDK (enables hardware)
#   -DOPENSSL_ROOT_DIR=path Path to OpenSSL installation
#
# Usage:
#   mkdir build && cd build
#   cmake ..
#   cmake --build .
#   ctest
#   cmake --install . --prefix /usr/local
#
# Copyright 2025 Dyber, Inc. All Rights Reserved.
# ==============================================================================

cmake_minimum_required(VERSION 3.16)

project(quac_tls
    VERSION 1.0.0
    DESCRIPTION "QUAC 100 TLS Integration with Post-Quantum Cryptography"
    HOMEPAGE_URL "https://dyber.io"
    LANGUAGES C CXX
)

# ==============================================================================
# Build Options
# ==============================================================================

option(BUILD_TESTS "Build test suite" ON)
option(BUILD_EXAMPLES "Build example programs" ON)
option(BUILD_TOOLS "Build utility tools" ON)
option(BUILD_SHARED_LIBS "Build shared library" ON)
option(QUAC_ENABLE_HARDWARE "Enable QUAC 100 hardware acceleration" OFF)

# QUAC SDK path for hardware acceleration
set(QUAC_SDK_PATH "" CACHE PATH "Path to QUAC 100 SDK")

# ==============================================================================
# Compiler Configuration
# ==============================================================================

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Position independent code for shared libraries
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Export compile commands for IDE support
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Default to Release build if not specified
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
        "Debug" "Release" "MinSizeRel" "RelWithDebInfo")
endif()

# Compiler warnings
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()
if(MSVC)
    add_compile_options(/W4 /WX-)
endif()

# ==============================================================================
# Dependencies
# ==============================================================================

# Find OpenSSL
find_package(OpenSSL REQUIRED)
message(STATUS "OpenSSL version: ${OPENSSL_VERSION}")
message(STATUS "OpenSSL include: ${OPENSSL_INCLUDE_DIR}")
message(STATUS "OpenSSL libraries: ${OPENSSL_LIBRARIES}")

# Find Threads
find_package(Threads REQUIRED)

# QUAC SDK (optional hardware acceleration)
if(QUAC_SDK_PATH)
    if(EXISTS "${QUAC_SDK_PATH}/include/quac100/quac.h")
        set(QUAC_ENABLE_HARDWARE ON)
        message(STATUS "QUAC SDK found: ${QUAC_SDK_PATH}")
        message(STATUS "Hardware acceleration: ENABLED")
    else()
        message(WARNING "QUAC SDK path specified but SDK not found")
        set(QUAC_ENABLE_HARDWARE OFF)
    endif()
else()
    message(STATUS "Hardware acceleration: DISABLED (software fallback)")
endif()

# ==============================================================================
# Library Sources
# ==============================================================================

set(LIB_SOURCES
    quac_tls.c
    quac_tls_pqc.c
)

set(LIB_HEADERS
    quac_tls.h
    quac_tls_internal.h
)

# ==============================================================================
# Library Target
# ==============================================================================

add_library(quac_tls ${LIB_SOURCES})
add_library(quac_tls::quac_tls ALIAS quac_tls)

target_include_directories(quac_tls
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        $<INSTALL_INTERFACE:include/quac>
    PRIVATE
        ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(quac_tls
    PUBLIC
        OpenSSL::SSL
        OpenSSL::Crypto
        Threads::Threads
)

# QUAC hardware support
if(QUAC_ENABLE_HARDWARE)
    target_compile_definitions(quac_tls PRIVATE QUAC_HAS_HARDWARE)
    target_include_directories(quac_tls PRIVATE ${QUAC_SDK_PATH}/include)
    target_link_directories(quac_tls PRIVATE ${QUAC_SDK_PATH}/lib)
    target_link_libraries(quac_tls PRIVATE quac100)
endif()

# Windows DLL export
if(WIN32 AND BUILD_SHARED_LIBS)
    target_compile_definitions(quac_tls PRIVATE QUAC_TLS_EXPORTS)
    set_target_properties(quac_tls PROPERTIES
        WINDOWS_EXPORT_ALL_SYMBOLS ON
    )
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/quac_tls.def")
        set_target_properties(quac_tls PROPERTIES
            LINK_FLAGS "/DEF:${CMAKE_CURRENT_SOURCE_DIR}/quac_tls.def"
        )
    endif()
endif()

# Library versioning
set_target_properties(quac_tls PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    OUTPUT_NAME quac_tls
)

# ==============================================================================
# Test Suite
# ==============================================================================

if(BUILD_TESTS)
    enable_testing()
    
    add_executable(test_quac_tls tests/test_quac_tls.c)
    target_link_libraries(test_quac_tls PRIVATE quac_tls)
    target_include_directories(test_quac_tls PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    
    add_test(NAME test_quac_tls COMMAND test_quac_tls)
    set_tests_properties(test_quac_tls PROPERTIES
        ENVIRONMENT "LD_LIBRARY_PATH=${CMAKE_BINARY_DIR};DYLD_LIBRARY_PATH=${CMAKE_BINARY_DIR}"
    )
    
    # Benchmark (not added as test, run manually)
    add_executable(bench_quac_tls tests/bench_quac_tls.c)
    target_link_libraries(bench_quac_tls PRIVATE quac_tls m)
    target_include_directories(bench_quac_tls PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
endif()

# ==============================================================================
# Examples
# ==============================================================================

if(BUILD_EXAMPLES)
    add_executable(example_tls_server examples/example_tls_server.c)
    target_link_libraries(example_tls_server PRIVATE quac_tls)
    target_include_directories(example_tls_server PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    
    add_executable(example_tls_client examples/example_tls_client.c)
    target_link_libraries(example_tls_client PRIVATE quac_tls)
    target_include_directories(example_tls_client PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
endif()

# ==============================================================================
# Tools
# ==============================================================================

if(BUILD_TOOLS)
    add_executable(quac-tls-keygen tools/quac_tls_keygen.c)
    target_link_libraries(quac-tls-keygen PRIVATE quac_tls)
    target_include_directories(quac-tls-keygen PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
endif()

# ==============================================================================
# Installation
# ==============================================================================

include(GNUInstallDirs)

install(TARGETS quac_tls
    EXPORT quac_tls-targets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/quac
)

install(FILES ${LIB_HEADERS}
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/quac
)

if(BUILD_TOOLS)
    install(TARGETS quac-tls-keygen
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
endif()

# CMake package configuration
install(EXPORT quac_tls-targets
    FILE quac_tls-targets.cmake
    NAMESPACE quac_tls::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/quac_tls
)

include(CMakePackageConfigHelpers)

configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/quac_tls-config.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/quac_tls-config.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/quac_tls
)

write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/quac_tls-config-version.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/quac_tls-config.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/quac_tls-config-version.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/quac_tls
)

# ==============================================================================
# Package Configuration
# ==============================================================================

set(CPACK_PACKAGE_NAME "quac-tls")
set(CPACK_PACKAGE_VENDOR "Dyber, Inc.")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "QUAC 100 TLS Integration with PQC")
set(CPACK_PACKAGE_VERSION_MAJOR ${PROJECT_VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR ${PROJECT_VERSION_MINOR})
set(CPACK_PACKAGE_VERSION_PATCH ${PROJECT_VERSION_PATCH})
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/../../../LICENSE")

include(CPack)

# ==============================================================================
# Build Summary
# ==============================================================================

message(STATUS "")
message(STATUS "QUAC TLS Build Configuration")
message(STATUS "============================")
message(STATUS "  Version:          ${PROJECT_VERSION}")
message(STATUS "  Build type:       ${CMAKE_BUILD_TYPE}")
message(STATUS "  C Compiler:       ${CMAKE_C_COMPILER_ID} ${CMAKE_C_COMPILER_VERSION}")
message(STATUS "  Install prefix:   ${CMAKE_INSTALL_PREFIX}")
message(STATUS "  OpenSSL:          ${OPENSSL_VERSION}")
message(STATUS "  Hardware accel:   ${QUAC_ENABLE_HARDWARE}")
message(STATUS "  Build tests:      ${BUILD_TESTS}")
message(STATUS "  Build examples:   ${BUILD_EXAMPLES}")
message(STATUS "  Build tools:      ${BUILD_TOOLS}")
message(STATUS "  Shared library:   ${BUILD_SHARED_LIBS}")
message(STATUS "")