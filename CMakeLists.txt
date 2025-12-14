#===============================================================================
# QuantaCore SDK - QUAC 100 Post-Quantum Cryptographic Accelerator
# Top-Level CMake Configuration
#
# Copyright (c) 2025 Dyber, Inc. All Rights Reserved.
# Document Number: QUAC100-SDK-DEV-001
#===============================================================================

cmake_minimum_required(VERSION 3.16)

#-------------------------------------------------------------------------------
# Version Configuration
#-------------------------------------------------------------------------------
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" QUAC_VERSION_RAW)
string(STRIP "${QUAC_VERSION_RAW}" QUAC_VERSION)
string(REPLACE "." ";" VERSION_LIST ${QUAC_VERSION})
list(GET VERSION_LIST 0 QUAC_VERSION_MAJOR)
list(GET VERSION_LIST 1 QUAC_VERSION_MINOR)
list(GET VERSION_LIST 2 QUAC_VERSION_PATCH)

project(quantacore-sdk
    VERSION ${QUAC_VERSION}
    DESCRIPTION "QUAC 100 Post-Quantum Cryptographic Accelerator SDK"
    HOMEPAGE_URL "https://dyber.com"
    LANGUAGES C CXX
)

message(STATUS "")
message(STATUS "========================================")
message(STATUS " QuantaCore SDK v${QUAC_VERSION}")
message(STATUS " Dyber, Inc. - QUAC 100")
message(STATUS "========================================")
message(STATUS "")

#-------------------------------------------------------------------------------
# Build Options
#-------------------------------------------------------------------------------
option(BUILD_SHARED_LIBS        "Build shared libraries"                    ON)
option(QUAC_BUILD_SIMULATOR     "Build software simulator"                  ON)
option(QUAC_BUILD_TESTS         "Build test suite"                          ON)
option(QUAC_BUILD_EXAMPLES      "Build example applications"                ON)
option(QUAC_BUILD_TOOLS         "Build CLI tools"                           ON)
option(QUAC_BUILD_DOCS          "Build documentation"                       OFF)

# Integration options
option(QUAC_BUILD_OPENSSL       "Build OpenSSL 3.x provider"                ON)
option(QUAC_BUILD_PKCS11        "Build PKCS#11 module"                      ON)
option(QUAC_BUILD_BORINGSSL     "Build BoringSSL engine"                    OFF)

# Language binding options
option(QUAC_BUILD_PYTHON        "Build Python bindings"                     ON)
option(QUAC_BUILD_RUST          "Build Rust bindings"                       OFF)
option(QUAC_BUILD_JAVA          "Build Java JNI bindings"                   OFF)
option(QUAC_BUILD_GO            "Build Go CGO bindings"                     OFF)
option(QUAC_BUILD_NODEJS        "Build Node.js N-API bindings"              OFF)
option(QUAC_BUILD_CSHARP        "Build C# P/Invoke bindings"                OFF)

# Security options
option(QUAC_ENABLE_ZEROIZE      "Enable secure memory zeroization"          ON)
option(QUAC_ENABLE_FIPS_MODE    "Enable FIPS 140-3 compliant mode"          OFF)

#-------------------------------------------------------------------------------
# Compiler Standards and Flags
#-------------------------------------------------------------------------------
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Position Independent Code (required for shared libraries)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Export compile commands for IDE support
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

#-------------------------------------------------------------------------------
# Platform Detection
#-------------------------------------------------------------------------------
if(WIN32)
    set(QUAC_PLATFORM "windows")
    set(QUAC_PLATFORM_WINDOWS TRUE)
    add_definitions(-DQUAC_PLATFORM_WINDOWS=1)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
    add_definitions(-DWIN32_LEAN_AND_MEAN)
    add_definitions(-DNOMINMAX)
elseif(UNIX AND NOT APPLE)
    set(QUAC_PLATFORM "linux")
    set(QUAC_PLATFORM_LINUX TRUE)
    add_definitions(-DQUAC_PLATFORM_LINUX=1)
    add_definitions(-D_GNU_SOURCE)
elseif(APPLE)
    set(QUAC_PLATFORM "macos")
    set(QUAC_PLATFORM_MACOS TRUE)
    add_definitions(-DQUAC_PLATFORM_MACOS=1)
    message(WARNING "macOS support is experimental - no hardware driver available")
else()
    message(FATAL_ERROR "Unsupported platform")
endif()

message(STATUS "Platform: ${QUAC_PLATFORM}")
message(STATUS "Architecture: ${CMAKE_SYSTEM_PROCESSOR}")

#-------------------------------------------------------------------------------
# Architecture Detection
#-------------------------------------------------------------------------------
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|amd64")
    set(QUAC_ARCH "x86_64")
    set(QUAC_ARCH_X64 TRUE)
    add_definitions(-DQUAC_ARCH_X64=1)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|ARM64|arm64")
    set(QUAC_ARCH "aarch64")
    set(QUAC_ARCH_ARM64 TRUE)
    add_definitions(-DQUAC_ARCH_ARM64=1)
else()
    message(WARNING "Unknown architecture: ${CMAKE_SYSTEM_PROCESSOR}")
    set(QUAC_ARCH "unknown")
endif()

#-------------------------------------------------------------------------------
# Build Type Configuration
#-------------------------------------------------------------------------------
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build type" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
        "Debug" "Release" "RelWithDebInfo" "MinSizeRel")
endif()
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")

# Compiler-specific flags
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(
        -Wall
        -Wextra
        -Wpedantic
        -Wconversion
        -Wsign-conversion
        -Wformat=2
        -Wformat-security
        -Werror=format-security
        -fstack-protector-strong
    )
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        add_compile_options(-g3 -O0 -fno-omit-frame-pointer)
        add_definitions(-DQUAC_DEBUG=1)
    else()
        add_compile_options(-O3)
        add_definitions(-DNDEBUG)
    endif()
elseif(MSVC)
    add_compile_options(
        /W4
        /WX-
        /sdl
        /GS
        /guard:cf
    )
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        add_compile_options(/Od /Zi)
        add_definitions(-DQUAC_DEBUG=1)
    else()
        add_compile_options(/O2 /GL)
        add_definitions(-DNDEBUG)
    endif()
endif()

#-------------------------------------------------------------------------------
# Output Directories
#-------------------------------------------------------------------------------
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

#-------------------------------------------------------------------------------
# CMake Module Path
#-------------------------------------------------------------------------------
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

#-------------------------------------------------------------------------------
# Dependencies
#-------------------------------------------------------------------------------

# Threads (required)
find_package(Threads REQUIRED)

# OpenSSL (optional, for provider integration)
if(QUAC_BUILD_OPENSSL)
    find_package(OpenSSL 3.0)
    if(OpenSSL_FOUND)
        message(STATUS "OpenSSL ${OPENSSL_VERSION} found - provider will be built")
    else()
        message(WARNING "OpenSSL 3.x not found - provider will not be built")
        set(QUAC_BUILD_OPENSSL OFF)
    endif()
endif()

# Python (optional, for bindings)
if(QUAC_BUILD_PYTHON)
    find_package(Python3 COMPONENTS Interpreter Development)
    if(Python3_FOUND)
        message(STATUS "Python ${Python3_VERSION} found - bindings will be built")
    else()
        message(WARNING "Python3 not found - bindings will not be built")
        set(QUAC_BUILD_PYTHON OFF)
    endif()
endif()

#-------------------------------------------------------------------------------
# Version Header Generation
#-------------------------------------------------------------------------------
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/quac100_version.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/include/quac100_version.h"
    @ONLY
)

#-------------------------------------------------------------------------------
# Core Library Sources
#-------------------------------------------------------------------------------
set(QUAC_CORE_SOURCES
    src/core/device.c
    src/core/init.c
    src/core/kem.c
    src/core/sign.c
    src/core/random.c
    src/core/async.c
    src/core/batch.c
    src/core/key_mgmt.c
    src/core/diag.c
    src/core/error.c
    src/util/memory.c
    src/util/threading.c
    src/util/logging.c
)

# Platform-specific sources
if(QUAC_PLATFORM_LINUX)
    list(APPEND QUAC_CORE_SOURCES
        src/platform/linux/device_linux.c
        src/platform/linux/mmap_linux.c
        src/platform/linux/ioctl_linux.c
    )
elseif(QUAC_PLATFORM_WINDOWS)
    list(APPEND QUAC_CORE_SOURCES
        src/platform/windows/device_win.c
        src/platform/windows/ioctl_win.c
        src/platform/windows/registry_win.c
    )
endif()

#-------------------------------------------------------------------------------
# Core Library Target
#-------------------------------------------------------------------------------
add_library(quac100 ${QUAC_CORE_SOURCES})

target_include_directories(quac100
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include/internal
)

target_link_libraries(quac100
    PRIVATE
        Threads::Threads
)

# Platform-specific libraries
if(QUAC_PLATFORM_WINDOWS)
    target_link_libraries(quac100 PRIVATE setupapi cfgmgr32)
elseif(QUAC_PLATFORM_LINUX)
    target_link_libraries(quac100 PRIVATE dl)
endif()

# Library version
set_target_properties(quac100 PROPERTIES
    VERSION ${QUAC_VERSION}
    SOVERSION ${QUAC_VERSION_MAJOR}
    OUTPUT_NAME quac100
)

# Export symbols on Windows
if(WIN32 AND BUILD_SHARED_LIBS)
    target_compile_definitions(quac100 PRIVATE QUAC100_BUILDING_DLL)
    target_compile_definitions(quac100 INTERFACE QUAC100_DLL)
endif()

# Secure memory zeroization
if(QUAC_ENABLE_ZEROIZE)
    target_compile_definitions(quac100 PRIVATE QUAC_ENABLE_ZEROIZE=1)
endif()

# FIPS mode
if(QUAC_ENABLE_FIPS_MODE)
    target_compile_definitions(quac100 PRIVATE QUAC_FIPS_MODE=1)
    message(STATUS "FIPS 140-3 mode enabled")
endif()

#-------------------------------------------------------------------------------
# Simulator Library
#-------------------------------------------------------------------------------
if(QUAC_BUILD_SIMULATOR)
    set(QUAC_SIM_SOURCES
        simulator/src/sim_main.c
        simulator/src/sim_device.c
        simulator/src/sim_kem.c
        simulator/src/sim_sign.c
        simulator/src/ref_impl/kyber_ref.c
        simulator/src/ref_impl/dilithium_ref.c
        simulator/src/ref_impl/sphincs_ref.c
    )
    
    add_library(quac100_sim ${QUAC_SIM_SOURCES})
    
    target_include_directories(quac100_sim
        PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/simulator/include>
            $<INSTALL_INTERFACE:include>
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    
    target_link_libraries(quac100_sim
        PRIVATE
            quac100
            Threads::Threads
    )
    
    set_target_properties(quac100_sim PROPERTIES
        VERSION ${QUAC_VERSION}
        SOVERSION ${QUAC_VERSION_MAJOR}
    )
    
    message(STATUS "Simulator: ENABLED")
endif()

#-------------------------------------------------------------------------------
# Subdirectories
#-------------------------------------------------------------------------------

# OpenSSL Provider
if(QUAC_BUILD_OPENSSL AND OpenSSL_FOUND)
    add_subdirectory(integrations/openssl)
endif()

# PKCS#11 Module
if(QUAC_BUILD_PKCS11)
    add_subdirectory(integrations/pkcs11)
endif()

# Python Bindings
if(QUAC_BUILD_PYTHON AND Python3_FOUND)
    add_subdirectory(bindings/python)
endif()

# Examples
if(QUAC_BUILD_EXAMPLES)
    add_subdirectory(examples/c)
endif()

# Tests
if(QUAC_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# Tools
if(QUAC_BUILD_TOOLS)
    add_subdirectory(tools/quac100-cli)
    add_subdirectory(tools/quac100-bench)
    add_subdirectory(tools/quac100-diag)
endif()

#-------------------------------------------------------------------------------
# Installation
#-------------------------------------------------------------------------------
include(GNUInstallDirs)

# Libraries
install(TARGETS quac100
    EXPORT quac100-targets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

if(QUAC_BUILD_SIMULATOR)
    install(TARGETS quac100_sim
        EXPORT quac100-targets
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
endif()

# Headers
install(DIRECTORY include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    FILES_MATCHING PATTERN "*.h"
    PATTERN "internal" EXCLUDE
)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/include/quac100_version.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

# CMake package configuration
install(EXPORT quac100-targets
    FILE Quac100Targets.cmake
    NAMESPACE Quac100::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/Quac100
)

include(CMakePackageConfigHelpers)
configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/Quac100Config.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/Quac100Config.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/Quac100
)

write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/Quac100ConfigVersion.cmake
    VERSION ${QUAC_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/Quac100Config.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/Quac100ConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/Quac100
)

#-------------------------------------------------------------------------------
# Package Configuration (CPack)
#-------------------------------------------------------------------------------
set(CPACK_PACKAGE_NAME "quantacore-sdk")
set(CPACK_PACKAGE_VENDOR "Dyber, Inc.")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "QUAC 100 Post-Quantum Cryptographic Accelerator SDK")
set(CPACK_PACKAGE_VERSION ${QUAC_VERSION})
set(CPACK_PACKAGE_VERSION_MAJOR ${QUAC_VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR ${QUAC_VERSION_MINOR})
set(CPACK_PACKAGE_VERSION_PATCH ${QUAC_VERSION_PATCH})
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE.txt")
set(CPACK_RESOURCE_FILE_README "${CMAKE_CURRENT_SOURCE_DIR}/README.md")

if(QUAC_PLATFORM_LINUX)
    set(CPACK_GENERATOR "DEB;RPM;TGZ")
    
    # DEB specific
    set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Dyber, Inc. <support@dyber.com>")
    set(CPACK_DEBIAN_PACKAGE_SECTION "libs")
    set(CPACK_DEBIAN_PACKAGE_DEPENDS "libc6 (>= 2.31)")
    
    # RPM specific
    set(CPACK_RPM_PACKAGE_LICENSE "Proprietary")
    set(CPACK_RPM_PACKAGE_GROUP "System Environment/Libraries")
    
elseif(QUAC_PLATFORM_WINDOWS)
    set(CPACK_GENERATOR "WIX;ZIP")
    set(CPACK_WIX_UPGRADE_GUID "F8A7B9C1-2D3E-4F5A-B6C7-D8E9F0A1B2C3")
endif()

include(CPack)

#-------------------------------------------------------------------------------
# Build Summary
#-------------------------------------------------------------------------------
message(STATUS "")
message(STATUS "========================================")
message(STATUS " Build Configuration Summary")
message(STATUS "========================================")
message(STATUS "")
message(STATUS "  Version:        ${QUAC_VERSION}")
message(STATUS "  Platform:       ${QUAC_PLATFORM}")
message(STATUS "  Architecture:   ${QUAC_ARCH}")
message(STATUS "  Build type:     ${CMAKE_BUILD_TYPE}")
message(STATUS "  Shared libs:    ${BUILD_SHARED_LIBS}")
message(STATUS "")
message(STATUS "  Components:")
message(STATUS "    Simulator:    ${QUAC_BUILD_SIMULATOR}")
message(STATUS "    Tests:        ${QUAC_BUILD_TESTS}")
message(STATUS "    Examples:     ${QUAC_BUILD_EXAMPLES}")
message(STATUS "    Tools:        ${QUAC_BUILD_TOOLS}")
message(STATUS "")
message(STATUS "  Integrations:")
message(STATUS "    OpenSSL:      ${QUAC_BUILD_OPENSSL}")
message(STATUS "    PKCS#11:      ${QUAC_BUILD_PKCS11}")
message(STATUS "    BoringSSL:    ${QUAC_BUILD_BORINGSSL}")
message(STATUS "")
message(STATUS "  Language Bindings:")
message(STATUS "    Python:       ${QUAC_BUILD_PYTHON}")
message(STATUS "    Rust:         ${QUAC_BUILD_RUST}")
message(STATUS "    Java:         ${QUAC_BUILD_JAVA}")
message(STATUS "    Go:           ${QUAC_BUILD_GO}")
message(STATUS "    Node.js:      ${QUAC_BUILD_NODEJS}")
message(STATUS "    C#:           ${QUAC_BUILD_CSHARP}")
message(STATUS "")
message(STATUS "  Security:")
message(STATUS "    Zeroize:      ${QUAC_ENABLE_ZEROIZE}")
message(STATUS "    FIPS mode:    ${QUAC_ENABLE_FIPS_MODE}")
message(STATUS "")
message(STATUS "========================================")
message(STATUS "")
