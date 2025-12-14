# QUAC 100 OpenSSL Provider
# Copyright 2025 Dyber, Inc. All Rights Reserved.
#
# This builds an OpenSSL 3.x provider that enables transparent
# hardware acceleration for post-quantum cryptographic operations.

cmake_minimum_required(VERSION 3.16)
project(quac100_provider VERSION 1.0.0 LANGUAGES C)

# =============================================================================
# Options
# =============================================================================

option(QUAC_PROVIDER_SHARED "Build as shared library" ON)
option(QUAC_PROVIDER_INSTALL "Install provider" ON)
option(QUAC_PROVIDER_TESTS "Build provider tests" ON)

# =============================================================================
# Find Dependencies
# =============================================================================

# OpenSSL 3.0+
find_package(OpenSSL 3.0 REQUIRED)
message(STATUS "OpenSSL version: ${OPENSSL_VERSION}")
message(STATUS "OpenSSL include: ${OPENSSL_INCLUDE_DIR}")
message(STATUS "OpenSSL libraries: ${OPENSSL_LIBRARIES}")

# QUAC 100 SDK
find_library(QUAC100_LIBRARY 
    NAMES quac100 libquac100
    PATHS 
        ${CMAKE_SOURCE_DIR}/../../lib
        /usr/local/lib
        /usr/lib
)

find_path(QUAC100_INCLUDE_DIR 
    NAMES quac100.h
    PATHS 
        ${CMAKE_SOURCE_DIR}/../../include
        /usr/local/include
        /usr/include
)

if(NOT QUAC100_LIBRARY OR NOT QUAC100_INCLUDE_DIR)
    message(WARNING "QUAC 100 SDK not found, building with simulator support only")
    set(QUAC_USE_SIMULATOR ON)
else()
    message(STATUS "QUAC 100 SDK: ${QUAC100_LIBRARY}")
    set(QUAC_USE_SIMULATOR OFF)
endif()

# =============================================================================
# Provider Library
# =============================================================================

set(PROVIDER_SOURCES
    quac100_provider.c
    quac100_kem_alg.c
    quac100_sig_alg.c
    quac100_rand.c
)

if(QUAC_PROVIDER_SHARED)
    add_library(quac100_provider SHARED ${PROVIDER_SOURCES})
    set_target_properties(quac100_provider PROPERTIES
        PREFIX ""
        OUTPUT_NAME "quac100"
        SUFFIX ".so"
    )
    
    # On Windows, use .dll
    if(WIN32)
        set_target_properties(quac100_provider PROPERTIES SUFFIX ".dll")
    endif()
    
    # On macOS, use .dylib
    if(APPLE)
        set_target_properties(quac100_provider PROPERTIES SUFFIX ".dylib")
    endif()
else()
    add_library(quac100_provider STATIC ${PROVIDER_SOURCES})
endif()

target_include_directories(quac100_provider PRIVATE
    ${OPENSSL_INCLUDE_DIR}
    ${QUAC100_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(quac100_provider PRIVATE
    ${OPENSSL_LIBRARIES}
)

if(NOT QUAC_USE_SIMULATOR)
    target_link_libraries(quac100_provider PRIVATE ${QUAC100_LIBRARY})
    target_compile_definitions(quac100_provider PRIVATE QUAC_HAS_HARDWARE=1)
endif()

# Compiler flags
target_compile_options(quac100_provider PRIVATE
    -Wall -Wextra -Wpedantic
    -fvisibility=hidden
)

# Export only OSSL_provider_init
if(NOT WIN32)
    set_target_properties(quac100_provider PROPERTIES
        LINK_FLAGS "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/quac100.map"
    )
endif()

# =============================================================================
# Version Script (Linux)
# =============================================================================

file(WRITE ${CMAKE_CURRENT_SOURCE_DIR}/quac100.map
"QUAC100_1.0 {
    global:
        OSSL_provider_init;
    local:
        *;
};
")

# =============================================================================
# Installation
# =============================================================================

if(QUAC_PROVIDER_INSTALL)
    # Determine OpenSSL provider directory
    execute_process(
        COMMAND ${OPENSSL_EXECUTABLE} version -d
        OUTPUT_VARIABLE OPENSSL_DIR_OUTPUT
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    string(REGEX REPLACE "OPENSSLDIR: \"(.*)\"" "\\1" OPENSSL_DIR "${OPENSSL_DIR_OUTPUT}")
    
    # Default provider paths
    if(UNIX AND NOT APPLE)
        set(PROVIDER_INSTALL_DIR "${CMAKE_INSTALL_PREFIX}/lib/ossl-modules" CACHE PATH "Provider install directory")
    elseif(APPLE)
        set(PROVIDER_INSTALL_DIR "${CMAKE_INSTALL_PREFIX}/lib/ossl-modules" CACHE PATH "Provider install directory")
    else()
        set(PROVIDER_INSTALL_DIR "${CMAKE_INSTALL_PREFIX}/bin" CACHE PATH "Provider install directory")
    endif()
    
    install(TARGETS quac100_provider
        LIBRARY DESTINATION ${PROVIDER_INSTALL_DIR}
        RUNTIME DESTINATION ${PROVIDER_INSTALL_DIR}
    )
    
    # Install example config
    install(FILES openssl.cnf.example
        DESTINATION ${CMAKE_INSTALL_PREFIX}/share/quac100
    )
    
    message(STATUS "Provider will be installed to: ${PROVIDER_INSTALL_DIR}")
endif()

# =============================================================================
# Tests
# =============================================================================

if(QUAC_PROVIDER_TESTS)
    enable_testing()
    
    # Test: Provider loads
    add_test(NAME provider_load
        COMMAND ${OPENSSL_EXECUTABLE} list -providers 
            -provider-path $<TARGET_FILE_DIR:quac100_provider>
            -provider quac100
    )
    
    # Test: List algorithms
    add_test(NAME provider_algorithms
        COMMAND ${OPENSSL_EXECUTABLE} list -kem-algorithms
            -provider-path $<TARGET_FILE_DIR:quac100_provider>
            -provider quac100
    )
endif()

# =============================================================================
# Documentation
# =============================================================================

message(STATUS "")
message(STATUS "QUAC 100 OpenSSL Provider Configuration:")
message(STATUS "  Provider type: ${QUAC_PROVIDER_SHARED}")
message(STATUS "  Hardware support: ${NOT QUAC_USE_SIMULATOR}")
message(STATUS "  OpenSSL version: ${OPENSSL_VERSION}")
message(STATUS "")
message(STATUS "After building, load the provider with:")
message(STATUS "  export OPENSSL_MODULES=\${PWD}")
message(STATUS "  openssl list -providers -provider quac100")
message(STATUS "")