# QUAC 100 Diagnostics Tool
# Copyright 2025 Dyber, Inc. All Rights Reserved.

cmake_minimum_required(VERSION 3.16)
project(quac100-diag VERSION 1.0.0 LANGUAGES C)

# C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Source files
set(DIAG_SOURCES
    src/main.c
    src/diag.c
    src/tests.c
    src/hardware.c
    src/report.c
    src/utils.c
)

# Executable
add_executable(quac100-diag ${DIAG_SOURCES})

# Include directories
target_include_directories(quac100-diag PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/include
)

# Link to QUAC SDK
target_link_libraries(quac100-diag PRIVATE quac100)

# Platform-specific
if(WIN32)
    target_link_libraries(quac100-diag PRIVATE ws2_32)
else()
    target_link_libraries(quac100-diag PRIVATE m pthread)
endif()

# Compiler warnings
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(quac100-diag PRIVATE -Wall -Wextra -Wpedantic)
elseif(MSVC)
    target_compile_options(quac100-diag PRIVATE /W4)
endif()

# Install
install(TARGETS quac100-diag
    RUNTIME DESTINATION bin
)

# Tests
if(BUILD_TESTING)
    enable_testing()
    add_test(NAME diag_help COMMAND quac100-diag --help)
    add_test(NAME diag_version COMMAND quac100-diag --version)
    add_test(NAME diag_list COMMAND quac100-diag --list-tests)
endif()