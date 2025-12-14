# QUAC 100 Command Line Interface
# Copyright 2025 Dyber, Inc. All Rights Reserved.

cmake_minimum_required(VERSION 3.16)
project(quac100-cli VERSION 1.0.0 LANGUAGES C)

# C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Source files
set(CLI_SOURCES
    src/main.c
    src/commands.c
    src/device.c
    src/kem.c
    src/sign.c
    src/random.c
    src/keys.c
    src/shell.c
    src/utils.c
)

# Executable
add_executable(quac100-cli ${CLI_SOURCES})

# Include directories
target_include_directories(quac100-cli PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/include
)

# Link to QUAC SDK
target_link_libraries(quac100-cli PRIVATE quac100)

# Platform-specific
if(WIN32)
    target_link_libraries(quac100-cli PRIVATE ws2_32)
else()
    target_link_libraries(quac100-cli PRIVATE m pthread readline)
endif()

# Compiler warnings
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(quac100-cli PRIVATE -Wall -Wextra -Wpedantic)
elseif(MSVC)
    target_compile_options(quac100-cli PRIVATE /W4)
endif()

# Install
install(TARGETS quac100-cli
    RUNTIME DESTINATION bin
)

# Tests
if(BUILD_TESTING)
    enable_testing()
    add_test(NAME cli_help COMMAND quac100-cli --help)
    add_test(NAME cli_version COMMAND quac100-cli --version)
    add_test(NAME cli_list COMMAND quac100-cli list)
endif()