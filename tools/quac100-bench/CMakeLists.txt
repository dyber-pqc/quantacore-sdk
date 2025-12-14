# QUAC 100 Benchmark Tool
# Copyright 2025 Dyber, Inc. All Rights Reserved.

cmake_minimum_required(VERSION 3.16)
project(quac100-bench VERSION 1.0.0 LANGUAGES C)

# C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Source files
set(BENCH_SOURCES
    src/main.c
    src/benchmark.c
    src/stats.c
    src/output.c
    src/algorithms.c
)

# Executable
add_executable(quac100-bench ${BENCH_SOURCES})

# Include directories
target_include_directories(quac100-bench PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/include
)

# Link to QUAC SDK
target_link_libraries(quac100-bench PRIVATE quac100)

# Platform-specific
if(WIN32)
    target_link_libraries(quac100-bench PRIVATE ws2_32)
else()
    target_link_libraries(quac100-bench PRIVATE m pthread)
endif()

# Compiler warnings
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(quac100-bench PRIVATE -Wall -Wextra -Wpedantic)
elseif(MSVC)
    target_compile_options(quac100-bench PRIVATE /W4)
endif()

# Install
install(TARGETS quac100-bench
    RUNTIME DESTINATION bin
)

# Tests
if(BUILD_TESTING)
    enable_testing()
    add_test(NAME bench_help COMMAND quac100-bench --help)
    add_test(NAME bench_version COMMAND quac100-bench --version)
endif()