# QUAC 100 Binding Generator
# CMakeLists.txt
#
# Copyright 2025 Dyber, Inc. All Rights Reserved.

cmake_minimum_required(VERSION 3.16)
project(quac-bindgen VERSION 1.0.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Compiler flags
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra -Wpedantic)
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        add_compile_options(-g -O0)
    else()
        add_compile_options(-O2)
    endif()
elseif(MSVC)
    add_compile_options(/W4 /WX-)
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        add_compile_options(/Od /Zi)
    else()
        add_compile_options(/O2)
    endif()
endif()

# Source files
set(BINDGEN_SOURCES
    src/main.c
    src/parser.c
    src/types.c
    src/generator.c
    src/gen_python.c
    src/gen_rust.c
    src/gen_go.c
    src/gen_java.c
    src/gen_csharp.c
    src/gen_nodejs.c
)

set(BINDGEN_HEADERS
    src/parser.h
    src/types.h
    src/generator.h
)

# Main executable
add_executable(quac-bindgen ${BINDGEN_SOURCES} ${BINDGEN_HEADERS})

target_include_directories(quac-bindgen PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# Platform-specific linking
if(WIN32)
    target_link_libraries(quac-bindgen PRIVATE)
else()
    target_link_libraries(quac-bindgen PRIVATE m)
endif()

# Install target
install(TARGETS quac-bindgen
    RUNTIME DESTINATION bin
)

# Tests
option(BUILD_TESTS "Build unit tests" ON)
if(BUILD_TESTS)
    enable_testing()
    
    add_executable(test_parser
        tests/test_parser.c
        src/parser.c
        src/types.c
        src/generator.c
    )
    
    target_include_directories(test_parser PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
    )
    
    if(NOT WIN32)
        target_link_libraries(test_parser PRIVATE m)
    endif()
    
    add_test(NAME parser_tests COMMAND test_parser)
endif()

# Package info
set(CPACK_PACKAGE_NAME "quac-bindgen")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_VENDOR "Dyber, Inc.")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "QUAC 100 Binding Generator")
include(CPack)