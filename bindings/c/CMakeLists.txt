cmake_minimum_required(VERSION 3.16)

project(quac100
    VERSION 1.0.0
    DESCRIPTION "QUAC 100 Post-Quantum Cryptographic Accelerator SDK"
    LANGUAGES C
)

# Options
option(QUAC_BUILD_EXAMPLES "Build example programs" ON)
option(QUAC_BUILD_TESTS "Build test programs" ON)
option(QUAC_ENABLE_SIMULATION "Enable hardware simulation (no real device)" ON)

# Set C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Compiler warnings
if(MSVC)
    add_compile_options(/W4)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# Simulation mode definition
if(QUAC_ENABLE_SIMULATION)
    add_definitions(-DQUAC_ENABLE_SIMULATION=1)
endif()

# Platform detection
if(WIN32)
    add_definitions(-DQUAC_PLATFORM_WINDOWS=1)
elseif(APPLE)
    add_definitions(-DQUAC_PLATFORM_MACOS=1)
else()
    add_definitions(-DQUAC_PLATFORM_LINUX=1)
endif()

# Source files (in src/ directory)
set(QUAC_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/quac100.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/device.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/kem.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/sign.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/random.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/hash.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/keys.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/utils.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/hal.c
)

# Header files (in include/quac100/ directory)
set(QUAC_HEADERS
    ${CMAKE_CURRENT_SOURCE_DIR}/include/quac100/quac100.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/quac100/types.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/quac100/device.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/quac100/kem.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/quac100/sign.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/quac100/random.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/quac100/hash.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/quac100/keys.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/quac100/utils.h
    ${CMAKE_CURRENT_SOURCE_DIR}/src/internal.h
)

# Include directories
set(QUAC_INCLUDE_DIRS
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# Build static library
add_library(quac100_static STATIC ${QUAC_SOURCES} ${QUAC_HEADERS})
target_include_directories(quac100_static PUBLIC ${QUAC_INCLUDE_DIRS})
set_target_properties(quac100_static PROPERTIES OUTPUT_NAME quac100)

# Build shared library
add_library(quac100_shared SHARED ${QUAC_SOURCES} ${QUAC_HEADERS})
target_include_directories(quac100_shared PUBLIC ${QUAC_INCLUDE_DIRS})
set_target_properties(quac100_shared PROPERTIES OUTPUT_NAME quac100)
if(WIN32)
    target_compile_definitions(quac100_shared PRIVATE QUAC_BUILD_DLL)
endif()

# Link libraries (pthread on non-Windows)
if(NOT WIN32)
    target_link_libraries(quac100_static PRIVATE pthread)
    target_link_libraries(quac100_shared PRIVATE pthread)
endif()

# Alias for convenience
add_library(quac100 ALIAS quac100_static)

# Build examples
if(QUAC_BUILD_EXAMPLES)
    # Basic example (in root)
    if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/basic.c)
        add_executable(basic_example ${CMAKE_CURRENT_SOURCE_DIR}/basic.c)
        target_link_libraries(basic_example PRIVATE quac100_static)
        target_include_directories(basic_example PRIVATE ${QUAC_INCLUDE_DIRS})
    endif()

    # KEM example
    add_executable(kem_example ${CMAKE_CURRENT_SOURCE_DIR}/examples/kem_example.c)
    target_link_libraries(kem_example PRIVATE quac100_static)
    target_include_directories(kem_example PRIVATE ${QUAC_INCLUDE_DIRS})

    # Sign example
    add_executable(sign_example ${CMAKE_CURRENT_SOURCE_DIR}/examples/sign_example.c)
    target_link_libraries(sign_example PRIVATE quac100_static)
    target_include_directories(sign_example PRIVATE ${QUAC_INCLUDE_DIRS})

    # Random example
    add_executable(random_example ${CMAKE_CURRENT_SOURCE_DIR}/examples/random_example.c)
    target_link_libraries(random_example PRIVATE quac100_static)
    target_include_directories(random_example PRIVATE ${QUAC_INCLUDE_DIRS})

    # Hash example
    add_executable(hash_example ${CMAKE_CURRENT_SOURCE_DIR}/examples/hash_example.c)
    target_link_libraries(hash_example PRIVATE quac100_static)
    target_include_directories(hash_example PRIVATE ${QUAC_INCLUDE_DIRS})
endif()

# Build tests
if(QUAC_BUILD_TESTS)
    enable_testing()
    
    add_executable(test_quac100 ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_quac100.c)
    target_link_libraries(test_quac100 PRIVATE quac100_static)
    target_include_directories(test_quac100 PRIVATE ${QUAC_INCLUDE_DIRS})
    
    add_test(NAME quac100_tests COMMAND test_quac100)

    # Simple test if it exists in src/
    if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/src/simple_test.c)
        add_executable(simple_test ${CMAKE_CURRENT_SOURCE_DIR}/src/simple_test.c)
        target_link_libraries(simple_test PRIVATE quac100_static)
        target_include_directories(simple_test PRIVATE ${QUAC_INCLUDE_DIRS})
    endif()
endif()

# Print configuration
message(STATUS "")
message(STATUS "QUAC 100 SDK Configuration:")
message(STATUS "  Version: ${PROJECT_VERSION}")
message(STATUS "  Simulation mode: ${QUAC_ENABLE_SIMULATION}")
message(STATUS "  Build examples: ${QUAC_BUILD_EXAMPLES}")
message(STATUS "  Build tests: ${QUAC_BUILD_TESTS}")
message(STATUS "  Source dir: ${CMAKE_CURRENT_SOURCE_DIR}/src")
message(STATUS "  Include dir: ${CMAKE_CURRENT_SOURCE_DIR}/include")
message(STATUS "")