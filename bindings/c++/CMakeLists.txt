cmake_minimum_required(VERSION 3.16)

project(quac100pp
    VERSION 1.0.0
    DESCRIPTION "QUAC 100 Post-Quantum Cryptographic Accelerator - C++ SDK"
    LANGUAGES CXX
)

# Options
option(QUAC_BUILD_EXAMPLES "Build example programs" ON)
option(QUAC_BUILD_TESTS "Build test programs" OFF)
option(QUAC_BUILD_SHARED "Build shared library" ON)
option(QUAC_BUILD_STATIC "Build static library" ON)

# C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Compiler warnings
if(MSVC)
    add_compile_options(/W4 /EHsc)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# Find the C library (quac100)
find_library(QUAC100_C_LIBRARY 
    NAMES quac100 
    PATHS 
        ${CMAKE_CURRENT_SOURCE_DIR}/../c/build/Release
        ${CMAKE_CURRENT_SOURCE_DIR}/../c/build
        /usr/local/lib
        /usr/lib
)

find_path(QUAC100_C_INCLUDE_DIR 
    NAMES quac100/quac100.h
    PATHS 
        ${CMAKE_CURRENT_SOURCE_DIR}/../c/include
        /usr/local/include
        /usr/include
)

# Find the C library DLL for runtime
if(WIN32)
    find_file(QUAC100_C_DLL
        NAMES quac100.dll
        PATHS
            ${CMAKE_CURRENT_SOURCE_DIR}/../c/build/Release
            ${CMAKE_CURRENT_SOURCE_DIR}/../c/build
    )
    if(QUAC100_C_DLL)
        message(STATUS "Found QUAC 100 C DLL: ${QUAC100_C_DLL}")
    endif()
endif()

if(NOT QUAC100_C_LIBRARY OR NOT QUAC100_C_INCLUDE_DIR)
    message(WARNING "QUAC 100 C library not found. Building in header-only mode.")
    set(QUAC_HEADER_ONLY ON)
else()
    message(STATUS "Found QUAC 100 C library: ${QUAC100_C_LIBRARY}")
    message(STATUS "Found QUAC 100 C headers: ${QUAC100_C_INCLUDE_DIR}")
    set(QUAC_HEADER_ONLY OFF)
endif()

# Source files
set(QUAC_CPP_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/quac100.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/device.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/kem.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/sign.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/random.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/hash.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/keys.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/utils.cpp
)

# Header files
set(QUAC_CPP_HEADERS
    ${CMAKE_CURRENT_SOURCE_DIR}/include/quac100/quac100.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/include/quac100/types.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/include/quac100/exception.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/include/quac100/device.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/include/quac100/kem.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/include/quac100/sign.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/include/quac100/random.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/include/quac100/hash.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/include/quac100/keys.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/include/quac100/utils.hpp
)

# Static library
if(QUAC_BUILD_STATIC)
    add_library(quac100pp_static STATIC ${QUAC_CPP_SOURCES} ${QUAC_CPP_HEADERS})
    
    # Use generator expressions for include directories
    target_include_directories(quac100pp_static
        PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
            $<INSTALL_INTERFACE:include>
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src
    )
    
    if(NOT QUAC_HEADER_ONLY)
        target_include_directories(quac100pp_static PRIVATE ${QUAC100_C_INCLUDE_DIR})
        target_link_libraries(quac100pp_static PUBLIC ${QUAC100_C_LIBRARY})
    endif()
    
    set_target_properties(quac100pp_static PROPERTIES OUTPUT_NAME quac100pp)
    
    # Alias for use in build tree
    add_library(quac100pp ALIAS quac100pp_static)
endif()

# Shared library
if(QUAC_BUILD_SHARED)
    add_library(quac100pp_shared SHARED ${QUAC_CPP_SOURCES} ${QUAC_CPP_HEADERS})
    
    # Use generator expressions for include directories
    target_include_directories(quac100pp_shared
        PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
            $<INSTALL_INTERFACE:include>
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src
    )
    
    if(NOT QUAC_HEADER_ONLY)
        target_include_directories(quac100pp_shared PRIVATE ${QUAC100_C_INCLUDE_DIR})
        target_link_libraries(quac100pp_shared PUBLIC ${QUAC100_C_LIBRARY})
    endif()
    
    set_target_properties(quac100pp_shared PROPERTIES OUTPUT_NAME quac100pp)
    
    if(WIN32)
        target_compile_definitions(quac100pp_shared PRIVATE QUAC_BUILD_DLL)
    endif()
endif()

# Use static library by default for examples/tests
if(QUAC_BUILD_STATIC)
    set(QUAC_LINK_TARGET quac100pp_static)
elseif(QUAC_BUILD_SHARED)
    set(QUAC_LINK_TARGET quac100pp_shared)
endif()

# Copy C library DLL to output directory (Windows only)
if(WIN32 AND QUAC100_C_DLL AND DEFINED QUAC_LINK_TARGET)
    # Copy DLL after building the library
    add_custom_command(TARGET ${QUAC_LINK_TARGET} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${QUAC100_C_DLL}"
            "$<TARGET_FILE_DIR:${QUAC_LINK_TARGET}>"
        COMMENT "Copying quac100.dll to output directory"
    )
endif()

# Examples
if(QUAC_BUILD_EXAMPLES AND DEFINED QUAC_LINK_TARGET)
    add_executable(cpp_basic_example examples/basic_example.cpp)
    target_link_libraries(cpp_basic_example PRIVATE ${QUAC_LINK_TARGET})
    
    add_executable(cpp_kem_example examples/kem_example.cpp)
    target_link_libraries(cpp_kem_example PRIVATE ${QUAC_LINK_TARGET})
    
    add_executable(cpp_sign_example examples/sign_example.cpp)
    target_link_libraries(cpp_sign_example PRIVATE ${QUAC_LINK_TARGET})
    
    add_executable(cpp_random_example examples/random_example.cpp)
    target_link_libraries(cpp_random_example PRIVATE ${QUAC_LINK_TARGET})
    
    add_executable(cpp_hash_example examples/hash_example.cpp)
    target_link_libraries(cpp_hash_example PRIVATE ${QUAC_LINK_TARGET})
endif()

# Tests
if(QUAC_BUILD_TESTS AND DEFINED QUAC_LINK_TARGET)
    enable_testing()
    
    add_executable(test_quac100pp tests/test_quac100pp.cpp)
    target_link_libraries(test_quac100pp PRIVATE ${QUAC_LINK_TARGET})
    
    add_test(NAME quac100pp_tests COMMAND test_quac100pp)
endif()

# Installation
include(GNUInstallDirs)

# Install headers
install(DIRECTORY include/quac100
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

# Install libraries
if(QUAC_BUILD_STATIC)
    install(TARGETS quac100pp_static
            EXPORT quac100ppTargets
            LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
            ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
            RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

if(QUAC_BUILD_SHARED)
    install(TARGETS quac100pp_shared
            EXPORT quac100ppTargets
            LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
            ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
            RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

# CMake package config
install(EXPORT quac100ppTargets
        FILE quac100ppTargets.cmake
        NAMESPACE quac100pp::
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/quac100pp)

include(CMakePackageConfigHelpers)

configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/quac100ppConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/quac100ppConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/quac100pp
)

write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/quac100ppConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/quac100ppConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/quac100ppConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/quac100pp
)

# Print configuration
message(STATUS "")
message(STATUS "QUAC 100 C++ SDK Configuration:")
message(STATUS "  Version: ${PROJECT_VERSION}")
message(STATUS "  C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "  Build static: ${QUAC_BUILD_STATIC}")
message(STATUS "  Build shared: ${QUAC_BUILD_SHARED}")
message(STATUS "  Build examples: ${QUAC_BUILD_EXAMPLES}")
message(STATUS "  Build tests: ${QUAC_BUILD_TESTS}")
if(NOT QUAC_HEADER_ONLY)
    message(STATUS "  C Library: ${QUAC100_C_LIBRARY}")
endif()
if(WIN32 AND QUAC100_C_DLL)
    message(STATUS "  C Library DLL: ${QUAC100_C_DLL}")
endif()
message(STATUS "")