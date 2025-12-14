#!/bin/bash
# QUAC 100 Java SDK - Native Library Build Script (Linux/macOS)
# Copyright (c) 2025 Dyber, Inc. All Rights Reserved.

set -e

echo "============================================================"
echo "QUAC 100 Java SDK - Native Library Build"
echo "============================================================"
echo ""

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NATIVE_DIR="${SCRIPT_DIR}/native"
BUILD_DIR="${NATIVE_DIR}/build"

# Default QUAC100_ROOT if not set
if [ -z "$QUAC100_ROOT" ]; then
    QUAC100_ROOT="${SCRIPT_DIR}/../c"
fi

# Verify QUAC 100 C library exists
if [ ! -f "${QUAC100_ROOT}/include/quac100/quac100.h" ]; then
    echo "ERROR: QUAC 100 C library not found at ${QUAC100_ROOT}"
    echo "Please set QUAC100_ROOT environment variable or build the C library first."
    exit 1
fi

echo "Using QUAC 100 C library: ${QUAC100_ROOT}"
echo ""

# Check if C library is built
if [ ! -f "${QUAC100_ROOT}/build/libquac100.so" ] && [ ! -f "${QUAC100_ROOT}/build/libquac100.dylib" ]; then
    echo "WARNING: QUAC 100 C library shared object not found."
    echo "Please build the C library first:"
    echo "  cd ${QUAC100_ROOT}"
    echo "  mkdir -p build && cd build"
    echo "  cmake .."
    echo "  make"
    echo ""
fi

# Create build directory
mkdir -p "${BUILD_DIR}"
cd "${BUILD_DIR}"

# Configure with CMake
echo "Configuring CMake..."
cmake .. -DQUAC100_ROOT="${QUAC100_ROOT}"

# Build
echo ""
echo "Building..."
make -j$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)

echo ""
echo "============================================================"
echo "Build Complete!"
echo "============================================================"
echo ""
echo "Native libraries built in: ${BUILD_DIR}/"

if [ "$(uname)" == "Darwin" ]; then
    echo "  - libquac100_jni.dylib"
    echo "  - libquac100.dylib (copied from C library)"
else
    echo "  - libquac100_jni.so"
    echo "  - libquac100.so (copied from C library)"
fi

echo ""
echo "To run Java tests:"
echo "  cd ${SCRIPT_DIR}"
echo "  mvn test -DargLine=\"-Djava.library.path=${BUILD_DIR}\""
echo ""