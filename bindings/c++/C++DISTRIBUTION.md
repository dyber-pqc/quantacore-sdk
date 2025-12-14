# QUAC 100 C++ SDK - Distribution Guide

This guide explains how to distribute and integrate the QUAC 100 C++ SDK.

## Building Release Packages

### Windows

```powershell
# Build Release
mkdir build
cd build
cmake .. -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release

# Create release package
$version = "1.0.0"
$releaseDir = "release\quac100pp-$version-windows-x64"

# Create directories
New-Item -ItemType Directory -Force -Path "$releaseDir\include\quac100"
New-Item -ItemType Directory -Force -Path "$releaseDir\lib"
New-Item -ItemType Directory -Force -Path "$releaseDir\bin"

# Copy files
Copy-Item "..\include\quac100\*.hpp" "$releaseDir\include\quac100\"
Copy-Item "Release\quac100pp.lib" "$releaseDir\lib\"
Copy-Item "Release\quac100pp.dll" "$releaseDir\bin\" -ErrorAction SilentlyContinue
Copy-Item "..\README.md" "$releaseDir\"

# Create ZIP
Compress-Archive -Path $releaseDir -DestinationPath "release\quac100pp-$version-windows-x64.zip" -Force

Write-Host "Created: release\quac100pp-$version-windows-x64.zip"
```

### Linux

```bash
#!/bin/bash
VERSION="1.0.0"
RELEASE_DIR="release/quac100pp-${VERSION}-linux-x64"

# Build
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
cd ..

# Create release structure
mkdir -p "${RELEASE_DIR}/include/quac100"
mkdir -p "${RELEASE_DIR}/lib"

# Copy files
cp include/quac100/*.hpp "${RELEASE_DIR}/include/quac100/"
cp build/libquac100pp.a "${RELEASE_DIR}/lib/"
cp build/libquac100pp.so* "${RELEASE_DIR}/lib/" 2>/dev/null || true
cp README.md "${RELEASE_DIR}/"

# Create tarball
tar -czvf "release/quac100pp-${VERSION}-linux-x64.tar.gz" -C release "quac100pp-${VERSION}-linux-x64"

echo "Created: release/quac100pp-${VERSION}-linux-x64.tar.gz"
```

## GitHub Releases

1. Tag the release:
```bash
git tag -a v1.0.0 -m "QUAC 100 C++ SDK v1.0.0"
git push origin v1.0.0
```

2. Create release on GitHub with:
   - Release notes
   - Windows ZIP: `quac100pp-1.0.0-windows-x64.zip`
   - Linux tarball: `quac100pp-1.0.0-linux-x64.tar.gz`

## Package Manager Integration

### vcpkg

Create `vcpkg-port/portfile.cmake`:

```cmake
vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO dyber-inc/quantacore-sdk
    REF v${VERSION}
    SHA512 <sha512-hash>
    HEAD_REF main
)

vcpkg_cmake_configure(
    SOURCE_PATH "${SOURCE_PATH}/bindings/cpp"
    OPTIONS
        -DQUAC_BUILD_EXAMPLES=OFF
        -DQUAC_BUILD_TESTS=OFF
)

vcpkg_cmake_install()
vcpkg_cmake_config_fixup(CONFIG_PATH lib/cmake/quac100pp)

file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug/include")

file(INSTALL "${SOURCE_PATH}/bindings/cpp/LICENSE" 
     DESTINATION "${CURRENT_PACKAGES_DIR}/share/${PORT}" 
     RENAME copyright)
```

Create `vcpkg-port/vcpkg.json`:

```json
{
  "name": "quac100pp",
  "version": "1.0.0",
  "description": "C++ SDK for QUAC 100 Post-Quantum Cryptographic Accelerator",
  "homepage": "https://github.com/dyber-inc/quantacore-sdk",
  "license": "Proprietary",
  "dependencies": [
    "quac100",
    {
      "name": "vcpkg-cmake",
      "host": true
    },
    {
      "name": "vcpkg-cmake-config",
      "host": true
    }
  ]
}
```

### Conan

Create `conan/conanfile.py`:

```python
from conan import ConanFile
from conan.tools.cmake import CMake, cmake_layout, CMakeToolchain
from conan.tools.files import copy, get
import os

class Quac100ppConan(ConanFile):
    name = "quac100pp"
    version = "1.0.0"
    license = "Proprietary"
    author = "Dyber, Inc."
    url = "https://github.com/dyber-inc/quantacore-sdk"
    description = "C++ SDK for QUAC 100 Post-Quantum Cryptographic Accelerator"
    topics = ("cryptography", "post-quantum", "hardware-acceleration")
    settings = "os", "compiler", "build_type", "arch"
    options = {
        "shared": [True, False],
        "fPIC": [True, False]
    }
    default_options = {
        "shared": False,
        "fPIC": True
    }
    requires = "quac100/1.0.0"

    def config_options(self):
        if self.settings.os == "Windows":
            del self.options.fPIC

    def layout(self):
        cmake_layout(self)

    def generate(self):
        tc = CMakeToolchain(self)
        tc.variables["QUAC_BUILD_EXAMPLES"] = False
        tc.variables["QUAC_BUILD_TESTS"] = False
        tc.variables["QUAC_BUILD_SHARED"] = self.options.shared
        tc.variables["QUAC_BUILD_STATIC"] = not self.options.shared
        tc.generate()

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()

    def package(self):
        copy(self, "*.hpp", src=os.path.join(self.source_folder, "include"),
             dst=os.path.join(self.package_folder, "include"))
        copy(self, "*.lib", src=self.build_folder, 
             dst=os.path.join(self.package_folder, "lib"), keep_path=False)
        copy(self, "*.dll", src=self.build_folder,
             dst=os.path.join(self.package_folder, "bin"), keep_path=False)
        copy(self, "*.so*", src=self.build_folder,
             dst=os.path.join(self.package_folder, "lib"), keep_path=False)
        copy(self, "*.a", src=self.build_folder,
             dst=os.path.join(self.package_folder, "lib"), keep_path=False)
        copy(self, "*.dylib", src=self.build_folder,
             dst=os.path.join(self.package_folder, "lib"), keep_path=False)

    def package_info(self):
        self.cpp_info.libs = ["quac100pp"]
        self.cpp_info.set_property("cmake_file_name", "quac100pp")
        self.cpp_info.set_property("cmake_target_name", "quac100pp::quac100pp")
```

## User Integration Methods

### Method 1: Direct Download

```cmake
# User's CMakeLists.txt
# Assumes quac100pp installed to /opt/quac100pp

set(QUAC100PP_ROOT "/opt/quac100pp")
include_directories(${QUAC100PP_ROOT}/include)
link_directories(${QUAC100PP_ROOT}/lib)

add_executable(myapp main.cpp)
target_link_libraries(myapp quac100pp quac100)
```

### Method 2: CMake find_package

After installing:
```cmake
find_package(quac100pp REQUIRED)
target_link_libraries(myapp PRIVATE quac100pp::quac100pp)
```

### Method 3: CMake FetchContent

```cmake
include(FetchContent)
FetchContent_Declare(quac100pp
    GIT_REPOSITORY https://github.com/dyber-inc/quantacore-sdk.git
    GIT_TAG v1.0.0
    SOURCE_SUBDIR bindings/cpp)
FetchContent_MakeAvailable(quac100pp)
target_link_libraries(myapp PRIVATE quac100pp)
```

### Method 4: vcpkg

```bash
vcpkg install quac100pp
```

```cmake
find_package(quac100pp CONFIG REQUIRED)
target_link_libraries(myapp PRIVATE quac100pp::quac100pp)
```

### Method 5: Conan

```bash
conan install quac100pp/1.0.0@
```

## Header-Only Usage (Limited)

For simple cases, you can include headers and link the C library:

```cpp
// Only types and exceptions work without linking C++ lib
#include <quac100/types.hpp>
#include <quac100/exception.hpp>

// Must link quac100 (C library) for actual functionality
```

## Dependency Notes

The C++ SDK depends on the C library (quac100). Users must:

1. Install C library first
2. Ensure C library is in library search path
3. Link both libraries: `-lquac100pp -lquac100`

## Platform-Specific Notes

### Windows
- MSVC 2019+ required
- Use `/EHsc` for exception handling
- DLLs must be in PATH or alongside executable

### Linux
- GCC 8+ or Clang 7+ required
- May need `-pthread` for threading
- Set `LD_LIBRARY_PATH` if not in standard location

### macOS
- Clang from Xcode 11+ required
- May need to set `DYLD_LIBRARY_PATH`

## Version Compatibility

| C++ SDK | C SDK | Status |
|---------|-------|--------|
| 1.0.x   | 1.0.x | Current |

Always use matching major versions of C++ and C SDKs.