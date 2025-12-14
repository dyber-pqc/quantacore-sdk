# QUAC 100 C SDK

The official C SDK for the QUAC 100 (Quantum-Resistant Universal Accelerator Card) post-quantum cryptographic accelerator.

## Overview

The QUAC 100 C SDK provides a high-performance, hardware-accelerated API for post-quantum cryptography operations including:

- **ML-KEM (Kyber)**: Key encapsulation mechanism for secure key exchange
- **ML-DSA (Dilithium)**: Digital signatures
- **SLH-DSA (SPHINCS+)**: Hash-based digital signatures
- **QRNG**: Quantum random number generation
- **Hardware-Accelerated Hashing**: SHA-2, SHA-3, SHAKE

## Features

- ✅ FIPS 140-3 Level 3 compliant (certification pending)
- ✅ Hardware acceleration with sub-microsecond latency
- ✅ Thread-safe API
- ✅ Batch processing support
- ✅ Secure key storage (up to 256 keys)
- ✅ Quantum random number generation
- ✅ Cross-platform (Linux, Windows, macOS)
- ✅ Comprehensive documentation (Doxygen)

## Quick Start

```c
#include <quac100/quac100.h>
#include <stdio.h>

int main(void) {
    // Initialize library
    quac_init(QUAC_FLAG_DEFAULT);
    
    // Open device
    quac_device_t device;
    quac_open_first_device(&device);
    
    // Generate ML-KEM-768 key pair
    uint8_t pk[QUAC_ML_KEM_768_PUBLIC_KEY_SIZE];
    uint8_t sk[QUAC_ML_KEM_768_SECRET_KEY_SIZE];
    size_t pk_len = sizeof(pk), sk_len = sizeof(sk);
    
    quac_kem_keygen(device, QUAC_KEM_ML_KEM_768, pk, &pk_len, sk, &sk_len);
    
    printf("Generated ML-KEM-768 key pair!\n");
    
    // Cleanup
    quac_close_device(device);
    quac_cleanup();
    return 0;
}
```

## Installation

### Prerequisites

- CMake 3.16+
- C11 compatible compiler (GCC 7+, Clang 6+, MSVC 2019+)
- QUAC 100 hardware (or use simulation mode for development)

### Building from Source

```bash
# Clone repository
git clone https://github.com/dyber-io/quac100-sdk.git
cd quac100-sdk/bindings/c

# Create build directory
mkdir build && cd build

# Configure
cmake .. -DCMAKE_BUILD_TYPE=Release

# Build
cmake --build . --config Release

# Run tests
ctest --output-on-failure

# Install
sudo cmake --install .
```

### Build Options

| Option | Default | Description |
|--------|---------|-------------|
| `QUAC_BUILD_SHARED` | ON | Build shared library (.so/.dll) |
| `QUAC_BUILD_STATIC` | ON | Build static library (.a/.lib) |
| `QUAC_BUILD_EXAMPLES` | ON | Build example programs |
| `QUAC_BUILD_TESTS` | ON | Build test suite |
| `QUAC_BUILD_DOCS` | OFF | Build Doxygen documentation |
| `QUAC_ENABLE_SIMULATION` | ON | Enable hardware simulation |

### Installing on Linux

```bash
# Install to /usr/local
sudo cmake --install . --prefix /usr/local

# Update library cache
sudo ldconfig

# Verify installation
pkg-config --modversion quac100
```

### Installing on Windows

```powershell
# Install to Program Files
cmake --install . --prefix "C:/Program Files/QUAC100"

# Add to PATH (run as Administrator)
[Environment]::SetEnvironmentVariable(
    "PATH",
    $env:PATH + ";C:\Program Files\QUAC100\bin",
    [EnvironmentVariableTarget]::Machine
)
```

### Installing on macOS

```bash
# Install to /usr/local
sudo cmake --install . --prefix /usr/local

# Update dyld cache
sudo update_dyld_shared_cache
```

## Usage Examples

### Key Exchange (ML-KEM)

```c
#include <quac100/quac100.h>

// Alice generates key pair
uint8_t alice_pk[QUAC_ML_KEM_768_PUBLIC_KEY_SIZE];
uint8_t alice_sk[QUAC_ML_KEM_768_SECRET_KEY_SIZE];
size_t alice_pk_len = sizeof(alice_pk), alice_sk_len = sizeof(alice_sk);

quac_kem_keygen(device, QUAC_KEM_ML_KEM_768,
                alice_pk, &alice_pk_len, alice_sk, &alice_sk_len);

// Bob encapsulates shared secret using Alice's public key
uint8_t ciphertext[QUAC_ML_KEM_768_CIPHERTEXT_SIZE];
uint8_t bob_shared_secret[QUAC_ML_KEM_SHARED_SECRET_SIZE];
size_t ct_len = sizeof(ciphertext), ss_len = sizeof(bob_shared_secret);

quac_kem_encaps(device, QUAC_KEM_ML_KEM_768,
                alice_pk, alice_pk_len,
                ciphertext, &ct_len,
                bob_shared_secret, &ss_len);

// Alice decapsulates to get same shared secret
uint8_t alice_shared_secret[QUAC_ML_KEM_SHARED_SECRET_SIZE];
ss_len = sizeof(alice_shared_secret);

quac_kem_decaps(device, QUAC_KEM_ML_KEM_768,
                alice_sk, alice_sk_len,
                ciphertext, ct_len,
                alice_shared_secret, &ss_len);

// alice_shared_secret == bob_shared_secret
```

### Digital Signatures (ML-DSA)

```c
#include <quac100/quac100.h>

// Generate key pair
uint8_t pk[QUAC_ML_DSA_65_PUBLIC_KEY_SIZE];
uint8_t sk[QUAC_ML_DSA_65_SECRET_KEY_SIZE];
size_t pk_len = sizeof(pk), sk_len = sizeof(sk);

quac_sign_keygen(device, QUAC_SIGN_ML_DSA_65, pk, &pk_len, sk, &sk_len);

// Sign message
const char* message = "Important document";
uint8_t signature[QUAC_ML_DSA_65_SIGNATURE_SIZE];
size_t sig_len = sizeof(signature);

quac_sign(device, QUAC_SIGN_ML_DSA_65,
          sk, sk_len,
          (const uint8_t*)message, strlen(message),
          signature, &sig_len);

// Verify signature
quac_status_t status = quac_verify(device, QUAC_SIGN_ML_DSA_65,
                                    pk, pk_len,
                                    (const uint8_t*)message, strlen(message),
                                    signature, sig_len);

if (status == QUAC_SUCCESS) {
    printf("Signature valid!\n");
} else if (status == QUAC_ERROR_VERIFY_FAILED) {
    printf("Signature invalid!\n");
}
```

### Quantum Random Numbers

```c
#include <quac100/quac100.h>

// Generate random bytes
uint8_t random_bytes[32];
quac_random_bytes(device, random_bytes, sizeof(random_bytes));

// Generate random integer in range [0, 100)
uint32_t dice_roll;
quac_random_range(device, 100, &dice_roll);

// Generate random double [0.0, 1.0)
double random_double;
quac_random_double(device, &random_double);

// Generate UUID
char uuid[37];
quac_random_uuid_string(device, uuid, sizeof(uuid));
```

## API Reference

### Algorithm Support

| Algorithm | Type | Security Level | Key Sizes |
|-----------|------|----------------|-----------|
| ML-KEM-512 | KEM | NIST Level 1 | PK: 800, SK: 1632, CT: 768 |
| ML-KEM-768 | KEM | NIST Level 3 | PK: 1184, SK: 2400, CT: 1088 |
| ML-KEM-1024 | KEM | NIST Level 5 | PK: 1568, SK: 3168, CT: 1568 |
| ML-DSA-44 | Signature | NIST Level 2 | PK: 1312, SK: 2560, Sig: 2420 |
| ML-DSA-65 | Signature | NIST Level 3 | PK: 1952, SK: 4032, Sig: 3309 |
| ML-DSA-87 | Signature | NIST Level 5 | PK: 2592, SK: 4896, Sig: 4627 |

### Error Handling

```c
quac_status_t status = quac_kem_keygen(device, ...);
if (status != QUAC_SUCCESS) {
    fprintf(stderr, "Error: %s\n", quac_error_string(status));
}
```

## Linking Your Project

### Using CMake (Recommended)

```cmake
# CMakeLists.txt
cmake_minimum_required(VERSION 3.16)
project(my_app)

find_package(quac100 REQUIRED)

add_executable(my_app main.c)
target_link_libraries(my_app PRIVATE quac100::quac100)
```

### Using pkg-config

```bash
# Compile
gcc -o my_app main.c $(pkg-config --cflags --libs quac100)

# Or manually
gcc -o my_app main.c -I/usr/local/include -L/usr/local/lib -lquac100
```

### Manual Linking

**Linux:**
```bash
gcc -o my_app main.c -I/usr/local/include -L/usr/local/lib -lquac100 -lpthread
```

**Windows (MSVC):**
```cmd
cl /I"C:\Program Files\QUAC100\include" main.c /link /LIBPATH:"C:\Program Files\QUAC100\lib" quac100.lib
```

**macOS:**
```bash
clang -o my_app main.c -I/usr/local/include -L/usr/local/lib -lquac100
```

---

# Publishing the C Library

This section provides instructions for making the QUAC 100 C SDK publicly available for developers.

## Distribution Methods

### 1. GitHub Releases (Primary)

Create binary releases for each platform:

```bash
# Create release tarball (Linux)
mkdir quac100-sdk-1.0.0-linux-x64
cp -r include quac100-sdk-1.0.0-linux-x64/
cp build/libquac100.so* quac100-sdk-1.0.0-linux-x64/lib/
cp build/libquac100.a quac100-sdk-1.0.0-linux-x64/lib/
tar czf quac100-sdk-1.0.0-linux-x64.tar.gz quac100-sdk-1.0.0-linux-x64/

# Create release zip (Windows)
# Similar process with .dll and .lib files
```

**Release Checklist:**
- [ ] Source tarball (quac100-sdk-1.0.0-src.tar.gz)
- [ ] Linux x64 binary (quac100-sdk-1.0.0-linux-x64.tar.gz)
- [ ] Windows x64 binary (quac100-sdk-1.0.0-win64.zip)
- [ ] macOS x64 binary (quac100-sdk-1.0.0-macos-x64.tar.gz)
- [ ] macOS ARM64 binary (quac100-sdk-1.0.0-macos-arm64.tar.gz)
- [ ] Changelog
- [ ] SHA256 checksums

### 2. Package Managers

#### vcpkg (Microsoft C++ Package Manager)

Create `ports/quac100/portfile.cmake`:

```cmake
vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO dyber-io/quac100-sdk
    REF v1.0.0
    SHA512 <sha512-hash>
    HEAD_REF main
)

vcpkg_cmake_configure(
    SOURCE_PATH "${SOURCE_PATH}/bindings/c"
)

vcpkg_cmake_install()
vcpkg_cmake_config_fixup()
vcpkg_copy_pdbs()

file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug/include")
file(INSTALL "${SOURCE_PATH}/LICENSE" DESTINATION "${CURRENT_PACKAGES_DIR}/share/${PORT}" RENAME copyright)
```

Create `ports/quac100/vcpkg.json`:

```json
{
  "name": "quac100",
  "version": "1.0.0",
  "description": "QUAC 100 Post-Quantum Cryptographic Accelerator SDK",
  "homepage": "https://dyber.io",
  "license": "Apache-2.0",
  "dependencies": []
}
```

Submit PR to [microsoft/vcpkg](https://github.com/microsoft/vcpkg).

#### Conan (C/C++ Package Manager)

Create `conanfile.py`:

```python
from conan import ConanFile
from conan.tools.cmake import CMake, cmake_layout

class Quac100Recipe(ConanFile):
    name = "quac100"
    version = "1.0.0"
    license = "Apache-2.0"
    url = "https://github.com/dyber-io/quac100-sdk"
    description = "QUAC 100 Post-Quantum Cryptographic Accelerator SDK"
    settings = "os", "compiler", "build_type", "arch"
    options = {"shared": [True, False]}
    default_options = {"shared": True}
    exports_sources = "bindings/c/*"

    def layout(self):
        cmake_layout(self, src_folder="bindings/c")

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()

    def package(self):
        cmake = CMake(self)
        cmake.install()

    def package_info(self):
        self.cpp_info.libs = ["quac100"]
```

Publish to [Conan Center](https://conan.io/center).

#### Linux Package Managers

**Debian/Ubuntu (.deb):**

Create `debian/control`:

```
Source: libquac100
Section: libs
Priority: optional
Maintainer: Dyber Inc <support@dyber.io>
Build-Depends: debhelper (>= 10), cmake (>= 3.16)
Standards-Version: 4.5.0
Homepage: https://dyber.io

Package: libquac100
Architecture: any
Depends: ${shlibs:Depends}, ${misc:Depends}
Description: QUAC 100 Post-Quantum Cryptographic Accelerator SDK
 Hardware-accelerated post-quantum cryptography library for
 the QUAC 100 accelerator card.

Package: libquac100-dev
Section: libdevel
Architecture: any
Depends: libquac100 (= ${binary:Version}), ${misc:Depends}
Description: QUAC 100 SDK - Development files
 Header files and documentation for the QUAC 100 SDK.
```

Build package:

```bash
dpkg-buildpackage -us -uc
```

**RPM (Fedora/RHEL):**

Create `quac100.spec`:

```spec
Name:           quac100
Version:        1.0.0
Release:        1%{?dist}
Summary:        QUAC 100 Post-Quantum Cryptographic Accelerator SDK

License:        Apache-2.0
URL:            https://dyber.io
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  cmake >= 3.16
BuildRequires:  gcc

%description
Hardware-accelerated post-quantum cryptography library for
the QUAC 100 accelerator card.

%package devel
Summary:        Development files for %{name}
Requires:       %{name}%{?_isa} = %{version}-%{release}

%description devel
Header files and documentation for the QUAC 100 SDK.

%prep
%autosetup

%build
%cmake bindings/c
%cmake_build

%install
%cmake_install

%files
%license LICENSE
%{_libdir}/libquac100.so.*

%files devel
%{_includedir}/quac100/
%{_libdir}/libquac100.so
%{_libdir}/libquac100.a
%{_libdir}/cmake/quac100/
%{_libdir}/pkgconfig/quac100.pc
```

**Homebrew (macOS):**

Create `Formula/quac100.rb`:

```ruby
class Quac100 < Formula
  desc "QUAC 100 Post-Quantum Cryptographic Accelerator SDK"
  homepage "https://dyber.io"
  url "https://github.com/dyber-io/quac100-sdk/archive/v1.0.0.tar.gz"
  sha256 "<sha256-hash>"
  license "Apache-2.0"

  depends_on "cmake" => :build

  def install
    cd "bindings/c" do
      system "cmake", "-S", ".", "-B", "build", *std_cmake_args
      system "cmake", "--build", "build"
      system "cmake", "--install", "build"
    end
  end

  test do
    (testpath/"test.c").write <<~EOS
      #include <quac100/quac100.h>
      #include <stdio.h>
      int main() {
        printf("Version: %s\\n", quac_version());
        return 0;
      }
    EOS
    system ENV.cc, "test.c", "-I#{include}", "-L#{lib}", "-lquac100", "-o", "test"
    system "./test"
  end
end
```

Submit to [homebrew-core](https://github.com/Homebrew/homebrew-core) or create a tap:

```bash
# Create your own tap
brew tap dyber-io/tap
brew install dyber-io/tap/quac100
```

### 3. Documentation Hosting

Generate and host Doxygen documentation:

```bash
# Build docs
cmake -DQUAC_BUILD_DOCS=ON ..
cmake --build . --target docs

# Output in build/docs/html/
```

Host on:
- GitHub Pages (free)
- Read the Docs
- Your own website

### 4. Integration Examples

Create example projects demonstrating integration:

```
examples/
├── cmake-project/          # CMake find_package example
├── makefile-project/       # Traditional Makefile
├── vcpkg-project/          # vcpkg integration
├── conan-project/          # Conan integration
└── visual-studio-project/  # Windows .vcxproj
```

## Directory Structure

```
quac100-sdk/
├── bindings/
│   └── c/
│       ├── CMakeLists.txt         # Main build file
│       ├── cmake/
│       │   └── quac100Config.cmake.in
│       ├── pkg-config/
│       │   └── quac100.pc.in
│       ├── include/
│       │   └── quac100/
│       │       ├── quac100.h      # Main header
│       │       ├── types.h        # Type definitions
│       │       ├── device.h       # Device management
│       │       ├── kem.h          # Key encapsulation
│       │       ├── sign.h         # Digital signatures
│       │       ├── random.h       # Random generation
│       │       ├── hash.h         # Hash functions
│       │       ├── keys.h         # Key storage
│       │       └── utils.h        # Utilities
│       ├── src/
│       │   ├── quac100.c          # Library core
│       │   ├── device.c           # Device implementation
│       │   ├── kem.c              # KEM implementation
│       │   ├── sign.c             # Signature implementation
│       │   ├── random.c           # Random implementation
│       │   ├── hash.c             # Hash implementation
│       │   ├── keys.c             # Key storage implementation
│       │   ├── utils.c            # Utilities implementation
│       │   ├── hal.c              # Hardware abstraction layer
│       │   └── internal.h         # Internal header
│       ├── examples/
│       │   ├── CMakeLists.txt
│       │   ├── basic.c
│       │   ├── kem_example.c
│       │   ├── sign_example.c
│       │   ├── random_example.c
│       │   └── hash_example.c
│       ├── tests/
│       │   ├── CMakeLists.txt
│       │   └── test_quac100.c
│       └── README.md              # This file
├── LICENSE
└── CHANGELOG.md
```

## Versioning

This project follows [Semantic Versioning](https://semver.org/):

- **MAJOR**: Incompatible API changes
- **MINOR**: Backward-compatible new features
- **PATCH**: Backward-compatible bug fixes

## License

Apache License 2.0 - See [LICENSE](../../LICENSE) for details.

## Support

- **Documentation**: https://docs.dyber.io/quac100
- **Issues**: https://github.com/dyber-io/quac100-sdk/issues
- **Email**: support@dyber.io

## Contributing

See [CONTRIBUTING.md](../../CONTRIBUTING.md) for guidelines.

---

Copyright © 2025 Dyber, Inc. All Rights Reserved.