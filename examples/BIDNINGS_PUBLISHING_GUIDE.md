# QUAC 100 SDK Language Bindings Guide

This guide explains how to create, build, and publish the QUAC 100 SDK language bindings.

## Overview

The QUAC 100 SDK is written in C and provides bindings for:
- **Python** (via cffi/ctypes) → Published to **PyPI**
- **Rust** (via FFI) → Published to **crates.io**
- **Go** (via CGO) → Published to **GitHub** (Go modules)
- **Java** (via JNI) → Published to **Maven Central**
- **C/C++** (native) → Distributed with SDK

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Application Layer                            │
├──────────┬──────────┬──────────┬──────────┬────────────────────┤
│  Python  │   Rust   │    Go    │   Java   │   C/C++ Native     │
│  (PyPI)  │(crates.io)│ (GitHub) │ (Maven)  │                    │
├──────────┴──────────┴──────────┴──────────┼────────────────────┤
│              Language Bindings             │                    │
│         (FFI/JNI/CGO wrappers)            │                    │
├───────────────────────────────────────────┴────────────────────┤
│                    libquac100.so / quac100.dll                  │
│                         (Core C Library)                        │
├────────────────────────────────────────────────────────────────┤
│                    QUAC 100 Hardware / Simulator                │
└────────────────────────────────────────────────────────────────┘
```

---

## 1. C/C++ (Native Library)

The C library is the foundation. No separate package needed - distributed with SDK.

### Build

```bash
cd quantacore-sdk
mkdir build && cd build
cmake ..
make
sudo make install
```

### Installation Locations

| Platform | Library | Headers |
|----------|---------|---------|
| Linux | `/usr/local/lib/libquac100.so` | `/usr/local/include/quac100/` |
| macOS | `/usr/local/lib/libquac100.dylib` | `/usr/local/include/quac100/` |
| Windows | `C:\Program Files\QUAC100\bin\quac100.dll` | `C:\Program Files\QUAC100\include\` |

---

## 2. Python Bindings (PyPI)

### Directory Structure

```
bindings/python/
├── pyproject.toml
├── setup.py
├── MANIFEST.in
├── README.md
├── quac100/
│   ├── __init__.py
│   ├── _ffi.py           # FFI bindings (cffi)
│   ├── context.py        # Context class
│   ├── device.py         # Device class
│   ├── algorithms.py     # Algorithm enums
│   ├── exceptions.py     # Custom exceptions
│   └── _quac100.abi3.so  # Compiled extension (built)
└── tests/
    └── test_quac100.py
```

### pyproject.toml

```toml
[build-system]
requires = ["setuptools>=61", "wheel", "cffi>=1.15"]
build-backend = "setuptools.build_meta"

[project]
name = "quac100"
version = "1.0.0"
description = "Python bindings for QUAC 100 Post-Quantum Cryptographic Accelerator"
readme = "README.md"
license = {text = "Proprietary"}
authors = [{name = "Dyber, Inc.", email = "support@dyber.io"}]
classifiers = [
    "Development Status :: 4 - Beta",
    "Intended Audience :: Developers",
    "Topic :: Security :: Cryptography",
    "Programming Language :: Python :: 3.8",
    "Programming Language :: Python :: 3.9",
    "Programming Language :: Python :: 3.10",
    "Programming Language :: Python :: 3.11",
    "Programming Language :: Python :: 3.12",
]
requires-python = ">=3.8"
dependencies = ["cffi>=1.15"]

[project.urls]
Homepage = "https://dyber.io"
Documentation = "https://docs.dyber.io/quac100"
Repository = "https://github.com/dyber/quac100-python"

[project.optional-dependencies]
dev = ["pytest", "pytest-cov", "black", "mypy"]
```

### Publishing to PyPI

```bash
# 1. Build the package
cd bindings/python
python -m build

# 2. Test on TestPyPI first
python -m twine upload --repository testpypi dist/*

# 3. Publish to PyPI
python -m twine upload dist/*
```

### PyPI Account Setup

1. Create account at https://pypi.org/account/register/
2. Enable 2FA
3. Create API token at https://pypi.org/manage/account/token/
4. Store in `~/.pypirc`:
```ini
[pypi]
username = __token__
password = pypi-AgEIcHlwaS5vcmc...
```

---

## 3. Rust Bindings (crates.io)

### Directory Structure

```
bindings/rust/
├── Cargo.toml
├── README.md
├── LICENSE
├── build.rs              # Build script for FFI
├── src/
│   ├── lib.rs           # Main library
│   ├── ffi.rs           # Raw FFI bindings
│   ├── context.rs       # Context wrapper
│   ├── device.rs        # Device wrapper
│   ├── kem.rs           # KEM operations
│   ├── sign.rs          # Signature operations
│   ├── random.rs        # QRNG operations
│   └── error.rs         # Error types
└── examples/
    └── basic.rs
```

### Cargo.toml

```toml
[package]
name = "quac100"
version = "1.0.0"
edition = "2021"
authors = ["Dyber, Inc. <support@dyber.io>"]
description = "Rust bindings for QUAC 100 Post-Quantum Cryptographic Accelerator"
documentation = "https://docs.rs/quac100"
homepage = "https://dyber.io"
repository = "https://github.com/dyber/quac100-rs"
license = "LicenseRef-Proprietary"
keywords = ["cryptography", "post-quantum", "pqc", "hardware", "accelerator"]
categories = ["cryptography", "hardware-support"]
readme = "README.md"

[dependencies]
libc = "0.2"
thiserror = "1.0"
zeroize = { version = "1.6", features = ["derive"] }

[build-dependencies]
bindgen = "0.69"
pkg-config = "0.3"

[features]
default = ["std"]
std = []
async = ["tokio"]
serde = ["dep:serde"]

[dev-dependencies]
criterion = "0.5"

[[bench]]
name = "benchmarks"
harness = false
```

### build.rs

```rust
use std::env;
use std::path::PathBuf;

fn main() {
    // Link to libquac100
    println!("cargo:rustc-link-lib=quac100");
    
    // Search paths
    if let Ok(lib_dir) = env::var("QUAC100_LIB_DIR") {
        println!("cargo:rustc-link-search={}", lib_dir);
    }
    
    // Generate bindings with bindgen
    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate bindings");
    
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
```

### Publishing to crates.io

```bash
# 1. Login to crates.io
cargo login

# 2. Verify package
cargo publish --dry-run

# 3. Publish
cargo publish
```

### crates.io Account Setup

1. Login at https://crates.io with GitHub
2. Go to Account Settings → API Tokens
3. Create new token
4. Run `cargo login <token>`

---

## 4. Go Bindings (Go Modules on GitHub)

### Directory Structure

```
bindings/go/
├── go.mod
├── go.sum
├── README.md
├── LICENSE
├── quac100.go           # Main package
├── context.go           # Context type
├── device.go            # Device type
├── kem.go               # KEM operations
├── sign.go              # Signature operations
├── random.go            # QRNG operations
├── error.go             # Error handling
├── quac100.h            # C header (cgo)
└── examples/
    └── basic/
        └── main.go
```

### go.mod

```go
module github.com/dyber/quac100-go

go 1.21

require (
    golang.org/x/crypto v0.17.0
)
```

### Main Package (quac100.go)

```go
package quac100

/*
#cgo LDFLAGS: -lquac100
#cgo CFLAGS: -I/usr/local/include
#include <quac100.h>
*/
import "C"

import (
    "runtime"
    "unsafe"
)

// Algorithm represents cryptographic algorithms
type Algorithm int

const (
    AlgMLKEM512  Algorithm = C.QUAC_ALG_ML_KEM_512
    AlgMLKEM768  Algorithm = C.QUAC_ALG_ML_KEM_768
    AlgMLKEM1024 Algorithm = C.QUAC_ALG_ML_KEM_1024
    AlgMLDSA44   Algorithm = C.QUAC_ALG_ML_DSA_44
    AlgMLDSA65   Algorithm = C.QUAC_ALG_ML_DSA_65
    AlgMLDSA87   Algorithm = C.QUAC_ALG_ML_DSA_87
)

// ... rest of implementation
```

### Publishing Go Module

Go modules are published by pushing to GitHub with semantic version tags:

```bash
# 1. Create GitHub repo: github.com/dyber/quac100-go
# 2. Push code
git push origin main

# 3. Tag release
git tag v1.0.0
git push origin v1.0.0

# 4. Users install with:
go get github.com/dyber/quac100-go@v1.0.0
```

### Go Module Proxy

Go modules are automatically cached by https://proxy.golang.org after first request.

---

## 5. Java Bindings (Maven Central)

### Directory Structure

```
bindings/java/
├── pom.xml
├── README.md
├── LICENSE
├── src/
│   ├── main/
│   │   ├── java/
│   │   │   └── com/dyber/quac100/
│   │   │       ├── QUAC100.java
│   │   │       ├── Context.java
│   │   │       ├── Device.java
│   │   │       ├── Algorithm.java
│   │   │       ├── KeyPair.java
│   │   │       └── QUACException.java
│   │   └── resources/
│   │       └── native/
│   │           ├── linux-x86_64/libquac100_jni.so
│   │           ├── darwin-x86_64/libquac100_jni.dylib
│   │           └── windows-x86_64/quac100_jni.dll
│   └── test/
│       └── java/
│           └── com/dyber/quac100/
│               └── QUAC100Test.java
└── native/
    └── jni/
        ├── CMakeLists.txt
        └── quac100_jni.c
```

### pom.xml

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 
                             http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>com.dyber</groupId>
    <artifactId>quac100</artifactId>
    <version>1.0.0</version>
    <packaging>jar</packaging>

    <name>QUAC 100 Java Bindings</name>
    <description>Java bindings for QUAC 100 Post-Quantum Cryptographic Accelerator</description>
    <url>https://dyber.io</url>

    <licenses>
        <license>
            <name>Proprietary</name>
            <url>https://dyber.io/license</url>
        </license>
    </licenses>

    <developers>
        <developer>
            <name>Dyber, Inc.</name>
            <email>support@dyber.io</email>
            <organization>Dyber, Inc.</organization>
            <organizationUrl>https://dyber.io</organizationUrl>
        </developer>
    </developers>

    <scm>
        <connection>scm:git:git://github.com/dyber/quac100-java.git</connection>
        <developerConnection>scm:git:ssh://github.com:dyber/quac100-java.git</developerConnection>
        <url>https://github.com/dyber/quac100-java</url>
    </scm>

    <properties>
        <maven.compiler.source>17</maven.compiler.source>
        <maven.compiler.target>17</maven.compiler.target>
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
    </properties>

    <dependencies>
        <dependency>
            <groupId>org.junit.jupiter</groupId>
            <artifactId>junit-jupiter</artifactId>
            <version>5.10.0</version>
            <scope>test</scope>
        </dependency>
    </dependencies>

    <build>
        <plugins>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-source-plugin</artifactId>
                <version>3.3.0</version>
                <executions>
                    <execution>
                        <id>attach-sources</id>
                        <goals><goal>jar-no-fork</goal></goals>
                    </execution>
                </executions>
            </plugin>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-javadoc-plugin</artifactId>
                <version>3.6.0</version>
                <executions>
                    <execution>
                        <id>attach-javadocs</id>
                        <goals><goal>jar</goal></goals>
                    </execution>
                </executions>
            </plugin>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-gpg-plugin</artifactId>
                <version>3.1.0</version>
                <executions>
                    <execution>
                        <id>sign-artifacts</id>
                        <phase>verify</phase>
                        <goals><goal>sign</goal></goals>
                    </execution>
                </executions>
            </plugin>
        </plugins>
    </build>

    <distributionManagement>
        <snapshotRepository>
            <id>ossrh</id>
            <url>https://s01.oss.sonatype.org/content/repositories/snapshots</url>
        </snapshotRepository>
        <repository>
            <id>ossrh</id>
            <url>https://s01.oss.sonatype.org/service/local/staging/deploy/maven2/</url>
        </repository>
    </distributionManagement>
</project>
```

### Publishing to Maven Central

1. **Create Sonatype Account**
   - Register at https://issues.sonatype.org
   - Create JIRA ticket for new project (groupId claim)

2. **Setup GPG Signing**
   ```bash
   gpg --gen-key
   gpg --keyserver keyserver.ubuntu.com --send-keys <KEY_ID>
   ```

3. **Configure ~/.m2/settings.xml**
   ```xml
   <settings>
     <servers>
       <server>
         <id>ossrh</id>
         <username>your-jira-id</username>
         <password>your-jira-password</password>
       </server>
     </servers>
   </settings>
   ```

4. **Deploy**
   ```bash
   mvn clean deploy -P release
   ```

5. **Release on Sonatype**
   - Login to https://s01.oss.sonatype.org
   - Close and Release staging repository

---

## Summary: Publishing Checklist

| Language | Package Registry | Account Required | Key Steps |
|----------|------------------|------------------|-----------|
| Python | PyPI | pypi.org account | `twine upload dist/*` |
| Rust | crates.io | GitHub login | `cargo publish` |
| Go | GitHub | GitHub account | `git tag v1.0.0 && git push` |
| Java | Maven Central | Sonatype JIRA | `mvn deploy` + GPG signing |
| C/C++ | N/A | N/A | Distributed with SDK |

## Do You Need Custom Libraries?

**Yes**, to make the examples work for real users, you need:

1. **Core C Library** (`libquac100`) - Already being built by the SDK

2. **Python Package** - Wraps the C library with cffi
   - Publish to PyPI: `pip install quac100`

3. **Rust Crate** - FFI wrapper with safe Rust API
   - Publish to crates.io: Add `quac100 = "1.0"` to Cargo.toml

4. **Go Module** - CGO wrapper
   - Publish to GitHub: `go get github.com/dyber/quac100-go`

5. **Java JAR** - JNI wrapper with native libs bundled
   - Publish to Maven: Add dependency to pom.xml

## Making Examples Work Standalone

The current examples use **simulation mode** so they work without the actual bindings installed. For production:

1. Build and install the C library
2. Build each language binding that links to the C library
3. Publish to respective package registries
4. Update examples to use real imports instead of simulated classes

## Recommended Publishing Timeline

1. **Phase 1**: C library stable release
2. **Phase 2**: Python + Rust bindings (most popular for crypto)
3. **Phase 3**: Go + Java bindings
4. **Phase 4**: Additional languages (C#, Node.js, Ruby)

---

*Copyright 2025 Dyber, Inc. All Rights Reserved.*