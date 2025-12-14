<# 
    QuantaCore SDK Directory Structure Setup Script
    Dyber, Inc. - QUAC 100 Post-Quantum Cryptographic Accelerator
    
    Run from the root of your SDK directory:
    PS D:\quantacore-sdk> .\setup-quantacore-sdk.ps1
#>

param(
    [string]$RootPath = "."
)

$ErrorActionPreference = "Stop"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host " QuantaCore SDK Directory Setup" -ForegroundColor Cyan
Write-Host " Dyber, Inc. - QUAC 100" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Navigate to root
Set-Location $RootPath

# ============================================================================
# DIRECTORIES
# ============================================================================

$directories = @(
    # Include headers
    "include/internal"
    
    # Source directories
    "src/core"
    "src/platform/linux"
    "src/platform/windows"
    "src/util"
    
    # Pre-built libraries
    "lib/linux/x86_64"
    "lib/linux/aarch64"
    "lib/windows/x64"
    "lib/windows/arm64"
    
    # Drivers
    "drivers/linux/udev"
    "drivers/windows/cng"
    
    # Language bindings
    "bindings/rust/src"
    "bindings/rust/examples"
    "bindings/rust/tests"
    "bindings/python/quac100"
    "bindings/python/src"
    "bindings/python/examples"
    "bindings/python/tests"
    "bindings/java/native"
    "bindings/java/src/main/java/com/dyber/quac100"
    "bindings/go/examples"
    "bindings/go/tests"
    "bindings/nodejs/src"
    "bindings/nodejs/lib"
    "bindings/csharp"
    
    # Integrations
    "integrations/openssl"
    "integrations/pkcs11"
    "integrations/boringssl"
    "integrations/tls/nginx"
    "integrations/tls/haproxy"
    "integrations/tls/envoy"
    
    # Simulator
    "simulator/include"
    "simulator/src/ref_impl"
    "simulator/config"
    
    # Tools
    "tools/quac100-cli"
    "tools/quac100-bench"
    "tools/quac100-diag"
    "tools/bindgen"
    
    # Examples
    "examples/c"
    "examples/python"
    "examples/rust"
    "examples/java"
    "examples/go"
    
    # Tests
    "tests/unit"
    "tests/integration"
    "tests/kat"
    "tests/performance"
    "tests/conformance"
    
    # Documentation
    "docs/api"
    "docs/guides"
    "docs/reference"
    
    # Scripts
    "scripts/build"
    "scripts/install"
    "scripts/test"
    "scripts/release"
    
    # CMake modules
    "cmake"
    
    # Packaging
    "packaging/deb"
    "packaging/rpm"
    "packaging/windows"
    "packaging/docker"
)

Write-Host "Creating directories..." -ForegroundColor Yellow
foreach ($dir in $directories) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Write-Host "  [+] $dir" -ForegroundColor Green
    } else {
        Write-Host "  [=] $dir (exists)" -ForegroundColor DarkGray
    }
}

# ============================================================================
# FILES
# ============================================================================

$files = @(
    # Root files
    "LICENSE.txt"
    "README.md"
    "VERSION"
    "CHANGELOG.md"
    "CMakeLists.txt"
    "Cargo.toml"
    "setup.py"
    "pyproject.toml"
    "pom.xml"
    "go.mod"
    
    # Public headers
    "include/quac100.h"
    "include/quac100_types.h"
    "include/quac100_error.h"
    "include/quac100_kem.h"
    "include/quac100_sign.h"
    "include/quac100_random.h"
    "include/quac100_async.h"
    "include/quac100_batch.h"
    "include/quac100_diag.h"
    
    # Internal headers
    "include/internal/quac100_ioctl.h"
    "include/internal/quac100_dma.h"
    "include/internal/quac100_pcie.h"
    
    # Core source files
    "src/core/device.c"
    "src/core/init.c"
    "src/core/kem.c"
    "src/core/sign.c"
    "src/core/random.c"
    "src/core/async.c"
    "src/core/batch.c"
    "src/core/key_mgmt.c"
    "src/core/diag.c"
    "src/core/error.c"
    
    # Platform - Linux
    "src/platform/linux/device_linux.c"
    "src/platform/linux/mmap_linux.c"
    "src/platform/linux/ioctl_linux.c"
    
    # Platform - Windows
    "src/platform/windows/device_win.c"
    "src/platform/windows/ioctl_win.c"
    "src/platform/windows/registry_win.c"
    
    # Utilities
    "src/util/memory.c"
    "src/util/threading.c"
    "src/util/logging.c"
    
    # Linux driver
    "drivers/linux/Makefile"
    "drivers/linux/Kbuild"
    "drivers/linux/quac100_main.c"
    "drivers/linux/quac100_pcie.c"
    "drivers/linux/quac100_dma.c"
    "drivers/linux/quac100_irq.c"
    "drivers/linux/quac100_ioctl.c"
    "drivers/linux/quac100_sysfs.c"
    "drivers/linux/quac100_sriov.c"
    "drivers/linux/dkms.conf"
    "drivers/linux/udev/99-quac100.rules"
    
    # Windows driver
    "drivers/windows/quac100.inf"
    "drivers/windows/quac100.vcxproj"
    "drivers/windows/quac100_main.c"
    "drivers/windows/quac100_device.c"
    "drivers/windows/quac100_queue.c"
    "drivers/windows/cng/quac100cng.c"
    
    # Rust bindings
    "bindings/rust/Cargo.toml"
    "bindings/rust/build.rs"
    "bindings/rust/src/lib.rs"
    "bindings/rust/src/ffi.rs"
    "bindings/rust/src/device.rs"
    "bindings/rust/src/kem.rs"
    "bindings/rust/src/sign.rs"
    "bindings/rust/src/error.rs"
    
    # Python bindings
    "bindings/python/setup.py"
    "bindings/python/pyproject.toml"
    "bindings/python/quac100/__init__.py"
    "bindings/python/quac100/device.py"
    "bindings/python/quac100/kem.py"
    "bindings/python/quac100/sign.py"
    "bindings/python/quac100/exceptions.py"
    
    # Java bindings
    "bindings/java/pom.xml"
    "bindings/java/native/quac100_jni.c"
    "bindings/java/src/main/java/com/dyber/quac100/Quac100.java"
    "bindings/java/src/main/java/com/dyber/quac100/Device.java"
    "bindings/java/src/main/java/com/dyber/quac100/KEM.java"
    "bindings/java/src/main/java/com/dyber/quac100/Signature.java"
    
    # Go bindings
    "bindings/go/go.mod"
    "bindings/go/quac100.go"
    "bindings/go/device.go"
    "bindings/go/kem.go"
    "bindings/go/sign.go"
    "bindings/go/cgo_bridge.go"
    
    # Node.js bindings
    "bindings/nodejs/package.json"
    "bindings/nodejs/binding.gyp"
    "bindings/nodejs/src/addon.cc"
    "bindings/nodejs/lib/index.js"
    
    # C# bindings
    "bindings/csharp/Quac100.csproj"
    "bindings/csharp/NativeMethods.cs"
    "bindings/csharp/Device.cs"
    
    # OpenSSL integration
    "integrations/openssl/CMakeLists.txt"
    "integrations/openssl/quac100_provider.c"
    "integrations/openssl/quac100_kem_alg.c"
    "integrations/openssl/quac100_sig_alg.c"
    "integrations/openssl/quac100_rand.c"
    "integrations/openssl/openssl.cnf.example"
    
    # PKCS#11 integration
    "integrations/pkcs11/CMakeLists.txt"
    "integrations/pkcs11/quac100_pkcs11.c"
    "integrations/pkcs11/slot.c"
    "integrations/pkcs11/session.c"
    "integrations/pkcs11/mechanism.c"
    
    # BoringSSL integration
    "integrations/boringssl/BUILD.gn"
    "integrations/boringssl/quac100_engine.c"
    
    # TLS integrations
    "integrations/tls/nginx/README.md"
    "integrations/tls/haproxy/README.md"
    "integrations/tls/envoy/README.md"
    
    # Simulator
    "simulator/CMakeLists.txt"
    "simulator/include/quac100_sim.h"
    "simulator/src/sim_main.c"
    "simulator/src/sim_device.c"
    "simulator/src/sim_kem.c"
    "simulator/src/sim_sign.c"
    "simulator/src/ref_impl/kyber_ref.c"
    "simulator/src/ref_impl/dilithium_ref.c"
    "simulator/src/ref_impl/sphincs_ref.c"
    "simulator/config/default.json"
    "simulator/config/high_perf.json"
    
    # Tools
    "tools/quac100-cli/README.md"
    "tools/quac100-bench/README.md"
    "tools/quac100-diag/README.md"
    "tools/bindgen/README.md"
    
    # C Examples
    "examples/c/hello_quac.c"
    "examples/c/kyber_demo.c"
    "examples/c/dilithium_sign.c"
    "examples/c/tls_server.c"
    
    # Other language examples
    "examples/python/README.md"
    "examples/rust/README.md"
    "examples/java/README.md"
    "examples/go/README.md"
    
    # Tests
    "tests/unit/README.md"
    "tests/integration/README.md"
    "tests/kat/kyber_kat.json"
    "tests/kat/dilithium_kat.json"
    "tests/kat/run_kat.c"
    "tests/performance/README.md"
    "tests/conformance/README.md"
    
    # Documentation
    "docs/guides/quick_start.md"
    "docs/guides/installation.md"
    "docs/guides/programming_guide.md"
    "docs/guides/simulator_guide.md"
    "docs/guides/cloudflare_integration.md"
    "docs/reference/README.md"
    "docs/api/README.md"
    
    # Scripts
    "scripts/build/build.ps1"
    "scripts/build/build.sh"
    "scripts/install/install.ps1"
    "scripts/install/install.sh"
    "scripts/test/run_tests.ps1"
    "scripts/test/run_tests.sh"
    "scripts/release/release.ps1"
    "scripts/release/release.sh"
    
    # CMake modules
    "cmake/FindQuac100.cmake"
    "cmake/Quac100Config.cmake.in"
    
    # Packaging - Debian
    "packaging/deb/control"
    "packaging/deb/rules"
    "packaging/deb/postinst"
    "packaging/deb/prerm"
    
    # Packaging - RPM
    "packaging/rpm/quantacore-sdk.spec"
    
    # Packaging - Windows
    "packaging/windows/installer.wxs"
    "packaging/windows/bundle.wxs"
    
    # Packaging - Docker
    "packaging/docker/Dockerfile.sdk"
    "packaging/docker/Dockerfile.sim"
)

Write-Host ""
Write-Host "Creating files..." -ForegroundColor Yellow
foreach ($file in $files) {
    if (-not (Test-Path $file)) {
        # Ensure parent directory exists
        $parentDir = Split-Path -Parent $file
        if ($parentDir -and -not (Test-Path $parentDir)) {
            New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
        }
        # Create empty file
        New-Item -ItemType File -Path $file -Force | Out-Null
        Write-Host "  [+] $file" -ForegroundColor Green
    } else {
        Write-Host "  [=] $file (exists)" -ForegroundColor DarkGray
    }
}

# ============================================================================
# SUMMARY
# ============================================================================

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Setup Complete!" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$dirCount = (Get-ChildItem -Directory -Recurse | Measure-Object).Count
$fileCount = (Get-ChildItem -File -Recurse | Measure-Object).Count

Write-Host "  Directories: $dirCount" -ForegroundColor White
Write-Host "  Files:       $fileCount" -ForegroundColor White
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. Open in VSCode: code ." -ForegroundColor White
Write-Host "  2. Start with CMakeLists.txt and include/quac100.h" -ForegroundColor White
Write-Host ""