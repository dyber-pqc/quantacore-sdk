# Installation Guide

## QuantaCore SDK - QUAC 100 Post-Quantum Cryptographic Accelerator

This guide covers the installation of the QuantaCore SDK for the QUAC 100 hardware accelerator on supported platforms.

---

## Table of Contents

1. [System Requirements](#system-requirements)
2. [Platform Support](#platform-support)
3. [Linux Installation](#linux-installation)
4. [Windows Installation](#windows-installation)
5. [Driver Installation](#driver-installation)
6. [SDK Installation](#sdk-installation)
7. [Verification](#verification)
8. [Troubleshooting](#troubleshooting)

---

## System Requirements

### Hardware Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | x86_64 or ARM64 | x86_64 with AES-NI |
| RAM | 4 GB | 16 GB |
| PCIe Slot | Gen3 x8 | Gen4 x8 |
| Storage | 500 MB | 2 GB |

### QUAC 100 Hardware Specifications

- **Interface**: PCIe Gen4 x8 (up to 16 GT/s per lane)
- **Memory Map**: 64MB BAR0 for control registers
- **Interrupts**: MSI-X (up to 32 vectors)
- **Power**: Typical 25W, Maximum 75W

### Software Requirements

| Component | Linux | Windows |
|-----------|-------|---------|
| OS Version | Ubuntu 22.04+, RHEL 8+ | Windows 10/11, Server 2019+ |
| Kernel | 5.15+ | N/A |
| Compiler | GCC 11+ or Clang 14+ | MSVC 2019+ |
| CMake | 3.20+ | 3.20+ |

---

## Platform Support

The QuantaCore SDK supports the following platforms:

### Linux
- Ubuntu 22.04 LTS, 24.04 LTS
- Red Hat Enterprise Linux 8, 9
- Rocky Linux 8, 9
- Debian 11, 12
- SUSE Linux Enterprise Server 15

### Windows
- Windows 10 (21H2 or later)
- Windows 11
- Windows Server 2019, 2022

---

## Linux Installation

### Step 1: Install Prerequisites

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y build-essential cmake git pkg-config \
    libssl-dev libudev-dev linux-headers-$(uname -r)

# RHEL/Rocky/CentOS
sudo dnf install -y gcc gcc-c++ cmake git openssl-devel \
    systemd-devel kernel-devel kernel-headers

# SUSE
sudo zypper install -y gcc gcc-c++ cmake git libopenssl-devel \
    systemd-devel kernel-devel
```

### Step 2: Install DKMS (Optional but Recommended)

DKMS ensures the driver rebuilds automatically after kernel updates:

```bash
# Ubuntu/Debian
sudo apt install -y dkms

# RHEL/Rocky
sudo dnf install -y dkms

# SUSE
sudo zypper install -y dkms
```

### Step 3: Download the SDK

```bash
# Clone the repository
git clone https://github.com/dyber/quantacore-sdk.git
cd quantacore-sdk

# Or download a release tarball
wget https://releases.dyber.com/quantacore-sdk-1.0.0.tar.gz
tar xzf quantacore-sdk-1.0.0.tar.gz
cd quantacore-sdk-1.0.0
```

### Step 4: Build and Install

```bash
# Create build directory
mkdir build && cd build

# Configure (with default options)
cmake ..

# Configure with custom options
cmake .. \
    -DCMAKE_INSTALL_PREFIX=/usr/local \
    -DBUILD_SHARED_LIBS=ON \
    -DBUILD_EXAMPLES=ON \
    -DBUILD_TESTS=ON \
    -DENABLE_SIMULATOR=ON

# Build
make -j$(nproc)

# Install (requires root)
sudo make install

# Update library cache
sudo ldconfig
```

### Step 5: Install the Kernel Driver

```bash
# From the build directory
cd driver

# Build the driver
make

# Install with DKMS (recommended)
sudo make dkms-install

# Or install manually
sudo insmod quac100.ko
sudo cp quac100.ko /lib/modules/$(uname -r)/kernel/drivers/crypto/
sudo depmod -a
```

### Step 6: Configure udev Rules

```bash
# Install udev rules for non-root access
sudo cp ../scripts/99-quac100.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules
sudo udevadm trigger
```

### Step 7: Load Driver at Boot

```bash
# Add to modules list
echo "quac100" | sudo tee /etc/modules-load.d/quac100.conf

# Or use systemd
sudo systemctl enable quac100
```

---

## Windows Installation

### Step 1: Install Prerequisites

1. **Visual Studio 2019 or later** with C++ desktop development workload
2. **CMake 3.20+** from https://cmake.org/download/
3. **Git** from https://git-scm.com/download/win
4. **Windows SDK** (installed with Visual Studio)

### Step 2: Download the SDK

```powershell
# Clone repository
git clone https://github.com/dyber/quantacore-sdk.git
cd quantacore-sdk

# Or download and extract release ZIP
Invoke-WebRequest -Uri "https://releases.dyber.com/quantacore-sdk-1.0.0.zip" -OutFile "quantacore-sdk.zip"
Expand-Archive -Path "quantacore-sdk.zip" -DestinationPath "."
cd quantacore-sdk-1.0.0
```

### Step 3: Build the SDK

```powershell
# Create build directory
mkdir build
cd build

# Configure with CMake
cmake .. -G "Visual Studio 17 2022" -A x64 `
    -DBUILD_SHARED_LIBS=ON `
    -DBUILD_EXAMPLES=ON `
    -DENABLE_SIMULATOR=ON

# Build Release configuration
cmake --build . --config Release

# Install (run as Administrator)
cmake --install . --prefix "C:\Program Files\QuantaCore"
```

### Step 4: Install the Driver

1. Open **Device Manager**
2. Find the QUAC 100 device under "Other devices"
3. Right-click and select **Update driver**
4. Choose **Browse my computer for drivers**
5. Navigate to `C:\Program Files\QuantaCore\drivers`
6. Click **Next** and follow the prompts

Alternatively, use the command line (Administrator):

```powershell
pnputil /add-driver "C:\Program Files\QuantaCore\drivers\quac100.inf" /install
```

### Step 5: Set Environment Variables

```powershell
# Add to system PATH (run as Administrator)
[Environment]::SetEnvironmentVariable(
    "Path",
    [Environment]::GetEnvironmentVariable("Path", "Machine") + ";C:\Program Files\QuantaCore\bin",
    "Machine"
)

# Set library path
[Environment]::SetEnvironmentVariable(
    "QUAC_SDK_PATH",
    "C:\Program Files\QuantaCore",
    "Machine"
)
```

---

## Driver Installation

### Linux Driver Details

The QUAC 100 kernel driver (`quac100.ko`) provides:

- Device enumeration via PCIe
- DMA buffer management
- MSI-X interrupt handling
- Memory-mapped register access
- Character device interface (`/dev/quac100_X`)

**Driver Parameters:**

```bash
# View available parameters
modinfo quac100

# Load with custom parameters
sudo modprobe quac100 \
    max_devices=4 \
    enable_msix=1 \
    debug_level=2
```

**Device Files:**

| Path | Description |
|------|-------------|
| `/dev/quac100_0` | First QUAC 100 device |
| `/dev/quac100_1` | Second QUAC 100 device |
| `/sys/class/quac100/` | Sysfs attributes |

### Windows Driver Details

The Windows driver (`quac100.sys`) is a KMDF driver that provides:

- WDF-based device management
- Direct Memory Access (DMA)
- MSI-X interrupt support
- Device interface for userspace access

**Registry Settings:**

```
HKLM\SYSTEM\CurrentControlSet\Services\quac100\Parameters
    MaxDevices: DWORD (default: 16)
    EnableMSIX: DWORD (default: 1)
    DebugLevel: DWORD (default: 0)
```

---

## SDK Installation

### CMake Integration

Add QuantaCore SDK to your CMake project:

```cmake
# Find the package
find_package(QuantaCore REQUIRED)

# Link to your target
target_link_libraries(your_app PRIVATE QuantaCore::quac100)
```

### pkg-config (Linux)

```bash
# Check installation
pkg-config --modversion quac100

# Get compiler flags
pkg-config --cflags quac100

# Get linker flags
pkg-config --libs quac100
```

### Manual Linking

**Linux:**
```bash
gcc -I/usr/local/include -L/usr/local/lib -lquac100 your_app.c -o your_app
```

**Windows:**
```
cl /I"C:\Program Files\QuantaCore\include" your_app.c /link /LIBPATH:"C:\Program Files\QuantaCore\lib" quac100.lib
```

---

## Verification

### Check Device Detection

**Linux:**
```bash
# List PCI devices
lspci | grep -i quac

# Check device files
ls -la /dev/quac100*

# View driver info
cat /sys/class/quac100/quac100_0/device_info
```

**Windows:**
```powershell
# Check device in Device Manager
Get-PnpDevice | Where-Object { $_.FriendlyName -like "*QUAC*" }
```

### Run Verification Tool

```bash
# Linux
quac-verify

# Windows
quac-verify.exe
```

Expected output:
```
QuantaCore SDK Verification Tool v1.0.0
========================================
SDK Version: 1.0.0
Driver Version: 1.0.0

Device Detection:
  [OK] Found 1 QUAC 100 device(s)
  [OK] Device 0: QUAC 100 Enterprise (Serial: QC100-2025-00001)

Hardware Tests:
  [OK] PCIe Link: Gen4 x8 (15.8 GB/s)
  [OK] Memory Test: PASSED
  [OK] DMA Test: PASSED

Cryptographic Tests:
  [OK] ML-KEM-768 Key Generation: PASSED (1.2ms)
  [OK] ML-KEM-768 Encapsulation: PASSED (0.8ms)
  [OK] ML-KEM-768 Decapsulation: PASSED (0.9ms)
  [OK] ML-DSA-65 Key Generation: PASSED (2.1ms)
  [OK] ML-DSA-65 Sign: PASSED (1.5ms)
  [OK] ML-DSA-65 Verify: PASSED (1.1ms)
  [OK] QRNG: PASSED (100+ Mbps)

FIPS Self-Tests:
  [OK] All KAT tests passed

All tests PASSED!
```

### Run Example Program

```bash
# Build and run the basic example
cd examples/basic
make
./basic_example

# Expected output:
# QuantaCore SDK initialized
# Device opened: QUAC 100 (Serial: QC100-2025-00001)
# Generated Kyber768 key pair
# Encapsulation successful
# Decapsulation successful
# Shared secrets match!
```

---

## Troubleshooting

### Common Issues

#### Device Not Detected

**Linux:**
```bash
# Check if driver is loaded
lsmod | grep quac100

# Check dmesg for errors
dmesg | grep -i quac

# Verify PCIe device
lspci -vvv -d 1DYB:0100
```

**Windows:**
```powershell
# Check driver status
sc query quac100

# View event log
Get-EventLog -LogName System -Source "quac100" -Newest 10
```

#### Permission Denied

**Linux:**
```bash
# Check device permissions
ls -la /dev/quac100*

# Add user to quac100 group
sudo usermod -aG quac100 $USER

# Re-login or use newgrp
newgrp quac100
```

#### Driver Load Failure

**Linux:**
```bash
# Check for missing dependencies
modprobe --show-depends quac100

# View detailed error
sudo dmesg | tail -50
```

**Windows:**
```powershell
# Check driver signing
signtool verify /v /pa "C:\Program Files\QuantaCore\drivers\quac100.sys"
```

### Getting Help

- **Documentation**: https://docs.dyber.com/quantacore
- **GitHub Issues**: https://github.com/dyber/quantacore-sdk/issues
- **Support Email**: support@dyber.com
- **Community Forum**: https://community.dyber.com

### Diagnostic Information

When reporting issues, please include:

```bash
# Generate diagnostic report
quac-diag --report > quac_diagnostic.txt

# Include:
# - OS version (uname -a / winver)
# - SDK version (quac-version)
# - Driver version
# - lspci output (Linux)
# - dmesg output (Linux)
```

---

## Next Steps

After successful installation:

1. Read the [Quick Start Guide](quick_start.md) for your first program
2. Review the [Programming Guide](programming_guide.md) for detailed API usage
3. Try the [Simulator Guide](simulator_guide.md) for development without hardware
4. Explore the example programs in the `examples/` directory

---

*Document Version: 1.0.0*
*Last Updated: 2025*
*Copyright © 2025 Dyber, Inc. All Rights Reserved.*
