# QUAC 100 Linux Kernel Driver

Linux kernel module for the QuantaCore QUAC 100 Post-Quantum Cryptographic Accelerator.

## Overview

The QUAC 100 is a hardware accelerator providing high-performance post-quantum cryptographic operations:

- **ML-KEM (Kyber)**: Key encapsulation at security levels 1, 3, and 5
- **ML-DSA (Dilithium)**: Digital signatures at security levels 2, 3, and 5
- **SLH-DSA (SPHINCS+)**: Hash-based signatures (SHA2 and SHAKE variants)
- **QRNG**: Hardware quantum random number generation

## Directory Structure

```
drivers/linux/
├── src/                          # Kernel module source code
│   ├── quac100_drv.h             # Internal driver header
│   ├── quac100_main.c            # Module entry/exit
│   ├── quac100_pcie.c            # PCIe initialization
│   ├── quac100_dma.c             # DMA engine
│   ├── quac100_ioctl.c           # IOCTL interface
│   ├── quac100_irq.c             # Interrupt handling
│   ├── quac100_sriov.c           # SR-IOV virtualization
│   ├── quac100_sysfs.c           # sysfs attributes
│   ├── Makefile                  # Kernel build makefile
│   └── Kbuild                    # Kbuild configuration
├── scripts/                      # Installation scripts
│   ├── install.sh                # Main installer
│   ├── uninstall.sh              # Uninstaller
│   ├── dkms-install.sh           # DKMS installation
│   ├── dkms-uninstall.sh         # DKMS removal
│   ├── sign-module.sh            # Secure Boot signing
│   └── check-hardware.sh         # Hardware detection
├── dkms/                         # DKMS configuration
│   └── dkms.conf
├── udev/                         # udev rules
│   └── 99-quac100.rules
├── modprobe/                     # modprobe configuration
│   └── quac100.conf
├── systemd/                      # systemd service files
│   └── quac100.service
├── keys/                         # Secure Boot signing
│   └── README.md
├── packaging/                    # Distribution packages
│   ├── deb/                      # Debian packaging
│   │   ├── control
│   │   ├── postinst
│   │   ├── prerm
│   │   ├── rules
│   │   └── changelog
│   ├── rpm/                      # RPM packaging
│   │   └── quac100-dkms.spec
│   └── build-packages.sh
├── testing/                      # Test suite
│   └── test_driver_no_hw_v2.sh   # Hardware-independent tests
├── README.md                     # This file
├── LICENSE                       # Driver license
└── CHANGELOG.md                  # Version history
```

## System Requirements

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| Kernel | 5.4+ | 5.15 LTS or 6.1 LTS |
| Architecture | x86_64 | x86_64 |
| PCIe Slot | Gen3 x8 | Gen4 x8 |
| RAM | 4 GB | 8 GB+ |

### Tested Distributions

- Ubuntu 20.04, 22.04, 24.04
- Debian 11, 12
- RHEL/Rocky/Alma 8, 9
- Fedora 38, 39, 40
- SUSE Linux Enterprise 15 SP4+

## Quick Start

### Option 1: Automated Install

```bash
sudo ./scripts/install.sh
```

### Option 2: DKMS Install (Recommended)

```bash
sudo ./scripts/dkms-install.sh
```

### Option 3: Manual Build

```bash
cd src/
make
sudo insmod quac100.ko
```

## Installation Guide

### Prerequisites

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install -y build-essential linux-headers-$(uname -r) dkms
```

**RHEL/Rocky/Alma:**
```bash
sudo dnf install -y gcc make kernel-devel-$(uname -r) dkms elfutils-libelf-devel
```

**Fedora:**
```bash
sudo dnf install -y gcc make kernel-devel dkms
```

**SUSE:**
```bash
sudo zypper install -y gcc make kernel-devel dkms
```

### Verify Hardware

```bash
./scripts/check-hardware.sh
```

### Run Installation

```bash
sudo ./scripts/install.sh
```

### Verify Installation

```bash
# Check module loaded
lsmod | grep quac100

# Check device nodes
ls -la /dev/quac100*

# View kernel messages
dmesg | grep -i quac100

# Check sysfs
cat /sys/class/quac100/quac100_0/device_info
```

## Secure Boot

For systems with Secure Boot enabled:

1. **During install**, you'll be prompted to enroll the MOK key
2. **Reboot** and follow the blue MOK Manager prompts
3. **Verify** enrollment: `mokutil --list-enrolled | grep Dyber`

Manual enrollment:
```bash
sudo mokutil --import keys/MOK.der
# Set password, reboot, enroll via MOK Manager
```

## Configuration

### Module Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `max_devices` | 16 | Maximum devices supported |
| `dma_ring_size` | 256 | DMA descriptor ring size |
| `msix_vectors` | 8 | MSI-X interrupt vectors |
| `enable_sriov` | 0 | Enable SR-IOV (0/1) |
| `num_vfs` | 0 | Number of virtual functions |
| `debug_level` | 0 | Debug verbosity (0-4) |

Configure in `/etc/modprobe.d/quac100.conf`:
```
options quac100 debug_level=1 enable_sriov=1 num_vfs=4
```

### Device Nodes

| Device | Description |
|--------|-------------|
| `/dev/quac100_0` | First QUAC 100 device |
| `/dev/quac100_N` | Nth device |

### sysfs Interface

```bash
# Device information
cat /sys/class/quac100/quac100_0/device_info
cat /sys/class/quac100/quac100_0/firmware_version
cat /sys/class/quac100/quac100_0/serial_number
cat /sys/class/quac100/quac100_0/temperature

# Statistics
cat /sys/class/quac100/quac100_0/stats

# Reset statistics
echo 1 > /sys/class/quac100/quac100_0/reset_stats
```

## Testing

### Run Test Suite (No Hardware Required)

The driver includes a comprehensive test suite that validates the SDK headers, configuration files, and API contracts without requiring physical hardware:

```bash
cd testing/
./test_driver_no_hw_v2.sh --all
```

**Test Categories:**
- Static Analysis: Shell script linting, systemd/udev validation, C header syntax
- Unit Tests: Result codes, algorithm definitions, cryptographic constants, struct versioning
- API Contract Tests: Function signatures, return types, parameter documentation
- Configuration Tests: udev rules completeness, systemd service validation

**Expected Output:**
```
========== Test Summary ==========
  Passed:  12
  Failed:  0
  Skipped: 1
```

### Hardware Tests

With QUAC 100 hardware installed:
```bash
./test_driver_no_hw_v2.sh --hardware
```

## Uninstallation

```bash
sudo ./scripts/uninstall.sh
```

Or for DKMS:
```bash
sudo ./scripts/dkms-uninstall.sh
```

## Troubleshooting

### Driver Won't Load

```bash
# Check kernel compatibility
uname -r
modinfo src/quac100.ko | grep vermagic

# Check Secure Boot
mokutil --sb-state
dmesg | grep -i secure

# Check hardware
lspci -nn | grep -i 1DYB
```

### Permission Denied

```bash
# Add user to quac100 group
sudo usermod -aG quac100 $USER
# Log out and back in
```

### DMA Errors

```bash
# Check IOMMU
dmesg | grep -i iommu
cat /proc/cmdline | grep iommu
```

### Header Compilation Issues

If you encounter issues compiling against SDK headers:
```bash
# Ensure headers have Unix line endings
cd include/
sed -i 's/\r$//' *.h
sed -i 's/\r$//' internal/*.h
```

## API Reference

### Supported Algorithms

| Algorithm | Type | Security Level | Public Key | Secret Key | Ciphertext/Signature |
|-----------|------|----------------|------------|------------|----------------------|
| ML-KEM-512 | KEM | 1 | 800 B | 1632 B | 768 B |
| ML-KEM-768 | KEM | 3 | 1184 B | 2400 B | 1088 B |
| ML-KEM-1024 | KEM | 5 | 1568 B | 3168 B | 1568 B |
| ML-DSA-44 | Sign | 2 | 1312 B | 2528 B | 2420 B |
| ML-DSA-65 | Sign | 3 | 1952 B | 4000 B | 3293 B |
| ML-DSA-87 | Sign | 5 | 2592 B | 4864 B | 4595 B |
| SLH-DSA-SHA2-128s | Sign | 1 | 32 B | 64 B | 7856 B |
| SLH-DSA-SHA2-128f | Sign | 1 | 32 B | 64 B | 17088 B |
| SLH-DSA-SHA2-192s | Sign | 3 | 48 B | 96 B | 16224 B |
| SLH-DSA-SHA2-192f | Sign | 3 | 48 B | 96 B | 35664 B |
| SLH-DSA-SHA2-256s | Sign | 5 | 64 B | 128 B | 29792 B |
| SLH-DSA-SHA2-256f | Sign | 5 | 64 B | 128 B | 49856 B |

### Result Codes

The SDK defines 60 result codes across 8 categories:
- General errors (0x0001-0x00FF)
- Device errors (0x0100-0x01FF)
- Cryptographic errors (0x0200-0x02FF)
- Key management errors (0x0300-0x03FF)
- QRNG errors (0x0400-0x04FF)
- Async/batch errors (0x0500-0x05FF)
- Security errors (0x0600-0x06FF)
- Simulator errors (0x0700-0x07FF)

## Version History

See [CHANGELOG.md](CHANGELOG.md) for detailed version history.

## Support

- **Documentation:** https://docs.dyber.org/quac100/drivers/linux
- **Issues:** https://github.com/dyber-pqc/quantacore-sdk/issues
- **Email:** support@dyber.org
- **Website:** https://dyber.org

## License

Copyright © 2025 Dyber, Inc. All Rights Reserved.

This driver is dual-licensed:
- **GPL-2.0** for the kernel module (required for Linux kernel compatibility)
- **Proprietary** terms for userspace components and SDK

See [LICENSE](LICENSE) for full terms.