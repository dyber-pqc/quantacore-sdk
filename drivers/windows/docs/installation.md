# QUAC 100 Windows Driver Installation Guide

This guide covers installing, configuring, and verifying the QUAC 100 Windows driver.

## System Requirements

### Hardware Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| PCIe Slot | Gen3 x4 | Gen4 x8 |
| System RAM | 8 GB | 16 GB |
| CPU | x64 or ARM64 | Multi-core |
| Power | PCIe slot power | Auxiliary power (if required) |

### Software Requirements

| Component | Version |
|-----------|---------|
| Windows 11 | 22H2 or later |
| Windows 10 | 21H2 or later (limited support) |
| Windows Server | 2019 or 2022 |

### Firmware Requirements

- QUAC 100 firmware version 1.0.0 or later
- UEFI Secure Boot compatible

## Pre-Installation Checklist

- [ ] QUAC 100 hardware installed in PCIe slot
- [ ] System powered off during hardware installation
- [ ] BIOS/UEFI configured for PCIe device
- [ ] Windows fully updated
- [ ] Administrator access available
- [ ] Test signing enabled (for development drivers)

## Installation Methods

### Method 1: Quick Install Script (Recommended)

```powershell
# Run as Administrator
cd D:\quantacore-sdk\drivers\windows

# Full installation workflow
.\scripts\quickstart.ps1 -Action All
```

This script will:
1. Verify development environment
2. Build the driver (if needed)
3. Enable test signing (prompts for reboot)
4. Sign the driver
5. Install the driver
6. Run verification tests

### Method 2: Manual Installation

#### Step 1: Enable Test Signing (Development Only)

For test-signed (development) drivers:

```powershell
# Run as Administrator
.\tools\deploy\enable_testsigning.ps1

# Or manually
bcdedit /set testsigning on
```

**Reboot required** for test signing to take effect.

#### Step 2: Install the Driver

```powershell
# Using installation script
.\tools\deploy\install_driver.ps1 -InfPath .\bin\x64\Release\quac100\quac100.inf

# Or using pnputil directly
pnputil /add-driver .\bin\x64\Release\quac100\quac100.inf /install
```

#### Step 3: Verify Installation

```powershell
# Run diagnostic tool
.\tools\deploy\diagnose.ps1
```

### Method 3: Device Manager

1. Open Device Manager (devmgmt.msc)
2. Find "Unknown device" or QUAC 100 with warning icon
3. Right-click → Update driver
4. Browse my computer for drivers
5. Navigate to driver folder (e.g., `bin\x64\Release\quac100`)
6. Click Next to install

### Method 4: INF Installation

Double-click the INF file:

1. Navigate to `bin\x64\Release\quac100\`
2. Right-click `quac100.inf`
3. Select "Install"
4. Accept UAC prompt

## Production Installation

For production-signed drivers:

```powershell
# No test signing required
# Install signed driver package
pnputil /add-driver quac100.inf /install
```

Or distribute via:
- Windows Update (WHQL certified)
- System Center Configuration Manager (SCCM)
- Microsoft Endpoint Manager (Intune)
- Group Policy

## Post-Installation Configuration

### Verify Device Status

```powershell
# Check device in PowerShell
Get-PnpDevice -FriendlyName "*QUAC*"

# Expected output:
# Status: OK
# Class: System
# FriendlyName: QUAC 100 Post-Quantum Cryptographic Accelerator
```

### Check Driver Version

```powershell
# Get driver details
$device = Get-PnpDevice -FriendlyName "*QUAC*"
Get-PnpDeviceProperty -InstanceId $device.InstanceId | 
    Where-Object { $_.KeyName -like "*Driver*" }
```

### Verify in Device Manager

1. Open Device Manager
2. Expand "System devices" or "Security devices"
3. Find "QUAC 100 Post-Quantum Cryptographic Accelerator"
4. Right-click → Properties
5. Check:
   - Device status: "This device is working properly"
   - Driver tab: Version matches expected

## User-Mode Library Installation

The user-mode library (quac100.dll) should be installed for applications:

### System-Wide Installation

```powershell
# Copy to System32 (requires admin)
Copy-Item .\bin\x64\Release\quac100.dll C:\Windows\System32\

# Register (if COM support needed)
regsvr32 C:\Windows\System32\quac100.dll
```

### Application-Local Installation

Copy to application directory:
```powershell
Copy-Item .\bin\x64\Release\quac100.dll C:\MyApp\
Copy-Item .\bin\x64\Release\quac100.lib C:\MyApp\lib\  # For development
```

### Development Installation

```powershell
# Copy headers
Copy-Item .\include\*.h C:\Dev\include\quac100\
Copy-Item .\lib\quac100lib\quac100lib.h C:\Dev\include\quac100\

# Copy libraries
Copy-Item .\bin\x64\Release\quac100.lib C:\Dev\lib\
Copy-Item .\bin\x64\Release\quac100.dll C:\Dev\bin\
```

## Uninstallation

### Using Script

```powershell
# Uninstall driver, keep in store
.\tools\deploy\uninstall_driver.ps1

# Complete removal
.\tools\deploy\uninstall_driver.ps1 -RemovePackage -Force
```

### Using Device Manager

1. Open Device Manager
2. Find QUAC 100 device
3. Right-click → Uninstall device
4. Check "Delete the driver software for this device"
5. Click Uninstall

### Using pnputil

```powershell
# Find driver package
pnputil /enum-drivers | Select-String -Pattern "quac100" -Context 5

# Delete package (replace oemXX.inf with actual name)
pnputil /delete-driver oemXX.inf /force
```

### Clean System

```powershell
# Remove all traces
.\scripts\clean.ps1 -All -Force

# Disable test signing
bcdedit /set testsigning off
# Reboot
```

## Troubleshooting

### Device Not Detected

1. **Check hardware installation**
   - Reseat PCIe card
   - Try different PCIe slot
   - Check power connections

2. **Check BIOS/UEFI**
   - Enable PCIe slot
   - Disable Secure Boot (for test signing)
   - Update BIOS

3. **Check Windows**
   ```powershell
   # Scan for hardware changes
   pnputil /scan-devices
   
   # Check for hidden devices
   # Device Manager → View → Show hidden devices
   ```

### Driver Won't Load

1. **Test signing not enabled**
   ```powershell
   # Check status
   bcdedit | Select-String "testsigning"
   
   # Enable if needed
   bcdedit /set testsigning on
   # Reboot
   ```

2. **Driver not signed**
   ```powershell
   # Sign driver
   .\tools\sign\sign_driver.ps1 -DriverPath .\quac100.sys -TestSign
   ```

3. **Check Event Viewer**
   - Windows Logs → System
   - Filter by Source: "Service Control Manager"
   - Look for driver load errors

### Device Has Warning/Error

Run diagnostics:
```powershell
.\tools\deploy\diagnose.ps1 -IncludeLogs -OutputDir C:\Temp\QuacDiag
```

Common issues:
- **Code 10**: Driver failed to start
- **Code 28**: Driver not installed
- **Code 31**: Device not working properly
- **Code 52**: Digital signature issue

### Performance Issues

1. **Check PCIe link speed**
   ```powershell
   # In Device Manager, check PCIe properties
   # Should be Gen3 x4 or better
   ```

2. **Check DMA**
   - Ensure DMA is enabled in BIOS
   - Check for IOMMU/VT-d conflicts

3. **Run benchmarks**
   ```powershell
   .\scripts\benchmark.ps1 -Algorithm All
   ```

## Advanced Configuration

### Registry Settings

Driver settings in registry:
```
HKLM\SYSTEM\CurrentControlSet\Services\quac100\Parameters
```

| Value | Type | Description |
|-------|------|-------------|
| MaxDmaTransferSize | DWORD | Max DMA size (default: 4MB) |
| QrngPoolSize | DWORD | QRNG buffer size (default: 64KB) |
| EnableHealthMonitor | DWORD | Health monitoring (default: 1) |
| DebugLevel | DWORD | Debug verbosity (0-4) |

### Group Policy

For enterprise deployment, configure via Group Policy:

1. Create device installation policy
2. Allow specific hardware IDs
3. Configure driver signing requirements
4. Set installation restrictions

### Virtualization (SR-IOV)

For virtual machine support:

1. Enable SR-IOV in BIOS
2. Install PF driver on host
3. Configure VFs:
   ```powershell
   # Enable 4 virtual functions
   Set-NetAdapterSriov -Name "QUAC 100" -NumVFs 4
   ```
4. Install VF driver in VMs

## Verification

### Quick Verification

```powershell
# Test basic functionality
.\test\quac100test.exe --quick
```

### Full Verification

```powershell
# Run all tests
.\scripts\test.ps1 -Category All -Verbose
```

### Hardware Verification

```powershell
# Check hardware health
.\tools\deploy\diagnose.ps1

# Run self-test
.\test\quac100test.exe --selftest
```

## Getting Help

### Diagnostic Information

Collect before requesting support:
```powershell
.\tools\deploy\diagnose.ps1 -OutputDir C:\Temp\QuacDiag -IncludeLogs
```

### Support Resources

- Documentation: https://github.com/dyber-pqc/quantacore-sdk
- Issues: https://github.com/dyber-pqc/quantacore-sdk/issues
- Email: support@dyber.org
- Web: https://dyber.org/support

---

Copyright © 2025 Dyber, Inc. All Rights Reserved.
