# QUAC 100 Windows Driver Troubleshooting Guide

This guide covers common issues and their solutions when working with the QUAC 100 Windows driver.

## Quick Diagnostics

Run the diagnostic tool first:
```powershell
.\tools\deploy\diagnose.ps1 -IncludeLogs -OutputDir C:\Temp\QuacDiag
```

## Common Issues

### Device Not Found

**Symptoms:**
- Device doesn't appear in Device Manager
- `quaccon list` shows no devices
- Error: "QUAC 100 device not found"

**Solutions:**

1. **Check hardware installation**
   - Ensure card is fully seated in PCIe slot
   - Try a different PCIe slot
   - Check power connections if applicable

2. **Check BIOS/UEFI settings**
   - Ensure PCIe slot is enabled
   - Check for "Above 4G Decoding" setting
   - Try disabling Secure Boot temporarily

3. **Scan for hardware changes**
   ```powershell
   pnputil /scan-devices
   ```

4. **Check Windows Event Log**
   - Event Viewer → System
   - Look for PCI or device enumeration errors

---

### Driver Won't Install

**Symptoms:**
- Error during driver installation
- Driver package rejected
- Signature errors

**Solutions:**

1. **Enable test signing (for development builds)**
   ```powershell
   bcdedit /set testsigning on
   # Reboot required
   ```

2. **Check driver signature**
   ```powershell
   .\tools\sign\sign_driver.ps1 -DriverPath .\quac100.sys -TestSign
   ```

3. **Verify WDK version matches SDK**
   - Both should be same version (e.g., 10.0.22621.0)

4. **Check for conflicting drivers**
   ```powershell
   pnputil /enum-drivers | findstr /i quac
   # Remove old versions
   pnputil /delete-driver oemXX.inf /force
   ```

---

### Driver Won't Load (Code 10)

**Symptoms:**
- Device shows yellow warning in Device Manager
- Device status: "This device cannot start (Code 10)"

**Solutions:**

1. **Check Event Viewer**
   - Windows Logs → System
   - Filter by Source: "Service Control Manager"
   - Look for specific error messages

2. **Verify driver files**
   ```powershell
   # Check all files exist
   Test-Path .\quac100.sys
   Test-Path .\quac100.inf
   Test-Path .\quac100.cat
   ```

3. **Check driver signature status**
   ```powershell
   signtool verify /pa /v quac100.sys
   ```

4. **Run Driver Verifier**
   ```powershell
   .\scripts\verifier.ps1 -Action Enable
   # Reboot and check for BSODs
   ```

5. **Check test signing status**
   ```powershell
   bcdedit | findstr testsigning
   # Should show: testsigning Yes
   ```

---

### Device Not Working Properly (Code 31)

**Symptoms:**
- Device shows error in Device Manager
- Device status: "This device is not working properly (Code 31)"

**Solutions:**

1. **Reinstall driver**
   ```powershell
   .\tools\deploy\uninstall_driver.ps1 -RemovePackage
   # Reboot
   .\tools\deploy\install_driver.ps1
   ```

2. **Check resource conflicts**
   - Device Manager → View → Resources by type
   - Look for IRQ or memory conflicts

3. **Update firmware**
   - Contact Dyber support for firmware update

---

### Digital Signature Issues (Code 52)

**Symptoms:**
- "Windows cannot verify the digital signature" error
- Code 52 in Device Manager

**Solutions:**

1. **For development:**
   ```powershell
   bcdedit /set testsigning on
   # Reboot
   ```

2. **For production:**
   - Ensure driver is signed with valid EV certificate
   - Submit to Microsoft for WHQL certification

3. **Disable Secure Boot temporarily** (development only)
   - BIOS/UEFI → Secure Boot → Disabled
   - **Warning:** Reduces system security

---

### BSOD (Blue Screen of Death)

**Symptoms:**
- System crashes with blue screen
- Stop codes like DRIVER_IRQL_NOT_LESS_OR_EQUAL

**Solutions:**

1. **Collect crash dump**
   ```powershell
   # Dumps are in C:\Windows\Minidump\
   .\tools\deploy\diagnose.ps1 -IncludeMemoryDump
   ```

2. **Analyze with WinDbg**
   ```
   !analyze -v
   ```

3. **Enable Driver Verifier**
   ```powershell
   .\scripts\verifier.ps1 -Action Standard
   # Reproduce the issue
   ```

4. **Check for memory issues**
   - Run Windows Memory Diagnostic
   - Check PCIe seating

5. **Common BSOD causes:**
   - 0x0A: IRQL issue - driver accessing invalid memory
   - 0xD1: Driver accessing paged memory at high IRQL
   - 0x9F: Power management issue
   - 0xC4: Driver Verifier caught a bug

---

### Performance Issues

**Symptoms:**
- Operations slower than expected
- High CPU usage
- Timeouts

**Solutions:**

1. **Check PCIe link speed**
   ```powershell
   # Device Manager → QUAC 100 → Details → PCIe Link Speed
   # Should be Gen3 x4 or better
   ```

2. **Check for thermal throttling**
   ```powershell
   quaccon health
   # Temperature should be below 75°C
   ```

3. **Run benchmark**
   ```powershell
   .\scripts\benchmark.ps1 -Algorithm All
   ```

4. **Check system resources**
   - CPU not overloaded
   - Sufficient free memory
   - No disk bottlenecks

5. **Disable power saving**
   - Power Options → High Performance
   - Disable PCIe Link State Power Management

---

### QRNG Issues

**Symptoms:**
- "QRNG not ready" error
- Low entropy warnings
- Health check failures

**Solutions:**

1. **Check QRNG status**
   ```powershell
   quaccon health
   ```

2. **Run QRNG health test**
   ```powershell
   quaccon test 0x20  # QRNG only
   ```

3. **Reset device**
   ```powershell
   quaccon reset 0
   ```

4. **Check temperature**
   - QRNG quality degrades at high temperatures
   - Ensure adequate cooling

---

### DMA Errors

**Symptoms:**
- DMA transfer timeouts
- Corrupted data
- "DMA error" in logs

**Solutions:**

1. **Check IOMMU/VT-d settings**
   - May need to disable in BIOS for testing
   - Or configure properly for DMA remapping

2. **Check memory allocation**
   - Ensure contiguous physical memory available
   - Check for memory pressure

3. **Verify PCIe configuration**
   ```powershell
   quaccon resources 0
   ```

4. **Run DMA test**
   ```powershell
   quaccon test 0x04  # DMA only
   ```

---

### Virtualization Issues (SR-IOV)

**Symptoms:**
- VFs not appearing
- VF driver won't load
- VM can't access device

**Solutions:**

1. **Check SR-IOV support**
   - BIOS: Enable SR-IOV
   - BIOS: Enable VT-d/IOMMU

2. **Verify VF creation**
   ```powershell
   # On host
   Get-NetAdapterSriov
   ```

3. **Install VF driver in VM**
   - Use quac100vf.inf

4. **Check VM configuration**
   - Hyper-V: Enable SR-IOV on virtual switch
   - VMware: Enable passthrough

---

## Collecting Debug Information

### For Bug Reports

Collect this information before contacting support:

```powershell
# 1. Run full diagnostics
.\tools\deploy\diagnose.ps1 -IncludeLogs -IncludeMemoryDump -OutputDir C:\QuacDebug

# 2. Get driver version
quaccon version

# 3. Export event logs
wevtutil epl System C:\QuacDebug\system.evtx

# 4. Get system info
systeminfo > C:\QuacDebug\systeminfo.txt

# 5. Zip everything
Compress-Archive C:\QuacDebug\* C:\QuacDebug.zip
```

### For Performance Issues

```powershell
# Collect performance data
.\scripts\benchmark.ps1 -Algorithm All -Iterations 1000 -OutputFile perf.csv

# Collect ETW traces
.\scripts\trace.ps1 -Action Start -Level Verbose -Duration 60
# Reproduce issue
.\scripts\trace.ps1 -Action Save -OutputFile trace.etl
```

## Contact Support

If you can't resolve the issue:

1. Collect diagnostic information (see above)
2. Contact support:
   - Email: support@dyber.org
   - GitHub: https://github.com/dyber-pqc/quantacore-sdk/issues
   - Web: https://dyber.org/support

Include:
- Description of the problem
- Steps to reproduce
- Diagnostic zip file
- Screenshots if applicable

---

Copyright © 2025 Dyber, Inc. All Rights Reserved.
