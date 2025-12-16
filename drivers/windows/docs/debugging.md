# QUAC 100 Windows Driver Debugging Guide

This guide covers debugging techniques for the QUAC 100 Windows driver, from basic troubleshooting to advanced kernel debugging.

## Debugging Overview

### Debug Tools

| Tool | Purpose | Level |
|------|---------|-------|
| Event Viewer | System logs | Basic |
| diagnose.ps1 | Automated diagnostics | Basic |
| WPP Tracing | Driver trace messages | Intermediate |
| Driver Verifier | Bug detection | Intermediate |
| WinDbg | Kernel debugging | Advanced |
| Performance Monitor | Performance analysis | Intermediate |

### Debug Builds

Use Debug configuration for development:
```powershell
.\scripts\build.ps1 -Configuration Debug
```

Debug builds include:
- Full debug symbols (.pdb)
- ASSERT macros enabled
- Verbose WPP tracing
- Code analysis checks
- No optimization

## Basic Debugging

### Event Viewer

Check Windows Event Viewer for driver issues:

1. Open Event Viewer (eventvwr.msc)
2. Navigate to Windows Logs → System
3. Filter by:
   - Source: "quac100" or "Service Control Manager"
   - Level: Error, Warning

Common events:
- **Event 7000**: Service failed to start
- **Event 7026**: Driver failed to load
- **Event 14**: Device configuration error

### Diagnostic Script

Run comprehensive diagnostics:

```powershell
# Basic diagnostics
.\tools\deploy\diagnose.ps1

# Full diagnostics with logs
.\tools\deploy\diagnose.ps1 -IncludeLogs -OutputDir C:\Temp\QuacDiag

# Include crash dumps
.\tools\deploy\diagnose.ps1 -IncludeLogs -IncludeMemoryDump -OutputDir C:\Temp\QuacDiag
```

### Device Manager

Check device status:
1. Open Device Manager (devmgmt.msc)
2. Find QUAC 100 device
3. Right-click → Properties
4. Check:
   - General tab: Device status
   - Driver tab: Version, provider
   - Resources tab: IRQ, memory
   - Events tab: Recent events

## WPP Tracing

Windows Software Trace Preprocessor (WPP) provides detailed driver tracing.

### Start Tracing

```powershell
# Start with default settings
.\scripts\trace.ps1 -Action Start

# Start with verbose level
.\scripts\trace.ps1 -Action Start -Level Verbose

# Start with auto-stop after 60 seconds
.\scripts\trace.ps1 -Action Start -Level Debug -Duration 60
```

### View Traces

```powershell
# Real-time viewing
.\scripts\trace.ps1 -Action View

# Check status
.\scripts\trace.ps1 -Action Status
```

### Save Traces

```powershell
# Stop and save
.\scripts\trace.ps1 -Action Stop
.\scripts\trace.ps1 -Action Save -OutputFile C:\Temp\quac_trace.etl
```

### Trace Levels

| Level | Description |
|-------|-------------|
| Error | Critical errors only |
| Warning | Errors and warnings |
| Info | Normal operation messages |
| Verbose | Detailed operation info |
| All | Everything including debug |

### Manual WPP Tracing

```powershell
# QUAC 100 trace GUID (from trace.h)
$TraceGuid = "{F4E12345-ABCD-4567-89AB-CDEF01234567}"

# Start session
logman create trace Quac100Trace -ets -p $TraceGuid 0xFF 0xFF -o quac_trace.etl

# Stop session
logman stop Quac100Trace -ets

# Format trace
tracefmt quac_trace.etl -o quac_trace.txt
```

## Driver Verifier

Driver Verifier detects bugs and improper driver behavior.

### Enable Verifier

```powershell
# Standard verification
.\scripts\verifier.ps1 -Action Enable

# Full verification (performance impact)
.\scripts\verifier.ps1 -Action Full

# Check status
.\scripts\verifier.ps1 -Action Status
```

Reboot required after enabling.

### Verifier Checks

Standard checks include:
- Special Pool (buffer overruns)
- Force IRQL Checking
- Pool Tracking (memory leaks)
- I/O Verification
- Deadlock Detection
- DMA Verification
- Security Checks

### Analyze Verifier Crashes

When Driver Verifier catches a bug:

1. System will BSOD (Blue Screen)
2. Crash dump created in `C:\Windows\Minidump\`
3. Analyze with WinDbg:
   ```
   !analyze -v
   ```

### Disable Verifier

```powershell
.\scripts\verifier.ps1 -Action Disable
# Reboot required
```

## Kernel Debugging

### Setup WinDbg

1. Install WinDbg (Windows SDK or Microsoft Store)
2. Configure symbol path:
   ```
   .sympath srv*C:\Symbols*https://msdl.microsoft.com/download/symbols
   .sympath+ D:\quantacore-sdk\drivers\windows\bin\x64\Debug
   ```

### Local Kernel Debugging

```powershell
# Enable local debugging
bcdedit /debug on
bcdedit /dbgsettings local
# Reboot

# Open WinDbg as Administrator
# File → Kernel Debug → Local
```

### Remote Kernel Debugging

Target machine:
```powershell
# Configure network debugging
bcdedit /debug on
bcdedit /dbgsettings net hostip:192.168.1.100 port:50000 key:1.2.3.4
# Reboot
```

Host machine:
```
# WinDbg
File → Kernel Debug → Net
Port: 50000
Key: 1.2.3.4
```

### Useful WinDbg Commands

```
# Load QUAC 100 driver symbols
.reload quac100.sys

# List loaded modules
lm m quac*

# Set breakpoint
bp quac100!DriverEntry
bp quac100!Quac100EvtIoDeviceControl

# View device extension
!devext <device_address>

# View IRP
!irp <irp_address>

# Stack trace
k
kp      # With parameters
kb      # With first 3 params

# Memory dump
db <address>        # Bytes
dd <address>        # DWORDs
dq <address>        # QWORDs

# Analyze crash
!analyze -v

# Driver information
!drvobj quac100

# Device object
!devobj <device_address>

# Check pool allocations
!poolused 2 quac

# View KMDF objects
!wdfkd.wdfdriverinfo quac100
!wdfkd.wdfdevice <device>
!wdfkd.wdfqueue <queue>
```

### Common Breakpoints

```
# Driver load
bp quac100!DriverEntry

# Device creation
bp quac100!Quac100EvtDeviceAdd

# IOCTL handling
bp quac100!Quac100EvtIoDeviceControl

# DMA operations
bp quac100!Quac100DmaTransferSubmit

# Crypto operations
bp quac100!Quac100KemKeyGen
bp quac100!Quac100SignSign
bp quac100!Quac100QrngGenerate

# Interrupt handling
bp quac100!Quac100EvtInterruptIsr
bp quac100!Quac100EvtInterruptDpc
```

## Performance Debugging

### Performance Counters

```powershell
# View available counters
Get-Counter -ListSet *quac* | Select-Object CounterSetName, Paths

# Collect performance data
$counters = @(
    "\QUAC100\Operations/sec",
    "\QUAC100\DMA Transfers/sec",
    "\QUAC100\Average Latency"
)
Get-Counter -Counter $counters -SampleInterval 1 -MaxSamples 60
```

### ETW Tracing for Performance

```powershell
# Start performance trace
xperf -on LOADER+PROC_THREAD+DPC+INTERRUPT -stackwalk DPC+TimerSetPeriodic

# Reproduce issue
# ...

# Stop and analyze
xperf -d perf.etl
xperf perf.etl
```

### Benchmark Tool

```powershell
# Run performance benchmarks
.\scripts\benchmark.ps1 -Algorithm All -Iterations 1000 -OutputFormat CSV -OutputFile results.csv
```

## Common Issues

### BSOD Analysis

Common bug check codes:

| Code | Name | Common Cause |
|------|------|--------------|
| 0x0A | IRQL_NOT_LESS_OR_EQUAL | Bad memory access at wrong IRQL |
| 0x1E | KMODE_EXCEPTION_NOT_HANDLED | Unhandled exception |
| 0xD1 | DRIVER_IRQL_NOT_LESS_OR_EQUAL | Bad memory access in driver |
| 0xC4 | DRIVER_VERIFIER_DETECTED_VIOLATION | Verifier caught bug |
| 0x9F | DRIVER_POWER_STATE_FAILURE | Power management bug |

Analyze with WinDbg:
```
!analyze -v
.bugcheck
```

### Memory Leaks

1. Enable pool tracking in Driver Verifier
2. Run workload
3. Check pool usage:
   ```
   # In WinDbg
   !poolused 2 Quac
   ```

### DMA Issues

```
# Check DMA adapter
!dma

# View scatter-gather list
!sglist <address>
```

### Deadlocks

1. Enable deadlock detection in Driver Verifier
2. If deadlock occurs, in WinDbg:
   ```
   !locks
   !deadlock
   ```

## Debug Print Statements

### Adding Debug Output

In driver code:
```c
// Using DbgPrintEx
DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, 
           "QUAC100: Operation completed, status=%x\n", status);

// Using WPP (preferred)
TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER,
            "Operation completed, status=%!STATUS!", status);
```

### Viewing Debug Output

```powershell
# Install DebugView from Sysinternals
# Enable Capture Kernel and global Win32

# Or in WinDbg
# Break into debugger and:
ed nt!Kd_DEFAULT_Mask 0xF
g
```

## Log Files

### Driver Log Locations

| Log | Location |
|-----|----------|
| Event Log | Event Viewer → System |
| Setup Log | `C:\Windows\inf\setupapi.dev.log` |
| WPP Trace | `%TEMP%\quac100_trace.etl` |
| Crash Dumps | `C:\Windows\Minidump\` |

### Enable Setup Logging

```
# In registry
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup
LogLevel = 0x2000FFFF
```

## Testing After Fixes

### Regression Testing

```powershell
# Run full test suite
.\scripts\test.ps1 -Category All

# Run specific tests
.\scripts\test.ps1 -Category KEM
.\scripts\test.ps1 -Category Sign
.\scripts\test.ps1 -Category QRNG
```

### Stress Testing

```powershell
# Run stress test
.\test\quac100test.exe --stress --duration 3600

# Run with verifier
.\scripts\verifier.ps1 -Action Enable
# Reboot
.\test\quac100test.exe --stress --duration 3600
```

## Getting Help

### Collecting Debug Information

Before requesting support:
```powershell
# Collect everything
.\tools\deploy\diagnose.ps1 -IncludeLogs -IncludeMemoryDump -OutputDir C:\QuacDebug

# Zip for submission
Compress-Archive C:\QuacDebug\* C:\QuacDebug.zip
```

### Support Channels

- GitHub Issues: https://github.com/dyber-pqc/quantacore-sdk/issues
- Email: support@dyber.org

---

Copyright © 2025 Dyber, Inc. All Rights Reserved.
