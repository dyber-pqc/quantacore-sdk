<#
.SYNOPSIS
    QUAC 100 Driver Diagnostic Tool

.DESCRIPTION
    Collects diagnostic information about the QUAC 100 driver and device
    including driver status, device properties, event logs, and system info.

.PARAMETER OutputDir
    Directory to save diagnostic report

.PARAMETER IncludeLogs
    Include event log entries

.PARAMETER IncludeMemoryDump
    Include driver memory dump (requires debug build)

.EXAMPLE
    .\diagnose.ps1
    Run basic diagnostics and display results

.EXAMPLE
    .\diagnose.ps1 -OutputDir C:\Temp\QuacDiag -IncludeLogs
    Save full diagnostic report with logs
#>

param(
    [string]$OutputDir,
    [switch]$IncludeLogs,
    [switch]$IncludeMemoryDump
)

$ErrorActionPreference = "Continue"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "QUAC 100 Driver Diagnostic Tool" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan
Write-Host ""

$report = @()
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$report += "QUAC 100 Diagnostic Report"
$report += "Generated: $timestamp"
$report += "Computer: $env:COMPUTERNAME"
$report += "=" * 60
$report += ""

# System Information
Write-Host "Collecting system information..." -ForegroundColor Yellow
$report += "SYSTEM INFORMATION"
$report += "-" * 40

$os = Get-CimInstance Win32_OperatingSystem
$report += "OS: $($os.Caption) $($os.Version)"
$report += "Architecture: $($env:PROCESSOR_ARCHITECTURE)"
$report += "Build: $($os.BuildNumber)"

$cs = Get-CimInstance Win32_ComputerSystem
$report += "System: $($cs.Manufacturer) $($cs.Model)"
$report += "RAM: $([math]::Round($cs.TotalPhysicalMemory / 1GB, 2)) GB"
$report += ""

# Test Signing Status
Write-Host "Checking test signing status..." -ForegroundColor Yellow
$report += "DRIVER SIGNING"
$report += "-" * 40

try {
    $bcdOutput = & bcdedit /enum "{current}" 2>&1 | Out-String
    $testSigning = $bcdOutput -match "testsigning\s+Yes"
    $report += "Test Signing: $(if ($testSigning) { 'ENABLED' } else { 'DISABLED' })"
    
    if ($testSigning) {
        Write-Host "  Test signing: ENABLED" -ForegroundColor Green
    } else {
        Write-Host "  Test signing: DISABLED" -ForegroundColor Yellow
    }
} catch {
    $report += "Test Signing: Unable to determine"
}
$report += ""

# Device Status
Write-Host "Checking QUAC 100 device status..." -ForegroundColor Yellow
$report += "DEVICE STATUS"
$report += "-" * 40

$devices = Get-PnpDevice -FriendlyName "*QUAC*" -ErrorAction SilentlyContinue
if (-not $devices) {
    $devices = Get-PnpDevice | Where-Object { 
        $_.HardwareID -like "*VEN_1234&DEV_QUAC*" -or 
        $_.HardwareID -like "*QUAC100*" 
    }
}

if ($devices) {
    foreach ($device in $devices) {
        Write-Host "  Found: $($device.FriendlyName)" -ForegroundColor Green
        $report += "Device: $($device.FriendlyName)"
        $report += "  Status: $($device.Status)"
        $report += "  Instance ID: $($device.InstanceId)"
        $report += "  Class: $($device.Class)"
        
        # Get detailed properties
        $props = Get-PnpDeviceProperty -InstanceId $device.InstanceId -ErrorAction SilentlyContinue
        
        $hwIds = ($props | Where-Object { $_.KeyName -eq "DEVPKEY_Device_HardwareIds" }).Data
        if ($hwIds) {
            $report += "  Hardware IDs: $($hwIds -join ', ')"
        }
        
        $driverDesc = ($props | Where-Object { $_.KeyName -eq "DEVPKEY_Device_DriverDesc" }).Data
        if ($driverDesc) {
            $report += "  Driver: $driverDesc"
        }
        
        $driverVersion = ($props | Where-Object { $_.KeyName -eq "DEVPKEY_Device_DriverVersion" }).Data
        if ($driverVersion) {
            $report += "  Driver Version: $driverVersion"
        }
        
        $driverProvider = ($props | Where-Object { $_.KeyName -eq "DEVPKEY_Device_DriverProvider" }).Data
        if ($driverProvider) {
            $report += "  Driver Provider: $driverProvider"
        }
        
        # Check for problems
        $problem = ($props | Where-Object { $_.KeyName -eq "DEVPKEY_Device_ProblemCode" }).Data
        if ($problem -and $problem -ne 0) {
            Write-Host "    Problem Code: $problem" -ForegroundColor Red
            $report += "  PROBLEM CODE: $problem"
            
            $problemDesc = ($props | Where-Object { $_.KeyName -eq "DEVPKEY_Device_ProblemStatus" }).Data
            if ($problemDesc) {
                $report += "  Problem: $problemDesc"
            }
        }
        
        $report += ""
    }
} else {
    Write-Host "  No QUAC 100 devices found" -ForegroundColor Red
    $report += "No QUAC 100 devices detected"
    $report += ""
}

# Driver Package Status
Write-Host "Checking driver store..." -ForegroundColor Yellow
$report += "DRIVER PACKAGES"
$report += "-" * 40

$driverPackages = & pnputil.exe /enum-drivers 2>&1 | Out-String
$lines = $driverPackages -split "`n"
$currentBlock = @()
$foundQuac = $false

for ($i = 0; $i -lt $lines.Count; $i++) {
    $line = $lines[$i].Trim()
    
    if ($line -match "Published Name") {
        $currentBlock = @($line)
    } elseif ($line -eq "" -and $currentBlock.Count -gt 0) {
        $blockText = $currentBlock -join "`n"
        if ($blockText -match "quac100") {
            $report += $blockText
            $report += ""
            $foundQuac = $true
            Write-Host "  Found driver package in store" -ForegroundColor Green
        }
        $currentBlock = @()
    } else {
        $currentBlock += $line
    }
}

if (-not $foundQuac) {
    $report += "No QUAC 100 driver packages in driver store"
    Write-Host "  No QUAC 100 packages in driver store" -ForegroundColor Yellow
}
$report += ""

# Service Status
Write-Host "Checking driver service..." -ForegroundColor Yellow
$report += "SERVICE STATUS"
$report += "-" * 40

$service = Get-Service -Name "quac100" -ErrorAction SilentlyContinue
if ($service) {
    $report += "Service: quac100"
    $report += "  Status: $($service.Status)"
    $report += "  Start Type: $($service.StartType)"
    Write-Host "  Service status: $($service.Status)" -ForegroundColor $(if ($service.Status -eq 'Running') { 'Green' } else { 'Yellow' })
} else {
    $report += "Service 'quac100' not found"
    Write-Host "  Service not installed" -ForegroundColor Yellow
}

# Check registry
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\quac100"
if (Test-Path $regPath) {
    $regInfo = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
    if ($regInfo) {
        $report += "  ImagePath: $($regInfo.ImagePath)"
        $report += "  Type: $($regInfo.Type)"
        $report += "  Start: $($regInfo.Start)"
        $report += "  ErrorControl: $($regInfo.ErrorControl)"
    }
}
$report += ""

# PCIe Configuration
Write-Host "Checking PCIe configuration..." -ForegroundColor Yellow
$report += "PCIE CONFIGURATION"
$report += "-" * 40

$pciDevices = Get-PnpDevice -Class "System" -Status "OK" | Where-Object {
    $_.InstanceId -like "PCI\*QUAC*" -or $_.FriendlyName -like "*QUAC*"
}

if ($pciDevices) {
    foreach ($pci in $pciDevices) {
        $report += "PCI Device: $($pci.FriendlyName)"
        $report += "  Instance: $($pci.InstanceId)"
        
        # Get resources
        $resources = Get-PnpDeviceProperty -InstanceId $pci.InstanceId -KeyName "DEVPKEY_Device_Resources" -ErrorAction SilentlyContinue
        if ($resources.Data) {
            $report += "  Resources:"
            foreach ($res in $resources.Data) {
                $report += "    $res"
            }
        }
    }
} else {
    $report += "No QUAC 100 PCI devices detected"
}
$report += ""

# Event Logs
if ($IncludeLogs) {
    Write-Host "Collecting event logs..." -ForegroundColor Yellow
    $report += "EVENT LOGS"
    $report += "-" * 40
    
    # System log entries for our driver
    $events = Get-WinEvent -FilterHashtable @{
        LogName = 'System'
        StartTime = (Get-Date).AddDays(-7)
    } -ErrorAction SilentlyContinue | Where-Object {
        $_.Message -like "*quac100*" -or 
        $_.ProviderName -like "*quac*" -or
        $_.Message -like "*QUAC*"
    } | Select-Object -First 50
    
    if ($events) {
        foreach ($event in $events) {
            $report += "[$($event.TimeCreated)] [$($event.LevelDisplayName)] $($event.ProviderName)"
            $report += "  $($event.Message.Substring(0, [Math]::Min(200, $event.Message.Length)))..."
            $report += ""
        }
    } else {
        $report += "No recent QUAC 100 related events found"
    }
    
    # Also check Application log
    $appEvents = Get-WinEvent -FilterHashtable @{
        LogName = 'Application'
        StartTime = (Get-Date).AddDays(-7)
    } -ErrorAction SilentlyContinue | Where-Object {
        $_.Message -like "*quac*" -or $_.Message -like "*QUAC*"
    } | Select-Object -First 20
    
    if ($appEvents) {
        $report += "APPLICATION LOG ENTRIES:"
        foreach ($event in $appEvents) {
            $report += "[$($event.TimeCreated)] [$($event.LevelDisplayName)] $($event.Message.Substring(0, [Math]::Min(200, $event.Message.Length)))..."
        }
    }
    $report += ""
}

# Verifier Status
Write-Host "Checking Driver Verifier..." -ForegroundColor Yellow
$report += "DRIVER VERIFIER"
$report += "-" * 40

$verifier = & verifier /query 2>&1 | Out-String
if ($verifier -match "quac100") {
    $report += "Driver Verifier is ACTIVE for quac100"
    $report += $verifier
    Write-Host "  Driver Verifier: ACTIVE" -ForegroundColor Yellow
} else {
    $report += "Driver Verifier is not enabled for quac100"
    Write-Host "  Driver Verifier: Not active" -ForegroundColor Gray
}
$report += ""

# Memory dump check
if ($IncludeMemoryDump) {
    Write-Host "Checking for crash dumps..." -ForegroundColor Yellow
    $report += "CRASH DUMPS"
    $report += "-" * 40
    
    $dumpPath = "$env:SystemRoot\Minidump"
    if (Test-Path $dumpPath) {
        $dumps = Get-ChildItem $dumpPath -Filter "*.dmp" | 
                 Sort-Object LastWriteTime -Descending | 
                 Select-Object -First 10
        
        if ($dumps) {
            $report += "Recent minidumps:"
            foreach ($dump in $dumps) {
                $report += "  $($dump.Name) - $($dump.LastWriteTime)"
            }
        } else {
            $report += "No minidumps found"
        }
    }
    
    $bsodDump = "$env:SystemRoot\MEMORY.DMP"
    if (Test-Path $bsodDump) {
        $dumpInfo = Get-Item $bsodDump
        $report += "Full memory dump: $($dumpInfo.LastWriteTime)"
    }
    $report += ""
}

# Summary
Write-Host ""
Write-Host "DIAGNOSTIC SUMMARY" -ForegroundColor Cyan
Write-Host "-" * 40

$hasIssues = $false

if (-not $devices) {
    Write-Host "  [!] No QUAC 100 device detected" -ForegroundColor Red
    $hasIssues = $true
} else {
    foreach ($device in $devices) {
        if ($device.Status -ne "OK") {
            Write-Host "  [!] Device status: $($device.Status)" -ForegroundColor Red
            $hasIssues = $true
        } else {
            Write-Host "  [OK] Device detected and working" -ForegroundColor Green
        }
    }
}

if (-not $service) {
    Write-Host "  [!] Driver service not installed" -ForegroundColor Red
    $hasIssues = $true
} elseif ($service.Status -ne "Running") {
    Write-Host "  [!] Driver service not running" -ForegroundColor Yellow
    $hasIssues = $true
} else {
    Write-Host "  [OK] Driver service running" -ForegroundColor Green
}

if (-not $testSigning) {
    Write-Host "  [!] Test signing disabled (may be needed for development)" -ForegroundColor Yellow
}

# Output report
if ($OutputDir) {
    if (-not (Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    }
    
    $reportFile = Join-Path $OutputDir "quac100_diagnostic_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    $report | Out-File -FilePath $reportFile -Encoding UTF8
    
    Write-Host ""
    Write-Host "Diagnostic report saved to: $reportFile" -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "Full Report:" -ForegroundColor Cyan
    Write-Host "-" * 60
    $report | ForEach-Object { Write-Host $_ }
}

if ($hasIssues) {
    exit 1
} else {
    exit 0
}
