<#
.SYNOPSIS
    Uninstall QUAC 100 Windows Driver

.DESCRIPTION
    Removes the QUAC 100 driver from the system. Can optionally remove
    the driver package from the driver store.

.PARAMETER RemovePackage
    Also remove the driver package from the driver store

.PARAMETER Force
    Force removal even if device is in use

.EXAMPLE
    .\uninstall_driver.ps1
    Uninstall driver, keep package in store

.EXAMPLE
    .\uninstall_driver.ps1 -RemovePackage -Force
    Completely remove driver and force if needed
#>

param(
    [switch]$RemovePackage,
    [switch]$Force
)

$ErrorActionPreference = "Stop"

# Require admin
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script requires administrator privileges."
    exit 1
}

Write-Host "QUAC 100 Driver Uninstaller" -ForegroundColor Cyan
Write-Host "===========================" -ForegroundColor Cyan
Write-Host ""

# Find QUAC 100 devices
$devices = Get-PnpDevice -FriendlyName "*QUAC 100*" -ErrorAction SilentlyContinue

if (-not $devices) {
    # Try by hardware ID
    $devices = Get-PnpDevice | Where-Object { 
        $_.HardwareID -like "*VEN_1234&DEV_QUAC*" -or 
        $_.HardwareID -like "*QUAC100*" 
    }
}

if ($devices) {
    Write-Host "Found QUAC 100 device(s):" -ForegroundColor Yellow
    foreach ($device in $devices) {
        Write-Host "  - $($device.FriendlyName) [$($device.Status)]"
        Write-Host "    Instance: $($device.InstanceId)"
    }
    Write-Host ""
    
    # Disable and remove each device
    foreach ($device in $devices) {
        Write-Host "Removing device: $($device.InstanceId)..." -ForegroundColor Yellow
        
        try {
            # Disable first
            Disable-PnpDevice -InstanceId $device.InstanceId -Confirm:$false -ErrorAction SilentlyContinue
            
            # Remove device
            $removeArgs = @("/remove-device", $device.InstanceId)
            if ($Force) {
                $removeArgs += "/force"
            }
            
            $result = & pnputil.exe $removeArgs 2>&1
            
            if ($LASTEXITCODE -eq 0) {
                Write-Host "  Device removed successfully" -ForegroundColor Green
            } else {
                Write-Warning "  Device removal returned: $result"
            }
        } catch {
            Write-Warning "  Could not remove device: $_"
        }
    }
} else {
    Write-Host "No QUAC 100 devices found in Device Manager" -ForegroundColor Yellow
}

# Find and remove driver package from store
Write-Host ""
Write-Host "Checking driver store..." -ForegroundColor Yellow

$driverPackages = & pnputil.exe /enum-drivers 2>&1 | Out-String

# Parse pnputil output to find our driver
$lines = $driverPackages -split "`n"
$currentOem = $null
$foundPackages = @()

foreach ($line in $lines) {
    if ($line -match "Published Name\s*:\s*(oem\d+\.inf)") {
        $currentOem = $Matches[1]
    }
    if ($line -match "Original Name\s*:\s*quac100\.inf") {
        if ($currentOem) {
            $foundPackages += $currentOem
        }
    }
    if ($line -match "Driver Version") {
        $currentOem = $null
    }
}

# Also find VF driver
$currentOem = $null
foreach ($line in $lines) {
    if ($line -match "Published Name\s*:\s*(oem\d+\.inf)") {
        $currentOem = $Matches[1]
    }
    if ($line -match "Original Name\s*:\s*quac100vf\.inf") {
        if ($currentOem) {
            $foundPackages += $currentOem
        }
    }
    if ($line -match "Driver Version") {
        $currentOem = $null
    }
}

if ($foundPackages.Count -gt 0) {
    Write-Host "Found QUAC 100 driver packages:" -ForegroundColor Yellow
    foreach ($pkg in $foundPackages) {
        Write-Host "  - $pkg"
    }
    
    if ($RemovePackage) {
        Write-Host ""
        foreach ($pkg in $foundPackages) {
            Write-Host "Removing driver package: $pkg..." -ForegroundColor Yellow
            
            $deleteArgs = @("/delete-driver", $pkg)
            if ($Force) {
                $deleteArgs += "/force"
            }
            
            $result = & pnputil.exe $deleteArgs 2>&1
            
            if ($LASTEXITCODE -eq 0) {
                Write-Host "  Package removed successfully" -ForegroundColor Green
            } else {
                Write-Warning "  Package removal returned: $result"
            }
        }
    } else {
        Write-Host ""
        Write-Host "Driver packages left in store. Use -RemovePackage to remove them." -ForegroundColor Yellow
    }
} else {
    Write-Host "No QUAC 100 driver packages found in driver store" -ForegroundColor Yellow
}

# Clean up registry entries (optional)
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\quac100"
if (Test-Path $regPath) {
    Write-Host ""
    Write-Host "Removing registry entries..." -ForegroundColor Yellow
    try {
        Remove-Item -Path $regPath -Recurse -Force
        Write-Host "  Registry entries removed" -ForegroundColor Green
    } catch {
        Write-Warning "  Could not remove registry entries: $_"
    }
}

# Also remove VF service
$regPathVF = "HKLM:\SYSTEM\CurrentControlSet\Services\quac100vf"
if (Test-Path $regPathVF) {
    try {
        Remove-Item -Path $regPathVF -Recurse -Force
    } catch {
        Write-Warning "  Could not remove VF registry entries: $_"
    }
}

Write-Host ""
Write-Host "Uninstallation complete!" -ForegroundColor Green
Write-Host ""
Write-Host "Note: A reboot may be required to fully remove the driver." -ForegroundColor Yellow
