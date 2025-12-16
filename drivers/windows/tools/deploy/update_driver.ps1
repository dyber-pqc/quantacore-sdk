<#
.SYNOPSIS
    Update QUAC 100 Windows Driver

.DESCRIPTION
    Updates an existing QUAC 100 driver installation with a new version.
    Handles driver unload, update, and reload automatically.

.PARAMETER DriverPath
    Path to new driver package (folder containing .sys and .inf)

.PARAMETER NoRestart
    Don't restart the device after update

.PARAMETER Force
    Force update even if versions match

.EXAMPLE
    .\update_driver.ps1 -DriverPath C:\NewDriver
    Update driver from specified path

.EXAMPLE
    .\update_driver.ps1 -Force
    Force reinstall from build output
#>

param(
    [string]$DriverPath,
    [switch]$NoRestart,
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Split-Path -Parent (Split-Path -Parent $ScriptDir)

# Require admin
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script requires administrator privileges."
    exit 1
}

Write-Host "QUAC 100 Driver Update" -ForegroundColor Cyan
Write-Host "======================" -ForegroundColor Cyan
Write-Host ""

# Find driver path
if (-not $DriverPath) {
    # Use latest build
    $searchPaths = @(
        (Join-Path $RootDir "bin\x64\Release\quac100"),
        (Join-Path $RootDir "bin\x64\Debug\quac100"),
        (Join-Path $RootDir "bin\ARM64\Release\quac100"),
        (Join-Path $RootDir "bin\ARM64\Debug\quac100")
    )
    
    foreach ($path in $searchPaths) {
        if (Test-Path (Join-Path $path "quac100.sys")) {
            $DriverPath = $path
            break
        }
    }
}

if (-not $DriverPath -or -not (Test-Path $DriverPath)) {
    Write-Error "Driver path not found. Specify -DriverPath or build the driver first."
    exit 1
}

$sysFile = Join-Path $DriverPath "quac100.sys"
$infFile = Join-Path $DriverPath "quac100.inf"

if (-not (Test-Path $sysFile)) {
    Write-Error "Driver file not found: $sysFile"
    exit 1
}

if (-not (Test-Path $infFile)) {
    Write-Error "INF file not found: $infFile"
    exit 1
}

Write-Host "New driver: $DriverPath" -ForegroundColor Yellow

# Get new driver version
$newVersion = (Get-Item $sysFile).VersionInfo.FileVersion
if (-not $newVersion) {
    $newVersion = "1.0.0.0"
}
Write-Host "New version: $newVersion" -ForegroundColor Yellow

# Find existing device
$devices = Get-PnpDevice -FriendlyName "*QUAC*" -ErrorAction SilentlyContinue
if (-not $devices) {
    $devices = Get-PnpDevice | Where-Object { 
        $_.HardwareID -like "*QUAC*" 
    }
}

if (-not $devices) {
    Write-Host "No existing QUAC 100 device found." -ForegroundColor Yellow
    Write-Host "Installing as new driver..." -ForegroundColor Yellow
    
    # Just install
    $result = & pnputil.exe /add-driver $infFile /install /force
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Driver installed successfully!" -ForegroundColor Green
    } else {
        Write-Error "Driver installation failed: $result"
    }
    exit $LASTEXITCODE
}

# Get current version
foreach ($device in $devices) {
    Write-Host ""
    Write-Host "Found device: $($device.FriendlyName)" -ForegroundColor Cyan
    Write-Host "  Instance: $($device.InstanceId)"
    Write-Host "  Status: $($device.Status)"
    
    $props = Get-PnpDeviceProperty -InstanceId $device.InstanceId -ErrorAction SilentlyContinue
    $currentVersion = ($props | Where-Object { $_.KeyName -eq "DEVPKEY_Device_DriverVersion" }).Data
    if ($currentVersion) {
        Write-Host "  Current version: $currentVersion"
    }
    
    # Check if update needed
    if ($currentVersion -eq $newVersion -and -not $Force) {
        Write-Host ""
        Write-Host "Driver is already up to date (version $newVersion)" -ForegroundColor Green
        Write-Host "Use -Force to reinstall anyway"
        continue
    }
    
    Write-Host ""
    Write-Host "Updating device..." -ForegroundColor Yellow
    
    # Disable device first
    Write-Host "  Disabling device..." -ForegroundColor Gray
    try {
        Disable-PnpDevice -InstanceId $device.InstanceId -Confirm:$false -ErrorAction Stop
    } catch {
        Write-Warning "  Could not disable device: $_"
    }
    
    # Update driver
    Write-Host "  Updating driver..." -ForegroundColor Gray
    $result = & pnputil.exe /add-driver $infFile /install /force 2>&1
    
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Driver update failed: $result"
        
        # Try to re-enable
        Enable-PnpDevice -InstanceId $device.InstanceId -Confirm:$false -ErrorAction SilentlyContinue
        exit 1
    }
    
    # Re-enable device
    if (-not $NoRestart) {
        Write-Host "  Enabling device..." -ForegroundColor Gray
        try {
            Enable-PnpDevice -InstanceId $device.InstanceId -Confirm:$false -ErrorAction Stop
            Start-Sleep -Seconds 2
            
            # Verify
            $updated = Get-PnpDevice -InstanceId $device.InstanceId -ErrorAction SilentlyContinue
            if ($updated -and $updated.Status -eq "OK") {
                Write-Host "  Device is working!" -ForegroundColor Green
            } else {
                Write-Warning "  Device status: $($updated.Status)"
            }
        } catch {
            Write-Warning "  Could not enable device: $_"
            Write-Host "  Try manually enabling in Device Manager" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  Device left disabled (use Device Manager to enable)" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "Driver update complete!" -ForegroundColor Green
