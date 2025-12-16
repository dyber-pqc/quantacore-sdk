<#
.SYNOPSIS
    Clean QUAC 100 Build Environment

.DESCRIPTION
    Cleans build outputs, intermediate files, and optionally
    uninstalls the driver and clears caches.

.PARAMETER All
    Clean everything including driver and caches

.PARAMETER Build
    Clean build outputs only

.PARAMETER Driver
    Uninstall driver and remove from store

.PARAMETER Cache
    Clear test and trace caches

.PARAMETER Force
    Don't prompt for confirmation

.EXAMPLE
    .\clean.ps1 -Build
    Clean build outputs

.EXAMPLE
    .\clean.ps1 -All -Force
    Full cleanup without prompts
#>

param(
    [switch]$All,
    [switch]$Build,
    [switch]$Driver,
    [switch]$Cache,
    [switch]$Force
)

$ErrorActionPreference = "Continue"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Split-Path -Parent $ScriptDir

Write-Host "QUAC 100 Clean Utility" -ForegroundColor Cyan
Write-Host "======================" -ForegroundColor Cyan
Write-Host ""

# Default to build clean if no flags
if (-not $All -and -not $Build -and -not $Driver -and -not $Cache) {
    $Build = $true
}

# Expand All flag
if ($All) {
    $Build = $true
    $Driver = $true
    $Cache = $true
}

# Confirmation
if (-not $Force -and ($Driver -or $All)) {
    Write-Host "This will:" -ForegroundColor Yellow
    if ($Build) { Write-Host "  - Delete all build outputs" }
    if ($Driver) { Write-Host "  - Uninstall the driver" }
    if ($Cache) { Write-Host "  - Clear trace and test caches" }
    Write-Host ""
    
    $response = Read-Host "Continue? [y/N]"
    if ($response -ne 'y' -and $response -ne 'Y') {
        Write-Host "Cancelled." -ForegroundColor Gray
        exit 0
    }
    Write-Host ""
}

$cleaned = @()
$errors = @()

# Clean build outputs
if ($Build) {
    Write-Host "Cleaning build outputs..." -ForegroundColor Yellow
    
    $buildDirs = @(
        (Join-Path $RootDir "bin"),
        (Join-Path $RootDir "obj"),
        (Join-Path $RootDir "package"),
        (Join-Path $RootDir "x64"),
        (Join-Path $RootDir "ARM64"),
        (Join-Path $RootDir ".vs")
    )
    
    foreach ($dir in $buildDirs) {
        if (Test-Path $dir) {
            try {
                Remove-Item $dir -Recurse -Force
                Write-Host "  Removed: $dir" -ForegroundColor Gray
                $cleaned += $dir
            } catch {
                Write-Warning "  Failed to remove: $dir - $_"
                $errors += $dir
            }
        }
    }
    
    # Clean intermediate files
    $patterns = @("*.obj", "*.pdb", "*.log", "*.tlog", "*.lastbuildstate")
    foreach ($pattern in $patterns) {
        $files = Get-ChildItem -Path $RootDir -Filter $pattern -Recurse -ErrorAction SilentlyContinue
        foreach ($file in $files) {
            try {
                Remove-Item $file.FullName -Force
            } catch {
                # Ignore errors for intermediate files
            }
        }
    }
    
    Write-Host "  Build outputs cleaned" -ForegroundColor Green
}

# Uninstall driver
if ($Driver) {
    Write-Host "Uninstalling driver..." -ForegroundColor Yellow
    
    # Require admin
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Warning "  Skipping driver uninstall (requires admin)"
    } else {
        $uninstallScript = Join-Path $RootDir "tools\deploy\uninstall_driver.ps1"
        if (Test-Path $uninstallScript) {
            & $uninstallScript -RemovePackage -Force
        } else {
            # Manual uninstall
            $devices = Get-PnpDevice -FriendlyName "*QUAC*" -ErrorAction SilentlyContinue
            foreach ($device in $devices) {
                & pnputil.exe /remove-device $device.InstanceId /force 2>$null
            }
            
            # Remove from driver store
            $packages = & pnputil.exe /enum-drivers | Out-String
            $lines = $packages -split "`n"
            $oemFile = $null
            
            foreach ($line in $lines) {
                if ($line -match "Published Name\s*:\s*(oem\d+\.inf)") {
                    $oemFile = $Matches[1]
                }
                if ($line -match "quac100" -and $oemFile) {
                    & pnputil.exe /delete-driver $oemFile /force 2>$null
                }
            }
        }
        
        Write-Host "  Driver uninstalled" -ForegroundColor Green
    }
}

# Clear caches
if ($Cache) {
    Write-Host "Clearing caches..." -ForegroundColor Yellow
    
    $cacheDirs = @(
        (Join-Path $env:TEMP "Quac100Simulator"),
        (Join-Path $env:TEMP "Quac100Test"),
        (Join-Path $env:TEMP "quac100_trace.etl")
    )
    
    foreach ($dir in $cacheDirs) {
        if (Test-Path $dir) {
            try {
                Remove-Item $dir -Recurse -Force
                Write-Host "  Removed: $dir" -ForegroundColor Gray
                $cleaned += $dir
            } catch {
                Write-Warning "  Failed to remove: $dir"
            }
        }
    }
    
    # Stop any trace sessions
    $traceSession = & logman query Quac100Trace -ets 2>&1
    if ($traceSession -notmatch "does not exist") {
        & logman stop Quac100Trace -ets 2>$null
        Write-Host "  Stopped trace session" -ForegroundColor Gray
    }
    
    Write-Host "  Caches cleared" -ForegroundColor Green
}

# Summary
Write-Host ""
Write-Host "-" * 40
Write-Host "Clean Complete" -ForegroundColor Cyan
Write-Host ""

if ($cleaned.Count -gt 0) {
    Write-Host "Cleaned $($cleaned.Count) items" -ForegroundColor Green
}

if ($errors.Count -gt 0) {
    Write-Host "Failed to clean $($errors.Count) items" -ForegroundColor Yellow
    foreach ($err in $errors) {
        Write-Host "  - $err" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "To rebuild: .\scripts\build.ps1" -ForegroundColor Gray
