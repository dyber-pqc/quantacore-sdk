<#
.SYNOPSIS
    Create QUAC 100 Driver Package

.DESCRIPTION
    Creates a distributable driver package including:
    - Driver files (.sys, .inf, .cat)
    - User-mode library (quac100.dll)
    - Installation scripts
    - Documentation

.PARAMETER Configuration
    Build configuration (Debug/Release)

.PARAMETER Platform
    Target platform (x64/ARM64)

.PARAMETER OutputDir
    Output directory for the package

.PARAMETER Sign
    Sign the driver package

.EXAMPLE
    .\create_package.ps1 -Configuration Release -Platform x64
#>

param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",
    
    [ValidateSet("x64", "ARM64")]
    [string]$Platform = "x64",
    
    [string]$OutputDir,
    
    [switch]$Sign
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Split-Path -Parent (Split-Path -Parent $ScriptDir)

# Set output directory
if (-not $OutputDir) {
    $OutputDir = Join-Path $RootDir "package\$Platform\$Configuration"
}

Write-Host "Creating QUAC 100 Driver Package" -ForegroundColor Cyan
Write-Host "Configuration: $Configuration"
Write-Host "Platform: $Platform"
Write-Host "Output: $OutputDir"
Write-Host ""

# Build paths
$binDir = Join-Path $RootDir "bin\$Platform\$Configuration"
$driverDir = Join-Path $binDir "quac100"
$driverPkg = Join-Path $driverDir "quac100"

# Verify build outputs exist
$requiredFiles = @(
    (Join-Path $driverDir "quac100.sys"),
    (Join-Path $driverDir "quac100.inf"),
    (Join-Path $binDir "quac100.dll")
)

foreach ($file in $requiredFiles) {
    if (-not (Test-Path $file)) {
        Write-Error "Required file not found: $file`nPlease build the solution first."
        exit 1
    }
}

# Create output directories
$dirs = @(
    $OutputDir,
    (Join-Path $OutputDir "driver"),
    (Join-Path $OutputDir "lib"),
    (Join-Path $OutputDir "include"),
    (Join-Path $OutputDir "docs"),
    (Join-Path $OutputDir "tools")
)

foreach ($dir in $dirs) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
}

# Copy driver files
Write-Host "Copying driver files..." -ForegroundColor Yellow
$driverFiles = @("quac100.sys", "quac100.inf", "quac100.cat", "quac100.pdb")
foreach ($file in $driverFiles) {
    $src = Join-Path $driverDir $file
    if (Test-Path $src) {
        Copy-Item $src (Join-Path $OutputDir "driver") -Force
    }
}

# Copy VF driver if exists
$vfDir = Join-Path $binDir "quac100vf"
if (Test-Path $vfDir) {
    $vfOutDir = Join-Path $OutputDir "driver\vf"
    New-Item -ItemType Directory -Path $vfOutDir -Force | Out-Null
    Copy-Item (Join-Path $vfDir "*") $vfOutDir -Force
}

# Copy library files
Write-Host "Copying library files..." -ForegroundColor Yellow
Copy-Item (Join-Path $binDir "quac100.dll") (Join-Path $OutputDir "lib") -Force
Copy-Item (Join-Path $binDir "quac100.lib") (Join-Path $OutputDir "lib") -Force -ErrorAction SilentlyContinue
Copy-Item (Join-Path $binDir "quac100.pdb") (Join-Path $OutputDir "lib") -Force -ErrorAction SilentlyContinue

# Copy header files
Write-Host "Copying header files..." -ForegroundColor Yellow
$includeDir = Join-Path $RootDir "include"
Copy-Item (Join-Path $includeDir "*.h") (Join-Path $OutputDir "include") -Force
Copy-Item (Join-Path $RootDir "lib\quac100lib\quac100lib.h") (Join-Path $OutputDir "include") -Force

# Copy documentation
Write-Host "Copying documentation..." -ForegroundColor Yellow
$docsDir = Join-Path $RootDir "docs"
if (Test-Path $docsDir) {
    Copy-Item (Join-Path $docsDir "*") (Join-Path $OutputDir "docs") -Force -Recurse
}
Copy-Item (Join-Path $RootDir "README.md") $OutputDir -Force
Copy-Item (Join-Path $RootDir "LICENSE") $OutputDir -Force

# Copy tools
Write-Host "Copying tools..." -ForegroundColor Yellow
$deployDir = Join-Path $RootDir "tools\deploy"
Copy-Item (Join-Path $deployDir "*.ps1") (Join-Path $OutputDir "tools") -Force

# Copy test application if exists
$testExe = Join-Path $binDir "quac100test.exe"
if (Test-Path $testExe) {
    Copy-Item $testExe (Join-Path $OutputDir "tools") -Force
}

# Sign if requested
if ($Sign) {
    Write-Host "Signing driver package..." -ForegroundColor Yellow
    $signScript = Join-Path $RootDir "tools\sign\sign_driver.ps1"
    & $signScript -DriverPath (Join-Path $OutputDir "driver\quac100.sys") -TestSign
}

# Create version info file
$versionInfo = @"
QUAC 100 Windows Driver Package
===============================
Version: 1.0.0
Configuration: $Configuration
Platform: $Platform
Build Date: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

Contents:
- driver/     : Kernel-mode driver files
- lib/        : User-mode library (quac100.dll)
- include/    : Header files for development
- docs/       : Documentation
- tools/      : Installation and test utilities

Installation:
1. Enable test signing (if using test-signed driver):
   .\tools\enable_testsigning.ps1
   [Reboot required]

2. Install driver:
   .\tools\install_driver.ps1 -InfPath .\driver\quac100.inf

3. Verify installation in Device Manager

For more information, see docs/installation.md
"@

$versionInfo | Out-File (Join-Path $OutputDir "VERSION.txt") -Encoding UTF8

# Create ZIP archive
$zipPath = Join-Path (Split-Path -Parent $OutputDir) "quac100-$Platform-$Configuration.zip"
Write-Host "Creating ZIP archive: $zipPath" -ForegroundColor Yellow

if (Test-Path $zipPath) {
    Remove-Item $zipPath -Force
}

Compress-Archive -Path "$OutputDir\*" -DestinationPath $zipPath -Force

# Summary
Write-Host ""
Write-Host "Package created successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "Package contents:"
Get-ChildItem $OutputDir -Recurse | ForEach-Object {
    $relativePath = $_.FullName.Replace($OutputDir, "").TrimStart("\")
    if ($_.PSIsContainer) {
        Write-Host "  [DIR]  $relativePath"
    } else {
        Write-Host "  [FILE] $relativePath ($([math]::Round($_.Length/1KB, 1)) KB)"
    }
}

Write-Host ""
Write-Host "ZIP archive: $zipPath"
Write-Host "Size: $([math]::Round((Get-Item $zipPath).Length/1MB, 2)) MB"
