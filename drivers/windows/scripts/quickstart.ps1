<#
.SYNOPSIS
    QUAC 100 Developer Quick Start Script

.DESCRIPTION
    Complete developer workflow script that handles:
    - Environment verification
    - Building the driver and library
    - Test signing
    - Driver installation
    - Running tests
    - Cleanup

.PARAMETER Action
    Action to perform: Setup, Build, Install, Test, Uninstall, All

.PARAMETER Configuration
    Build configuration (Debug/Release)

.PARAMETER SkipTests
    Skip running tests after installation

.EXAMPLE
    .\quickstart.ps1 -Action Setup
    Verify environment and enable test signing

.EXAMPLE
    .\quickstart.ps1 -Action All
    Full workflow: build, sign, install, test

.EXAMPLE
    .\quickstart.ps1 -Action Build -Configuration Release
    Build release configuration only
#>

param(
    [ValidateSet("Setup", "Build", "Install", "Test", "Uninstall", "All")]
    [string]$Action = "All",
    
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Debug",
    
    [ValidateSet("x64", "ARM64")]
    [string]$Platform = "x64",
    
    [switch]$SkipTests
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Split-Path -Parent $ScriptDir

# Colors and helpers
function Write-Step($msg) { Write-Host "`n>> $msg" -ForegroundColor Cyan }
function Write-Success($msg) { Write-Host "   [OK] $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "   [WARN] $msg" -ForegroundColor Yellow }
function Write-Fail($msg) { Write-Host "   [FAIL] $msg" -ForegroundColor Red }

# Banner
Write-Host ""
Write-Host "  ╔═══════════════════════════════════════════════════════╗" -ForegroundColor Magenta
Write-Host "  ║       QUAC 100 Windows Driver - Quick Start           ║" -ForegroundColor Magenta
Write-Host "  ║              Dyber, Inc. (dyber.org)                  ║" -ForegroundColor Magenta
Write-Host "  ╚═══════════════════════════════════════════════════════╝" -ForegroundColor Magenta
Write-Host ""

# Check admin for install/uninstall actions
if ($Action -in @("Setup", "Install", "Uninstall", "All")) {
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Error "This action requires administrator privileges. Please run as Administrator."
        exit 1
    }
}

# ============================================================================
# SETUP: Verify development environment
# ============================================================================
function Invoke-Setup {
    Write-Step "Verifying Development Environment"
    
    $issues = @()
    
    # Visual Studio
    $vs = & "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" `
        -latest -property installationPath 2>$null
    if ($vs) {
        Write-Success "Visual Studio: $vs"
    } else {
        Write-Fail "Visual Studio 2022 not found"
        $issues += "Install Visual Studio 2022 with C++ and Windows Driver Development workloads"
    }
    
    # WDK
    $wdkPath = "${env:ProgramFiles(x86)}\Windows Kits\10\Include"
    if (Test-Path $wdkPath) {
        $wdkVersions = Get-ChildItem $wdkPath -Directory | Sort-Object Name -Descending | Select-Object -First 1
        Write-Success "Windows Driver Kit: $($wdkVersions.Name)"
    } else {
        Write-Fail "Windows Driver Kit not found"
        $issues += "Install Windows Driver Kit (WDK)"
    }
    
    # MSBuild
    $msbuild = & "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" `
        -latest -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe 2>$null | Select-Object -First 1
    if ($msbuild) {
        Write-Success "MSBuild: Found"
    } else {
        Write-Fail "MSBuild not found"
        $issues += "Install MSBuild via Visual Studio Installer"
    }
    
    # SignTool
    $signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin" -Recurse -Filter "signtool.exe" 2>$null | Select-Object -First 1
    if ($signtool) {
        Write-Success "SignTool: Found"
    } else {
        Write-Warn "SignTool not found (needed for driver signing)"
    }
    
    # Test signing status
    $bcdOutput = & bcdedit /enum "{current}" 2>&1 | Out-String
    $testSigning = $bcdOutput -match "testsigning\s+Yes"
    if ($testSigning) {
        Write-Success "Test Signing: Enabled"
    } else {
        Write-Warn "Test Signing: Disabled"
        
        $response = Read-Host "   Enable test signing now? (requires reboot) [y/N]"
        if ($response -eq 'y' -or $response -eq 'Y') {
            & bcdedit /set testsigning on
            Write-Success "Test signing enabled. REBOOT REQUIRED."
            $issues += "REBOOT REQUIRED for test signing to take effect"
        } else {
            $issues += "Enable test signing before installing test-signed drivers"
        }
    }
    
    if ($issues.Count -gt 0) {
        Write-Host "`n   Issues to address:" -ForegroundColor Yellow
        foreach ($issue in $issues) {
            Write-Host "   - $issue" -ForegroundColor Yellow
        }
        return $false
    }
    
    Write-Success "Environment ready for driver development!"
    return $true
}

# ============================================================================
# BUILD: Compile driver and library
# ============================================================================
function Invoke-Build {
    Write-Step "Building QUAC 100 Driver ($Configuration|$Platform)"
    
    $buildScript = Join-Path $ScriptDir "build.ps1"
    & $buildScript -Configuration $Configuration -Platform $Platform -Clean
    
    if ($LASTEXITCODE -ne 0) {
        Write-Fail "Build failed!"
        return $false
    }
    
    # Verify outputs
    $binDir = Join-Path $RootDir "bin\$Platform\$Configuration"
    $expectedFiles = @(
        "quac100\quac100.sys",
        "quac100\quac100.inf",
        "quac100.dll"
    )
    
    foreach ($file in $expectedFiles) {
        $path = Join-Path $binDir $file
        if (Test-Path $path) {
            Write-Success "Built: $file"
        } else {
            Write-Warn "Missing: $file"
        }
    }
    
    Write-Success "Build completed!"
    return $true
}

# ============================================================================
# INSTALL: Sign and install driver
# ============================================================================
function Invoke-Install {
    Write-Step "Installing QUAC 100 Driver"
    
    $binDir = Join-Path $RootDir "bin\$Platform\$Configuration"
    $driverDir = Join-Path $binDir "quac100"
    $driverPath = Join-Path $driverDir "quac100.sys"
    $infPath = Join-Path $driverDir "quac100.inf"
    
    # Verify driver exists
    if (-not (Test-Path $driverPath)) {
        Write-Fail "Driver not found: $driverPath"
        Write-Fail "Run build first!"
        return $false
    }
    
    # Sign driver
    Write-Host "   Signing driver..." -ForegroundColor Yellow
    $signScript = Join-Path $RootDir "tools\sign\sign_driver.ps1"
    & $signScript -DriverPath $driverPath -TestSign
    
    if ($LASTEXITCODE -ne 0) {
        Write-Warn "Signing may have issues, but continuing..."
    }
    
    # Uninstall existing driver first
    Write-Host "   Removing existing driver (if any)..." -ForegroundColor Yellow
    $uninstallScript = Join-Path $RootDir "tools\deploy\uninstall_driver.ps1"
    if (Test-Path $uninstallScript) {
        & $uninstallScript -Force -ErrorAction SilentlyContinue
    }
    
    # Install driver
    Write-Host "   Installing driver..." -ForegroundColor Yellow
    $installScript = Join-Path $RootDir "tools\deploy\install_driver.ps1"
    & $installScript -InfPath $infPath -Force
    
    if ($LASTEXITCODE -ne 0) {
        Write-Fail "Driver installation failed!"
        Write-Host "   Run diagnose.ps1 for troubleshooting" -ForegroundColor Yellow
        return $false
    }
    
    # Verify installation
    Start-Sleep -Seconds 2
    $device = Get-PnpDevice -FriendlyName "*QUAC*" -ErrorAction SilentlyContinue
    if ($device -and $device.Status -eq "OK") {
        Write-Success "Driver installed and device is working!"
    } else {
        Write-Warn "Device may need manual configuration or hardware is not present"
    }
    
    return $true
}

# ============================================================================
# TEST: Run test suite
# ============================================================================
function Invoke-Test {
    Write-Step "Running QUAC 100 Tests"
    
    $testScript = Join-Path $ScriptDir "test.ps1"
    & $testScript -Category All -Configuration $Configuration -Platform $Platform
    
    if ($LASTEXITCODE -ne 0) {
        Write-Warn "Some tests failed"
        return $false
    }
    
    Write-Success "All tests passed!"
    return $true
}

# ============================================================================
# UNINSTALL: Remove driver
# ============================================================================
function Invoke-Uninstall {
    Write-Step "Uninstalling QUAC 100 Driver"
    
    $uninstallScript = Join-Path $RootDir "tools\deploy\uninstall_driver.ps1"
    & $uninstallScript -RemovePackage -Force
    
    Write-Success "Driver uninstalled"
    return $true
}

# ============================================================================
# Execute requested action(s)
# ============================================================================
$success = $true

switch ($Action) {
    "Setup" {
        $success = Invoke-Setup
    }
    "Build" {
        $success = Invoke-Build
    }
    "Install" {
        $success = Invoke-Install
    }
    "Test" {
        $success = Invoke-Test
    }
    "Uninstall" {
        $success = Invoke-Uninstall
    }
    "All" {
        # Full workflow
        if (-not (Invoke-Setup)) {
            Write-Host "`nSetup has issues. Fix them before continuing." -ForegroundColor Red
            exit 1
        }
        
        if (-not (Invoke-Build)) {
            Write-Host "`nBuild failed. Cannot continue." -ForegroundColor Red
            exit 1
        }
        
        if (-not (Invoke-Install)) {
            Write-Host "`nInstallation failed." -ForegroundColor Red
            exit 1
        }
        
        if (-not $SkipTests) {
            Invoke-Test  # Don't fail overall if tests fail
        }
        
        Write-Host "`n"
        Write-Host "  ╔═══════════════════════════════════════════════════════╗" -ForegroundColor Green
        Write-Host "  ║              Setup Complete!                          ║" -ForegroundColor Green
        Write-Host "  ╚═══════════════════════════════════════════════════════╝" -ForegroundColor Green
        Write-Host ""
        Write-Host "  Next steps:" -ForegroundColor Cyan
        Write-Host "  - Check Device Manager for QUAC 100 device"
        Write-Host "  - Run: .\tools\deploy\diagnose.ps1 for diagnostics"
        Write-Host "  - Run: .\scripts\test.ps1 -Category Perf for benchmarks"
        Write-Host ""
    }
}

if (-not $success) {
    exit 1
}
