<#
.SYNOPSIS
    Prepare QUAC 100 Driver for Release

.DESCRIPTION
    Comprehensive release preparation script that:
    - Builds release configurations for all platforms
    - Signs drivers with production certificate
    - Creates driver packages
    - Generates release notes
    - Runs validation tests

.PARAMETER Version
    Version number for the release (e.g., "1.0.0")

.PARAMETER CertFile
    Path to production code signing certificate (PFX)

.PARAMETER CertPassword
    Password for the certificate

.PARAMETER SkipTests
    Skip validation tests

.PARAMETER OutputDir
    Output directory for release packages

.EXAMPLE
    .\prepare_release.ps1 -Version "1.0.0" -CertFile .\cert.pfx
    Build release with production signing

.EXAMPLE
    .\prepare_release.ps1 -Version "1.0.0-beta1"
    Build beta release with test signing
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$Version,
    
    [string]$CertFile,
    [string]$CertPassword,
    
    [switch]$SkipTests,
    
    [string]$OutputDir
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Split-Path -Parent $ScriptDir

# Determine signing mode
$TestSign = [string]::IsNullOrEmpty($CertFile)

Write-Host ""
Write-Host "  ╔═══════════════════════════════════════════════════════╗" -ForegroundColor Magenta
Write-Host "  ║         QUAC 100 Release Preparation                  ║" -ForegroundColor Magenta
Write-Host "  ║              Version: $($Version.PadRight(24))        ║" -ForegroundColor Magenta
Write-Host "  ╚═══════════════════════════════════════════════════════╝" -ForegroundColor Magenta
Write-Host ""

if (-not $OutputDir) {
    $OutputDir = Join-Path $RootDir "release\v$Version"
}

Write-Host "Configuration:" -ForegroundColor Yellow
Write-Host "  Version: $Version"
Write-Host "  Signing: $(if ($TestSign) { 'Test (development)' } else { 'Production' })"
Write-Host "  Output: $OutputDir"
Write-Host ""

# Create output directory
if (Test-Path $OutputDir) {
    $response = Read-Host "Output directory exists. Overwrite? [y/N]"
    if ($response -ne 'y' -and $response -ne 'Y') {
        Write-Host "Cancelled." -ForegroundColor Gray
        exit 0
    }
    Remove-Item $OutputDir -Recurse -Force
}
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

$logFile = Join-Path $OutputDir "build.log"
$startTime = Get-Date

# Step tracking
$steps = @()
function Add-Step($name, $status, $duration = 0) {
    $steps += [PSCustomObject]@{
        Name = $name
        Status = $status
        Duration = $duration
    }
}

try {
    # =========================================================================
    # Step 1: Update version
    # =========================================================================
    Write-Host "Step 1: Updating version information..." -ForegroundColor Cyan
    
    $versionFile = Join-Path $RootDir "src\common\version.h"
    if (Test-Path $versionFile) {
        $content = Get-Content $versionFile -Raw
        
        # Parse version
        $versionParts = $Version -split '[\.-]'
        $major = if ($versionParts.Count -ge 1) { $versionParts[0] } else { "1" }
        $minor = if ($versionParts.Count -ge 2) { $versionParts[1] } else { "0" }
        $patch = if ($versionParts.Count -ge 3) { $versionParts[2] } else { "0" }
        $build = if ($versionParts.Count -ge 4) { $versionParts[3] } else { "0" }
        
        # Update version.h
        $content = $content -replace '#define QUAC100_VERSION_MAJOR\s+\d+', "#define QUAC100_VERSION_MAJOR $major"
        $content = $content -replace '#define QUAC100_VERSION_MINOR\s+\d+', "#define QUAC100_VERSION_MINOR $minor"
        $content = $content -replace '#define QUAC100_VERSION_PATCH\s+\d+', "#define QUAC100_VERSION_PATCH $patch"
        $content = $content -replace '#define QUAC100_VERSION_BUILD\s+\d+', "#define QUAC100_VERSION_BUILD $build"
        $content = $content -replace '#define QUAC100_VERSION_STRING\s+"[^"]+"', "#define QUAC100_VERSION_STRING `"$Version`""
        
        $content | Out-File $versionFile -Encoding UTF8 -NoNewline
        
        Write-Host "  Version updated to: $Version" -ForegroundColor Green
    }
    Add-Step "Version Update" "Success"
    
    # =========================================================================
    # Step 2: Clean build
    # =========================================================================
    Write-Host ""
    Write-Host "Step 2: Cleaning previous builds..." -ForegroundColor Cyan
    
    $cleanScript = Join-Path $ScriptDir "clean.ps1"
    & $cleanScript -Build -Force
    Add-Step "Clean" "Success"
    
    # =========================================================================
    # Step 3: Build all configurations
    # =========================================================================
    Write-Host ""
    Write-Host "Step 3: Building release configurations..." -ForegroundColor Cyan
    
    $buildScript = Join-Path $ScriptDir "build.ps1"
    $platforms = @("x64", "ARM64")
    $buildResults = @{}
    
    foreach ($platform in $platforms) {
        Write-Host "  Building $platform Release..." -ForegroundColor Yellow
        $buildStart = Get-Date
        
        & $buildScript -Configuration Release -Platform $platform 2>&1 | Tee-Object -Append $logFile
        
        if ($LASTEXITCODE -eq 0) {
            $buildResults[$platform] = "Success"
            Write-Host "    $platform build succeeded" -ForegroundColor Green
        } else {
            $buildResults[$platform] = "Failed"
            Write-Host "    $platform build FAILED" -ForegroundColor Red
            Add-Step "Build ($platform)" "Failed"
            throw "Build failed for $platform"
        }
        
        Add-Step "Build ($platform)" "Success" ((Get-Date) - $buildStart).TotalSeconds
    }
    
    # =========================================================================
    # Step 4: Run tests
    # =========================================================================
    if (-not $SkipTests) {
        Write-Host ""
        Write-Host "Step 4: Running validation tests..." -ForegroundColor Cyan
        
        $testScript = Join-Path $ScriptDir "test.ps1"
        & $testScript -Category All -Configuration Release -Platform x64 2>&1 | Tee-Object -Append $logFile
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "  All tests passed" -ForegroundColor Green
            Add-Step "Tests" "Success"
        } else {
            Write-Warning "  Some tests failed - check logs"
            Add-Step "Tests" "Warning"
        }
    } else {
        Write-Host ""
        Write-Host "Step 4: Skipping tests (--SkipTests)" -ForegroundColor Yellow
        Add-Step "Tests" "Skipped"
    }
    
    # =========================================================================
    # Step 5: Sign drivers
    # =========================================================================
    Write-Host ""
    Write-Host "Step 5: Signing drivers..." -ForegroundColor Cyan
    
    $signScript = Join-Path $RootDir "tools\sign\sign_driver.ps1"
    
    foreach ($platform in $platforms) {
        $driverPath = Join-Path $RootDir "bin\$platform\Release\quac100\quac100.sys"
        
        if (Test-Path $driverPath) {
            Write-Host "  Signing $platform driver..." -ForegroundColor Yellow
            
            if ($TestSign) {
                & $signScript -DriverPath $driverPath -TestSign 2>&1 | Tee-Object -Append $logFile
            } else {
                $signArgs = @{
                    DriverPath = $driverPath
                    CertFile = $CertFile
                }
                if ($CertPassword) {
                    $signArgs.CertPassword = $CertPassword
                }
                & $signScript @signArgs 2>&1 | Tee-Object -Append $logFile
            }
            
            if ($LASTEXITCODE -eq 0) {
                Write-Host "    $platform signed successfully" -ForegroundColor Green
            } else {
                Write-Warning "    $platform signing may have issues"
            }
        }
    }
    Add-Step "Signing" "Success"
    
    # =========================================================================
    # Step 6: Create packages
    # =========================================================================
    Write-Host ""
    Write-Host "Step 6: Creating release packages..." -ForegroundColor Cyan
    
    $packageScript = Join-Path $RootDir "tools\package\create_package.ps1"
    
    foreach ($platform in $platforms) {
        Write-Host "  Creating $platform package..." -ForegroundColor Yellow
        
        $pkgOutput = Join-Path $OutputDir $platform
        & $packageScript -Configuration Release -Platform $platform -OutputDir $pkgOutput 2>&1 | Tee-Object -Append $logFile
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "    $platform package created" -ForegroundColor Green
        } else {
            Write-Warning "    $platform package creation failed"
        }
    }
    Add-Step "Packages" "Success"
    
    # =========================================================================
    # Step 7: Generate release notes
    # =========================================================================
    Write-Host ""
    Write-Host "Step 7: Generating release notes..." -ForegroundColor Cyan
    
    $releaseNotes = @"
QUAC 100 Windows Driver - Version $Version
==========================================
Release Date: $(Get-Date -Format "yyyy-MM-dd")
Signing Mode: $(if ($TestSign) { "Test (Development)" } else { "Production" })

Package Contents
----------------
- Kernel-mode driver (quac100.sys)
- SR-IOV Virtual Function driver (quac100vf.sys)
- User-mode library (quac100.dll)
- Public headers
- Installation scripts
- Documentation

Supported Platforms
------------------
- Windows 10 (1903 and later)
- Windows 11
- Windows Server 2019/2022

Architectures
------------
$(foreach ($platform in $platforms) { "- $platform`n" })

Cryptographic Algorithms
------------------------
- ML-KEM (Kyber) - 512, 768, 1024
- ML-DSA (Dilithium) - 2, 3, 5
- SLH-DSA (SPHINCS+) - All variants
- Quantum Random Number Generation (QRNG)

Installation
------------
1. Enable test signing (if using test-signed driver):
   .\tools\enable_testsigning.ps1
   [Reboot required]

2. Install driver:
   .\tools\install_driver.ps1

3. Verify in Device Manager

Build Information
-----------------
Build Host: $env:COMPUTERNAME
Build Date: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Build Duration: $([math]::Round(((Get-Date) - $startTime).TotalMinutes, 2)) minutes

$(foreach ($step in $steps) { "$($step.Name): $($step.Status)`n" })

For more information, visit: https://github.com/dyber-pqc/quantacore-sdk
"@
    
    $releaseNotes | Out-File (Join-Path $OutputDir "RELEASE_NOTES.txt") -Encoding UTF8
    Write-Host "  Release notes generated" -ForegroundColor Green
    Add-Step "Release Notes" "Success"
    
    # =========================================================================
    # Step 8: Create final archive
    # =========================================================================
    Write-Host ""
    Write-Host "Step 8: Creating release archive..." -ForegroundColor Cyan
    
    $archiveName = "quac100-driver-v$Version-windows.zip"
    $archivePath = Join-Path (Split-Path -Parent $OutputDir) $archiveName
    
    if (Test-Path $archivePath) {
        Remove-Item $archivePath -Force
    }
    
    Compress-Archive -Path "$OutputDir\*" -DestinationPath $archivePath -Force
    
    $archiveSize = [math]::Round((Get-Item $archivePath).Length / 1MB, 2)
    Write-Host "  Archive created: $archiveName ($archiveSize MB)" -ForegroundColor Green
    Add-Step "Archive" "Success"
    
} catch {
    Write-Host ""
    Write-Host "Release preparation FAILED!" -ForegroundColor Red
    Write-Host "Error: $_" -ForegroundColor Red
    Write-Host ""
    Write-Host "Check log file: $logFile"
    exit 1
}

# Summary
$duration = (Get-Date) - $startTime

Write-Host ""
Write-Host "=" * 60 -ForegroundColor Cyan
Write-Host "Release Preparation Complete!" -ForegroundColor Green
Write-Host "=" * 60 -ForegroundColor Cyan
Write-Host ""
Write-Host "Version: $Version"
Write-Host "Duration: $([math]::Round($duration.TotalMinutes, 2)) minutes"
Write-Host ""
Write-Host "Output:"
Write-Host "  Directory: $OutputDir"
Write-Host "  Archive: $archivePath"
Write-Host "  Build Log: $logFile"
Write-Host ""
Write-Host "Steps:"
foreach ($step in $steps) {
    $color = switch ($step.Status) {
        "Success" { "Green" }
        "Warning" { "Yellow" }
        "Skipped" { "Gray" }
        default { "Red" }
    }
    Write-Host "  [$(if ($step.Status -eq 'Success') { 'OK' } elseif ($step.Status -eq 'Warning') { '!!' } elseif ($step.Status -eq 'Skipped') { '--' } else { 'XX' })] $($step.Name)" -ForegroundColor $color
}
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
if ($TestSign) {
    Write-Host "  1. Obtain production code signing certificate (EV)"
    Write-Host "  2. Re-run with: .\prepare_release.ps1 -Version $Version -CertFile <cert.pfx>"
} else {
    Write-Host "  1. Submit to Windows Hardware Compatibility Program (HLK)"
    Write-Host "  2. Upload to GitHub Releases"
    Write-Host "  3. Update documentation"
}
