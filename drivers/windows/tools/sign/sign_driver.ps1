<#
.SYNOPSIS
    Sign QUAC 100 Windows Driver

.DESCRIPTION
    Signs the driver package using a certificate. For development, uses
    a test certificate. For production, uses an EV certificate.

.PARAMETER DriverPath
    Path to the driver (.sys) file

.PARAMETER CertFile
    Path to PFX certificate file (optional for test signing)

.PARAMETER CertPassword
    Password for PFX certificate (optional)

.PARAMETER Timestamp
    Timestamp server URL (default: http://timestamp.digicert.com)

.PARAMETER TestSign
    Use test signing mode (creates self-signed certificate if needed)

.EXAMPLE
    .\sign_driver.ps1 -DriverPath .\quac100.sys -TestSign
    Sign with test certificate

.EXAMPLE
    .\sign_driver.ps1 -DriverPath .\quac100.sys -CertFile .\cert.pfx -CertPassword "password"
    Sign with production certificate
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$DriverPath,
    
    [string]$CertFile,
    [string]$CertPassword,
    [string]$Timestamp = "http://timestamp.digicert.com",
    [switch]$TestSign
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Check for admin privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script requires administrator privileges."
    exit 1
}

# Verify driver exists
if (-not (Test-Path $DriverPath)) {
    Write-Error "Driver file not found: $DriverPath"
    exit 1
}

# Find signtool
$signtool = $null
$wdkPaths = @(
    "${env:ProgramFiles(x86)}\Windows Kits\10\bin\10.0.22621.0\x64\signtool.exe",
    "${env:ProgramFiles(x86)}\Windows Kits\10\bin\10.0.22000.0\x64\signtool.exe",
    "${env:ProgramFiles(x86)}\Windows Kits\10\bin\10.0.19041.0\x64\signtool.exe"
)

foreach ($path in $wdkPaths) {
    if (Test-Path $path) {
        $signtool = $path
        break
    }
}

if (-not $signtool) {
    # Try to find via vswhere
    $signtool = & "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" `
        -latest -find "**\signtool.exe" | Select-Object -First 1
}

if (-not $signtool) {
    Write-Error "SignTool not found. Please install Windows Driver Kit (WDK)."
    exit 1
}

Write-Host "Using SignTool: $signtool" -ForegroundColor Cyan

if ($TestSign) {
    Write-Host "Test signing mode enabled" -ForegroundColor Yellow
    
    $certStore = "Cert:\CurrentUser\My"
    $certSubject = "CN=QUAC100 Test Certificate"
    
    # Check for existing test certificate
    $cert = Get-ChildItem $certStore | Where-Object { $_.Subject -eq $certSubject } | Select-Object -First 1
    
    if (-not $cert) {
        Write-Host "Creating test certificate..." -ForegroundColor Yellow
        
        # Create self-signed certificate
        $cert = New-SelfSignedCertificate `
            -Type CodeSigningCert `
            -Subject $certSubject `
            -CertStoreLocation $certStore `
            -NotAfter (Get-Date).AddYears(5)
        
        Write-Host "Created certificate: $($cert.Thumbprint)" -ForegroundColor Green
        
        # Export to trusted root for test signing
        $rootStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
        $rootStore.Open("ReadWrite")
        $rootStore.Add($cert)
        $rootStore.Close()
        
        Write-Host "Added certificate to trusted root store" -ForegroundColor Green
    } else {
        Write-Host "Using existing test certificate: $($cert.Thumbprint)" -ForegroundColor Green
    }
    
    # Sign with test certificate
    Write-Host "Signing driver..." -ForegroundColor Cyan
    
    & $signtool sign /v /s My /n "QUAC100 Test Certificate" /t $Timestamp /fd SHA256 $DriverPath
    
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Signing failed with exit code $LASTEXITCODE"
        exit $LASTEXITCODE
    }
    
} else {
    # Production signing
    if (-not $CertFile) {
        Write-Error "Certificate file required for production signing. Use -TestSign for test signing."
        exit 1
    }
    
    if (-not (Test-Path $CertFile)) {
        Write-Error "Certificate file not found: $CertFile"
        exit 1
    }
    
    Write-Host "Production signing with certificate: $CertFile" -ForegroundColor Cyan
    
    $signArgs = @("sign", "/v", "/f", $CertFile, "/fd", "SHA256", "/t", $Timestamp)
    
    if ($CertPassword) {
        $signArgs += @("/p", $CertPassword)
    }
    
    $signArgs += $DriverPath
    
    & $signtool $signArgs
    
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Signing failed with exit code $LASTEXITCODE"
        exit $LASTEXITCODE
    }
}

# Verify signature
Write-Host "Verifying signature..." -ForegroundColor Cyan
& $signtool verify /v /pa $DriverPath

if ($LASTEXITCODE -eq 0) {
    Write-Host "Driver signed successfully!" -ForegroundColor Green
} else {
    Write-Warning "Signature verification failed, but driver may still be usable in test mode"
}

# Get driver path directory for catalog
$driverDir = Split-Path -Parent $DriverPath
$driverName = [System.IO.Path]::GetFileNameWithoutExtension($DriverPath)
$catPath = Join-Path $driverDir "$driverName.cat"
$infPath = Join-Path $driverDir "$driverName.inf"

# Sign catalog if it exists
if (Test-Path $catPath) {
    Write-Host "Signing catalog file..." -ForegroundColor Cyan
    
    if ($TestSign) {
        & $signtool sign /v /s My /n "QUAC100 Test Certificate" /t $Timestamp /fd SHA256 $catPath
    } else {
        $signArgs = @("sign", "/v", "/f", $CertFile, "/fd", "SHA256", "/t", $Timestamp)
        if ($CertPassword) { $signArgs += @("/p", $CertPassword) }
        $signArgs += $catPath
        & $signtool $signArgs
    }
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Catalog signed successfully!" -ForegroundColor Green
    }
}

Write-Host "`nSigning complete!" -ForegroundColor Green
Write-Host "Driver: $DriverPath"
if (Test-Path $catPath) {
    Write-Host "Catalog: $catPath"
}
