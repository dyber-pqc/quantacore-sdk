<#
.SYNOPSIS
    Build script for QUAC 100 Windows Driver

.PARAMETER Configuration
    Build configuration (Debug/Release)

.PARAMETER Platform
    Target platform (x64/ARM64)

.PARAMETER Clean
    Clean before building
#>

param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Debug",
    
    [ValidateSet("x64", "ARM64")]
    [string]$Platform = "x64",
    
    [switch]$Clean
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Split-Path -Parent $ScriptDir

# Find MSBuild
$msbuild = & "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" `
    -latest -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe | Select-Object -First 1

if (-not $msbuild) {
    Write-Error "MSBuild not found. Ensure Visual Studio 2022 is installed."
    exit 1
}

Write-Host "Using MSBuild: $msbuild" -ForegroundColor Cyan

$solution = Join-Path $RootDir "quac100.sln"

if ($Clean) {
    Write-Host "Cleaning solution..." -ForegroundColor Yellow
    & $msbuild $solution /t:Clean /p:Configuration=$Configuration /p:Platform=$Platform /v:minimal
}

Write-Host "Building $Configuration|$Platform..." -ForegroundColor Green
& $msbuild $solution /t:Build /p:Configuration=$Configuration /p:Platform=$Platform /v:minimal

if ($LASTEXITCODE -eq 0) {
    Write-Host "Build succeeded!" -ForegroundColor Green
} else {
    Write-Error "Build failed with exit code $LASTEXITCODE"
    exit $LASTEXITCODE
}