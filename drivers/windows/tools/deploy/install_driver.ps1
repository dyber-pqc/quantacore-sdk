<#
.SYNOPSIS
    Install QUAC 100 Windows Driver

.PARAMETER InfPath
    Path to the INF file

.PARAMETER Force
    Force installation even if driver exists
#>

param(
    [string]$InfPath,
    [switch]$Force
)

$ErrorActionPreference = "Stop"

# Require admin
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script requires administrator privileges."
    exit 1
}

# Find INF file
if (-not $InfPath) {
    $ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    $RootDir = Split-Path -Parent (Split-Path -Parent $ScriptDir)
    $InfPath = Get-ChildItem -Path $RootDir -Recurse -Filter "quac100.inf" | Select-Object -First 1 -ExpandProperty FullName
}

if (-not (Test-Path $InfPath)) {
    Write-Error "INF file not found: $InfPath"
    exit 1
}

Write-Host "Installing driver from: $InfPath" -ForegroundColor Cyan

# Install using pnputil
$args = @("/add-driver", $InfPath, "/install")
if ($Force) {
    $args += "/force"
}

$result = & pnputil.exe $args

if ($LASTEXITCODE -eq 0) {
    Write-Host "Driver installed successfully!" -ForegroundColor Green
    Write-Host $result
} else {
    Write-Error "Driver installation failed: $result"
    exit $LASTEXITCODE
}