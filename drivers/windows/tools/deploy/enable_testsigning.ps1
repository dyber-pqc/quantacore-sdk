<#
.SYNOPSIS
    Enable test signing mode for driver development

.DESCRIPTION
    Enables Windows test signing mode, which allows loading of test-signed drivers.
    Requires a reboot to take effect.

.PARAMETER Disable
    Disable test signing mode instead of enabling
#>

param(
    [switch]$Disable
)

$ErrorActionPreference = "Stop"

# Require admin
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script requires administrator privileges."
    exit 1
}

if ($Disable) {
    Write-Host "Disabling test signing mode..." -ForegroundColor Yellow
    bcdedit /set testsigning off
} else {
    Write-Host "Enabling test signing mode..." -ForegroundColor Yellow
    bcdedit /set testsigning on
}

if ($LASTEXITCODE -eq 0) {
    Write-Host "Success! Please reboot for changes to take effect." -ForegroundColor Green
} else {
    Write-Error "Failed to modify boot configuration."
    exit $LASTEXITCODE
}