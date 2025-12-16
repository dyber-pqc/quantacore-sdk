<#
.SYNOPSIS
    QUAC 100 Driver Verifier Control

.DESCRIPTION
    Configures Windows Driver Verifier for the QUAC 100 driver.
    Helps detect driver bugs, memory leaks, and other issues.

.PARAMETER Action
    Action to perform: Enable, Disable, Status, Standard, Full

.PARAMETER NoReboot
    Don't prompt for reboot

.EXAMPLE
    .\verifier.ps1 -Action Enable
    Enable standard verification

.EXAMPLE
    .\verifier.ps1 -Action Full
    Enable all verification options (may cause performance impact)

.EXAMPLE
    .\verifier.ps1 -Action Disable
    Disable driver verifier
#>

param(
    [ValidateSet("Enable", "Disable", "Status", "Standard", "Full", "Query")]
    [string]$Action = "Status",
    
    [switch]$NoReboot
)

$ErrorActionPreference = "Stop"

# Require admin
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script requires administrator privileges."
    exit 1
}

$DriverName = "quac100.sys"

Write-Host "QUAC 100 Driver Verifier" -ForegroundColor Cyan
Write-Host "========================" -ForegroundColor Cyan
Write-Host ""

function Show-VerifierStatus {
    Write-Host "Current Driver Verifier Status:" -ForegroundColor Yellow
    Write-Host ""
    
    $output = & verifier /query 2>&1 | Out-String
    
    if ($output -match "No drivers are currently verified") {
        Write-Host "Driver Verifier is not active for any drivers." -ForegroundColor Gray
        return $false
    }
    
    if ($output -match $DriverName) {
        Write-Host "Driver Verifier is ACTIVE for $DriverName" -ForegroundColor Green
        Write-Host ""
        
        # Show flags
        $flagOutput = & verifier /querysettings 2>&1 | Out-String
        Write-Host "Active verification options:"
        $flagOutput -split "`n" | ForEach-Object {
            if ($_ -match "^\s*\w") {
                Write-Host "  $_"
            }
        }
        return $true
    } else {
        Write-Host "Driver Verifier is not active for $DriverName" -ForegroundColor Gray
        
        # Show what is being verified
        if (-not ($output -match "No drivers")) {
            Write-Host ""
            Write-Host "Currently verified drivers:"
            Write-Host $output
        }
        return $false
    }
}

function Request-Reboot {
    if (-not $NoReboot) {
        Write-Host ""
        $response = Read-Host "Reboot now to apply changes? [y/N]"
        if ($response -eq 'y' -or $response -eq 'Y') {
            Write-Host "Rebooting..." -ForegroundColor Yellow
            Restart-Computer -Force
        } else {
            Write-Host "Please reboot manually for changes to take effect." -ForegroundColor Yellow
        }
    } else {
        Write-Host ""
        Write-Host "REBOOT REQUIRED for changes to take effect." -ForegroundColor Yellow
    }
}

switch ($Action) {
    "Status" {
        Show-VerifierStatus
    }
    
    "Query" {
        # Show runtime statistics
        Write-Host "Runtime Verification Statistics:" -ForegroundColor Yellow
        Write-Host ""
        & verifier /query
    }
    
    "Enable" {
        Write-Host "Enabling Standard Driver Verifier for $DriverName..." -ForegroundColor Yellow
        
        # Standard flags: special pool, force IRQL checking, pool tracking, I/O verification
        $result = & verifier /standard /driver $DriverName 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host ""
            Write-Host "Driver Verifier enabled!" -ForegroundColor Green
            Write-Host ""
            Write-Host "Enabled checks:"
            Write-Host "  - Special Pool"
            Write-Host "  - Force IRQL Checking"
            Write-Host "  - Pool Tracking"
            Write-Host "  - I/O Verification"
            Write-Host "  - Deadlock Detection"
            Write-Host "  - DMA Checking"
            Write-Host "  - Security Checks"
            
            Request-Reboot
        } else {
            Write-Error "Failed to enable verifier: $result"
        }
    }
    
    "Standard" {
        # Same as Enable
        Write-Host "Enabling Standard Driver Verifier for $DriverName..." -ForegroundColor Yellow
        
        $result = & verifier /standard /driver $DriverName 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Driver Verifier enabled (standard)!" -ForegroundColor Green
            Request-Reboot
        } else {
            Write-Error "Failed to enable verifier: $result"
        }
    }
    
    "Full" {
        Write-Host "Enabling FULL Driver Verifier for $DriverName..." -ForegroundColor Yellow
        Write-Host ""
        Write-Warning "Full verification will significantly impact performance!"
        Write-Host ""
        
        # All flags
        $flags = @(
            "/flags", "0xBB",  # Standard + additional checks
            "/driver", $DriverName
        )
        
        # Add all options
        $result = & verifier /flags 0xFFFFFFFF /driver $DriverName 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host ""
            Write-Host "Full Driver Verifier enabled!" -ForegroundColor Green
            Write-Host ""
            Write-Host "Enabled ALL verification checks including:"
            Write-Host "  - All standard checks"
            Write-Host "  - Randomized low resources simulation"
            Write-Host "  - Systematic low resources simulation"
            Write-Host "  - DDI compliance checking"
            Write-Host "  - Power framework delay fuzzing"
            Write-Host "  - WDF verification"
            
            Request-Reboot
        } else {
            Write-Error "Failed to enable full verifier: $result"
        }
    }
    
    "Disable" {
        Write-Host "Disabling Driver Verifier..." -ForegroundColor Yellow
        
        # Check if it's currently enabled
        if (-not (Show-VerifierStatus)) {
            Write-Host ""
            Write-Host "Driver Verifier is already disabled." -ForegroundColor Gray
            exit 0
        }
        
        Write-Host ""
        $result = & verifier /reset 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Driver Verifier disabled!" -ForegroundColor Green
            Request-Reboot
        } else {
            Write-Error "Failed to disable verifier: $result"
        }
    }
}

Write-Host ""
Write-Host "Tips:" -ForegroundColor Cyan
Write-Host "  - Use 'Standard' for normal development testing"
Write-Host "  - Use 'Full' only for thorough pre-release testing"
Write-Host "  - Check Event Viewer > Windows Logs > System for verifier crashes"
Write-Host "  - Memory dumps in C:\Windows\Minidump contain crash details"
