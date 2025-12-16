<#
.SYNOPSIS
    QUAC 100 Hardware Simulator Control

.DESCRIPTION
    Controls the QUAC 100 software simulator for development and testing
    without physical hardware.

.PARAMETER Action
    Action to perform: Start, Stop, Status, Install, Uninstall

.PARAMETER Config
    Simulator configuration: Default, Fast, Accurate, Debug

.PARAMETER LogLevel
    Logging level: None, Error, Warning, Info, Debug, Trace

.EXAMPLE
    .\simulator.ps1 -Action Start
    Start simulator with default settings

.EXAMPLE
    .\simulator.ps1 -Action Start -Config Debug -LogLevel Trace
    Start with debug config and full tracing

.EXAMPLE
    .\simulator.ps1 -Action Stop
    Stop the simulator
#>

param(
    [ValidateSet("Start", "Stop", "Status", "Install", "Uninstall", "Restart")]
    [string]$Action = "Status",
    
    [ValidateSet("Default", "Fast", "Accurate", "Debug")]
    [string]$Config = "Default",
    
    [ValidateSet("None", "Error", "Warning", "Info", "Debug", "Trace")]
    [string]$LogLevel = "Info"
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Split-Path -Parent $ScriptDir

$SimulatorName = "Quac100Simulator"
$SimulatorExe = Join-Path $RootDir "tools\simulator\quac100sim.exe"
$SimulatorDir = Join-Path $RootDir "tools\simulator"
$LogDir = Join-Path $env:TEMP "Quac100Simulator"

Write-Host "QUAC 100 Hardware Simulator" -ForegroundColor Cyan
Write-Host "===========================" -ForegroundColor Cyan
Write-Host ""

# Check if simulator exists
function Test-SimulatorInstalled {
    if (Test-Path $SimulatorExe) {
        return $true
    }
    
    # Check for built simulator
    $builtPaths = @(
        (Join-Path $RootDir "bin\x64\Release\quac100sim.exe"),
        (Join-Path $RootDir "bin\x64\Debug\quac100sim.exe")
    )
    
    foreach ($path in $builtPaths) {
        if (Test-Path $path) {
            return $true
        }
    }
    
    return $false
}

function Get-SimulatorProcess {
    Get-Process -Name "quac100sim" -ErrorAction SilentlyContinue
}

function Show-Status {
    $proc = Get-SimulatorProcess
    
    if ($proc) {
        Write-Host "Simulator Status: RUNNING" -ForegroundColor Green
        Write-Host ""
        Write-Host "Process Details:"
        Write-Host "  PID: $($proc.Id)"
        Write-Host "  CPU Time: $($proc.CPU)"
        Write-Host "  Memory: $([math]::Round($proc.WorkingSet64 / 1MB, 2)) MB"
        Write-Host "  Start Time: $($proc.StartTime)"
        Write-Host ""
        
        # Check log file
        $logFile = Join-Path $LogDir "simulator.log"
        if (Test-Path $logFile) {
            $logInfo = Get-Item $logFile
            Write-Host "Log file: $logFile"
            Write-Host "  Size: $([math]::Round($logInfo.Length / 1KB, 2)) KB"
            Write-Host ""
            Write-Host "Recent log entries:"
            Get-Content $logFile -Tail 10 | ForEach-Object {
                Write-Host "  $_" -ForegroundColor Gray
            }
        }
        
        return $true
    } else {
        Write-Host "Simulator Status: NOT RUNNING" -ForegroundColor Gray
        
        if (-not (Test-SimulatorInstalled)) {
            Write-Host ""
            Write-Host "Simulator executable not found." -ForegroundColor Yellow
            Write-Host "Build the solution or run: .\simulator.ps1 -Action Install"
        }
        
        return $false
    }
}

switch ($Action) {
    "Status" {
        Show-Status | Out-Null
    }
    
    "Start" {
        Write-Host "Starting QUAC 100 Simulator..." -ForegroundColor Yellow
        
        # Check if already running
        if (Get-SimulatorProcess) {
            Write-Host "Simulator is already running." -ForegroundColor Yellow
            Show-Status | Out-Null
            exit 0
        }
        
        # Find simulator
        $simPath = $null
        $searchPaths = @(
            $SimulatorExe,
            (Join-Path $RootDir "bin\x64\Release\quac100sim.exe"),
            (Join-Path $RootDir "bin\x64\Debug\quac100sim.exe")
        )
        
        foreach ($path in $searchPaths) {
            if (Test-Path $path) {
                $simPath = $path
                break
            }
        }
        
        if (-not $simPath) {
            Write-Error "Simulator executable not found. Build the solution first."
            exit 1
        }
        
        # Create log directory
        if (-not (Test-Path $LogDir)) {
            New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
        }
        
        # Build arguments based on config
        $simArgs = @("--log-level", $LogLevel.ToLower())
        
        switch ($Config) {
            "Fast" {
                $simArgs += @("--mode", "fast", "--skip-delays")
            }
            "Accurate" {
                $simArgs += @("--mode", "accurate", "--timing-model", "realistic")
            }
            "Debug" {
                $simArgs += @("--mode", "debug", "--verbose", "--break-on-error")
            }
            default {
                $simArgs += @("--mode", "default")
            }
        }
        
        $simArgs += @("--log-file", (Join-Path $LogDir "simulator.log"))
        
        Write-Host "  Executable: $simPath"
        Write-Host "  Config: $Config"
        Write-Host "  Log Level: $LogLevel"
        Write-Host ""
        
        # Start simulator
        try {
            $proc = Start-Process -FilePath $simPath -ArgumentList $simArgs `
                -WindowStyle Hidden -PassThru
            
            Start-Sleep -Seconds 2
            
            if ($proc.HasExited) {
                Write-Error "Simulator exited unexpectedly. Check logs."
                exit 1
            }
            
            Write-Host "Simulator started!" -ForegroundColor Green
            Write-Host "  PID: $($proc.Id)"
            Write-Host "  Log: $(Join-Path $LogDir 'simulator.log')"
            
        } catch {
            Write-Error "Failed to start simulator: $_"
            exit 1
        }
    }
    
    "Stop" {
        Write-Host "Stopping QUAC 100 Simulator..." -ForegroundColor Yellow
        
        $proc = Get-SimulatorProcess
        if (-not $proc) {
            Write-Host "Simulator is not running." -ForegroundColor Gray
            exit 0
        }
        
        try {
            $proc | Stop-Process -Force
            Start-Sleep -Seconds 1
            
            if (Get-SimulatorProcess) {
                Write-Warning "Simulator did not stop cleanly"
            } else {
                Write-Host "Simulator stopped." -ForegroundColor Green
            }
        } catch {
            Write-Error "Failed to stop simulator: $_"
            exit 1
        }
    }
    
    "Restart" {
        Write-Host "Restarting QUAC 100 Simulator..." -ForegroundColor Yellow
        
        $proc = Get-SimulatorProcess
        if ($proc) {
            $proc | Stop-Process -Force
            Start-Sleep -Seconds 2
        }
        
        # Recurse with Start
        & $MyInvocation.MyCommand.Path -Action Start -Config $Config -LogLevel $LogLevel
    }
    
    "Install" {
        Write-Host "Installing QUAC 100 Simulator..." -ForegroundColor Yellow
        
        # Create simulator directory
        if (-not (Test-Path $SimulatorDir)) {
            New-Item -ItemType Directory -Path $SimulatorDir -Force | Out-Null
        }
        
        # Look for simulator in build output
        $sourcePaths = @(
            (Join-Path $RootDir "bin\x64\Release\quac100sim.exe"),
            (Join-Path $RootDir "bin\x64\Debug\quac100sim.exe")
        )
        
        $source = $null
        foreach ($path in $sourcePaths) {
            if (Test-Path $path) {
                $source = $path
                break
            }
        }
        
        if ($source) {
            Copy-Item $source $SimulatorExe -Force
            Write-Host "Simulator installed to: $SimulatorExe" -ForegroundColor Green
        } else {
            Write-Warning "Simulator not found in build output."
            Write-Host "Build the solution first, or the simulator will be created when building."
            
            # Create placeholder
            $placeholder = @"
@echo off
echo QUAC 100 Simulator Placeholder
echo Build the solution to get the actual simulator.
pause
"@
            $placeholder | Out-File (Join-Path $SimulatorDir "quac100sim.bat") -Encoding ASCII
        }
    }
    
    "Uninstall" {
        Write-Host "Uninstalling QUAC 100 Simulator..." -ForegroundColor Yellow
        
        # Stop if running
        $proc = Get-SimulatorProcess
        if ($proc) {
            $proc | Stop-Process -Force
            Start-Sleep -Seconds 1
        }
        
        # Remove files
        if (Test-Path $SimulatorDir) {
            Remove-Item $SimulatorDir -Recurse -Force
            Write-Host "Simulator directory removed." -ForegroundColor Green
        }
        
        # Remove logs
        if (Test-Path $LogDir) {
            Remove-Item $LogDir -Recurse -Force
            Write-Host "Log directory removed." -ForegroundColor Green
        }
        
        Write-Host "Simulator uninstalled." -ForegroundColor Green
    }
}

Write-Host ""
Write-Host "Tips:" -ForegroundColor Cyan
Write-Host "  - Use 'Fast' config for quick functional testing"
Write-Host "  - Use 'Accurate' config to simulate real hardware timing"
Write-Host "  - Use 'Debug' config for troubleshooting issues"
Write-Host "  - Logs are stored in: $LogDir"
