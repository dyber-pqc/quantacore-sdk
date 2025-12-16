<#
.SYNOPSIS
    QUAC 100 WPP Tracing Control

.DESCRIPTION
    Controls Windows Software Trace Preprocessor (WPP) logging for the
    QUAC 100 driver. Enables collection of debug trace messages.

.PARAMETER Action
    Action to perform: Start, Stop, View, Save

.PARAMETER Level
    Trace level: Error, Warning, Info, Verbose, All

.PARAMETER OutputFile
    File to save trace logs (for Save action)

.PARAMETER Duration
    Duration in seconds for auto-stop (0 = manual stop)

.EXAMPLE
    .\trace.ps1 -Action Start -Level Verbose
    Start verbose tracing

.EXAMPLE
    .\trace.ps1 -Action Stop
    Stop tracing

.EXAMPLE
    .\trace.ps1 -Action View
    View current trace in real-time

.EXAMPLE
    .\trace.ps1 -Action Save -OutputFile C:\Temp\quac_trace.etl
    Save trace to file
#>

param(
    [ValidateSet("Start", "Stop", "View", "Save", "Status")]
    [string]$Action = "Status",
    
    [ValidateSet("Error", "Warning", "Info", "Verbose", "All")]
    [string]$Level = "Info",
    
    [string]$OutputFile,
    
    [int]$Duration = 0
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Split-Path -Parent (Split-Path -Parent $ScriptDir)

# Require admin
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script requires administrator privileges."
    exit 1
}

# QUAC 100 trace GUID (matches trace.h)
$TraceGuid = "{F4E12345-ABCD-4567-89AB-CDEF01234567}"
$SessionName = "Quac100Trace"
$DefaultEtlFile = Join-Path $env:TEMP "quac100_trace.etl"

Write-Host "QUAC 100 WPP Tracing" -ForegroundColor Cyan
Write-Host "====================" -ForegroundColor Cyan
Write-Host ""

# Map level to flags
$levelFlags = @{
    "Error"   = 0x1
    "Warning" = 0x3
    "Info"    = 0x7
    "Verbose" = 0xF
    "All"     = 0xFF
}

function Get-TraceStatus {
    $sessions = & logman query -ets 2>&1 | Out-String
    return $sessions -match $SessionName
}

switch ($Action) {
    "Start" {
        Write-Host "Starting WPP trace session..." -ForegroundColor Yellow
        Write-Host "  Session: $SessionName"
        Write-Host "  Provider: $TraceGuid"
        Write-Host "  Level: $Level (flags: 0x$($levelFlags[$Level].ToString('X')))"
        
        # Check if already running
        if (Get-TraceStatus) {
            Write-Warning "Trace session already running. Stopping first..."
            & logman stop $SessionName -ets 2>$null
            Start-Sleep -Seconds 1
        }
        
        # Create trace session
        $etlPath = $DefaultEtlFile
        $flags = "0x$($levelFlags[$Level].ToString('X'))"
        
        $result = & logman create trace $SessionName `
            -ets `
            -p $TraceGuid $flags 0xFF `
            -o $etlPath `
            -mode circular `
            -bs 64 `
            -nb 16 64 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host ""
            Write-Host "Trace session started!" -ForegroundColor Green
            Write-Host "  Output: $etlPath"
            
            if ($Duration -gt 0) {
                Write-Host "  Auto-stop in $Duration seconds..." -ForegroundColor Yellow
                Start-Sleep -Seconds $Duration
                & logman stop $SessionName -ets
                Write-Host "Trace session stopped." -ForegroundColor Green
            } else {
                Write-Host "  Run '$($MyInvocation.MyCommand.Name) -Action Stop' to stop tracing"
            }
        } else {
            Write-Error "Failed to start trace: $result"
        }
    }
    
    "Stop" {
        Write-Host "Stopping WPP trace session..." -ForegroundColor Yellow
        
        if (-not (Get-TraceStatus)) {
            Write-Host "No trace session is running." -ForegroundColor Yellow
            exit 0
        }
        
        $result = & logman stop $SessionName -ets 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Trace session stopped!" -ForegroundColor Green
            
            if (Test-Path $DefaultEtlFile) {
                $size = (Get-Item $DefaultEtlFile).Length / 1KB
                Write-Host "  Trace file: $DefaultEtlFile ($([math]::Round($size, 2)) KB)"
            }
        } else {
            Write-Error "Failed to stop trace: $result"
        }
    }
    
    "View" {
        Write-Host "Viewing trace in real-time..." -ForegroundColor Yellow
        Write-Host "Press Ctrl+C to stop" -ForegroundColor Gray
        Write-Host ""
        
        # Find TMF files (trace message format)
        $tmfPath = Join-Path $RootDir "bin\x64\Debug\quac100"
        if (-not (Test-Path $tmfPath)) {
            $tmfPath = Join-Path $RootDir "bin\x64\Release\quac100"
        }
        
        # Use tracefmt if available
        $tracefmt = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin" -Recurse -Filter "tracefmt.exe" 2>$null | Select-Object -First 1
        
        if ($tracefmt -and (Test-Path $DefaultEtlFile)) {
            & $tracefmt.FullName -tmf $tmfPath -o - $DefaultEtlFile -rt $SessionName
        } else {
            # Fallback to tracerpt
            if (Test-Path $DefaultEtlFile) {
                & tracerpt $DefaultEtlFile -o "$env:TEMP\quac_trace.xml" -of XML -summary "$env:TEMP\quac_summary.txt" -y
                Get-Content "$env:TEMP\quac_summary.txt"
            } else {
                Write-Warning "No trace file found. Start a trace first."
            }
        }
    }
    
    "Save" {
        if (-not $OutputFile) {
            $OutputFile = Join-Path $env:USERPROFILE "Desktop\quac100_trace_$(Get-Date -Format 'yyyyMMdd_HHmmss').etl"
        }
        
        Write-Host "Saving trace..." -ForegroundColor Yellow
        
        # Stop session if running
        if (Get-TraceStatus) {
            & logman stop $SessionName -ets 2>$null
            Start-Sleep -Seconds 1
        }
        
        if (Test-Path $DefaultEtlFile) {
            Copy-Item $DefaultEtlFile $OutputFile -Force
            $size = (Get-Item $OutputFile).Length / 1KB
            Write-Host "Trace saved to: $OutputFile ($([math]::Round($size, 2)) KB)" -ForegroundColor Green
            
            # Also create readable text output
            $txtFile = [System.IO.Path]::ChangeExtension($OutputFile, ".txt")
            & tracerpt $OutputFile -o $txtFile -of CSV -summary "$([System.IO.Path]::ChangeExtension($OutputFile, '_summary.txt'))" -y 2>$null
            
            if (Test-Path $txtFile) {
                Write-Host "Text output: $txtFile" -ForegroundColor Green
            }
        } else {
            Write-Error "No trace file to save. Start a trace first."
        }
    }
    
    "Status" {
        Write-Host "Trace Session Status" -ForegroundColor Yellow
        Write-Host ""
        
        if (Get-TraceStatus) {
            Write-Host "Session: $SessionName" -ForegroundColor Green
            Write-Host "Status: RUNNING" -ForegroundColor Green
            
            # Get session details
            $details = & logman query $SessionName -ets 2>&1 | Out-String
            Write-Host ""
            Write-Host $details
        } else {
            Write-Host "Session: $SessionName" -ForegroundColor Gray
            Write-Host "Status: NOT RUNNING" -ForegroundColor Gray
        }
        
        Write-Host ""
        if (Test-Path $DefaultEtlFile) {
            $info = Get-Item $DefaultEtlFile
            Write-Host "Last trace file: $DefaultEtlFile"
            Write-Host "  Size: $([math]::Round($info.Length / 1KB, 2)) KB"
            Write-Host "  Modified: $($info.LastWriteTime)"
        }
    }
}
