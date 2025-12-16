<#
.SYNOPSIS
    QUAC 100 Performance Benchmark

.DESCRIPTION
    Runs comprehensive performance benchmarks on the QUAC 100 device.
    Tests KEM operations, signatures, and QRNG throughput.

.PARAMETER Algorithm
    Algorithm to benchmark: All, KEM, Sign, QRNG

.PARAMETER Iterations
    Number of iterations per test

.PARAMETER WarmupIterations
    Number of warmup iterations (not counted)

.PARAMETER OutputFormat
    Output format: Console, CSV, JSON

.PARAMETER OutputFile
    File to save results

.EXAMPLE
    .\benchmark.ps1 -Algorithm All -Iterations 1000
    Run all benchmarks with 1000 iterations

.EXAMPLE
    .\benchmark.ps1 -Algorithm KEM -OutputFormat CSV -OutputFile results.csv
    Benchmark KEM and save as CSV
#>

param(
    [ValidateSet("All", "KEM", "Sign", "QRNG")]
    [string]$Algorithm = "All",
    
    [int]$Iterations = 100,
    
    [int]$WarmupIterations = 10,
    
    [ValidateSet("Console", "CSV", "JSON")]
    [string]$OutputFormat = "Console",
    
    [string]$OutputFile
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Split-Path -Parent $ScriptDir

Write-Host ""
Write-Host "  ╔═══════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "  ║         QUAC 100 Performance Benchmark                ║" -ForegroundColor Cyan
Write-Host "  ║              Dyber, Inc. (dyber.org)                  ║" -ForegroundColor Cyan
Write-Host "  ╚═══════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Find test executable
$testExe = $null
$searchPaths = @(
    (Join-Path $RootDir "bin\x64\Release\quac100test.exe"),
    (Join-Path $RootDir "bin\x64\Debug\quac100test.exe")
)

foreach ($path in $searchPaths) {
    if (Test-Path $path) {
        $testExe = $path
        break
    }
}

if (-not $testExe) {
    Write-Error "Test executable not found. Please build the solution first."
    exit 1
}

Write-Host "Test executable: $testExe" -ForegroundColor Gray
Write-Host "Iterations: $Iterations (warmup: $WarmupIterations)"
Write-Host ""

# System info
$cpuInfo = Get-CimInstance Win32_Processor | Select-Object -First 1
$ramInfo = Get-CimInstance Win32_ComputerSystem

Write-Host "System Information:" -ForegroundColor Yellow
Write-Host "  CPU: $($cpuInfo.Name)"
Write-Host "  Cores: $($cpuInfo.NumberOfCores) (Logical: $($cpuInfo.NumberOfLogicalProcessors))"
Write-Host "  RAM: $([math]::Round($ramInfo.TotalPhysicalMemory / 1GB, 2)) GB"
Write-Host ""

# Check device
$device = Get-PnpDevice -FriendlyName "*QUAC*" -ErrorAction SilentlyContinue
if ($device -and $device.Status -eq "OK") {
    Write-Host "Device: $($device.FriendlyName) [Hardware Mode]" -ForegroundColor Green
    $mode = "Hardware"
} else {
    Write-Host "Device: Software Simulator Mode" -ForegroundColor Yellow
    $mode = "Simulator"
}
Write-Host ""

# Build arguments
$args = @("--benchmark", "--iterations", $Iterations, "--warmup", $WarmupIterations)

switch ($Algorithm) {
    "KEM"  { $args += "--kem-only" }
    "Sign" { $args += "--sign-only" }
    "QRNG" { $args += "--qrng-only" }
}

if ($OutputFormat -eq "JSON") {
    $args += "--json"
} elseif ($OutputFormat -eq "CSV") {
    $args += "--csv"
}

# Run benchmark
Write-Host "Running benchmarks..." -ForegroundColor Cyan
Write-Host "-" * 60
Write-Host ""

$startTime = Get-Date
$output = & $testExe $args 2>&1
$duration = (Get-Date) - $startTime

# Parse and display results
if ($OutputFormat -eq "Console") {
    Write-Host $output
    
    Write-Host ""
    Write-Host "-" * 60
    Write-Host "Benchmark Summary" -ForegroundColor Cyan
    Write-Host "-" * 60
    Write-Host ""
    Write-Host "Mode: $mode"
    Write-Host "Total Duration: $([math]::Round($duration.TotalSeconds, 2)) seconds"
    Write-Host "Test Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    
} else {
    # Output raw data
    if ($OutputFile) {
        $output | Out-File -FilePath $OutputFile -Encoding UTF8
        Write-Host "Results saved to: $OutputFile" -ForegroundColor Green
    } else {
        Write-Host $output
    }
}

# Generate report if output file specified
if ($OutputFile -and $OutputFormat -eq "Console") {
    $report = @"
QUAC 100 Performance Benchmark Report
=====================================
Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Mode: $mode
Iterations: $Iterations
Warmup: $WarmupIterations

System:
  CPU: $($cpuInfo.Name)
  Cores: $($cpuInfo.NumberOfCores)
  RAM: $([math]::Round($ramInfo.TotalPhysicalMemory / 1GB, 2)) GB

Results:
$output

Total Duration: $([math]::Round($duration.TotalSeconds, 2)) seconds
"@
    
    $report | Out-File -FilePath $OutputFile -Encoding UTF8
    Write-Host "Report saved to: $OutputFile" -ForegroundColor Green
}

Write-Host ""
Write-Host "Benchmark complete!" -ForegroundColor Green
