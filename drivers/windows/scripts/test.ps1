<#
.SYNOPSIS
    Run QUAC 100 Driver Tests

.DESCRIPTION
    Executes the quac100test.exe test application with various test suites.
    Can run all tests or specific categories.

.PARAMETER Category
    Test category to run: All, KEM, Sign, QRNG, Perf

.PARAMETER Configuration
    Build configuration (Debug/Release)

.PARAMETER Platform
    Target platform (x64/ARM64)

.PARAMETER Verbose
    Enable verbose output

.PARAMETER Iterations
    Number of iterations for performance tests

.EXAMPLE
    .\test.ps1 -Category All
    Run all tests

.EXAMPLE
    .\test.ps1 -Category KEM -Verbose
    Run KEM tests with verbose output

.EXAMPLE
    .\test.ps1 -Category Perf -Iterations 1000
    Run performance tests with 1000 iterations
#>

param(
    [ValidateSet("All", "KEM", "Sign", "QRNG", "Perf")]
    [string]$Category = "All",
    
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Debug",
    
    [ValidateSet("x64", "ARM64")]
    [string]$Platform = "x64",
    
    [switch]$Verbose,
    
    [int]$Iterations = 100
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Split-Path -Parent $ScriptDir

Write-Host "QUAC 100 Driver Test Runner" -ForegroundColor Cyan
Write-Host "==========================" -ForegroundColor Cyan
Write-Host ""

# Find test executable
$binDir = Join-Path $RootDir "bin\$Platform\$Configuration"
$testExe = Join-Path $binDir "quac100test.exe"

if (-not (Test-Path $testExe)) {
    Write-Error "Test executable not found: $testExe`nPlease build the solution first."
    exit 1
}

Write-Host "Test executable: $testExe" -ForegroundColor Yellow
Write-Host "Configuration: $Configuration | Platform: $Platform"
Write-Host ""

# Check if driver is loaded
$driver = Get-PnpDevice -FriendlyName "*QUAC*" -ErrorAction SilentlyContinue
if (-not $driver) {
    Write-Warning "QUAC 100 device not detected. Tests may fail or use simulator mode."
}

# Build test arguments
$testArgs = @()

switch ($Category) {
    "All"  { $testArgs += "--all" }
    "KEM"  { $testArgs += "--kem" }
    "Sign" { $testArgs += "--sign" }
    "QRNG" { $testArgs += "--qrng" }
    "Perf" { $testArgs += "--perf", "--iterations", $Iterations }
}

if ($Verbose) {
    $testArgs += "--verbose"
}

# Run tests
Write-Host "Running $Category tests..." -ForegroundColor Green
Write-Host "Command: $testExe $($testArgs -join ' ')"
Write-Host ""

$startTime = Get-Date
$process = Start-Process -FilePath $testExe -ArgumentList $testArgs -NoNewWindow -Wait -PassThru

$duration = (Get-Date) - $startTime

Write-Host ""
Write-Host "Test run completed" -ForegroundColor Cyan
Write-Host "Duration: $($duration.TotalSeconds.ToString("F2")) seconds"
Write-Host "Exit code: $($process.ExitCode)"

if ($process.ExitCode -eq 0) {
    Write-Host "All tests PASSED!" -ForegroundColor Green
} else {
    Write-Host "Some tests FAILED!" -ForegroundColor Red
    exit $process.ExitCode
}
