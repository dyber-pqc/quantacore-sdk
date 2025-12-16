<#
.SYNOPSIS
    Run Windows Hardware Lab Kit (HLK) Tests

.DESCRIPTION
    Submits the QUAC 100 driver to HLK for certification testing.
    Requires HLK Studio and Controller to be installed.

.PARAMETER HlkController
    HLK Controller hostname or IP address

.PARAMETER PoolName
    HLK machine pool name containing test machines

.PARAMETER ProjectName
    HLK project name (default: QUAC100)

.PARAMETER DriverPath
    Path to driver package

.PARAMETER RunTests
    Run tests after creating project

.PARAMETER TestNames
    Specific tests to run (comma-separated, or "All")

.EXAMPLE
    .\run_hlk_tests.ps1 -HlkController "hlk-controller" -PoolName "TestPool" -RunTests
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$HlkController,
    
    [Parameter(Mandatory=$true)]
    [string]$PoolName,
    
    [string]$ProjectName = "QUAC100",
    
    [string]$DriverPath,
    
    [switch]$RunTests,
    
    [string]$TestNames = "All"
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Check for HLK Object Model
$hlkAssembly = "C:\Program Files (x86)\Windows Kits\10\Hardware Lab Kit\Studio\Microsoft.Windows.Kits.Hardware.ObjectModel.dll"
if (-not (Test-Path $hlkAssembly)) {
    Write-Error "HLK Studio not found. Please install Windows Hardware Lab Kit."
    exit 1
}

Add-Type -Path $hlkAssembly

Write-Host "QUAC 100 HLK Test Runner" -ForegroundColor Cyan
Write-Host "Controller: $HlkController"
Write-Host "Pool: $PoolName"
Write-Host "Project: $ProjectName"
Write-Host ""

try {
    # Connect to HLK Controller
    Write-Host "Connecting to HLK Controller..." -ForegroundColor Yellow
    $manager = New-Object Microsoft.Windows.Kits.Hardware.ObjectModel.ProjectManager -ArgumentList $HlkController
    
    # Get or create project
    $project = $manager.GetProject($ProjectName)
    if (-not $project) {
        Write-Host "Creating new project: $ProjectName" -ForegroundColor Yellow
        $project = $manager.CreateProject($ProjectName)
    } else {
        Write-Host "Using existing project: $ProjectName" -ForegroundColor Green
    }
    
    # Get machine pool
    Write-Host "Finding machine pool: $PoolName" -ForegroundColor Yellow
    $rootPool = $manager.GetRootMachinePool()
    $pool = $rootPool.GetChildPools() | Where-Object { $_.Name -eq $PoolName }
    
    if (-not $pool) {
        Write-Error "Machine pool not found: $PoolName"
        exit 1
    }
    
    # Get available machines
    $machines = $pool.GetMachines()
    Write-Host "Available machines in pool:" -ForegroundColor Cyan
    foreach ($machine in $machines) {
        $status = if ($machine.Status -eq "Ready") { "Ready" } else { $machine.Status }
        Write-Host "  - $($machine.Name): $status"
    }
    
    # Create product instance
    Write-Host "Creating product instance..." -ForegroundColor Yellow
    $productInstance = $project.CreateProductInstance("QUAC 100 Device", $pool, $machines[0].OSPlatform)
    
    # Get device family
    Write-Host "Finding target family..." -ForegroundColor Yellow
    $families = $productInstance.GetTargetFamilies()
    $deviceFamily = $families | Where-Object { $_.Name -like "*System*" } | Select-Object -First 1
    
    if ($deviceFamily) {
        Write-Host "Target family: $($deviceFamily.Name)" -ForegroundColor Green
    }
    
    # Get available tests
    Write-Host "Getting available tests..." -ForegroundColor Yellow
    $tests = $productInstance.GetTests()
    
    Write-Host "Available tests:" -ForegroundColor Cyan
    foreach ($test in $tests | Select-Object -First 20) {
        Write-Host "  - $($test.Name)"
    }
    
    if ($tests.Count -gt 20) {
        Write-Host "  ... and $($tests.Count - 20) more tests"
    }
    
    if ($RunTests) {
        Write-Host "`nRunning tests..." -ForegroundColor Yellow
        
        $testsToRun = @()
        if ($TestNames -eq "All") {
            $testsToRun = $tests
        } else {
            $testNameList = $TestNames -split ","
            foreach ($name in $testNameList) {
                $matchingTests = $tests | Where-Object { $_.Name -like "*$($name.Trim())*" }
                $testsToRun += $matchingTests
            }
        }
        
        if ($testsToRun.Count -eq 0) {
            Write-Warning "No matching tests found"
        } else {
            Write-Host "Running $($testsToRun.Count) tests..."
            
            foreach ($test in $testsToRun) {
                Write-Host "  Starting: $($test.Name)"
                $test.QueueTest()
            }
            
            Write-Host "Tests queued. Monitor progress in HLK Studio." -ForegroundColor Green
        }
    }
    
    Write-Host "`nHLK project ready!" -ForegroundColor Green
    Write-Host "Open HLK Studio to view results and create submission package."
    
} catch {
    Write-Error "HLK operation failed: $_"
    exit 1
}
