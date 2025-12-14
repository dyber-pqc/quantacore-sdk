# ============================================
# QUAC 100 C SDK - Build and Test Script
# PowerShell version for Windows
# ============================================

Write-Host "========================================"
Write-Host "QUAC 100 C SDK Build and Test"
Write-Host "========================================"
Write-Host ""

# Source files
$sources = @(
    "simple_test.c",
    "quac100.c",
    "device.c",
    "kem.c",
    "sign.c",
    "random.c",
    "hash.c",
    "keys.c",
    "utils.c",
    "hal.c"
)

# Check for compilers
$hasVS = $null -ne (Get-Command "cl" -ErrorAction SilentlyContinue)
$hasGCC = $null -ne (Get-Command "gcc" -ErrorAction SilentlyContinue)
$hasClang = $null -ne (Get-Command "clang" -ErrorAction SilentlyContinue)

if ($hasVS) {
    Write-Host "Using Visual Studio compiler (cl.exe)"
    Write-Host ""
    
    # Build with MSVC
    $args = @(
        "/nologo",
        "/W4",
        "/O2",
        "/DQUAC_ENABLE_SIMULATION=1",
        "/DQUAC_PLATFORM_WINDOWS=1",
        "/D_CRT_SECURE_NO_WARNINGS",
        "/Fe:simple_test.exe"
    ) + $sources
    
    & cl @args
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host ""
        Write-Host "BUILD FAILED!" -ForegroundColor Red
        exit 1
    }
}
elseif ($hasGCC) {
    Write-Host "Using GCC compiler"
    Write-Host ""
    
    # Build with GCC
    $args = @(
        "-Wall", "-Wextra", "-O2",
        "-DQUAC_ENABLE_SIMULATION=1",
        "-DQUAC_PLATFORM_WINDOWS=1",
        "-o", "simple_test.exe"
    ) + $sources
    
    & gcc @args
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host ""
        Write-Host "BUILD FAILED!" -ForegroundColor Red
        exit 1
    }
}
elseif ($hasClang) {
    Write-Host "Using Clang compiler"
    Write-Host ""
    
    $args = @(
        "-Wall", "-Wextra", "-O2",
        "-DQUAC_ENABLE_SIMULATION=1",
        "-DQUAC_PLATFORM_WINDOWS=1",
        "-o", "simple_test.exe"
    ) + $sources
    
    & clang @args
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host ""
        Write-Host "BUILD FAILED!" -ForegroundColor Red
        exit 1
    }
}
else {
    Write-Host "ERROR: No C compiler found!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Please install one of the following:"
    Write-Host "  1. Visual Studio (recommended)"
    Write-Host "     - Run this script from 'Developer PowerShell for VS'"
    Write-Host "  2. MinGW-w64 (https://www.mingw-w64.org/)"
    Write-Host "  3. LLVM/Clang (https://llvm.org/)"
    Write-Host ""
    exit 1
}

Write-Host ""
Write-Host "Build successful!" -ForegroundColor Green
Write-Host ""
Write-Host "========================================"
Write-Host "Running Tests..."
Write-Host "========================================"
Write-Host ""

# Run the test
.\simple_test.exe

Write-Host ""
Write-Host "========================================"
Write-Host "Test Complete!"
Write-Host "========================================"