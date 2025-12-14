@echo off
REM ============================================
REM QUAC 100 C SDK - Build and Test Script
REM For Windows with Visual Studio or MinGW
REM ============================================

echo ========================================
echo QUAC 100 C SDK Build and Test
echo ========================================
echo.

REM Check for Visual Studio compiler
where cl >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo Found Visual Studio compiler
    goto :build_msvc
)

REM Check for GCC (MinGW)
where gcc >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo Found GCC compiler
    goto :build_gcc
)

echo ERROR: No C compiler found!
echo Please install Visual Studio or MinGW-w64
echo.
echo For Visual Studio:
echo   Run this script from "Developer Command Prompt for VS"
echo.
echo For MinGW:
echo   Install from https://www.mingw-w64.org/
echo   Add to PATH: C:\mingw64\bin
goto :end

:build_msvc
echo.
echo Building with MSVC...
echo.

REM Compile all source files
cl /nologo /W4 /O2 /DQUAC_ENABLE_SIMULATION=1 /DQUAC_PLATFORM_WINDOWS=1 ^
   /D_CRT_SECURE_NO_WARNINGS ^
   /Fe:simple_test.exe ^
   simple_test.c ^
   quac100.c ^
   device.c ^
   kem.c ^
   sign.c ^
   random.c ^
   hash.c ^
   keys.c ^
   utils.c ^
   hal.c

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo BUILD FAILED!
    goto :end
)

echo.
echo Build successful!
goto :run_test

:build_gcc
echo.
echo Building with GCC...
echo.

gcc -Wall -Wextra -O2 -DQUAC_ENABLE_SIMULATION=1 -DQUAC_PLATFORM_WINDOWS=1 ^
    -o simple_test.exe ^
    simple_test.c ^
    quac100.c ^
    device.c ^
    kem.c ^
    sign.c ^
    random.c ^
    hash.c ^
    keys.c ^
    utils.c ^
    hal.c

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo BUILD FAILED!
    goto :end
)

echo.
echo Build successful!
goto :run_test

:run_test
echo.
echo ========================================
echo Running Tests...
echo ========================================
echo.

simple_test.exe

echo.
echo ========================================
echo Test Complete!
echo ========================================

:end
echo.
pause