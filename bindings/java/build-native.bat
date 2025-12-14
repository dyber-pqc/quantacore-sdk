@echo off
REM QUAC 100 Java SDK - Native Library Build Script (Windows)
REM Copyright (c) 2025 Dyber, Inc. All Rights Reserved.

setlocal enabledelayedexpansion

echo ============================================================
echo QUAC 100 Java SDK - Native Library Build
echo ============================================================
echo.

REM Check for required tools
where cmake >nul 2>&1
if errorlevel 1 (
    echo ERROR: CMake not found. Please install CMake and add to PATH.
    exit /b 1
)

REM Set paths
set SCRIPT_DIR=%~dp0
set NATIVE_DIR=%SCRIPT_DIR%native
set BUILD_DIR=%NATIVE_DIR%\build

REM Default QUAC100_ROOT if not set
if "%QUAC100_ROOT%"=="" (
    set QUAC100_ROOT=%SCRIPT_DIR%..\c
)

REM Verify QUAC 100 C library exists
if not exist "%QUAC100_ROOT%\include\quac100\quac100.h" (
    echo ERROR: QUAC 100 C library not found at %QUAC100_ROOT%
    echo Please set QUAC100_ROOT environment variable or build the C library first.
    exit /b 1
)

echo Using QUAC 100 C library: %QUAC100_ROOT%
echo.

REM Check if C library is built
if not exist "%QUAC100_ROOT%\build\Release\quac100.dll" (
    if not exist "%QUAC100_ROOT%\build\quac100.dll" (
        echo WARNING: QUAC 100 C library DLL not found.
        echo Please build the C library first:
        echo   cd %QUAC100_ROOT%
        echo   mkdir build ^&^& cd build
        echo   cmake .. -G "Visual Studio 17 2022" -A x64
        echo   cmake --build . --config Release
        echo.
    )
)

REM Create build directory
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"
cd /d "%BUILD_DIR%"

REM Configure with CMake
echo Configuring CMake...
cmake .. -G "Visual Studio 17 2022" -A x64 -DQUAC100_ROOT="%QUAC100_ROOT%"
if errorlevel 1 (
    echo ERROR: CMake configuration failed.
    exit /b 1
)

REM Build
echo.
echo Building...
cmake --build . --config Release
if errorlevel 1 (
    echo ERROR: Build failed.
    exit /b 1
)

echo.
echo ============================================================
echo Build Complete!
echo ============================================================
echo.
echo Native libraries built in: %BUILD_DIR%\Release\
echo   - quac100_jni.dll
echo   - quac100.dll (copied from C library)
echo.
echo To run Java tests:
echo   cd %SCRIPT_DIR%
echo   mvn test -DargLine="-Djava.library.path=%BUILD_DIR%\Release"
echo.

endlocal