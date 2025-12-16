# Building the QUAC 100 Windows Driver

This guide covers building the QUAC 100 Windows driver from source, including prerequisites, build configurations, and troubleshooting.

## Prerequisites

### Required Software

1. **Visual Studio 2022** (17.4 or later)
   - Workload: "Desktop development with C++"
   - Individual components:
     - MSVC v143 - VS 2022 C++ x64/x86 build tools
     - MSVC v143 - VS 2022 C++ ARM64 build tools (for ARM64)
     - Windows 11 SDK (10.0.22621.0 or later)
     - C++ Spectre-mitigated libraries

2. **Windows Driver Kit (WDK) 11**
   - Download from: https://docs.microsoft.com/windows-hardware/drivers/download-the-wdk
   - Must match SDK version

3. **Visual Studio WDK Extension**
   - Installed automatically with WDK
   - Provides driver project templates

### Verification

Open "Developer PowerShell for VS 2022" and run:

```powershell
# Check Visual Studio
& "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" -latest

# Check WDK
Test-Path "${env:ProgramFiles(x86)}\Windows Kits\10\Include\10.0.22621.0\km"

# Check MSBuild
Get-Command msbuild -ErrorAction SilentlyContinue
```

## Build Methods

### Method 1: Visual Studio IDE

1. Open `quac100.sln` in Visual Studio 2022
2. Select configuration from toolbar:
   - **Debug** - Unoptimized, full symbols, extra checks
   - **Release** - Optimized, minimal symbols
3. Select platform:
   - **x64** - 64-bit Intel/AMD
   - **ARM64** - 64-bit ARM
4. Build → Build Solution (Ctrl+Shift+B)

### Method 2: PowerShell Script

```powershell
# Basic build
.\scripts\build.ps1

# Release build
.\scripts\build.ps1 -Configuration Release

# ARM64 build
.\scripts\build.ps1 -Platform ARM64

# Clean and rebuild
.\scripts\build.ps1 -Clean -Configuration Release -Platform x64
```

### Method 3: MSBuild Command Line

```powershell
# Find MSBuild
$msbuild = & "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" `
    -latest -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe | Select-Object -First 1

# Build solution
& $msbuild quac100.sln /p:Configuration=Release /p:Platform=x64

# Build specific project
& $msbuild src\quac100\quac100.vcxproj /p:Configuration=Release /p:Platform=x64

# Rebuild
& $msbuild quac100.sln /t:Rebuild /p:Configuration=Release /p:Platform=x64
```

### Method 4: Developer Command Prompt

```cmd
:: Open "x64 Native Tools Command Prompt for VS 2022"
cd D:\quantacore-sdk\drivers\windows

:: Build
msbuild quac100.sln /p:Configuration=Release /p:Platform=x64

:: Verbose build
msbuild quac100.sln /p:Configuration=Debug /p:Platform=x64 /v:detailed
```

## Build Outputs

After a successful build, outputs are located in:

```
bin\
├── x64\
│   ├── Debug\
│   │   ├── quac100\
│   │   │   ├── quac100.sys      # Kernel driver
│   │   │   ├── quac100.inf      # Installation info
│   │   │   ├── quac100.pdb      # Debug symbols
│   │   │   └── quac100.cat      # Catalog (after signing)
│   │   ├── quac100vf\
│   │   │   └── quac100vf.sys    # VF driver
│   │   ├── quac100.dll          # User-mode library
│   │   ├── quac100.lib          # Import library
│   │   └── quac100test.exe      # Test application
│   └── Release\
│       └── ...                   # Same structure
└── ARM64\
    └── ...                       # Same structure
```

## Build Configurations

### Debug Configuration

- **Optimization**: Disabled (/Od)
- **Debug Info**: Full (/Zi)
- **Runtime Checks**: Enabled (/RTC1)
- **ASSERT**: Enabled
- **WPP Tracing**: Verbose
- **Code Analysis**: Enabled

Recommended for development and debugging.

### Release Configuration

- **Optimization**: Full (/O2)
- **Debug Info**: PDB only (/Zi)
- **Runtime Checks**: Disabled
- **ASSERT**: Disabled
- **WPP Tracing**: Errors only
- **Link Time Optimization**: Enabled (/LTCG)

Required for production and certification.

## Project Structure

### Solution Projects

| Project | Output | Description |
|---------|--------|-------------|
| quac100 | quac100.sys | Main kernel driver |
| quac100vf | quac100vf.sys | Virtual function driver |
| quac100lib | quac100.dll | User-mode library |
| quac100test | quac100test.exe | Test application |

### Build Dependencies

```
quac100test
    └── quac100lib
            └── (kernel headers)

quac100vf
    └── (common headers)

quac100
    └── (WDK headers)
```

## Compiler Options

### Driver-Specific Settings

```xml
<!-- From quac100.vcxproj -->
<ClCompile>
  <PreprocessorDefinitions>
    KMDF_VERSION_MAJOR=1;
    KMDF_VERSION_MINOR=31;
    _AMD64_;
    %(PreprocessorDefinitions)
  </PreprocessorDefinitions>
  <WppEnabled>true</WppEnabled>
  <WppScanConfigurationData>trace.h</WppScanConfigurationData>
  <TreatWarningAsError>true</TreatWarningAsError>
  <WarningLevel>Level4</WarningLevel>
</ClCompile>
```

### Security Hardening

All builds include:
- Control Flow Guard (/guard:cf)
- Spectre mitigation (/Qspectre)
- ASLR support (/DYNAMICBASE)
- DEP support (/NXCOMPAT)
- Safe exception handlers (/SAFESEH for x86)

## Signing

### Test Signing (Development)

```powershell
# Sign for development
.\tools\sign\sign_driver.ps1 -DriverPath bin\x64\Debug\quac100\quac100.sys -TestSign
```

This creates a self-signed certificate and signs the driver. Test signing must be enabled on the target machine.

### Production Signing

Production signing requires an EV code signing certificate:

```powershell
# Sign with production certificate
.\tools\sign\sign_driver.ps1 `
    -DriverPath bin\x64\Release\quac100\quac100.sys `
    -CertFile path\to\certificate.pfx `
    -CertPassword "password"
```

### Catalog Creation

The INF file and driver must be cataloged:

```powershell
# Create catalog (done automatically during build)
Inf2Cat /driver:bin\x64\Release\quac100 /os:10_x64
```

## Troubleshooting

### Common Build Errors

#### "WDK not found"

```
Error: WindowsDriver.Common.targets not found
```

**Solution**: Install Windows Driver Kit matching your SDK version.

#### "Spectre libraries not found"

```
Error: Cannot open include file: 'spectre.h'
```

**Solution**: Install Spectre-mitigated libraries via Visual Studio Installer:
1. Tools → Get Tools and Features
2. Individual Components → Search "Spectre"
3. Install matching version

#### "ARM64 build tools not found"

```
Error: The build tools for v143 (Platform Toolset = 'v143') cannot be found
```

**Solution**: Install ARM64 build tools via Visual Studio Installer.

#### "LNK2019: unresolved external symbol"

```
Error LNK2019: unresolved external symbol WdfDriverCreate
```

**Solution**: Ensure WDK is properly installed and project references WDF libraries.

### Build Warnings

#### Code Analysis Warnings

Enable/disable via project properties:
- Configuration Properties → Code Analysis → Enable Code Analysis

#### Prefast Warnings

Suppress specific warnings with:
```c
#pragma prefast(suppress:28118, "Intentional design")
```

### Clean Build Issues

If builds fail after changes:

```powershell
# Full clean
.\scripts\clean.ps1 -Build -Force

# Or manually
Remove-Item -Recurse -Force bin, obj, x64, ARM64, .vs
```

## Continuous Integration

### Azure DevOps Pipeline

```yaml
trigger:
  - main

pool:
  vmImage: 'windows-2022'

steps:
- task: VSBuild@1
  inputs:
    solution: 'drivers/windows/quac100.sln'
    configuration: 'Release'
    platform: 'x64'

- task: CopyFiles@2
  inputs:
    sourceFolder: 'drivers/windows/bin'
    contents: '**\*.sys'
    targetFolder: '$(Build.ArtifactStagingDirectory)'

- task: PublishBuildArtifacts@1
  inputs:
    pathToPublish: '$(Build.ArtifactStagingDirectory)'
    artifactName: 'driver'
```

### GitHub Actions

```yaml
name: Build Windows Driver

on: [push, pull_request]

jobs:
  build:
    runs-on: windows-2022
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Setup MSBuild
      uses: microsoft/setup-msbuild@v1
    
    - name: Build
      run: msbuild drivers\windows\quac100.sln /p:Configuration=Release /p:Platform=x64
    
    - name: Upload Artifacts
      uses: actions/upload-artifact@v3
      with:
        name: driver
        path: drivers\windows\bin\x64\Release\
```

## Advanced Topics

### Incremental Builds

MSBuild tracks dependencies automatically. For faster iteration:
- Build only changed projects
- Use `/m` for parallel builds
- Keep `.vs` folder for IntelliSense cache

### Multi-Configuration Builds

Build all configurations at once:

```powershell
$configs = @("Debug", "Release")
$platforms = @("x64", "ARM64")

foreach ($config in $configs) {
    foreach ($platform in $platforms) {
        msbuild quac100.sln /p:Configuration=$config /p:Platform=$platform
    }
}
```

### Custom Build Events

Add post-build events in project properties:
- Configuration Properties → Build Events → Post-Build Event

Example:
```cmd
copy "$(TargetPath)" "$(SolutionDir)\deploy\"
```

## Related Documentation

- [Installation Guide](installation.md)
- [Architecture Overview](architecture.md)
- [Debugging Guide](debugging.md)

---

Copyright © 2025 Dyber, Inc. All Rights Reserved.
