# QUAC 100 Test Suite

A professional Windows desktop application for testing, benchmarking, and monitoring the QUAC 100 Post-Quantum Cryptographic Accelerator.

![QUAC 100 Test Suite](Assets/quac100.ico)

## Features

### Dashboard
- Real-time device status and health monitoring
- Live performance metrics (ops/sec, latency, throughput)
- Temperature and power consumption graphs
- Quick action buttons for common tasks
- Recent activity log

### Performance Benchmark
- Benchmark all PQC algorithms (ML-KEM, ML-DSA, SLH-DSA)
- Configurable iterations and thread count
- Warmup phase option
- Real-time progress tracking
- Detailed results with latency percentiles
- Export results to CSV/JSON

### Load Testing
- Sustained load testing with configurable duration
- Target ops/sec with rate limiting
- Ramp-up period support
- Live throughput and latency charts
- Error rate monitoring
- Export comprehensive reports

### Algorithm Comparison
- Side-by-side comparison of all algorithms
- Throughput, latency, and key size charts
- Security level comparison
- Exportable comparison reports

### QRNG Testing
- Quantum random number generation
- Configurable output size and quality
- Statistical randomness tests (NIST SP 800-22)
- Byte distribution visualization
- Export random data to files

### Health Monitor
- Device temperature and power tracking
- Uptime and error counters
- Self-test execution
- Hardware diagnostics
- PCIe link information

### Settings
- Device mode (Hardware/Simulator)
- Benchmark defaults
- Display preferences
- Logging configuration
- Export path settings

## Requirements

- Windows 10/11 (x64)
- .NET 8.0 Runtime
- QUAC 100 hardware or simulator
- QUAC 100 driver installed

## Installation

1. Install the QUAC 100 driver (see driver installation guide)
2. Run `QuacTestSuite.exe`
3. The application will auto-detect the device

## Building from Source

### Prerequisites

- Visual Studio 2022
- .NET 8.0 SDK
- NuGet packages (restored automatically)

### Build Steps

```powershell
# Clone the repository
git clone https://github.com/dyber-pqc/quantacore-sdk.git
cd quantacore-sdk/tools/QuacTestSuite

# Restore packages and build
dotnet restore
dotnet build --configuration Release

# Run the application
dotnet run --configuration Release
```

## Project Structure

```
QuacTestSuite/
├── Assets/                 # Icons, images, branding
├── Controls/               # Custom WPF controls
├── Converters/             # Value converters
├── Models/                 # Data models
├── Services/               # Business logic services
├── Themes/                 # Dyber theme resources
├── ViewModels/             # MVVM view models
├── Views/                  # XAML views
├── App.xaml                # Application definition
├── appsettings.json        # Configuration
└── QuacTestSuite.csproj    # Project file
```

## Architecture

The application follows the MVVM (Model-View-ViewModel) pattern:

- **Models**: Data structures for device info, benchmarks, settings
- **Views**: XAML-based user interface
- **ViewModels**: Presentation logic with data binding
- **Services**: Device communication, benchmarking, export

### Key Technologies

- **WPF**: Windows Presentation Foundation
- **CommunityToolkit.Mvvm**: MVVM framework
- **LiveCharts2**: Charting library
- **MaterialDesign**: UI components
- **Serilog**: Logging framework

## Configuration

Edit `appsettings.json` to customize defaults:

```json
{
  "Device": {
    "Mode": "Auto-detect",
    "AutoConnect": true
  },
  "Benchmark": {
    "DefaultIterations": 1000,
    "WarmupIterations": 100
  },
  "Display": {
    "Theme": "Dark",
    "RefreshIntervalMs": 1000
  }
}
```

## Simulator Mode

If no hardware is available, the application runs in simulator mode:

1. Set Device Mode to "Simulator" in Settings
2. Optionally specify a simulator executable path
3. The app will generate simulated metrics

## Export Formats

- **CSV**: Benchmark results, comparison data
- **JSON**: Structured data export
- **HTML**: Formatted reports with charts
- **BIN**: Raw QRNG data

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| F5 | Refresh |
| Ctrl+E | Export |
| Ctrl+B | Start Benchmark |
| Ctrl+S | Save Settings |
| Escape | Stop Operation |

## Troubleshooting

### Device Not Found
1. Ensure QUAC 100 driver is installed
2. Check Device Manager for the device
3. Try running as Administrator
4. Use simulator mode for testing

### Benchmark Fails
1. Check device health status
2. Reduce thread count
3. Check temperature warnings
4. Review error logs

### Application Crash
1. Check logs in `logs/` folder
2. Ensure .NET 8.0 runtime is installed
3. Run as Administrator
4. Contact support with log files

## Support

- **Documentation**: https://docs.dyber.org/quac100
- **Issues**: https://github.com/dyber-pqc/quantacore-sdk/issues
- **Email**: support@dyber.org
- **Website**: https://dyber.org

## License

Copyright © 2025 Dyber, Inc. All Rights Reserved.

This software is proprietary and confidential. See LICENSE file for details.

---

**QUAC 100** - Post-Quantum Security, Today.
