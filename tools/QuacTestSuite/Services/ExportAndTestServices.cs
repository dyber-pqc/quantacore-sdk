using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Win32;
using Newtonsoft.Json;
using Serilog;
using QuacTestSuite.Models;

namespace QuacTestSuite.Services
{
    /// <summary>
    /// Interface for exporting reports and data
    /// </summary>
    public interface IExportService
    {
        Task ExportBenchmarkResultsAsync(IEnumerable<BenchmarkResultRow> results, string? filePath = null);
        Task ExportLoadTestReportAsync(LoadTestReport report, string? filePath = null);
        Task ExportQrngDataAsync(byte[] data, string? filePath = null);
        Task ExportDiagnosticsReportAsync(DiagnosticsReport report, string? filePath = null);
        Task ExportFullReportAsync(string? filePath = null);
    }

    /// <summary>
    /// Interface for running test sequences
    /// </summary>
    public interface ITestRunnerService
    {
        Task<TestSuiteResult> RunAllTestsAsync(IProgress<TestProgress>? progress = null);
        Task<SelfTestResultDto[]> RunSelfTestsAsync();
        Task<ValidationResult> ValidateDeviceAsync();
        void Cancel();
    }

    /// <summary>
    /// Export service implementation
    /// </summary>
    public class ExportService : IExportService
    {
        private readonly IQuacDeviceService _deviceService;

        public ExportService(IQuacDeviceService deviceService)
        {
            _deviceService = deviceService;
        }

        public async Task ExportBenchmarkResultsAsync(IEnumerable<BenchmarkResultRow> results, string? filePath = null)
        {
            if (string.IsNullOrEmpty(filePath))
            {
                var dialog = new SaveFileDialog
                {
                    Filter = "CSV files (*.csv)|*.csv|JSON files (*.json)|*.json|All files (*.*)|*.*",
                    DefaultExt = ".csv",
                    FileName = $"benchmark_results_{DateTime.Now:yyyyMMdd_HHmmss}"
                };

                if (dialog.ShowDialog() != true) return;
                filePath = dialog.FileName;
            }

            var extension = Path.GetExtension(filePath).ToLowerInvariant();

            if (extension == ".json")
            {
                var json = JsonConvert.SerializeObject(results, Formatting.Indented);
                await File.WriteAllTextAsync(filePath, json);
            }
            else
            {
                var csv = new StringBuilder();
                csv.AppendLine("Algorithm,Operation,Ops/Sec,Avg Latency (µs),Min Latency (µs),Max Latency (µs),P99 Latency (µs),Iterations,Errors");

                foreach (var r in results)
                {
                    csv.AppendLine($"{r.Algorithm},{r.Operation},{r.OpsPerSecond:F2},{r.AvgLatencyUs:F2},{r.MinLatencyUs:F2},{r.MaxLatencyUs:F2},{r.P99LatencyUs:F2},{r.Iterations},{r.Errors}");
                }

                await File.WriteAllTextAsync(filePath, csv.ToString());
            }

            Log.Information("Exported benchmark results to {FilePath}", filePath);
        }

        public async Task ExportLoadTestReportAsync(LoadTestReport report, string? filePath = null)
        {
            if (string.IsNullOrEmpty(filePath))
            {
                var dialog = new SaveFileDialog
                {
                    Filter = "HTML files (*.html)|*.html|JSON files (*.json)|*.json|All files (*.*)|*.*",
                    DefaultExt = ".html",
                    FileName = $"loadtest_report_{DateTime.Now:yyyyMMdd_HHmmss}"
                };

                if (dialog.ShowDialog() != true) return;
                filePath = dialog.FileName;
            }

            var extension = Path.GetExtension(filePath).ToLowerInvariant();

            if (extension == ".html")
            {
                var html = GenerateLoadTestHtmlReport(report);
                await File.WriteAllTextAsync(filePath, html);
            }
            else
            {
                var json = JsonConvert.SerializeObject(report, Formatting.Indented);
                await File.WriteAllTextAsync(filePath, json);
            }

            Log.Information("Exported load test report to {FilePath}", filePath);
        }

        public async Task ExportQrngDataAsync(byte[] data, string? filePath = null)
        {
            if (string.IsNullOrEmpty(filePath))
            {
                var dialog = new SaveFileDialog
                {
                    Filter = "Binary files (*.bin)|*.bin|All files (*.*)|*.*",
                    DefaultExt = ".bin",
                    FileName = $"qrng_data_{DateTime.Now:yyyyMMdd_HHmmss}"
                };

                if (dialog.ShowDialog() != true) return;
                filePath = dialog.FileName;
            }

            await File.WriteAllBytesAsync(filePath, data);
            Log.Information("Exported {Bytes} bytes of QRNG data to {FilePath}", data.Length, filePath);
        }

        public async Task ExportDiagnosticsReportAsync(DiagnosticsReport report, string? filePath = null)
        {
            if (string.IsNullOrEmpty(filePath))
            {
                var dialog = new SaveFileDialog
                {
                    Filter = "Text files (*.txt)|*.txt|JSON files (*.json)|*.json|All files (*.*)|*.*",
                    DefaultExt = ".txt",
                    FileName = $"diagnostics_{DateTime.Now:yyyyMMdd_HHmmss}"
                };

                if (dialog.ShowDialog() != true) return;
                filePath = dialog.FileName;
            }

            var extension = Path.GetExtension(filePath).ToLowerInvariant();

            if (extension == ".json")
            {
                var json = JsonConvert.SerializeObject(report, Formatting.Indented);
                await File.WriteAllTextAsync(filePath, json);
            }
            else
            {
                var text = GenerateDiagnosticsTextReport(report);
                await File.WriteAllTextAsync(filePath, text);
            }

            Log.Information("Exported diagnostics report to {FilePath}", filePath);
        }

        public async Task ExportFullReportAsync(string? filePath = null)
        {
            if (string.IsNullOrEmpty(filePath))
            {
                var dialog = new SaveFileDialog
                {
                    Filter = "HTML files (*.html)|*.html|All files (*.*)|*.*",
                    DefaultExt = ".html",
                    FileName = $"quac100_full_report_{DateTime.Now:yyyyMMdd_HHmmss}"
                };

                if (dialog.ShowDialog() != true) return;
                filePath = dialog.FileName;
            }

            var html = await GenerateFullHtmlReportAsync();
            await File.WriteAllTextAsync(filePath, html);

            Log.Information("Exported full report to {FilePath}", filePath);
        }

        private string GenerateLoadTestHtmlReport(LoadTestReport report)
        {
            return $@"<!DOCTYPE html>
<html>
<head>
    <title>QUAC 100 Load Test Report</title>
    <style>
        body {{ font-family: 'Segoe UI', sans-serif; background: #0f0f1a; color: #fff; margin: 40px; }}
        .header {{ border-bottom: 2px solid #00b4d8; padding-bottom: 20px; margin-bottom: 30px; }}
        .metric {{ background: #1a1a2e; border-radius: 8px; padding: 20px; margin: 10px 0; }}
        .metric-value {{ font-size: 32px; color: #00d4aa; font-weight: bold; }}
        .metric-label {{ color: #808080; font-size: 12px; text-transform: uppercase; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #2d2d44; }}
        th {{ color: #00b4d8; }}
    </style>
</head>
<body>
    <div class='header'>
        <h1>QUAC 100 Load Test Report</h1>
        <p>Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}</p>
        <p>Device: {report.DeviceName}</p>
    </div>
    <div class='metric'>
        <div class='metric-label'>Peak Throughput</div>
        <div class='metric-value'>{report.PeakOpsPerSecond:N0} ops/sec</div>
    </div>
    <div class='metric'>
        <div class='metric-label'>Average Latency</div>
        <div class='metric-value'>{report.AverageLatencyMs:N2} ms</div>
    </div>
    <div class='metric'>
        <div class='metric-label'>Total Operations</div>
        <div class='metric-value'>{report.TotalOperations:N0}</div>
    </div>
    <div class='metric'>
        <div class='metric-label'>Error Rate</div>
        <div class='metric-value'>{report.ErrorRate:P2}</div>
    </div>
    <p style='color:#606060;margin-top:40px;'>© 2025 Dyber, Inc. All Rights Reserved.</p>
</body>
</html>";
        }

        private string GenerateDiagnosticsTextReport(DiagnosticsReport report)
        {
            var sb = new StringBuilder();
            sb.AppendLine("=".PadRight(60, '='));
            sb.AppendLine("QUAC 100 Diagnostics Report");
            sb.AppendLine("=".PadRight(60, '='));
            sb.AppendLine($"Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"Device: {report.DeviceName}");
            sb.AppendLine($"Serial: {report.SerialNumber}");
            sb.AppendLine($"Driver Version: {report.DriverVersion}");
            sb.AppendLine($"Firmware Version: {report.FirmwareVersion}");
            sb.AppendLine();
            sb.AppendLine("-".PadRight(60, '-'));
            sb.AppendLine("Self-Test Results:");
            sb.AppendLine("-".PadRight(60, '-'));
            foreach (var test in report.SelfTestResults)
            {
                sb.AppendLine($"  [{(test.Passed ? "PASS" : "FAIL")}] {test.TestName}");
            }
            sb.AppendLine();
            sb.AppendLine("-".PadRight(60, '-'));
            sb.AppendLine("Health Status:");
            sb.AppendLine("-".PadRight(60, '-'));
            sb.AppendLine($"  Temperature: {report.Temperature}°C");
            sb.AppendLine($"  Power: {report.PowerWatts:N1}W");
            sb.AppendLine($"  Uptime: {report.Uptime}");
            sb.AppendLine($"  Error Count: {report.ErrorCount}");
            sb.AppendLine();
            sb.AppendLine("© 2025 Dyber, Inc. All Rights Reserved.");
            return sb.ToString();
        }

        private async Task<string> GenerateFullHtmlReportAsync()
        {
            var deviceInfo = await _deviceService.GetDeviceInfoAsync();
            var health = await _deviceService.GetHealthInfoAsync();

            return $@"<!DOCTYPE html>
<html>
<head>
    <title>QUAC 100 Full Report - Dyber, Inc.</title>
    <style>
        body {{ font-family: 'Segoe UI', sans-serif; background: #0f0f1a; color: #fff; margin: 0; padding: 40px; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{ display: flex; align-items: center; border-bottom: 2px solid #00b4d8; padding-bottom: 20px; margin-bottom: 30px; }}
        .logo {{ width: 60px; height: 60px; background: #00b4d8; border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 32px; font-weight: bold; margin-right: 20px; }}
        .section {{ background: #1a1a2e; border-radius: 12px; padding: 24px; margin: 20px 0; }}
        .section-title {{ color: #00b4d8; font-size: 18px; margin-bottom: 16px; border-bottom: 1px solid #2d2d44; padding-bottom: 8px; }}
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; }}
        .metric {{ background: #252538; border-radius: 8px; padding: 16px; }}
        .metric-value {{ font-size: 28px; color: #00d4aa; font-weight: bold; }}
        .metric-label {{ color: #808080; font-size: 11px; text-transform: uppercase; margin-bottom: 4px; }}
        .status-ok {{ color: #2ed573; }}
        .status-warn {{ color: #ffb800; }}
        .status-error {{ color: #ff4757; }}
        .footer {{ text-align: center; color: #606060; margin-top: 40px; padding-top: 20px; border-top: 1px solid #2d2d44; }}
    </style>
</head>
<body>
    <div class='container'>
        <div class='header'>
            <div class='logo'>Q</div>
            <div>
                <h1 style='margin:0;'>QUAC 100 Test Suite Report</h1>
                <p style='margin:5px 0 0 0;color:#808080;'>Post-Quantum Cryptographic Accelerator</p>
            </div>
        </div>

        <div class='section'>
            <div class='section-title'>Device Information</div>
            <div class='grid'>
                <div class='metric'>
                    <div class='metric-label'>Device Name</div>
                    <div class='metric-value' style='font-size:18px;'>{deviceInfo.Name}</div>
                </div>
                <div class='metric'>
                    <div class='metric-label'>Serial Number</div>
                    <div class='metric-value' style='font-size:18px;'>{deviceInfo.SerialNumber}</div>
                </div>
                <div class='metric'>
                    <div class='metric-label'>Driver Version</div>
                    <div class='metric-value' style='font-size:18px;'>{deviceInfo.DriverVersion}</div>
                </div>
                <div class='metric'>
                    <div class='metric-label'>Firmware Version</div>
                    <div class='metric-value' style='font-size:18px;'>{deviceInfo.FirmwareVersion}</div>
                </div>
            </div>
        </div>

        <div class='section'>
            <div class='section-title'>Health Status</div>
            <div class='grid'>
                <div class='metric'>
                    <div class='metric-label'>Status</div>
                    <div class='metric-value status-ok'>HEALTHY</div>
                </div>
                <div class='metric'>
                    <div class='metric-label'>Temperature</div>
                    <div class='metric-value'>{health.Temperature}°C</div>
                </div>
                <div class='metric'>
                    <div class='metric-label'>Power</div>
                    <div class='metric-value'>{health.PowerMw / 1000.0:N1}W</div>
                </div>
                <div class='metric'>
                    <div class='metric-label'>Uptime</div>
                    <div class='metric-value' style='font-size:18px;'>{TimeSpan.FromSeconds(health.Uptime):d\:hh\:mm\:ss}</div>
                </div>
            </div>
        </div>

        <div class='section'>
            <div class='section-title'>Supported Algorithms</div>
            <div class='grid'>
                <div class='metric'>
                    <div class='metric-label'>ML-KEM (Kyber)</div>
                    <div class='metric-value status-ok' style='font-size:16px;'>512 / 768 / 1024</div>
                </div>
                <div class='metric'>
                    <div class='metric-label'>ML-DSA (Dilithium)</div>
                    <div class='metric-value status-ok' style='font-size:16px;'>Level 2 / 3 / 5</div>
                </div>
                <div class='metric'>
                    <div class='metric-label'>SLH-DSA (SPHINCS+)</div>
                    <div class='metric-value status-ok' style='font-size:16px;'>128s / 128f / 192 / 256</div>
                </div>
                <div class='metric'>
                    <div class='metric-label'>QRNG</div>
                    <div class='metric-value status-ok' style='font-size:16px;'>SP 800-90B Compliant</div>
                </div>
            </div>
        </div>

        <div class='footer'>
            <p>Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}</p>
            <p>© 2025 Dyber, Inc. All Rights Reserved.</p>
            <p><a href='https://dyber.org' style='color:#00b4d8;'>dyber.org</a></p>
        </div>
    </div>
</body>
</html>";
        }
    }

    /// <summary>
    /// Test runner service implementation
    /// </summary>
    public class TestRunnerService : ITestRunnerService
    {
        private readonly IQuacDeviceService _deviceService;
        private readonly IBenchmarkService _benchmarkService;
        private bool _cancelled;

        public TestRunnerService(IQuacDeviceService deviceService, IBenchmarkService benchmarkService)
        {
            _deviceService = deviceService;
            _benchmarkService = benchmarkService;
        }

        public async Task<TestSuiteResult> RunAllTestsAsync(IProgress<TestProgress>? progress = null)
        {
            _cancelled = false;
            var result = new TestSuiteResult { StartTime = DateTime.Now };
            var tests = new List<TestResult>();

            // Self tests
            progress?.Report(new TestProgress("Running self-tests...", 0));
            var selfTests = await RunSelfTestsAsync();
            foreach (var st in selfTests)
            {
                tests.Add(new TestResult
                {
                    Category = "Self-Test",
                    Name = st.TestName,
                    Passed = st.Passed,
                    Message = st.ErrorMessage ?? "OK"
                });
            }

            if (_cancelled) return result;

            // Validation
            progress?.Report(new TestProgress("Validating device...", 30));
            var validation = await ValidateDeviceAsync();
            tests.Add(new TestResult
            {
                Category = "Validation",
                Name = "Device Validation",
                Passed = validation.IsValid,
                Message = validation.Message
            });

            if (_cancelled) return result;

            // Quick benchmark
            progress?.Report(new TestProgress("Running benchmarks...", 60));
            var benchResult = await _benchmarkService.RunAsync(new BenchmarkConfigDto(
                new[] { "Kyber768" },
                new[] { "KeyGen" },
                100,
                1,
                true
            ));
            tests.Add(new TestResult
            {
                Category = "Benchmark",
                Name = "ML-KEM-768 KeyGen",
                Passed = benchResult.OperationsPerSecond > 1000,
                Message = $"{benchResult.OperationsPerSecond:N0} ops/sec"
            });

            progress?.Report(new TestProgress("Complete", 100));

            result.EndTime = DateTime.Now;
            result.Tests = tests;
            result.PassedCount = tests.Count(t => t.Passed);
            result.FailedCount = tests.Count(t => !t.Passed);

            return result;
        }

        public async Task<SelfTestResultDto[]> RunSelfTestsAsync()
        {
            return await _deviceService.RunSelfTestAsync();
        }

        public async Task<ValidationResult> ValidateDeviceAsync()
        {
            try
            {
                var info = await _deviceService.GetDeviceInfoAsync();
                var health = await _deviceService.GetHealthInfoAsync();

                if (health.Status > 1)
                {
                    return new ValidationResult(false, "Device health check failed");
                }

                if (health.Temperature > 80)
                {
                    return new ValidationResult(false, $"Temperature too high: {health.Temperature}°C");
                }

                return new ValidationResult(true, "Device validated successfully");
            }
            catch (Exception ex)
            {
                return new ValidationResult(false, $"Validation error: {ex.Message}");
            }
        }

        public void Cancel()
        {
            _cancelled = true;
        }
    }

    // DTOs for export/test services
    public class BenchmarkResultRow
    {
        public string Algorithm { get; set; } = "";
        public string Operation { get; set; } = "";
        public double OpsPerSecond { get; set; }
        public double AvgLatencyUs { get; set; }
        public double MinLatencyUs { get; set; }
        public double MaxLatencyUs { get; set; }
        public double P99LatencyUs { get; set; }
        public int Iterations { get; set; }
        public int Errors { get; set; }
    }

    public class LoadTestReport
    {
        public string DeviceName { get; set; } = "QUAC 100";
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public double PeakOpsPerSecond { get; set; }
        public double AverageOpsPerSecond { get; set; }
        public double AverageLatencyMs { get; set; }
        public long TotalOperations { get; set; }
        public long TotalErrors { get; set; }
        public double ErrorRate { get; set; }
    }

    public class DiagnosticsReport
    {
        public string DeviceName { get; set; } = "QUAC 100";
        public string SerialNumber { get; set; } = "";
        public string DriverVersion { get; set; } = "";
        public string FirmwareVersion { get; set; } = "";
        public int Temperature { get; set; }
        public double PowerWatts { get; set; }
        public string Uptime { get; set; } = "";
        public int ErrorCount { get; set; }
        public List<SelfTestResultModel> SelfTestResults { get; set; } = new();
    }

    public class SelfTestResultModel
    {
        public string TestName { get; set; } = "";
        public bool Passed { get; set; }
    }

    public class TestSuiteResult
    {
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public List<TestResult> Tests { get; set; } = new();
        public int PassedCount { get; set; }
        public int FailedCount { get; set; }
    }

    public class TestResult
    {
        public string Category { get; set; } = "";
        public string Name { get; set; } = "";
        public bool Passed { get; set; }
        public string Message { get; set; } = "";
    }

    public record TestProgress(string Message, double PercentComplete);
    public record ValidationResult(bool IsValid, string Message);
}
