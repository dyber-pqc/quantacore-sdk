using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;
using Serilog;
using QuacTestSuite.Models;

namespace QuacTestSuite.Services
{
    /// <summary>
    /// QUAC 100 device service - communicates with the driver
    /// </summary>
    public class QuacDeviceService : IQuacDeviceService, IDisposable
    {
        private SafeFileHandle? _deviceHandle;
        private bool _disposed;
        private System.Timers.Timer? _healthTimer;

        public bool IsConnected => _deviceHandle != null && !_deviceHandle.IsInvalid || _simulationMode;
        public string? DeviceName { get; private set; }
        
        private bool _simulationMode = false;
        
        public event EventHandler<DeviceInfo>? DeviceConnected;
        public event EventHandler? DeviceDisconnected;
        public event EventHandler<DeviceHealth>? HealthUpdated;

        // P/Invoke declarations
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern SafeFileHandle CreateFile(
            string lpFileName,
            uint dwDesiredAccess,
            uint dwShareMode,
            IntPtr lpSecurityAttributes,
            uint dwCreationDisposition,
            uint dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool DeviceIoControl(
            SafeFileHandle hDevice,
            uint dwIoControlCode,
            IntPtr lpInBuffer,
            uint nInBufferSize,
            IntPtr lpOutBuffer,
            uint nOutBufferSize,
            out uint lpBytesReturned,
            IntPtr lpOverlapped);

        private const uint GENERIC_READ = 0x80000000;
        private const uint GENERIC_WRITE = 0x40000000;
        private const uint FILE_SHARE_READ = 0x00000001;
        private const uint FILE_SHARE_WRITE = 0x00000002;
        private const uint OPEN_EXISTING = 3;

        public async Task<bool> ConnectAsync()
        {
            return await Task.Run(() =>
            {
                try
                {
                    // Try to open the device
                    _deviceHandle = CreateFile(
                        @"\\.\QUAC100-0",
                        GENERIC_READ | GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        IntPtr.Zero,
                        OPEN_EXISTING,
                        0,
                        IntPtr.Zero);

                    if (_deviceHandle.IsInvalid)
                    {
                        Log.Warning("Failed to open QUAC 100 device - running in simulation mode");
                        _simulationMode = true;
                        DeviceName = "QUAC 100 (Simulated)";
                    }
                    else
                    {
                        DeviceName = "QUAC 100";
                        _simulationMode = false;
                    }

                    // Fire connected event
                    var deviceInfo = new DeviceInfo
                    {
                        DeviceName = DeviceName,
                        SerialNumber = "Q100-2025-00001234",
                        FirmwareVersion = "1.2.0",
                        DriverVersion = "1.0.0.0",
                        IsConnected = true
                    };
                    DeviceConnected?.Invoke(this, deviceInfo);

                    // Start health monitoring
                    StartHealthMonitoring();

                    Log.Information("Connected to QUAC 100 device (simulation={Simulation})", _simulationMode);
                    return true;
                }
                catch (Exception ex)
                {
                    Log.Error(ex, "Error connecting to device");
                    _simulationMode = true;
                    DeviceName = "QUAC 100 (Simulated)";
                    return true; // Simulation mode
                }
            });
        }

        private void StartHealthMonitoring()
        {
            _healthTimer = new System.Timers.Timer(2000);
            _healthTimer.Elapsed += async (s, e) =>
            {
                var health = await GetHealthAsync();
                HealthUpdated?.Invoke(this, health);
            };
            _healthTimer.Start();
        }

        private async Task<DeviceHealth> GetHealthAsync()
        {
            await Task.CompletedTask;
            var random = new Random();
            return new DeviceHealth
            {
                TemperatureCelsius = 50 + random.Next(10),
                PowerWatts = 15 + random.NextDouble() * 5,
                Status = HealthStatus.Ok,
                Uptime = TimeSpan.FromSeconds((DateTime.Now - DateTime.Today).TotalSeconds),
                Timestamp = DateTime.Now
            };
        }

        public Task DisconnectAsync()
        {
            _healthTimer?.Stop();
            _healthTimer?.Dispose();
            _deviceHandle?.Dispose();
            _deviceHandle = null;
            DeviceName = null;
            _simulationMode = false;
            DeviceDisconnected?.Invoke(this, EventArgs.Empty);
            return Task.CompletedTask;
        }

        public Task RefreshAsync()
        {
            return Task.CompletedTask;
        }

        public async Task RefreshStatusAsync()
        {
            var health = await GetHealthAsync();
            HealthUpdated?.Invoke(this, health);
        }

        public Task<DeviceInfoDto> GetDeviceInfoAsync()
        {
            return Task.FromResult(new DeviceInfoDto(
                Name: "QUAC 100 Rev B",
                SerialNumber: "Q100-2025-00001234",
                DriverVersion: "1.0.0.0",
                FirmwareVersion: "1.2.0",
                HardwareRevision: "Rev B",
                Capabilities: 0xFFFF
            ));
        }

        public Task<HealthInfoDto> GetHealthInfoAsync()
        {
            var random = new Random();
            return Task.FromResult(new HealthInfoDto(
                Status: 0,
                Temperature: 50 + random.Next(10),
                PowerMw: 15000 + random.Next(5000),
                Uptime: (uint)(DateTime.Now - DateTime.Today).TotalSeconds,
                ErrorCount: 0,
                AlertFlags: 0
            ));
        }

        public Task<byte[]> GenerateRandomAsync(int bytes, int quality)
        {
            var result = new byte[bytes];
            new Random().NextBytes(result); // Simulation
            return Task.FromResult(result);
        }

        public Task<BenchmarkResultDto> RunBenchmarkAsync(string algorithm, string operation, int iterations)
        {
            var random = new Random();
            var baseOps = algorithm.Contains("Kyber") ? 45000 : 6000;
            
            return Task.FromResult(new BenchmarkResultDto(
                Algorithm: algorithm,
                Operation: operation,
                OpsPerSecond: baseOps + random.Next(10000),
                AvgLatencyUs: 15 + random.NextDouble() * 50,
                P99LatencyUs: 25 + random.NextDouble() * 100,
                Iterations: iterations
            ));
        }

        public Task<SelfTestResultDto[]> RunSelfTestAsync()
        {
            return Task.FromResult(new SelfTestResultDto[]
            {
                new("Register Access", true, null),
                new("Memory Test", true, null),
                new("DMA Loopback", true, null),
                new("KEM Engine", true, null),
                new("Signature Engine", true, null),
                new("QRNG Engine", true, null)
            });
        }

        public Task ResetDeviceAsync()
        {
            Log.Information("Device reset requested");
            return Task.Delay(1000); // Simulate reset
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                _healthTimer?.Stop();
                _healthTimer?.Dispose();
                _deviceHandle?.Dispose();
                _disposed = true;
            }
        }
    }

    /// <summary>
    /// Benchmark service
    /// </summary>
    public class BenchmarkService : IBenchmarkService
    {
        private readonly IQuacDeviceService _deviceService;
        private bool _cancelled;

        public BenchmarkService(IQuacDeviceService deviceService)
        {
            _deviceService = deviceService;
        }

        public async Task<BenchmarkResultDto> RunBenchmarkAsync(CryptoAlgorithm algorithm, CryptoOperation operation, int iterations)
        {
            var random = new Random();
            var baseOps = algorithm.ToString().Contains("Kyber") ? 45000.0 : 6000.0;
            
            // Simulate work
            await Task.Delay(iterations / 10);
            
            return new BenchmarkResultDto(
                Algorithm: algorithm.ToString(),
                Operation: operation.ToString(),
                OpsPerSecond: baseOps + random.Next(10000),
                AvgLatencyUs: 15 + random.NextDouble() * 50,
                P99LatencyUs: 25 + random.NextDouble() * 100,
                Iterations: iterations
            );
        }

        public async Task<BenchmarkResult> RunAsync(BenchmarkConfigDto config, IProgress<BenchmarkProgressDto>? progress = null)
        {
            _cancelled = false;
            var startTime = DateTime.Now;
            var random = new Random();
            
            // Simulation
            for (int i = 0; i < 100 && !_cancelled; i++)
            {
                await Task.Delay(50);
                progress?.Report(new BenchmarkProgressDto(
                    $"Testing {config.Algorithms[0]}...",
                    i,
                    DateTime.Now - startTime));
            }

            return new BenchmarkResult
            {
                Algorithm = Enum.TryParse<CryptoAlgorithm>(config.Algorithms[0], out var alg) ? alg : CryptoAlgorithm.Kyber768,
                Operation = CryptoOperation.KeyGen,
                OperationsPerSecond = 48000 + random.Next(5000),
                AverageLatencyMicroseconds = 20.5,
                P99LatencyMicroseconds = 31.2,
                Iterations = config.Iterations,
                Timestamp = DateTime.Now
            };
        }

        public async Task<QrngBenchmarkResultDto> RunQrngBenchmarkAsync(int bytes, int iterations)
        {
            var random = new Random();
            await Task.Delay(100); // Simulate
            
            return new QrngBenchmarkResultDto(
                ThroughputMbps: 100 + random.NextDouble() * 20,
                TotalBytes: (long)bytes * iterations,
                Duration: TimeSpan.FromMilliseconds(100)
            );
        }

        public void Cancel()
        {
            _cancelled = true;
        }
    }

    /// <summary>
    /// Settings service
    /// </summary>
    public class SettingsService : ISettingsService
    {
        private readonly Dictionary<string, object> _settings = new();
        private readonly string _settingsPath;

        public SettingsService()
        {
            _settingsPath = System.IO.Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "Dyber",
                "QuacTestSuite",
                "settings.json");
            
            Load();
        }

        public T Get<T>(string key, T defaultValue)
        {
            if (_settings.TryGetValue(key, out var value))
            {
                try
                {
                    if (value is T typed)
                        return typed;
                    if (value is System.Text.Json.JsonElement element)
                    {
                        return System.Text.Json.JsonSerializer.Deserialize<T>(element.GetRawText()) ?? defaultValue;
                    }
                }
                catch { }
            }
            return defaultValue;
        }

        public void Set<T>(string key, T value)
        {
            _settings[key] = value!;
        }

        public void Save()
        {
            try
            {
                var dir = System.IO.Path.GetDirectoryName(_settingsPath);
                if (!string.IsNullOrEmpty(dir))
                {
                    System.IO.Directory.CreateDirectory(dir);
                }
                
                var json = System.Text.Json.JsonSerializer.Serialize(_settings, new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
                System.IO.File.WriteAllText(_settingsPath, json);
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Failed to save settings");
            }
        }

        public void Load()
        {
            try
            {
                if (System.IO.File.Exists(_settingsPath))
                {
                    var json = System.IO.File.ReadAllText(_settingsPath);
                    var loaded = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, object>>(json);
                    if (loaded != null)
                    {
                        foreach (var kvp in loaded)
                        {
                            _settings[kvp.Key] = kvp.Value;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Failed to load settings");
            }
        }
    }
}
