using System;
using System.Threading.Tasks;

namespace QuacTestSuite.Services
{
    /// <summary>
    /// Interface for QUAC 100 device communication
    /// </summary>
    public interface IQuacDeviceService
    {
        bool IsConnected { get; }
        string? DeviceName { get; }
        
        event EventHandler<Models.DeviceInfo>? DeviceConnected;
        event EventHandler? DeviceDisconnected;
        event EventHandler<Models.DeviceHealth>? HealthUpdated;
        
        Task<bool> ConnectAsync();
        Task DisconnectAsync();
        Task RefreshAsync();
        Task RefreshStatusAsync();
        
        // Device info
        Task<DeviceInfoDto> GetDeviceInfoAsync();
        Task<HealthInfoDto> GetHealthInfoAsync();
        
        // Operations
        Task<byte[]> GenerateRandomAsync(int bytes, int quality);
        Task<BenchmarkResultDto> RunBenchmarkAsync(string algorithm, string operation, int iterations);
        Task<SelfTestResultDto[]> RunSelfTestAsync();
        Task ResetDeviceAsync();
    }

    /// <summary>
    /// Interface for benchmark operations
    /// </summary>
    public interface IBenchmarkService
    {
        Task<BenchmarkResultDto> RunBenchmarkAsync(Models.CryptoAlgorithm algorithm, Models.CryptoOperation operation, int iterations);
        Task<Models.BenchmarkResult> RunAsync(BenchmarkConfigDto config, IProgress<BenchmarkProgressDto>? progress = null);
        Task<QrngBenchmarkResultDto> RunQrngBenchmarkAsync(int bytes, int iterations);
        void Cancel();
    }

    /// <summary>
    /// Interface for settings management
    /// </summary>
    public interface ISettingsService
    {
        T Get<T>(string key, T defaultValue);
        void Set<T>(string key, T value);
        void Save();
        void Load();
    }

    // DTOs
    public record DeviceInfoDto(
        string Name,
        string SerialNumber,
        string DriverVersion,
        string FirmwareVersion,
        string HardwareRevision,
        uint Capabilities
    );

    public record HealthInfoDto(
        int Status,
        int Temperature,
        int PowerMw,
        uint Uptime,
        uint ErrorCount,
        uint AlertFlags
    );

    public record BenchmarkConfigDto(
        string[] Algorithms,
        string[] Operations,
        int Iterations,
        int Threads,
        bool Warmup
    );

    public record BenchmarkProgressDto(
        string CurrentOperation,
        double PercentComplete,
        TimeSpan Elapsed
    );

    public record BenchmarkResultDto(
        string Algorithm,
        string Operation,
        double OpsPerSecond,
        double AvgLatencyUs,
        double P99LatencyUs,
        int Iterations
    );

    public record SelfTestResultDto(
        string TestName,
        bool Passed,
        string? ErrorMessage
    );

    public record QrngBenchmarkResultDto(
        double ThroughputMbps,
        long TotalBytes,
        TimeSpan Duration
    );
}
