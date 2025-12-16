using System;

namespace QuacTestSuite.Models
{
    /// <summary>
    /// Represents information about a connected QUAC 100 device
    /// </summary>
    public class DeviceInfo
    {
        public string DevicePath { get; set; } = string.Empty;
        public string DeviceName { get; set; } = "QUAC 100";
        public string SerialNumber { get; set; } = string.Empty;
        public string FirmwareVersion { get; set; } = string.Empty;
        public string DriverVersion { get; set; } = string.Empty;
        public int HardwareRevision { get; set; }
        public DeviceCapabilities Capabilities { get; set; } = new();
        public bool IsConnected { get; set; }
        public DateTime LastSeen { get; set; }
    }

    /// <summary>
    /// Device capabilities flags
    /// </summary>
    public class DeviceCapabilities
    {
        public bool SupportsKyber512 { get; set; } = true;
        public bool SupportsKyber768 { get; set; } = true;
        public bool SupportsKyber1024 { get; set; } = true;
        public bool SupportsDilithium2 { get; set; } = true;
        public bool SupportsDilithium3 { get; set; } = true;
        public bool SupportsDilithium5 { get; set; } = true;
        public bool SupportsSphincs { get; set; } = true;
        public bool SupportsQrng { get; set; } = true;
        public bool SupportsSriov { get; set; } = true;
        public int MaxDmaChannels { get; set; } = 4;
    }

    /// <summary>
    /// Real-time device health metrics
    /// </summary>
    public class DeviceHealth
    {
        public int TemperatureCelsius { get; set; }
        public double PowerWatts { get; set; }
        public HealthStatus Status { get; set; }
        public uint AlertFlags { get; set; }
        public uint ErrorCount { get; set; }
        public TimeSpan Uptime { get; set; }
        public DateTime Timestamp { get; set; }
    }

    public enum HealthStatus
    {
        Ok,
        Warning,
        Degraded,
        Critical,
        Failed
    }

    /// <summary>
    /// Cryptographic algorithm types
    /// </summary>
    public enum CryptoAlgorithm
    {
        // KEM Algorithms
        Kyber512,
        Kyber768,
        Kyber1024,
        
        // Signature Algorithms
        Dilithium2,
        Dilithium3,
        Dilithium5,
        SphincsShake128s,
        SphincsShake128f,
        SphincsShake192s,
        SphincsShake192f,
        SphincsShake256s,
        SphincsShake256f,
        
        // QRNG
        QrngNormal,
        QrngHigh
    }

    /// <summary>
    /// Cryptographic operation types
    /// </summary>
    public enum CryptoOperation
    {
        KeyGen,
        Encapsulate,
        Decapsulate,
        Sign,
        Verify,
        Random
    }

    /// <summary>
    /// Result of a single benchmark operation
    /// </summary>
    public class BenchmarkResult
    {
        public CryptoAlgorithm Algorithm { get; set; }
        public CryptoOperation Operation { get; set; }
        public int Iterations { get; set; }
        public TimeSpan TotalTime { get; set; }
        public double OperationsPerSecond { get; set; }
        public double AverageLatencyMicroseconds { get; set; }
        public double MinLatencyMicroseconds { get; set; }
        public double MaxLatencyMicroseconds { get; set; }
        public double P50LatencyMicroseconds { get; set; }
        public double P95LatencyMicroseconds { get; set; }
        public double P99LatencyMicroseconds { get; set; }
        public int Errors { get; set; }
        public DateTime Timestamp { get; set; }
    }

    /// <summary>
    /// Load test configuration
    /// </summary>
    public class LoadTestConfig
    {
        public CryptoAlgorithm Algorithm { get; set; } = CryptoAlgorithm.Kyber768;
        public CryptoOperation Operation { get; set; } = CryptoOperation.KeyGen;
        public int ConcurrentThreads { get; set; } = 4;
        public int TargetOpsPerSecond { get; set; } = 1000;
        public TimeSpan Duration { get; set; } = TimeSpan.FromMinutes(1);
        public TimeSpan RampUpTime { get; set; } = TimeSpan.FromSeconds(10);
        public bool EnableRateLimiting { get; set; } = true;
    }

    /// <summary>
    /// Real-time load test metrics
    /// </summary>
    public class LoadTestMetrics
    {
        public DateTime Timestamp { get; set; }
        public double CurrentOpsPerSecond { get; set; }
        public double AverageOpsPerSecond { get; set; }
        public long TotalOperations { get; set; }
        public long TotalErrors { get; set; }
        public double ErrorRate { get; set; }
        public double CurrentLatencyMs { get; set; }
        public double AverageLatencyMs { get; set; }
        public int ActiveThreads { get; set; }
        public int QueueDepth { get; set; }
        public double CpuUsage { get; set; }
        public double MemoryUsageMb { get; set; }
        public int DeviceTemperature { get; set; }
    }

    /// <summary>
    /// QRNG statistics
    /// </summary>
    public class QrngStatistics
    {
        public long TotalBytesGenerated { get; set; }
        public double ThroughputMbps { get; set; }
        public double EntropyEstimate { get; set; }
        public bool HealthTestPassed { get; set; }
        public int[] ByteDistribution { get; set; } = new int[256];
        public double BiasPercentage { get; set; }
        public DateTime Timestamp { get; set; }
    }

    /// <summary>
    /// Self-test result
    /// </summary>
    public class SelfTestResult
    {
        public string TestName { get; set; } = string.Empty;
        public bool Passed { get; set; }
        public string Details { get; set; } = string.Empty;
        public TimeSpan Duration { get; set; }
        public DateTime Timestamp { get; set; }
    }

    /// <summary>
    /// Diagnostic information
    /// </summary>
    public class DiagnosticInfo
    {
        public string Category { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public string Value { get; set; } = string.Empty;
        public string Status { get; set; } = "OK";
    }

    /// <summary>
    /// Application settings
    /// </summary>
    public class AppSettings
    {
        public bool UseSimulator { get; set; } = false;
        public string SimulatorPath { get; set; } = string.Empty;
        public int DefaultBenchmarkIterations { get; set; } = 1000;
        public int RefreshIntervalMs { get; set; } = 1000;
        public bool AutoConnectOnStartup { get; set; } = true;
        public bool EnableLogging { get; set; } = true;
        public string LogLevel { get; set; } = "Information";
        public string ExportPath { get; set; } = string.Empty;
        public string Theme { get; set; } = "Dark";
    }
}
