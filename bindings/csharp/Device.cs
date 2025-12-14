// D:\quantacore-sdk\bindings\csharp\Device.cs
// QUAC 100 SDK - Device Management
// Copyright © 2025 Dyber, Inc. All Rights Reserved.

using System.Runtime.InteropServices;

namespace Dyber.Quac100;

/// <summary>
/// Represents a QUAC 100 device connection
/// </summary>
public sealed class Device : IDisposable
{
    private IntPtr _handle;
    private bool _disposed;
    private readonly int _deviceIndex;
    private readonly DeviceFlags _flags;

    /// <summary>Native device handle</summary>
    internal IntPtr Handle
    {
        get
        {
            ThrowIfDisposed();
            return _handle;
        }
    }

    /// <summary>Device index</summary>
    public int DeviceIndex => _deviceIndex;

    /// <summary>Device flags</summary>
    public DeviceFlags Flags => _flags;

    /// <summary>Device is open and valid</summary>
    public bool IsOpen => _handle != IntPtr.Zero && !_disposed;

    /// <summary>
    /// Open a QUAC 100 device
    /// </summary>
    /// <param name="deviceIndex">Device index (0 for first device)</param>
    /// <param name="flags">Device operation flags</param>
    /// <exception cref="DeviceNotFoundException">Device not found</exception>
    /// <exception cref="Quac100Exception">Device open failed</exception>
    public Device(int deviceIndex = 0, DeviceFlags flags = DeviceFlags.HardwareAcceleration)
    {
        _deviceIndex = deviceIndex;
        _flags = flags;

        var status = (Quac100Status)NativeMethods.quac_open_device(deviceIndex, (uint)flags, out _handle);
        Quac100Exception.ThrowIfError(status, $"Failed to open device {deviceIndex}");
    }

    /// <summary>
    /// Get device information
    /// </summary>
    public DeviceInfo GetInfo()
    {
        ThrowIfDisposed();

        var status = (Quac100Status)NativeMethods.quac_get_device_info(_handle, out var native);
        Quac100Exception.ThrowIfError(status, "Failed to get device info");

        return new DeviceInfo
        {
            DeviceIndex = native.device_index,
            VendorId = native.vendor_id,
            ProductId = native.product_id,
            SerialNumber = native.serial_number ?? "",
            FirmwareVersion = native.firmware_version ?? "",
            HardwareVersion = native.hardware_version ?? "",
            ModelName = native.model_name ?? "",
            Capabilities = native.capabilities,
            MaxConcurrentOps = native.max_concurrent_ops,
            KeySlots = native.key_slots,
            FipsMode = native.fips_mode != 0,
            HardwareAvailable = native.hardware_available != 0,
        };
    }

    /// <summary>
    /// Get device status
    /// </summary>
    public DeviceStatus GetStatus()
    {
        ThrowIfDisposed();

        var status = (Quac100Status)NativeMethods.quac_get_device_status(_handle, out var native);
        Quac100Exception.ThrowIfError(status, "Failed to get device status");

        return new DeviceStatus
        {
            Temperature = native.temperature,
            PowerMilliwatts = native.power_mw,
            UptimeSeconds = native.uptime_seconds,
            TotalOperations = native.total_operations,
            OpsPerSecond = native.ops_per_second,
            EntropyLevel = native.entropy_level,
            ActiveSessions = native.active_sessions,
            UsedKeySlots = native.used_key_slots,
            LastError = (Quac100Status)native.last_error,
            TamperStatus = native.tamper_status,
        };
    }

    /// <summary>
    /// Reset the device
    /// </summary>
    public void Reset()
    {
        ThrowIfDisposed();

        var status = (Quac100Status)NativeMethods.quac_reset_device(_handle);
        Quac100Exception.ThrowIfError(status, "Failed to reset device");
    }

    /// <summary>
    /// Run device self-test
    /// </summary>
    /// <returns>True if self-test passed</returns>
    public bool SelfTest()
    {
        ThrowIfDisposed();

        var status = (Quac100Status)NativeMethods.quac_self_test(_handle);

        if (status == Quac100Status.Success)
            return true;

        if (status == Quac100Status.SelfTestFailed)
            return false;

        Quac100Exception.ThrowIfError(status, "Self-test error");
        return false;
    }

    /// <summary>
    /// Enumerate all available QUAC 100 devices
    /// </summary>
    /// <param name="maxDevices">Maximum devices to enumerate</param>
    /// <returns>Array of device information</returns>
    public static DeviceInfo[] EnumerateDevices(int maxDevices = 16)
    {
        var natives = new NativeMethods.NativeDeviceInfo[maxDevices];

        var status = (Quac100Status)NativeMethods.quac_enumerate_devices(natives, maxDevices, out int count);
        Quac100Exception.ThrowIfError(status, "Failed to enumerate devices");

        var result = new DeviceInfo[count];
        for (int i = 0; i < count; i++)
        {
            result[i] = new DeviceInfo
            {
                DeviceIndex = natives[i].device_index,
                VendorId = natives[i].vendor_id,
                ProductId = natives[i].product_id,
                SerialNumber = natives[i].serial_number ?? "",
                FirmwareVersion = natives[i].firmware_version ?? "",
                HardwareVersion = natives[i].hardware_version ?? "",
                ModelName = natives[i].model_name ?? "",
                Capabilities = natives[i].capabilities,
                MaxConcurrentOps = natives[i].max_concurrent_ops,
                KeySlots = natives[i].key_slots,
                FipsMode = natives[i].fips_mode != 0,
                HardwareAvailable = natives[i].hardware_available != 0,
            };
        }

        return result;
    }

    /// <summary>
    /// Get number of available devices
    /// </summary>
    public static int GetDeviceCount()
    {
        var natives = new NativeMethods.NativeDeviceInfo[1];
        NativeMethods.quac_enumerate_devices(natives, 0, out int count);
        return count;
    }

    /// <summary>
    /// Open the first available device
    /// </summary>
    public static Device OpenFirst(DeviceFlags flags = DeviceFlags.HardwareAcceleration)
    {
        return new Device(0, flags);
    }

    /// <summary>
    /// Try to open a device, returns null if not found
    /// </summary>
    public static Device? TryOpen(int deviceIndex = 0, DeviceFlags flags = DeviceFlags.HardwareAcceleration)
    {
        try
        {
            return new Device(deviceIndex, flags);
        }
        catch (DeviceNotFoundException)
        {
            return null;
        }
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(Device));
    }

    /// <summary>
    /// Close the device connection
    /// </summary>
    public void Dispose()
    {
        if (_disposed) return;

        if (_handle != IntPtr.Zero)
        {
            NativeMethods.quac_close_device(_handle);
            _handle = IntPtr.Zero;
        }

        _disposed = true;
        GC.SuppressFinalize(this);
    }

    ~Device() => Dispose();
}

/// <summary>
/// Device connection pool for high-throughput applications
/// </summary>
public sealed class DevicePool : IDisposable
{
    private readonly Device[] _devices;
    private readonly SemaphoreSlim[] _semaphores;
    private readonly int _poolSize;
    private bool _disposed;

    /// <summary>Number of devices in the pool</summary>
    public int PoolSize => _poolSize;

    /// <summary>
    /// Create a device pool with the specified number of connections
    /// </summary>
    /// <param name="poolSize">Number of device connections to create</param>
    /// <param name="flags">Device flags</param>
    public DevicePool(int poolSize = 4, DeviceFlags flags = DeviceFlags.HardwareAcceleration)
    {
        if (poolSize < 1)
            throw new ArgumentOutOfRangeException(nameof(poolSize), "Pool size must be at least 1");

        _poolSize = poolSize;
        _devices = new Device[poolSize];
        _semaphores = new SemaphoreSlim[poolSize];

        // Open all devices to the same physical device (different handles)
        for (int i = 0; i < poolSize; i++)
        {
            _devices[i] = new Device(0, flags);
            _semaphores[i] = new SemaphoreSlim(1, 1);
        }
    }

    /// <summary>
    /// Acquire a device from the pool
    /// </summary>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Pooled device handle</returns>
    public async Task<PooledDevice> AcquireAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        // Try to find an available device
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();

            for (int i = 0; i < _poolSize; i++)
            {
                if (await _semaphores[i].WaitAsync(0, cancellationToken))
                {
                    return new PooledDevice(_devices[i], _semaphores[i]);
                }
            }

            // Wait for any device to become available
            await Task.WhenAny(
                _semaphores.Select(s => s.WaitAsync(cancellationToken))
            );
        }
    }

    /// <summary>
    /// Acquire a device from the pool (synchronous)
    /// </summary>
    public PooledDevice Acquire()
    {
        ThrowIfDisposed();

        // Round-robin through devices waiting for availability
        var tasks = _semaphores.Select((s, i) => new { Semaphore = s, Index = i }).ToArray();

        while (true)
        {
            for (int i = 0; i < _poolSize; i++)
            {
                if (_semaphores[i].Wait(0))
                {
                    return new PooledDevice(_devices[i], _semaphores[i]);
                }
            }

            // Wait briefly and retry
            Thread.Sleep(1);
        }
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(DevicePool));
    }

    public void Dispose()
    {
        if (_disposed) return;

        foreach (var device in _devices)
            device?.Dispose();

        foreach (var semaphore in _semaphores)
            semaphore?.Dispose();

        _disposed = true;
    }
}

/// <summary>
/// Wrapper for a pooled device that automatically releases back to pool
/// </summary>
public sealed class PooledDevice : IDisposable
{
    private readonly Device _device;
    private readonly SemaphoreSlim _semaphore;
    private bool _released;

    /// <summary>The underlying device</summary>
    public Device Device => _device;

    internal PooledDevice(Device device, SemaphoreSlim semaphore)
    {
        _device = device;
        _semaphore = semaphore;
    }

    /// <summary>Release the device back to the pool</summary>
    public void Dispose()
    {
        if (_released) return;
        _semaphore.Release();
        _released = true;
    }
}