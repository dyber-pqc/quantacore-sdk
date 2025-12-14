// D:\quantacore-sdk\bindings\csharp\Exceptions.cs
// QUAC 100 SDK - Exception Types
// Copyright © 2025 Dyber, Inc. All Rights Reserved.

namespace Dyber.Quac100;

/// <summary>
/// Base exception for all QUAC 100 errors
/// </summary>
public class Quac100Exception : Exception
{
    /// <summary>Error status code</summary>
    public Quac100Status Status { get; }

    /// <summary>Native error code (if available)</summary>
    public int NativeErrorCode { get; }

    public Quac100Exception(string message)
        : base(message)
    {
        Status = Quac100Status.Error;
    }

    public Quac100Exception(string message, Quac100Status status)
        : base(message)
    {
        Status = status;
    }

    public Quac100Exception(string message, Quac100Status status, int nativeError)
        : base(message)
    {
        Status = status;
        NativeErrorCode = nativeError;
    }

    public Quac100Exception(string message, Exception innerException)
        : base(message, innerException)
    {
        Status = Quac100Status.Error;
    }

    public Quac100Exception(Quac100Status status)
        : base(GetDefaultMessage(status))
    {
        Status = status;
    }

    internal static string GetDefaultMessage(Quac100Status status)
    {
        return status switch
        {
            Quac100Status.Success => "Operation completed successfully",
            Quac100Status.Error => "An unspecified error occurred",
            Quac100Status.InvalidParameter => "Invalid parameter provided",
            Quac100Status.BufferTooSmall => "Output buffer too small",
            Quac100Status.DeviceNotFound => "QUAC 100 device not found",
            Quac100Status.DeviceBusy => "Device is busy",
            Quac100Status.DeviceError => "Device error occurred",
            Quac100Status.OutOfMemory => "Memory allocation failed",
            Quac100Status.NotSupported => "Operation not supported",
            Quac100Status.AuthRequired => "Authentication required",
            Quac100Status.AuthFailed => "Authentication failed",
            Quac100Status.KeyNotFound => "Key not found",
            Quac100Status.InvalidKey => "Invalid key",
            Quac100Status.VerifyFailed => "Signature verification failed",
            Quac100Status.DecapsFailed => "Decapsulation failed",
            Quac100Status.HardwareNotAvailable => "Hardware acceleration not available",
            Quac100Status.Timeout => "Operation timed out",
            Quac100Status.NotInitialized => "Library not initialized",
            Quac100Status.AlreadyInitialized => "Library already initialized",
            Quac100Status.InvalidHandle => "Invalid handle",
            Quac100Status.Cancelled => "Operation cancelled",
            Quac100Status.EntropyDepleted => "Entropy source depleted",
            Quac100Status.SelfTestFailed => "Self-test failed",
            Quac100Status.TamperDetected => "Tamper detected",
            Quac100Status.TemperatureError => "Temperature out of range",
            Quac100Status.PowerError => "Power supply issue",
            _ => $"Unknown error: {status}"
        };
    }

    internal static void ThrowIfError(Quac100Status status, string? context = null)
    {
        if (status == Quac100Status.Success)
            return;

        var message = context != null
            ? $"{context}: {GetDefaultMessage(status)}"
            : GetDefaultMessage(status);

        throw status switch
        {
            Quac100Status.DeviceNotFound => new DeviceNotFoundException(message),
            Quac100Status.DeviceBusy => new DeviceBusyException(message),
            Quac100Status.DeviceError => new DeviceException(message, status),
            Quac100Status.AuthRequired or Quac100Status.AuthFailed => new AuthenticationException(message, status),
            Quac100Status.KeyNotFound => new KeyNotFoundException(message),
            Quac100Status.InvalidKey => new InvalidKeyException(message),
            Quac100Status.VerifyFailed => new SignatureVerificationException(message),
            Quac100Status.DecapsFailed => new DecapsulationException(message),
            Quac100Status.HardwareNotAvailable => new HardwareNotAvailableException(message),
            Quac100Status.Timeout => new TimeoutException(message),
            Quac100Status.TamperDetected => new TamperException(message),
            Quac100Status.SelfTestFailed => new SelfTestException(message),
            Quac100Status.EntropyDepleted => new EntropyDepletedException(message),
            _ => new Quac100Exception(message, status)
        };
    }
}

/// <summary>
/// Device not found exception
/// </summary>
public class DeviceNotFoundException : Quac100Exception
{
    public DeviceNotFoundException()
        : base(Quac100Status.DeviceNotFound) { }

    public DeviceNotFoundException(string message)
        : base(message, Quac100Status.DeviceNotFound) { }
}

/// <summary>
/// Device busy exception
/// </summary>
public class DeviceBusyException : Quac100Exception
{
    public DeviceBusyException()
        : base(Quac100Status.DeviceBusy) { }

    public DeviceBusyException(string message)
        : base(message, Quac100Status.DeviceBusy) { }
}

/// <summary>
/// Generic device exception
/// </summary>
public class DeviceException : Quac100Exception
{
    public DeviceException(string message)
        : base(message, Quac100Status.DeviceError) { }

    public DeviceException(string message, Quac100Status status)
        : base(message, status) { }
}

/// <summary>
/// Authentication exception
/// </summary>
public class AuthenticationException : Quac100Exception
{
    public AuthenticationException(string message)
        : base(message, Quac100Status.AuthFailed) { }

    public AuthenticationException(string message, Quac100Status status)
        : base(message, status) { }
}

/// <summary>
/// Key not found exception
/// </summary>
public class KeyNotFoundException : Quac100Exception
{
    public KeyNotFoundException()
        : base(Quac100Status.KeyNotFound) { }

    public KeyNotFoundException(string message)
        : base(message, Quac100Status.KeyNotFound) { }
}

/// <summary>
/// Invalid key exception
/// </summary>
public class InvalidKeyException : Quac100Exception
{
    public InvalidKeyException()
        : base(Quac100Status.InvalidKey) { }

    public InvalidKeyException(string message)
        : base(message, Quac100Status.InvalidKey) { }
}

/// <summary>
/// Signature verification failed exception
/// </summary>
public class SignatureVerificationException : Quac100Exception
{
    public SignatureVerificationException()
        : base(Quac100Status.VerifyFailed) { }

    public SignatureVerificationException(string message)
        : base(message, Quac100Status.VerifyFailed) { }
}

/// <summary>
/// Decapsulation failed exception
/// </summary>
public class DecapsulationException : Quac100Exception
{
    public DecapsulationException()
        : base(Quac100Status.DecapsFailed) { }

    public DecapsulationException(string message)
        : base(message, Quac100Status.DecapsFailed) { }
}

/// <summary>
/// Hardware not available exception
/// </summary>
public class HardwareNotAvailableException : Quac100Exception
{
    public HardwareNotAvailableException()
        : base(Quac100Status.HardwareNotAvailable) { }

    public HardwareNotAvailableException(string message)
        : base(message, Quac100Status.HardwareNotAvailable) { }
}

/// <summary>
/// Tamper detected exception
/// </summary>
public class TamperException : Quac100Exception
{
    public TamperException()
        : base(Quac100Status.TamperDetected) { }

    public TamperException(string message)
        : base(message, Quac100Status.TamperDetected) { }
}

/// <summary>
/// Self-test failed exception
/// </summary>
public class SelfTestException : Quac100Exception
{
    public SelfTestException()
        : base(Quac100Status.SelfTestFailed) { }

    public SelfTestException(string message)
        : base(message, Quac100Status.SelfTestFailed) { }
}

/// <summary>
/// Entropy depleted exception
/// </summary>
public class EntropyDepletedException : Quac100Exception
{
    public EntropyDepletedException()
        : base(Quac100Status.EntropyDepleted) { }

    public EntropyDepletedException(string message)
        : base(message, Quac100Status.EntropyDepleted) { }
}