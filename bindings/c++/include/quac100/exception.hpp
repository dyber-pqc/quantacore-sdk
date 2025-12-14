/**
 * @file exception.hpp
 * @brief QUAC 100 C++ SDK - Exception Classes
 * @copyright Copyright © 2025 Dyber, Inc. All Rights Reserved.
 */

#ifndef QUAC100_EXCEPTION_HPP
#define QUAC100_EXCEPTION_HPP

#include <stdexcept>
#include <string>

namespace quac100
{

    /**
     * @brief Error codes matching C API
     */
    enum class ErrorCode
    {
        Success = 0,
        Error = -1,
        InvalidParam = -2,
        BufferSmall = -3,
        DeviceNotFound = -4,
        DeviceBusy = -5,
        DeviceError = -6,
        OutOfMemory = -7,
        NotSupported = -8,
        AuthRequired = -9,
        AuthFailed = -10,
        KeyNotFound = -11,
        InvalidKey = -12,
        VerifyFailed = -13,
        DecapsFailed = -14,
        HardwareUnavail = -15,
        Timeout = -16,
        NotInitialized = -17,
        AlreadyInit = -18,
        InvalidHandle = -19,
        Cancelled = -20,
        EntropyDepleted = -21,
        SelfTestFailed = -22,
        TamperDetected = -23,
        Temperature = -24,
        Power = -25,
        Internal = -99
    };

    /**
     * @brief Base exception class for QUAC 100 errors
     */
    class Exception : public std::runtime_error
    {
    public:
        Exception(int code, const std::string &message)
            : std::runtime_error(message), code_(static_cast<ErrorCode>(code)), message_(message) {}

        Exception(ErrorCode code, const std::string &message)
            : std::runtime_error(message), code_(code), message_(message) {}

        ErrorCode code() const noexcept { return code_; }
        int codeInt() const noexcept { return static_cast<int>(code_); }
        const std::string &message() const noexcept { return message_; }

    private:
        ErrorCode code_;
        std::string message_;
    };

    /**
     * @brief Device-related exception
     */
    class DeviceException : public Exception
    {
    public:
        using Exception::Exception;
    };

    /**
     * @brief Cryptographic operation exception
     */
    class CryptoException : public Exception
    {
    public:
        using Exception::Exception;
    };

    /**
     * @brief Verification failure exception
     */
    class VerificationException : public Exception
    {
    public:
        VerificationException(const std::string &message = "Verification failed")
            : Exception(ErrorCode::VerifyFailed, message) {}
    };

    /**
     * @brief Key storage exception
     */
    class KeyStorageException : public Exception
    {
    public:
        using Exception::Exception;
    };

} // namespace quac100

#endif // QUAC100_EXCEPTION_HPP