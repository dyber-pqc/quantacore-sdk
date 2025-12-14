/**
 * @file utils.cpp
 * @brief QUAC 100 C++ SDK - Utility Functions Implementation
 * @copyright Copyright © 2025 Dyber, Inc. All Rights Reserved.
 */

#include "quac100/utils.hpp"
#include "quac100/exception.hpp"
#include <cstring>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <ctime>

#ifdef _WIN32
#include <windows.h>
#endif

extern "C"
{
#include <quac100/quac100.h>
#include <quac100/utils.h>
}

namespace quac100
{
    namespace utils
    {

        void secureZero(void *ptr, size_t size)
        {
            quac_secure_zero(ptr, size);
        }

        bool secureCompare(const void *a, const void *b, size_t size)
        {
            return quac_secure_compare(a, b, size) == 0;
        }

        std::string toHex(const Bytes &data, bool uppercase)
        {
            if (data.empty())
                return "";

            // Calculate required size: 2 chars per byte + null terminator
            size_t bufSize = data.size() * 2 + 1;
            std::vector<char> buffer(bufSize);

            int status = quac_hex_encode(data.data(), data.size(), buffer.data(), bufSize, uppercase);
            if (status != QUAC_SUCCESS)
            {
                throw Exception(status, "Hex encoding failed");
            }

            return std::string(buffer.data());
        }

        std::string toHex(const uint8_t *data, size_t length, bool uppercase)
        {
            if (length == 0)
                return "";

            size_t bufSize = length * 2 + 1;
            std::vector<char> buffer(bufSize);

            int status = quac_hex_encode(data, length, buffer.data(), bufSize, uppercase);
            if (status != QUAC_SUCCESS)
            {
                throw Exception(status, "Hex encoding failed");
            }

            return std::string(buffer.data());
        }

        Bytes fromHex(const std::string &hex)
        {
            if (hex.empty())
                return Bytes();

            if (hex.length() % 2 != 0)
            {
                throw Exception(ErrorCode::InvalidParam, "Hex string must have even length");
            }

            Bytes data(hex.length() / 2);
            size_t dataLen = data.size();

            int status = quac_hex_decode(hex.c_str(), data.data(), &dataLen);
            if (status != QUAC_SUCCESS)
            {
                throw Exception(status, "Hex decoding failed");
            }

            data.resize(dataLen);
            return data;
        }

        std::string toBase64(const Bytes &data)
        {
            if (data.empty())
                return "";

            // Base64 output size: ceil(input_size / 3) * 4 + 1 for null terminator
            size_t bufSize = ((data.size() + 2) / 3) * 4 + 1;
            std::vector<char> buffer(bufSize);

            int status = quac_base64_encode(data.data(), data.size(), buffer.data(), bufSize);
            if (status != QUAC_SUCCESS)
            {
                throw Exception(status, "Base64 encoding failed");
            }

            return std::string(buffer.data());
        }

        std::string toBase64(const uint8_t *data, size_t length)
        {
            if (length == 0)
                return "";

            size_t bufSize = ((length + 2) / 3) * 4 + 1;
            std::vector<char> buffer(bufSize);

            int status = quac_base64_encode(data, length, buffer.data(), bufSize);
            if (status != QUAC_SUCCESS)
            {
                throw Exception(status, "Base64 encoding failed");
            }

            return std::string(buffer.data());
        }

        Bytes fromBase64(const std::string &b64)
        {
            if (b64.empty())
                return Bytes();

            // Decoded size is at most 3/4 of encoded size
            Bytes data((b64.length() * 3) / 4);
            size_t dataLen = data.size();

            int status = quac_base64_decode(b64.c_str(), data.data(), &dataLen);
            if (status != QUAC_SUCCESS)
            {
                throw Exception(status, "Base64 decoding failed");
            }

            data.resize(dataLen);
            return data;
        }

        std::string formatBytes(const Bytes &data, size_t maxLength)
        {
            if (data.empty())
                return "(empty)";

            std::ostringstream oss;
            size_t displayLen = (maxLength > 0 && data.size() > maxLength) ? maxLength : data.size();

            oss << std::hex << std::setfill('0');
            for (size_t i = 0; i < displayLen; ++i)
            {
                oss << std::setw(2) << static_cast<int>(data[i]);
            }

            if (maxLength > 0 && data.size() > maxLength)
            {
                oss << "...(" << data.size() << " bytes total)";
            }

            return oss.str();
        }

        std::string formatSize(size_t bytes)
        {
            const char *units[] = {"B", "KB", "MB", "GB", "TB"};
            int unitIndex = 0;
            double size = static_cast<double>(bytes);

            while (size >= 1024.0 && unitIndex < 4)
            {
                size /= 1024.0;
                unitIndex++;
            }

            std::ostringstream oss;
            if (unitIndex == 0)
            {
                oss << bytes << " " << units[unitIndex];
            }
            else
            {
                oss << std::fixed << std::setprecision(2) << size << " " << units[unitIndex];
            }

            return oss.str();
        }

        std::string formatDuration(double seconds)
        {
            std::ostringstream oss;

            if (seconds < 0.000001)
            {
                oss << std::fixed << std::setprecision(2) << (seconds * 1e9) << " ns";
            }
            else if (seconds < 0.001)
            {
                oss << std::fixed << std::setprecision(2) << (seconds * 1e6) << " us";
            }
            else if (seconds < 1.0)
            {
                oss << std::fixed << std::setprecision(2) << (seconds * 1e3) << " ms";
            }
            else if (seconds < 60.0)
            {
                oss << std::fixed << std::setprecision(2) << seconds << " s";
            }
            else
            {
                int mins = static_cast<int>(seconds) / 60;
                double secs = seconds - mins * 60;
                oss << mins << "m " << std::fixed << std::setprecision(1) << secs << "s";
            }

            return oss.str();
        }

        std::string algorithmName(KemAlgorithm algorithm)
        {
            switch (algorithm)
            {
            case KemAlgorithm::ML_KEM_512:
                return "ML-KEM-512";
            case KemAlgorithm::ML_KEM_768:
                return "ML-KEM-768";
            case KemAlgorithm::ML_KEM_1024:
                return "ML-KEM-1024";
            default:
                return "Unknown KEM";
            }
        }

        std::string algorithmName(SignAlgorithm algorithm)
        {
            switch (algorithm)
            {
            case SignAlgorithm::ML_DSA_44:
                return "ML-DSA-44";
            case SignAlgorithm::ML_DSA_65:
                return "ML-DSA-65";
            case SignAlgorithm::ML_DSA_87:
                return "ML-DSA-87";
            case SignAlgorithm::SLH_DSA_SHA2_128S:
                return "SLH-DSA-SHA2-128s";
            case SignAlgorithm::SLH_DSA_SHA2_128F:
                return "SLH-DSA-SHA2-128f";
            case SignAlgorithm::SLH_DSA_SHA2_192S:
                return "SLH-DSA-SHA2-192s";
            case SignAlgorithm::SLH_DSA_SHA2_192F:
                return "SLH-DSA-SHA2-192f";
            case SignAlgorithm::SLH_DSA_SHA2_256S:
                return "SLH-DSA-SHA2-256s";
            case SignAlgorithm::SLH_DSA_SHA2_256F:
                return "SLH-DSA-SHA2-256f";
            case SignAlgorithm::SLH_DSA_SHAKE_128S:
                return "SLH-DSA-SHAKE-128s";
            case SignAlgorithm::SLH_DSA_SHAKE_128F:
                return "SLH-DSA-SHAKE-128f";
            case SignAlgorithm::SLH_DSA_SHAKE_192S:
                return "SLH-DSA-SHAKE-192s";
            case SignAlgorithm::SLH_DSA_SHAKE_192F:
                return "SLH-DSA-SHAKE-192f";
            case SignAlgorithm::SLH_DSA_SHAKE_256S:
                return "SLH-DSA-SHAKE-256s";
            case SignAlgorithm::SLH_DSA_SHAKE_256F:
                return "SLH-DSA-SHAKE-256f";
            default:
                return "Unknown Signature";
            }
        }

        std::string algorithmName(HashAlgorithm algorithm)
        {
            switch (algorithm)
            {
            case HashAlgorithm::SHA256:
                return "SHA-256";
            case HashAlgorithm::SHA384:
                return "SHA-384";
            case HashAlgorithm::SHA512:
                return "SHA-512";
            case HashAlgorithm::SHA3_256:
                return "SHA3-256";
            case HashAlgorithm::SHA3_384:
                return "SHA3-384";
            case HashAlgorithm::SHA3_512:
                return "SHA3-512";
            case HashAlgorithm::SHAKE128:
                return "SHAKE128";
            case HashAlgorithm::SHAKE256:
                return "SHAKE256";
            default:
                return "Unknown Hash";
            }
        }

        bool isKemAlgorithm(int algorithm)
        {
            return quac_is_kem_algorithm(algorithm) != 0;
        }

        bool isSignAlgorithm(int algorithm)
        {
            return quac_is_sign_algorithm(algorithm) != 0;
        }

        bool isMlDsa(SignAlgorithm algorithm)
        {
            int val = static_cast<int>(algorithm);
            return val >= 0 && val <= 2;
        }

        bool isSlhDsa(SignAlgorithm algorithm)
        {
            int val = static_cast<int>(algorithm);
            return val >= 10;
        }

        uint64_t timestampMs()
        {
            return quac_timestamp_ms();
        }

        std::string formatTimestamp(uint64_t timestampMs)
        {
            time_t seconds = static_cast<time_t>(timestampMs / 1000);
            int millis = static_cast<int>(timestampMs % 1000);

            struct tm tmBuf;
#ifdef _WIN32
            localtime_s(&tmBuf, &seconds);
#else
            localtime_r(&seconds, &tmBuf);
#endif

            std::ostringstream oss;
            oss << std::put_time(&tmBuf, "%Y-%m-%d %H:%M:%S")
                << "." << std::setfill('0') << std::setw(3) << millis;

            return oss.str();
        }

    } // namespace utils
} // namespace quac100