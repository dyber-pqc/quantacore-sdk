/**
 * @file random.cpp
 * @brief QUAC 100 C++ SDK - Random Number Generation Implementation
 * @copyright Copyright © 2025 Dyber, Inc. All Rights Reserved.
 */

#include "quac100/random.hpp"
#include <cstring>
#include <sstream>
#include <iomanip>

extern "C"
{
#include <quac100/quac100.h>
#include <quac100/random.h>
}

namespace quac100
{

    Random::Random(quac_device_t device) : device_(device) {}

    Bytes Random::bytes(size_t length)
    {
        Bytes data(length);

        int status = quac_random_bytes(device_, data.data(), length);
        if (status != QUAC_SUCCESS)
        {
            throw CryptoException(status, "Random generation failed");
        }

        return data;
    }

    void Random::fill(uint8_t *buffer, size_t length)
    {
        int status = quac_random_bytes(device_, buffer, length);
        if (status != QUAC_SUCCESS)
        {
            throw CryptoException(status, "Random fill failed");
        }
    }

    uint32_t Random::uint32()
    {
        uint32_t value;
        int status = quac_random_uint32(device_, &value);
        if (status != QUAC_SUCCESS)
        {
            throw CryptoException(status, "Random uint32 generation failed");
        }
        return value;
    }

    uint64_t Random::uint64()
    {
        uint64_t value;
        int status = quac_random_uint64(device_, &value);
        if (status != QUAC_SUCCESS)
        {
            throw CryptoException(status, "Random uint64 generation failed");
        }
        return value;
    }

    uint64_t Random::range(uint64_t max)
    {
        if (max == 0)
        {
            throw Exception(ErrorCode::InvalidParam, "Range max must be > 0");
        }

        // For 32-bit range, use the C API directly
        if (max <= UINT32_MAX)
        {
            uint32_t value;
            int status = quac_random_range(device_, static_cast<uint32_t>(max), &value);
            if (status != QUAC_SUCCESS)
            {
                throw CryptoException(status, "Random range generation failed");
            }
            return value;
        }

        // For 64-bit, use rejection sampling
        uint64_t threshold = (UINT64_MAX / max) * max;
        uint64_t value;
        do
        {
            value = uint64();
        } while (value >= threshold);

        return value % max;
    }

    uint64_t Random::range(uint64_t min, uint64_t max)
    {
        if (min >= max)
        {
            throw Exception(ErrorCode::InvalidParam, "Range min must be < max");
        }
        return min + range(max - min);
    }

    double Random::uniform()
    {
        double value;
        int status = quac_random_double(device_, &value);
        if (status != QUAC_SUCCESS)
        {
            throw CryptoException(status, "Random double generation failed");
        }
        return value;
    }

    std::string Random::uuid()
    {
        char uuid_str[37];
        int status = quac_random_uuid_string(device_, uuid_str, sizeof(uuid_str));
        if (status != QUAC_SUCCESS)
        {
            // Fallback: generate manually
            Bytes data = bytes(16);

            // Set version 4 (random)
            data[6] = (data[6] & 0x0F) | 0x40;
            // Set variant (RFC 4122)
            data[8] = (data[8] & 0x3F) | 0x80;

            // Format as UUID string
            std::stringstream ss;
            ss << std::hex << std::setfill('0');

            for (size_t i = 0; i < 16; ++i)
            {
                if (i == 4 || i == 6 || i == 8 || i == 10)
                {
                    ss << '-';
                }
                ss << std::setw(2) << static_cast<int>(data[i]);
            }

            return ss.str();
        }

        return std::string(uuid_str);
    }

    EntropyStatus Random::entropyStatus()
    {
        EntropyStatus status;
        quac_entropy_status_t cstatus;

        int result = quac_entropy_status(device_, &cstatus);
        if (result != QUAC_SUCCESS)
        {
            throw CryptoException(result, "Failed to get entropy status");
        }

        status.level = cstatus.level;
        status.healthOk = cstatus.health_ok;
        status.bytesGenerated = cstatus.bytes_generated;
        status.bitRate = 0.0; // Not available in C struct

        return status;
    }

    void Random::setEntropySource(EntropySource source)
    {
        // The C API doesn't have quac_entropy_set_source
        // We can use quac_random_bytes_ex with source parameter instead
        // For now, just store the preference (would need implementation support)
        (void)source;
        // Note: This is a no-op since the C API doesn't support this directly
    }

} // namespace quac100