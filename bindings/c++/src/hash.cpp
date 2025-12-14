/**
 * @file hash.cpp
 * @brief QUAC 100 C++ SDK - Hash Operations Implementation
 * @copyright Copyright © 2025 Dyber, Inc. All Rights Reserved.
 */

#include "quac100/hash.hpp"
#include <fstream>

extern "C"
{
#include <quac100/quac100.h>
#include <quac100/hash.h>
}

namespace quac100
{

    // Convert C++ HashAlgorithm to C enum
    static inline quac_hash_algorithm_t toCAlgorithm(HashAlgorithm alg)
    {
        switch (alg)
        {
        case HashAlgorithm::SHA256:
            return QUAC_HASH_SHA256;
        case HashAlgorithm::SHA384:
            return QUAC_HASH_SHA384;
        case HashAlgorithm::SHA512:
            return QUAC_HASH_SHA512;
        case HashAlgorithm::SHA3_256:
            return QUAC_HASH_SHA3_256;
        case HashAlgorithm::SHA3_384:
            return QUAC_HASH_SHA3_384;
        case HashAlgorithm::SHA3_512:
            return QUAC_HASH_SHA3_512;
        case HashAlgorithm::SHAKE128:
            return QUAC_HASH_SHAKE128;
        case HashAlgorithm::SHAKE256:
            return QUAC_HASH_SHAKE256;
        default:
            return QUAC_HASH_SHA256;
        }
    }

    static size_t getHashSize(HashAlgorithm alg)
    {
        switch (alg)
        {
        case HashAlgorithm::SHA256:
            return 32;
        case HashAlgorithm::SHA384:
            return 48;
        case HashAlgorithm::SHA512:
            return 64;
        case HashAlgorithm::SHA3_256:
            return 32;
        case HashAlgorithm::SHA3_384:
            return 48;
        case HashAlgorithm::SHA3_512:
            return 64;
        case HashAlgorithm::SHAKE128:
            return 32; // Default, can be variable
        case HashAlgorithm::SHAKE256:
            return 64; // Default, can be variable
        default:
            return 32;
        }
    }

    Hash::Hash(quac_device_t device) : device_(device) {}

    Bytes Hash::hash(HashAlgorithm algorithm, const Bytes &data)
    {
        size_t hashSize = getHashSize(algorithm);
        Bytes result(hashSize);
        size_t outLen = hashSize;

        int status = quac_hash(
            device_,
            toCAlgorithm(algorithm),
            data.data(),
            data.size(),
            result.data(),
            &outLen);

        if (status != QUAC_SUCCESS)
        {
            throw CryptoException(status, "Hash computation failed");
        }

        result.resize(outLen);
        return result;
    }

    Bytes Hash::hash(HashAlgorithm algorithm, const uint8_t *data, size_t length)
    {
        size_t hashSize = getHashSize(algorithm);
        Bytes result(hashSize);
        size_t outLen = hashSize;

        int status = quac_hash(
            device_,
            toCAlgorithm(algorithm),
            data,
            length,
            result.data(),
            &outLen);

        if (status != QUAC_SUCCESS)
        {
            throw CryptoException(status, "Hash computation failed");
        }

        result.resize(outLen);
        return result;
    }

    Bytes Hash::hash(HashAlgorithm algorithm, const std::string &data)
    {
        return hash(algorithm, reinterpret_cast<const uint8_t *>(data.data()), data.size());
    }

    Bytes Hash::sha256(const Bytes &data)
    {
        Bytes result(QUAC_SHA256_SIZE);
        int status = quac_sha256(device_, data.data(), data.size(), result.data());
        if (status != QUAC_SUCCESS)
        {
            throw CryptoException(status, "SHA-256 computation failed");
        }
        return result;
    }

    Bytes Hash::sha384(const Bytes &data)
    {
        Bytes result(QUAC_SHA384_SIZE);
        int status = quac_sha384(device_, data.data(), data.size(), result.data());
        if (status != QUAC_SUCCESS)
        {
            throw CryptoException(status, "SHA-384 computation failed");
        }
        return result;
    }

    Bytes Hash::sha512(const Bytes &data)
    {
        Bytes result(QUAC_SHA512_SIZE);
        int status = quac_sha512(device_, data.data(), data.size(), result.data());
        if (status != QUAC_SUCCESS)
        {
            throw CryptoException(status, "SHA-512 computation failed");
        }
        return result;
    }

    Bytes Hash::sha3_256(const Bytes &data)
    {
        Bytes result(QUAC_SHA3_256_SIZE);
        int status = quac_sha3_256(device_, data.data(), data.size(), result.data());
        if (status != QUAC_SUCCESS)
        {
            throw CryptoException(status, "SHA3-256 computation failed");
        }
        return result;
    }

    Bytes Hash::sha3_384(const Bytes &data)
    {
        return hash(HashAlgorithm::SHA3_384, data);
    }

    Bytes Hash::sha3_512(const Bytes &data)
    {
        Bytes result(QUAC_SHA3_512_SIZE);
        int status = quac_sha3_512(device_, data.data(), data.size(), result.data());
        if (status != QUAC_SUCCESS)
        {
            throw CryptoException(status, "SHA3-512 computation failed");
        }
        return result;
    }

    Bytes Hash::shake128(const Bytes &data, size_t outputLength)
    {
        Bytes result(outputLength);
        int status = quac_shake128(device_, data.data(), data.size(), result.data(), outputLength);
        if (status != QUAC_SUCCESS)
        {
            throw CryptoException(status, "SHAKE128 computation failed");
        }
        return result;
    }

    Bytes Hash::shake256(const Bytes &data, size_t outputLength)
    {
        Bytes result(outputLength);
        int status = quac_shake256(device_, data.data(), data.size(), result.data(), outputLength);
        if (status != QUAC_SUCCESS)
        {
            throw CryptoException(status, "SHAKE256 computation failed");
        }
        return result;
    }

    Bytes Hash::hmac(HashAlgorithm algorithm, const Bytes &key, const Bytes &data)
    {
        size_t macSize = getHashSize(algorithm);
        Bytes result(macSize);
        size_t outLen = macSize;

        int status = quac_hmac(
            device_,
            toCAlgorithm(algorithm),
            key.data(),
            key.size(),
            data.data(),
            data.size(),
            result.data(),
            &outLen);

        if (status != QUAC_SUCCESS)
        {
            throw CryptoException(status, "HMAC computation failed");
        }

        result.resize(outLen);
        return result;
    }

    Bytes Hash::hmacSha256(const Bytes &key, const Bytes &data)
    {
        return hmac(HashAlgorithm::SHA256, key, data);
    }

    Bytes Hash::hmacSha512(const Bytes &key, const Bytes &data)
    {
        return hmac(HashAlgorithm::SHA512, key, data);
    }

    Bytes Hash::hkdf(HashAlgorithm algorithm, const Bytes &ikm, const Bytes &salt,
                     const Bytes &info, size_t outputLength)
    {
        Bytes result(outputLength);

        int status = quac_hkdf(
            device_,
            toCAlgorithm(algorithm),
            salt.empty() ? nullptr : salt.data(),
            salt.size(),
            ikm.data(),
            ikm.size(),
            info.empty() ? nullptr : info.data(),
            info.size(),
            result.data(),
            outputLength);

        if (status != QUAC_SUCCESS)
        {
            throw CryptoException(status, "HKDF computation failed");
        }

        return result;
    }

    Hash::Context Hash::createContext(HashAlgorithm algorithm)
    {
        return Context(device_, algorithm);
    }

    Bytes Hash::hashFile(HashAlgorithm algorithm, const std::string &filename)
    {
        std::ifstream file(filename, std::ios::binary);
        if (!file)
        {
            throw CryptoException(ErrorCode::Error, "Failed to open file: " + filename);
        }

        auto ctx = createContext(algorithm);

        char buffer[8192];
        while (file.read(buffer, sizeof(buffer)) || file.gcount() > 0)
        {
            ctx.update(reinterpret_cast<const uint8_t *>(buffer),
                       static_cast<size_t>(file.gcount()));
        }

        return ctx.finalize();
    }

    // Context implementation
    Hash::Context::Context(quac_device_t device, HashAlgorithm algorithm)
        : device_(device), algorithm_(algorithm), ctx_(nullptr)
    {
        int status = quac_hash_init(device_, toCAlgorithm(algorithm_), &ctx_);
        if (status != QUAC_SUCCESS)
        {
            throw CryptoException(status, "Failed to initialize hash context");
        }
    }

    Hash::Context::~Context()
    {
        if (ctx_)
        {
            quac_hash_free(ctx_);
        }
    }

    Hash::Context::Context(Context &&other) noexcept
        : device_(other.device_), algorithm_(other.algorithm_), ctx_(other.ctx_)
    {
        other.ctx_ = nullptr;
    }

    Hash::Context &Hash::Context::operator=(Context &&other) noexcept
    {
        if (this != &other)
        {
            if (ctx_)
            {
                quac_hash_free(ctx_);
            }
            device_ = other.device_;
            algorithm_ = other.algorithm_;
            ctx_ = other.ctx_;
            other.ctx_ = nullptr;
        }
        return *this;
    }

    void Hash::Context::update(const Bytes &data)
    {
        if (!ctx_)
        {
            throw CryptoException(ErrorCode::InvalidHandle, "Context not initialized");
        }
        int status = quac_hash_update(ctx_, data.data(), data.size());
        if (status != QUAC_SUCCESS)
        {
            throw CryptoException(status, "Hash update failed");
        }
    }

    void Hash::Context::update(const uint8_t *data, size_t length)
    {
        if (!ctx_)
        {
            throw CryptoException(ErrorCode::InvalidHandle, "Context not initialized");
        }
        int status = quac_hash_update(ctx_, data, length);
        if (status != QUAC_SUCCESS)
        {
            throw CryptoException(status, "Hash update failed");
        }
    }

    void Hash::Context::update(const std::string &data)
    {
        update(reinterpret_cast<const uint8_t *>(data.data()), data.size());
    }

    Bytes Hash::Context::finalize()
    {
        if (!ctx_)
        {
            throw CryptoException(ErrorCode::InvalidHandle, "Context not initialized");
        }

        size_t hashSize = getHashSize(algorithm_);
        Bytes result(hashSize);
        size_t outLen = hashSize;

        int status = quac_hash_final(ctx_, result.data(), &outLen);
        if (status != QUAC_SUCCESS)
        {
            throw CryptoException(status, "Hash finalization failed");
        }

        ctx_ = nullptr; // Context is invalidated after finalize
        result.resize(outLen);
        return result;
    }

    void Hash::Context::reset()
    {
        if (ctx_)
        {
            quac_hash_free(ctx_);
        }
        int status = quac_hash_init(device_, toCAlgorithm(algorithm_), &ctx_);
        if (status != QUAC_SUCCESS)
        {
            throw CryptoException(status, "Failed to reset hash context");
        }
    }

} // namespace quac100