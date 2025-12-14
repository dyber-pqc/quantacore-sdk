/**
 * @file types.hpp
 * @brief QUAC 100 C++ SDK - Type Definitions
 * @copyright Copyright © 2025 Dyber, Inc. All Rights Reserved.
 */

#ifndef QUAC100_TYPES_HPP
#define QUAC100_TYPES_HPP

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <array>
#include <optional>
#include <functional>

namespace quac100
{

    /*============================================================================
     * Constants
     *============================================================================*/

    constexpr uint32_t FLAG_DEFAULT = 0;
    constexpr uint32_t FLAG_VERBOSE = 1;
    constexpr uint32_t FLAG_SIMULATION = 2;

    constexpr int MAX_DEVICES = 16;

    // ML-KEM sizes
    constexpr size_t ML_KEM_512_PUBLIC_KEY_SIZE = 800;
    constexpr size_t ML_KEM_512_SECRET_KEY_SIZE = 1632;
    constexpr size_t ML_KEM_512_CIPHERTEXT_SIZE = 768;

    constexpr size_t ML_KEM_768_PUBLIC_KEY_SIZE = 1184;
    constexpr size_t ML_KEM_768_SECRET_KEY_SIZE = 2400;
    constexpr size_t ML_KEM_768_CIPHERTEXT_SIZE = 1088;

    constexpr size_t ML_KEM_1024_PUBLIC_KEY_SIZE = 1568;
    constexpr size_t ML_KEM_1024_SECRET_KEY_SIZE = 3168;
    constexpr size_t ML_KEM_1024_CIPHERTEXT_SIZE = 1568;

    constexpr size_t ML_KEM_SHARED_SECRET_SIZE = 32;

    // ML-DSA sizes
    constexpr size_t ML_DSA_44_PUBLIC_KEY_SIZE = 1312;
    constexpr size_t ML_DSA_44_SECRET_KEY_SIZE = 2560;
    constexpr size_t ML_DSA_44_SIGNATURE_SIZE = 2420;

    constexpr size_t ML_DSA_65_PUBLIC_KEY_SIZE = 1952;
    constexpr size_t ML_DSA_65_SECRET_KEY_SIZE = 4032;
    constexpr size_t ML_DSA_65_SIGNATURE_SIZE = 3309;

    constexpr size_t ML_DSA_87_PUBLIC_KEY_SIZE = 2592;
    constexpr size_t ML_DSA_87_SECRET_KEY_SIZE = 4896;
    constexpr size_t ML_DSA_87_SIGNATURE_SIZE = 4627;

    // Hash sizes
    constexpr size_t SHA256_SIZE = 32;
    constexpr size_t SHA384_SIZE = 48;
    constexpr size_t SHA512_SIZE = 64;
    constexpr size_t SHA3_256_SIZE = 32;
    constexpr size_t SHA3_384_SIZE = 48;
    constexpr size_t SHA3_512_SIZE = 64;

    /*============================================================================
     * Enumerations
     *============================================================================*/

    enum class KemAlgorithm
    {
        ML_KEM_512 = 0,
        ML_KEM_768 = 1,
        ML_KEM_1024 = 2
    };

    enum class SignAlgorithm
    {
        ML_DSA_44 = 0,
        ML_DSA_65 = 1,
        ML_DSA_87 = 2,
        SLH_DSA_SHA2_128S = 10,
        SLH_DSA_SHA2_128F = 11,
        SLH_DSA_SHA2_192S = 12,
        SLH_DSA_SHA2_192F = 13,
        SLH_DSA_SHA2_256S = 14,
        SLH_DSA_SHA2_256F = 15,
        SLH_DSA_SHAKE_128S = 20,
        SLH_DSA_SHAKE_128F = 21,
        SLH_DSA_SHAKE_192S = 22,
        SLH_DSA_SHAKE_192F = 23,
        SLH_DSA_SHAKE_256S = 24,
        SLH_DSA_SHAKE_256F = 25
    };

    enum class HashAlgorithm
    {
        SHA256 = 0,
        SHA384 = 1,
        SHA512 = 2,
        SHA3_256 = 10,
        SHA3_384 = 11,
        SHA3_512 = 12,
        SHAKE128 = 20,
        SHAKE256 = 21
    };

    enum class EntropySource
    {
        Default = 0,
        QRNG = 1,
        HybridQRNG = 2,
        SystemRNG = 3
    };

    enum class KeyType
    {
        Unknown = 0,
        KemPublic = 1,
        KemSecret = 2,
        SignPublic = 3,
        SignSecret = 4,
        Symmetric = 5
    };

    enum class KeyUsage : uint32_t
    {
        None = 0,
        Encrypt = 1 << 0,
        Decrypt = 1 << 1,
        Sign = 1 << 2,
        Verify = 1 << 3,
        Wrap = 1 << 4,
        Unwrap = 1 << 5,
        Derive = 1 << 6,
        All = 0xFFFFFFFF
    };

    inline KeyUsage operator|(KeyUsage a, KeyUsage b)
    {
        return static_cast<KeyUsage>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
    }

    inline KeyUsage operator&(KeyUsage a, KeyUsage b)
    {
        return static_cast<KeyUsage>(static_cast<uint32_t>(a) & static_cast<uint32_t>(b));
    }

    /*============================================================================
     * Structures
     *============================================================================*/

    struct Version
    {
        int major;
        int minor;
        int patch;

        std::string toString() const
        {
            return std::to_string(major) + "." + std::to_string(minor) + "." + std::to_string(patch);
        }
    };

    struct DeviceInfo
    {
        int index;
        std::string modelName;
        std::string serialNumber;
        std::string firmwareVersion;
        int keySlots;
        uint32_t capabilities;
    };

    struct DeviceStatus
    {
        float temperature;
        int entropyLevel;
        uint64_t totalOperations;
        uint64_t totalErrors;
        bool isHealthy;
    };

    struct KemParams
    {
        std::string name;
        size_t publicKeySize;
        size_t secretKeySize;
        size_t ciphertextSize;
        size_t sharedSecretSize;
        int securityLevel;
    };

    struct SignParams
    {
        std::string name;
        size_t publicKeySize;
        size_t secretKeySize;
        size_t signatureSize;
        int securityLevel;
    };

    struct EntropyStatus
    {
        int level;
        bool healthOk;
        uint64_t bytesGenerated;
        double bitRate;
    };

    struct KeyInfo
    {
        int slot;
        std::string label;
        KeyType type;
        int algorithm;
        KeyUsage usage;
        bool exportable;
        uint64_t createdAt;
    };

    /*============================================================================
     * Type Aliases
     *============================================================================*/

    using Bytes = std::vector<uint8_t>;

    struct KeyPair
    {
        Bytes publicKey;
        Bytes secretKey;
    };

    struct EncapsResult
    {
        Bytes ciphertext;
        Bytes sharedSecret;
    };

    using AsyncCallback = std::function<void(bool success, const std::string &error)>;

} // namespace quac100

#endif // QUAC100_TYPES_HPP