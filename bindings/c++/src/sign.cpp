/**
 * @file sign.cpp
 * @brief QUAC 100 C++ SDK - Digital Signature Operations Implementation
 * @copyright Copyright © 2025 Dyber, Inc. All Rights Reserved.
 */

#include "quac100/sign.hpp"

extern "C"
{
#include <quac100/quac100.h>
#include <quac100/sign.h>
}

namespace quac100
{

    // Convert C++ SignAlgorithm to C enum
    // C++ ML-DSA: 0,1,2 -> C: 1,2,3 (add 1)
    // C++ SLH-DSA: 10+ -> C: 10+ (same)
    static inline quac_sign_algorithm_t toCAlgorithm(SignAlgorithm alg)
    {
        int val = static_cast<int>(alg);
        if (val <= 2)
        {
            // ML-DSA: add 1
            return static_cast<quac_sign_algorithm_t>(val + 1);
        }
        // SLH-DSA: values match
        return static_cast<quac_sign_algorithm_t>(val);
    }

    // Convert C++ HashAlgorithm to C enum for prehash operations
    // C++: SHA256=0, SHA384=1, SHA512=2, SHA3_256=10, SHA3_384=11, SHA3_512=12, SHAKE128=20, SHAKE256=21
    // C:   SHA256=1, SHA384=2, SHA512=3, SHA3_256=4,  SHA3_384=5,  SHA3_512=6,  SHAKE128=7,  SHAKE256=8
    static inline quac_hash_algorithm_t toCHashAlgorithm(HashAlgorithm alg)
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

    Sign::Sign(quac_device_t device) : device_(device) {}

    SignParams Sign::getParams(SignAlgorithm algorithm)
    {
        SignParams params;

        switch (algorithm)
        {
        case SignAlgorithm::ML_DSA_44:
            params.name = "ML-DSA-44";
            params.publicKeySize = ML_DSA_44_PUBLIC_KEY_SIZE;
            params.secretKeySize = ML_DSA_44_SECRET_KEY_SIZE;
            params.signatureSize = ML_DSA_44_SIGNATURE_SIZE;
            params.securityLevel = 2;
            break;
        case SignAlgorithm::ML_DSA_65:
            params.name = "ML-DSA-65";
            params.publicKeySize = ML_DSA_65_PUBLIC_KEY_SIZE;
            params.secretKeySize = ML_DSA_65_SECRET_KEY_SIZE;
            params.signatureSize = ML_DSA_65_SIGNATURE_SIZE;
            params.securityLevel = 3;
            break;
        case SignAlgorithm::ML_DSA_87:
            params.name = "ML-DSA-87";
            params.publicKeySize = ML_DSA_87_PUBLIC_KEY_SIZE;
            params.secretKeySize = ML_DSA_87_SECRET_KEY_SIZE;
            params.signatureSize = ML_DSA_87_SIGNATURE_SIZE;
            params.securityLevel = 5;
            break;
        case SignAlgorithm::SLH_DSA_SHA2_128S:
        case SignAlgorithm::SLH_DSA_SHAKE_128S:
            params.name = "SLH-DSA-128s";
            params.publicKeySize = 32;
            params.secretKeySize = 64;
            params.signatureSize = 7856;
            params.securityLevel = 1;
            break;
        case SignAlgorithm::SLH_DSA_SHA2_128F:
        case SignAlgorithm::SLH_DSA_SHAKE_128F:
            params.name = "SLH-DSA-128f";
            params.publicKeySize = 32;
            params.secretKeySize = 64;
            params.signatureSize = 17088;
            params.securityLevel = 1;
            break;
        case SignAlgorithm::SLH_DSA_SHA2_192S:
        case SignAlgorithm::SLH_DSA_SHAKE_192S:
            params.name = "SLH-DSA-192s";
            params.publicKeySize = 48;
            params.secretKeySize = 96;
            params.signatureSize = 16224;
            params.securityLevel = 3;
            break;
        case SignAlgorithm::SLH_DSA_SHA2_192F:
        case SignAlgorithm::SLH_DSA_SHAKE_192F:
            params.name = "SLH-DSA-192f";
            params.publicKeySize = 48;
            params.secretKeySize = 96;
            params.signatureSize = 35664;
            params.securityLevel = 3;
            break;
        case SignAlgorithm::SLH_DSA_SHA2_256S:
        case SignAlgorithm::SLH_DSA_SHAKE_256S:
            params.name = "SLH-DSA-256s";
            params.publicKeySize = 64;
            params.secretKeySize = 128;
            params.signatureSize = 29792;
            params.securityLevel = 5;
            break;
        case SignAlgorithm::SLH_DSA_SHA2_256F:
        case SignAlgorithm::SLH_DSA_SHAKE_256F:
            params.name = "SLH-DSA-256f";
            params.publicKeySize = 64;
            params.secretKeySize = 128;
            params.signatureSize = 49856;
            params.securityLevel = 5;
            break;
        default:
            throw CryptoException(ErrorCode::InvalidParam, "Unknown signature algorithm");
        }

        return params;
    }

    KeyPair Sign::generateKeyPair(SignAlgorithm algorithm)
    {
        KeyPair kp;
        auto params = getParams(algorithm);

        kp.publicKey.resize(params.publicKeySize);
        kp.secretKey.resize(params.secretKeySize);

        size_t pkLen = kp.publicKey.size();
        size_t skLen = kp.secretKey.size();

        int status = quac_sign_keygen(
            device_,
            toCAlgorithm(algorithm),
            kp.publicKey.data(),
            &pkLen,
            kp.secretKey.data(),
            &skLen);

        if (status != QUAC_SUCCESS)
        {
            throw CryptoException(status, "Signature key generation failed");
        }

        kp.publicKey.resize(pkLen);
        kp.secretKey.resize(skLen);
        return kp;
    }

    Bytes Sign::sign(SignAlgorithm algorithm, const Bytes &secretKey, const Bytes &message)
    {
        auto params = getParams(algorithm);
        Bytes signature(params.signatureSize);
        size_t sigLen = signature.size();

        int status = quac_sign(
            device_,
            toCAlgorithm(algorithm),
            secretKey.data(),
            secretKey.size(),
            message.data(),
            message.size(),
            signature.data(),
            &sigLen);

        if (status != QUAC_SUCCESS)
        {
            throw CryptoException(status, "Signing failed");
        }

        signature.resize(sigLen);
        return signature;
    }

    Bytes Sign::sign(SignAlgorithm algorithm, const Bytes &secretKey, const std::string &message)
    {
        Bytes msgBytes(message.begin(), message.end());
        return sign(algorithm, secretKey, msgBytes);
    }

    bool Sign::verify(SignAlgorithm algorithm, const Bytes &publicKey, const Bytes &message, const Bytes &signature)
    {
        int status = quac_verify(
            device_,
            toCAlgorithm(algorithm),
            publicKey.data(),
            publicKey.size(),
            message.data(),
            message.size(),
            signature.data(),
            signature.size());

        if (status == QUAC_SUCCESS)
        {
            return true;
        }
        else if (status == QUAC_ERROR_VERIFY_FAILED)
        {
            throw VerificationException("Signature verification failed");
        }
        else
        {
            throw CryptoException(status, "Verification error");
        }
    }

    bool Sign::verify(SignAlgorithm algorithm, const Bytes &publicKey, const std::string &message, const Bytes &signature)
    {
        Bytes msgBytes(message.begin(), message.end());
        return verify(algorithm, publicKey, msgBytes, signature);
    }

    bool Sign::verifyNoThrow(SignAlgorithm algorithm, const Bytes &publicKey, const Bytes &message, const Bytes &signature) noexcept
    {
        int status = quac_verify(
            device_,
            toCAlgorithm(algorithm),
            publicKey.data(),
            publicKey.size(),
            message.data(),
            message.size(),
            signature.data(),
            signature.size());

        return status == QUAC_SUCCESS;
    }

    Bytes Sign::signPrehash(SignAlgorithm algorithm, const Bytes &secretKey, const Bytes &messageHash)
    {
        auto params = getParams(algorithm);
        Bytes signature(params.signatureSize);
        size_t sigLen = signature.size();

        // Use SHA256 as default hash algorithm for prehash
        int status = quac_sign_prehash(
            device_,
            toCAlgorithm(algorithm),
            secretKey.data(),
            secretKey.size(),
            messageHash.data(),
            messageHash.size(),
            QUAC_HASH_SHA256, // hash_alg parameter
            signature.data(),
            &sigLen);

        if (status != QUAC_SUCCESS)
        {
            throw CryptoException(status, "Pre-hash signing failed");
        }

        signature.resize(sigLen);
        return signature;
    }

    bool Sign::verifyPrehash(SignAlgorithm algorithm, const Bytes &publicKey, const Bytes &messageHash, const Bytes &signature)
    {
        int status = quac_verify_prehash(
            device_,
            toCAlgorithm(algorithm),
            publicKey.data(),
            publicKey.size(),
            messageHash.data(),
            messageHash.size(),
            QUAC_HASH_SHA256, // hash_alg parameter
            signature.data(),
            signature.size());

        return status == QUAC_SUCCESS;
    }

    std::vector<KeyPair> Sign::generateKeyPairBatch(SignAlgorithm algorithm, size_t count)
    {
        std::vector<KeyPair> results;
        results.reserve(count);

        for (size_t i = 0; i < count; ++i)
        {
            results.push_back(generateKeyPair(algorithm));
        }

        return results;
    }

    std::vector<Bytes> Sign::signBatch(SignAlgorithm algorithm, const Bytes &secretKey, const std::vector<Bytes> &messages)
    {
        std::vector<Bytes> results;
        results.reserve(messages.size());

        for (const auto &msg : messages)
        {
            results.push_back(sign(algorithm, secretKey, msg));
        }

        return results;
    }

    std::vector<bool> Sign::verifyBatch(SignAlgorithm algorithm, const Bytes &publicKey,
                                        const std::vector<Bytes> &messages, const std::vector<Bytes> &signatures)
    {
        if (messages.size() != signatures.size())
        {
            throw Exception(ErrorCode::InvalidParam, "Message and signature count mismatch");
        }

        std::vector<bool> results;
        results.reserve(messages.size());

        for (size_t i = 0; i < messages.size(); ++i)
        {
            results.push_back(verifyNoThrow(algorithm, publicKey, messages[i], signatures[i]));
        }

        return results;
    }

} // namespace quac100