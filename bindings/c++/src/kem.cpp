/**
 * @file kem.cpp
 * @brief QUAC 100 C++ SDK - KEM Operations Implementation
 * @copyright Copyright © 2025 Dyber, Inc. All Rights Reserved.
 */

#include "quac100/kem.hpp"

extern "C"
{
#include <quac100/quac100.h>
#include <quac100/kem.h>
}

namespace quac100
{

    // Convert C++ enum to C enum (C++ starts at 0, C starts at 1)
    static inline quac_kem_algorithm_t toCAlgorithm(KemAlgorithm alg)
    {
        return static_cast<quac_kem_algorithm_t>(static_cast<int>(alg) + 1);
    }

    Kem::Kem(quac_device_t device) : device_(device) {}

    KemParams Kem::getParams(KemAlgorithm algorithm)
    {
        KemParams params;

        switch (algorithm)
        {
        case KemAlgorithm::ML_KEM_512:
            params.name = "ML-KEM-512";
            params.publicKeySize = ML_KEM_512_PUBLIC_KEY_SIZE;
            params.secretKeySize = ML_KEM_512_SECRET_KEY_SIZE;
            params.ciphertextSize = ML_KEM_512_CIPHERTEXT_SIZE;
            params.sharedSecretSize = ML_KEM_SHARED_SECRET_SIZE;
            params.securityLevel = 1;
            break;
        case KemAlgorithm::ML_KEM_768:
            params.name = "ML-KEM-768";
            params.publicKeySize = ML_KEM_768_PUBLIC_KEY_SIZE;
            params.secretKeySize = ML_KEM_768_SECRET_KEY_SIZE;
            params.ciphertextSize = ML_KEM_768_CIPHERTEXT_SIZE;
            params.sharedSecretSize = ML_KEM_SHARED_SECRET_SIZE;
            params.securityLevel = 3;
            break;
        case KemAlgorithm::ML_KEM_1024:
            params.name = "ML-KEM-1024";
            params.publicKeySize = ML_KEM_1024_PUBLIC_KEY_SIZE;
            params.secretKeySize = ML_KEM_1024_SECRET_KEY_SIZE;
            params.ciphertextSize = ML_KEM_1024_CIPHERTEXT_SIZE;
            params.sharedSecretSize = ML_KEM_SHARED_SECRET_SIZE;
            params.securityLevel = 5;
            break;
        default:
            throw CryptoException(ErrorCode::InvalidParam, "Unknown KEM algorithm");
        }

        return params;
    }

    KeyPair Kem::generateKeyPair(KemAlgorithm algorithm)
    {
        KeyPair kp;
        auto params = getParams(algorithm);

        kp.publicKey.resize(params.publicKeySize);
        kp.secretKey.resize(params.secretKeySize);

        size_t pkLen = kp.publicKey.size();
        size_t skLen = kp.secretKey.size();

        int status = quac_kem_keygen(
            device_,
            toCAlgorithm(algorithm),
            kp.publicKey.data(),
            &pkLen,
            kp.secretKey.data(),
            &skLen);

        if (status != QUAC_SUCCESS)
        {
            throw CryptoException(status, "KEM key generation failed");
        }

        kp.publicKey.resize(pkLen);
        kp.secretKey.resize(skLen);
        return kp;
    }

    EncapsResult Kem::encapsulate(KemAlgorithm algorithm, const Bytes &publicKey)
    {
        EncapsResult result;
        auto params = getParams(algorithm);

        result.ciphertext.resize(params.ciphertextSize);
        result.sharedSecret.resize(params.sharedSecretSize);

        size_t ctLen = result.ciphertext.size();
        size_t ssLen = result.sharedSecret.size();

        int status = quac_kem_encaps(
            device_,
            toCAlgorithm(algorithm),
            publicKey.data(),
            publicKey.size(),
            result.ciphertext.data(),
            &ctLen,
            result.sharedSecret.data(),
            &ssLen);

        if (status != QUAC_SUCCESS)
        {
            throw CryptoException(status, "KEM encapsulation failed");
        }

        result.ciphertext.resize(ctLen);
        result.sharedSecret.resize(ssLen);
        return result;
    }

    Bytes Kem::decapsulate(KemAlgorithm algorithm, const Bytes &secretKey, const Bytes &ciphertext)
    {
        auto params = getParams(algorithm);
        Bytes sharedSecret(params.sharedSecretSize);
        size_t ssLen = sharedSecret.size();

        int status = quac_kem_decaps(
            device_,
            toCAlgorithm(algorithm),
            secretKey.data(),
            secretKey.size(),
            ciphertext.data(),
            ciphertext.size(),
            sharedSecret.data(),
            &ssLen);

        if (status != QUAC_SUCCESS)
        {
            throw CryptoException(status, "KEM decapsulation failed");
        }

        sharedSecret.resize(ssLen);
        return sharedSecret;
    }

    std::vector<KeyPair> Kem::generateKeyPairBatch(KemAlgorithm algorithm, size_t count)
    {
        std::vector<KeyPair> results;
        results.reserve(count);

        for (size_t i = 0; i < count; ++i)
        {
            results.push_back(generateKeyPair(algorithm));
        }

        return results;
    }

    std::vector<EncapsResult> Kem::encapsulateBatch(KemAlgorithm algorithm, const std::vector<Bytes> &publicKeys)
    {
        std::vector<EncapsResult> results;
        results.reserve(publicKeys.size());

        for (const auto &pk : publicKeys)
        {
            results.push_back(encapsulate(algorithm, pk));
        }

        return results;
    }

} // namespace quac100