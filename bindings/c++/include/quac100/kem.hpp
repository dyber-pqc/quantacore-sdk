/**
 * @file kem.hpp
 * @brief QUAC 100 C++ SDK - Key Encapsulation Mechanism
 * @copyright Copyright © 2025 Dyber, Inc. All Rights Reserved.
 */

#ifndef QUAC100_KEM_HPP
#define QUAC100_KEM_HPP

#include "types.hpp"
#include "exception.hpp"

// Forward declare C types
extern "C"
{
    typedef struct quac_device_handle *quac_device_t;
}

namespace quac100
{

    /**
     * @brief KEM operations wrapper
     */
    class Kem
    {
    public:
        explicit Kem(quac_device_t device);
        ~Kem() = default;

        // Non-copyable but movable
        Kem(const Kem &) = delete;
        Kem &operator=(const Kem &) = delete;
        Kem(Kem &&) = default;
        Kem &operator=(Kem &&) = default;

        /**
         * @brief Get algorithm parameters
         */
        KemParams getParams(KemAlgorithm algorithm);

        /**
         * @brief Generate a key pair
         */
        KeyPair generateKeyPair(KemAlgorithm algorithm);

        /**
         * @brief Encapsulate (generate shared secret)
         */
        EncapsResult encapsulate(KemAlgorithm algorithm, const Bytes &publicKey);

        /**
         * @brief Decapsulate (recover shared secret)
         */
        Bytes decapsulate(KemAlgorithm algorithm, const Bytes &secretKey, const Bytes &ciphertext);

        /*========================================================================
         * Convenience Methods
         *========================================================================*/

        KeyPair generateKeyPair512() { return generateKeyPair(KemAlgorithm::ML_KEM_512); }
        KeyPair generateKeyPair768() { return generateKeyPair(KemAlgorithm::ML_KEM_768); }
        KeyPair generateKeyPair1024() { return generateKeyPair(KemAlgorithm::ML_KEM_1024); }

        EncapsResult encapsulate512(const Bytes &pk) { return encapsulate(KemAlgorithm::ML_KEM_512, pk); }
        EncapsResult encapsulate768(const Bytes &pk) { return encapsulate(KemAlgorithm::ML_KEM_768, pk); }
        EncapsResult encapsulate1024(const Bytes &pk) { return encapsulate(KemAlgorithm::ML_KEM_1024, pk); }

        Bytes decapsulate512(const Bytes &sk, const Bytes &ct) { return decapsulate(KemAlgorithm::ML_KEM_512, sk, ct); }
        Bytes decapsulate768(const Bytes &sk, const Bytes &ct) { return decapsulate(KemAlgorithm::ML_KEM_768, sk, ct); }
        Bytes decapsulate1024(const Bytes &sk, const Bytes &ct) { return decapsulate(KemAlgorithm::ML_KEM_1024, sk, ct); }

        /*========================================================================
         * Batch Operations
         *========================================================================*/

        std::vector<KeyPair> generateKeyPairBatch(KemAlgorithm algorithm, size_t count);
        std::vector<EncapsResult> encapsulateBatch(KemAlgorithm algorithm, const std::vector<Bytes> &publicKeys);

    private:
        quac_device_t device_;
    };

} // namespace quac100

#endif // QUAC100_KEM_HPP