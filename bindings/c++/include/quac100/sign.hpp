/**
 * @file sign.hpp
 * @brief QUAC 100 C++ SDK - Digital Signatures
 * @copyright Copyright © 2025 Dyber, Inc. All Rights Reserved.
 */

#ifndef QUAC100_SIGN_HPP
#define QUAC100_SIGN_HPP

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
     * @brief Digital signature operations wrapper
     */
    class Sign
    {
    public:
        explicit Sign(quac_device_t device);
        ~Sign() = default;

        // Non-copyable but movable
        Sign(const Sign &) = delete;
        Sign &operator=(const Sign &) = delete;
        Sign(Sign &&) = default;
        Sign &operator=(Sign &&) = default;

        /**
         * @brief Get algorithm parameters
         */
        SignParams getParams(SignAlgorithm algorithm);

        /**
         * @brief Generate a key pair
         */
        KeyPair generateKeyPair(SignAlgorithm algorithm);

        /**
         * @brief Sign a message
         */
        Bytes sign(SignAlgorithm algorithm, const Bytes &secretKey, const Bytes &message);
        Bytes sign(SignAlgorithm algorithm, const Bytes &secretKey, const std::string &message);

        /**
         * @brief Verify a signature (throws on failure)
         */
        bool verify(SignAlgorithm algorithm, const Bytes &publicKey, const Bytes &message, const Bytes &signature);
        bool verify(SignAlgorithm algorithm, const Bytes &publicKey, const std::string &message, const Bytes &signature);

        /**
         * @brief Verify a signature (no throw, returns false on failure)
         */
        bool verifyNoThrow(SignAlgorithm algorithm, const Bytes &publicKey, const Bytes &message, const Bytes &signature) noexcept;

        /*========================================================================
         * Pre-hashed Operations
         *========================================================================*/

        Bytes signPrehash(SignAlgorithm algorithm, const Bytes &secretKey, const Bytes &messageHash);
        bool verifyPrehash(SignAlgorithm algorithm, const Bytes &publicKey, const Bytes &messageHash, const Bytes &signature);

        /*========================================================================
         * ML-DSA Convenience Methods
         *========================================================================*/

        KeyPair generateKeyPair44() { return generateKeyPair(SignAlgorithm::ML_DSA_44); }
        KeyPair generateKeyPair65() { return generateKeyPair(SignAlgorithm::ML_DSA_65); }
        KeyPair generateKeyPair87() { return generateKeyPair(SignAlgorithm::ML_DSA_87); }

        Bytes sign44(const Bytes &sk, const Bytes &msg) { return sign(SignAlgorithm::ML_DSA_44, sk, msg); }
        Bytes sign65(const Bytes &sk, const Bytes &msg) { return sign(SignAlgorithm::ML_DSA_65, sk, msg); }
        Bytes sign87(const Bytes &sk, const Bytes &msg) { return sign(SignAlgorithm::ML_DSA_87, sk, msg); }

        Bytes sign44(const Bytes &sk, const std::string &msg) { return sign(SignAlgorithm::ML_DSA_44, sk, msg); }
        Bytes sign65(const Bytes &sk, const std::string &msg) { return sign(SignAlgorithm::ML_DSA_65, sk, msg); }
        Bytes sign87(const Bytes &sk, const std::string &msg) { return sign(SignAlgorithm::ML_DSA_87, sk, msg); }

        bool verify44(const Bytes &pk, const Bytes &msg, const Bytes &sig) { return verify(SignAlgorithm::ML_DSA_44, pk, msg, sig); }
        bool verify65(const Bytes &pk, const Bytes &msg, const Bytes &sig) { return verify(SignAlgorithm::ML_DSA_65, pk, msg, sig); }
        bool verify87(const Bytes &pk, const Bytes &msg, const Bytes &sig) { return verify(SignAlgorithm::ML_DSA_87, pk, msg, sig); }

        bool verify44(const Bytes &pk, const std::string &msg, const Bytes &sig) { return verify(SignAlgorithm::ML_DSA_44, pk, msg, sig); }
        bool verify65(const Bytes &pk, const std::string &msg, const Bytes &sig) { return verify(SignAlgorithm::ML_DSA_65, pk, msg, sig); }
        bool verify87(const Bytes &pk, const std::string &msg, const Bytes &sig) { return verify(SignAlgorithm::ML_DSA_87, pk, msg, sig); }

        /*========================================================================
         * Batch Operations
         *========================================================================*/

        std::vector<KeyPair> generateKeyPairBatch(SignAlgorithm algorithm, size_t count);
        std::vector<Bytes> signBatch(SignAlgorithm algorithm, const Bytes &secretKey, const std::vector<Bytes> &messages);
        std::vector<bool> verifyBatch(SignAlgorithm algorithm, const Bytes &publicKey,
                                      const std::vector<Bytes> &messages, const std::vector<Bytes> &signatures);

    private:
        quac_device_t device_;
    };

} // namespace quac100

#endif // QUAC100_SIGN_HPP