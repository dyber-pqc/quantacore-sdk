/**
 * @file hash.hpp
 * @brief QUAC 100 C++ SDK - Hash Operations
 * @copyright Copyright © 2025 Dyber, Inc. All Rights Reserved.
 */

#ifndef QUAC100_HASH_HPP
#define QUAC100_HASH_HPP

#include "types.hpp"
#include "exception.hpp"

// Forward declare C types
extern "C"
{
    typedef struct quac_device_handle *quac_device_t;
    typedef struct quac_hash_context *quac_hash_ctx_t;
}

namespace quac100
{

    /**
     * @brief Hash operations wrapper
     */
    class Hash
    {
    public:
        /**
         * @brief Incremental hash context
         */
        class Context
        {
        public:
            Context(quac_device_t device, HashAlgorithm algorithm);
            ~Context();

            // Non-copyable
            Context(const Context &) = delete;
            Context &operator=(const Context &) = delete;

            // Movable
            Context(Context &&other) noexcept;
            Context &operator=(Context &&other) noexcept;

            void update(const Bytes &data);
            void update(const uint8_t *data, size_t size);
            void update(const std::string &data);

            Bytes finalize();
            void reset();

            HashAlgorithm algorithm() const noexcept { return algorithm_; }

        private:
            quac_device_t device_ = nullptr;
            quac_hash_ctx_t ctx_ = nullptr;
            HashAlgorithm algorithm_;
        };

        explicit Hash(quac_device_t device);
        ~Hash() = default;

        // Non-copyable but movable
        Hash(const Hash &) = delete;
        Hash &operator=(const Hash &) = delete;
        Hash(Hash &&) = default;
        Hash &operator=(Hash &&) = default;

        /*========================================================================
         * One-shot Hashing
         *========================================================================*/

        Bytes hash(HashAlgorithm algorithm, const Bytes &data);
        Bytes hash(HashAlgorithm algorithm, const uint8_t *data, size_t size);
        Bytes hash(HashAlgorithm algorithm, const std::string &data);

        // Convenience methods
        Bytes sha256(const Bytes &data);
        Bytes sha256(const std::string &data);
        Bytes sha384(const Bytes &data);
        Bytes sha384(const std::string &data);
        Bytes sha512(const Bytes &data);
        Bytes sha512(const std::string &data);

        Bytes sha3_256(const Bytes &data);
        Bytes sha3_256(const std::string &data);
        Bytes sha3_384(const Bytes &data);
        Bytes sha3_384(const std::string &data);
        Bytes sha3_512(const Bytes &data);
        Bytes sha3_512(const std::string &data);

        Bytes shake128(const Bytes &data, size_t outputLength);
        Bytes shake256(const Bytes &data, size_t outputLength);

        /*========================================================================
         * HMAC
         *========================================================================*/

        Bytes hmac(HashAlgorithm algorithm, const Bytes &key, const Bytes &data);
        Bytes hmacSha256(const Bytes &key, const Bytes &data);
        Bytes hmacSha512(const Bytes &key, const Bytes &data);

        /*========================================================================
         * HKDF
         *========================================================================*/

        Bytes hkdf(HashAlgorithm algorithm, const Bytes &ikm, const Bytes &salt,
                   const Bytes &info, size_t outputLength);

        /*========================================================================
         * Incremental Hashing
         *========================================================================*/

        Context createContext(HashAlgorithm algorithm);

        /*========================================================================
         * File Hashing
         *========================================================================*/

        Bytes hashFile(HashAlgorithm algorithm, const std::string &filepath);

    private:
        quac_device_t device_;
    };

} // namespace quac100

#endif // QUAC100_HASH_HPP