/**
 * @file random.hpp
 * @brief QUAC 100 C++ SDK - Random Number Generation
 * @copyright Copyright © 2025 Dyber, Inc. All Rights Reserved.
 */

#ifndef QUAC100_RANDOM_HPP
#define QUAC100_RANDOM_HPP

#include "types.hpp"
#include "exception.hpp"
#include <limits>
#include <random>
#include <algorithm>

// Forward declare C types
extern "C"
{
    typedef struct quac_device_handle *quac_device_t;
}

namespace quac100
{

    /**
     * @brief QRNG operations wrapper
     */
    class Random
    {
    public:
        /**
         * @brief STL-compatible random engine adapter
         */
        class Engine
        {
        public:
            using result_type = uint32_t;

            explicit Engine(Random &random) : random_(&random) {}

            static constexpr result_type min() { return 0; }
            static constexpr result_type max() { return std::numeric_limits<uint32_t>::max(); }

            result_type operator()() { return random_->uint32(); }

        private:
            Random *random_;
        };

        explicit Random(quac_device_t device);
        ~Random() = default;

        // Non-copyable but movable
        Random(const Random &) = delete;
        Random &operator=(const Random &) = delete;
        Random(Random &&) = default;
        Random &operator=(Random &&) = default;

        /*========================================================================
         * Basic Generation
         *========================================================================*/

        /**
         * @brief Generate random bytes
         */
        Bytes bytes(size_t length);

        /**
         * @brief Fill buffer with random bytes
         */
        void fill(uint8_t *buffer, size_t length);

        /**
         * @brief Generate random 32-bit unsigned integer
         */
        uint32_t uint32();

        /**
         * @brief Generate random 64-bit unsigned integer
         */
        uint64_t uint64();

        /**
         * @brief Generate random integer in range [0, max)
         */
        uint64_t range(uint64_t max);

        /**
         * @brief Generate random integer in range [min, max)
         */
        uint64_t range(uint64_t min, uint64_t max);

        /**
         * @brief Generate random double in range [0.0, 1.0)
         */
        double uniform();

        /*========================================================================
         * Utility Functions
         *========================================================================*/

        /**
         * @brief Generate a random UUID (version 4)
         */
        std::string uuid();

        /**
         * @brief Shuffle a vector in place
         */
        template <typename T>
        void shuffle(std::vector<T> &vec)
        {
            Engine eng(*this);
            std::shuffle(vec.begin(), vec.end(), eng);
        }

        /**
         * @brief Choose a random element from a vector
         */
        template <typename T>
        const T &choice(const std::vector<T> &vec)
        {
            if (vec.empty())
            {
                throw Exception(ErrorCode::InvalidParam, "Cannot choose from empty vector");
            }
            return vec[range(vec.size())];
        }

        /**
         * @brief Sample k elements from a vector without replacement
         */
        template <typename T>
        std::vector<T> sample(const std::vector<T> &vec, size_t k)
        {
            if (k > vec.size())
            {
                throw Exception(ErrorCode::InvalidParam, "Sample size larger than population");
            }
            std::vector<T> result = vec;
            shuffle(result);
            result.resize(k);
            return result;
        }

        /*========================================================================
         * STL Integration
         *========================================================================*/

        /**
         * @brief Get STL-compatible random engine
         */
        Engine engine() { return Engine(*this); }

        /*========================================================================
         * Entropy Status
         *========================================================================*/

        /**
         * @brief Get entropy source status
         */
        EntropyStatus entropyStatus();

        /**
         * @brief Set entropy source
         */
        void setEntropySource(EntropySource source);

    private:
        quac_device_t device_;
    };

} // namespace quac100

#endif // QUAC100_RANDOM_HPP