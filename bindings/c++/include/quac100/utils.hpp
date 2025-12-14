/**
 * @file utils.hpp
 * @brief QUAC 100 C++ SDK - Utility Functions
 * @copyright Copyright © 2025 Dyber, Inc. All Rights Reserved.
 */

#ifndef QUAC100_UTILS_HPP
#define QUAC100_UTILS_HPP

#include "types.hpp"
#include <string>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <ctime>

namespace quac100
{
    namespace utils
    {

        /*============================================================================
         * Secure Memory
         *============================================================================*/

        void secureZero(void *ptr, size_t size);
        bool secureCompare(const void *a, const void *b, size_t size);
        bool secureCompare(const Bytes &a, const Bytes &b);

        /*============================================================================
         * Encoding
         *============================================================================*/

        std::string toHex(const Bytes &data, bool uppercase = false);
        std::string toHex(const uint8_t *data, size_t size, bool uppercase = false);
        Bytes fromHex(const std::string &hex);

        std::string toBase64(const Bytes &data);
        std::string toBase64(const uint8_t *data, size_t size);
        Bytes fromBase64(const std::string &base64);

        /*============================================================================
         * Formatting
         *============================================================================*/

        std::string formatBytes(const Bytes &data, size_t maxBytes = 16);
        std::string formatSize(size_t bytes);
        std::string formatDuration(std::chrono::nanoseconds ns);

        /*============================================================================
         * Algorithm Helpers
         *============================================================================*/

        std::string algorithmName(KemAlgorithm algorithm);
        std::string algorithmName(SignAlgorithm algorithm);
        std::string algorithmName(HashAlgorithm algorithm);

        bool isKemAlgorithm(int algorithm);
        bool isSignAlgorithm(int algorithm);
        bool isMlDsa(SignAlgorithm algorithm);
        bool isSlhDsa(SignAlgorithm algorithm);

        /*============================================================================
         * Time
         *============================================================================*/

        uint64_t timestampMs();
        std::string formatTimestamp(uint64_t timestampMs);

        /*============================================================================
         * Benchmark Helper
         *============================================================================*/

        class Benchmark
        {
        public:
            Benchmark() : start_(std::chrono::high_resolution_clock::now()) {}

            void reset()
            {
                start_ = std::chrono::high_resolution_clock::now();
            }

            std::chrono::nanoseconds elapsed() const
            {
                auto now = std::chrono::high_resolution_clock::now();
                return std::chrono::duration_cast<std::chrono::nanoseconds>(now - start_);
            }

            double elapsedMs() const
            {
                return std::chrono::duration<double, std::milli>(elapsed()).count();
            }

            double elapsedUs() const
            {
                return std::chrono::duration<double, std::micro>(elapsed()).count();
            }

            std::string toString() const
            {
                return formatDuration(elapsed());
            }

        private:
            std::chrono::high_resolution_clock::time_point start_;
        };

    } // namespace utils
} // namespace quac100

#endif // QUAC100_UTILS_HPP