/**
 * @file quac100.hpp
 * @brief QUAC 100 C++ SDK - Main Header
 * @copyright Copyright © 2025 Dyber, Inc. All Rights Reserved.
 *
 * Include this single header to get access to the entire C++ SDK.
 */

#ifndef QUAC100_HPP
#define QUAC100_HPP

#include "types.hpp"
#include "exception.hpp"
#include "device.hpp"
#include "kem.hpp"
#include "sign.hpp"
#include "random.hpp"
#include "hash.hpp"
#include "keys.hpp"
#include "utils.hpp"

namespace quac100
{

    /**
     * @brief RAII library initialization
     */
    class Library
    {
    public:
        explicit Library(uint32_t flags = FLAG_DEFAULT);
        ~Library() noexcept;

        // Non-copyable
        Library(const Library &) = delete;
        Library &operator=(const Library &) = delete;

        // Movable
        Library(Library &&other) noexcept;
        Library &operator=(Library &&other) noexcept;

        bool isInitialized() const noexcept;

        static std::string version();
        static Version versionInfo();
        static std::string buildInfo();

        std::vector<DeviceInfo> enumerateDevices() const;
        Device openDevice(int index) const;
        Device openFirstDevice() const;

    private:
        bool initialized_ = false;
    };

} // namespace quac100

#endif // QUAC100_HPP