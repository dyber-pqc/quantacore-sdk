/**
 * @file device.hpp
 * @brief QUAC 100 C++ SDK - Device Management
 * @copyright Copyright © 2025 Dyber, Inc. All Rights Reserved.
 */

#ifndef QUAC100_DEVICE_HPP
#define QUAC100_DEVICE_HPP

#include "types.hpp"
#include "exception.hpp"

// Forward declare C types
extern "C"
{
    typedef struct quac_device_handle *quac_device_t;
}

namespace quac100
{

    // Forward declarations - full definitions are in their respective headers
    class Kem;
    class Sign;
    class Random;
    class Hash;
    class KeyStorage;

    /**
     * @brief RAII wrapper for QUAC 100 device
     */
    class Device
    {
    public:
        explicit Device(quac_device_t handle);
        ~Device();

        // Non-copyable
        Device(const Device &) = delete;
        Device &operator=(const Device &) = delete;

        // Movable
        Device(Device &&other) noexcept;
        Device &operator=(Device &&other) noexcept;

        bool isOpen() const noexcept;
        int index() const;
        DeviceInfo info() const;
        DeviceStatus status() const;
        void selfTest();
        void reset();

        quac_device_t handle() const noexcept { return handle_; }

        // Operation accessors - declared here, defined in device.cpp
        Kem &kem();
        const Kem &kem() const;
        Sign &sign();
        const Sign &sign() const;
        Random &random();
        const Random &random() const;
        Hash &hash();
        const Hash &hash() const;
        KeyStorage &keys();
        const KeyStorage &keys() const;

    private:
        quac_device_t handle_ = nullptr;

        // Raw pointers managed manually to avoid incomplete type issues
        mutable Kem *kem_ = nullptr;
        mutable Sign *sign_ = nullptr;
        mutable Random *random_ = nullptr;
        mutable Hash *hash_ = nullptr;
        mutable KeyStorage *keys_ = nullptr;

        void ensureOpen() const;
        void cleanup() noexcept;
    };

} // namespace quac100

#endif // QUAC100_DEVICE_HPP