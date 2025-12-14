/**
 * @file device.cpp
 * @brief QUAC 100 C++ SDK - Device Management Implementation
 * @copyright Copyright © 2025 Dyber, Inc. All Rights Reserved.
 */

#include "quac100/device.hpp"
#include "quac100/kem.hpp"
#include "quac100/sign.hpp"
#include "quac100/random.hpp"
#include "quac100/hash.hpp"
#include "quac100/keys.hpp"

extern "C"
{
#include <quac100/quac100.h>
#include <quac100/device.h>
}

namespace quac100
{

    Device::Device(quac_device_t handle) : handle_(handle) {}

    Device::~Device()
    {
        cleanup();
        if (handle_)
        {
            quac_close_device(handle_);
        }
    }

    Device::Device(Device &&other) noexcept
        : handle_(other.handle_),
          kem_(other.kem_),
          sign_(other.sign_),
          random_(other.random_),
          hash_(other.hash_),
          keys_(other.keys_)
    {
        other.handle_ = nullptr;
        other.kem_ = nullptr;
        other.sign_ = nullptr;
        other.random_ = nullptr;
        other.hash_ = nullptr;
        other.keys_ = nullptr;
    }

    Device &Device::operator=(Device &&other) noexcept
    {
        if (this != &other)
        {
            cleanup();
            if (handle_)
            {
                quac_close_device(handle_);
            }

            handle_ = other.handle_;
            kem_ = other.kem_;
            sign_ = other.sign_;
            random_ = other.random_;
            hash_ = other.hash_;
            keys_ = other.keys_;

            other.handle_ = nullptr;
            other.kem_ = nullptr;
            other.sign_ = nullptr;
            other.random_ = nullptr;
            other.hash_ = nullptr;
            other.keys_ = nullptr;
        }
        return *this;
    }

    bool Device::isOpen() const noexcept
    {
        return handle_ != nullptr;
    }

    int Device::index() const
    {
        ensureOpen();
        int idx = quac_get_device_index(handle_);
        if (idx < 0)
        {
            throw DeviceException(ErrorCode::Error, "Failed to get device index");
        }
        return idx;
    }

    DeviceInfo Device::info() const
    {
        ensureOpen();
        quac_device_info_t cinfo;
        int status = quac_get_device_info(handle_, &cinfo);
        if (status != QUAC_SUCCESS)
        {
            throw DeviceException(status, "Failed to get device info");
        }

        DeviceInfo info;
        info.index = cinfo.device_index;
        info.modelName = cinfo.model_name;
        info.serialNumber = cinfo.serial_number;
        info.firmwareVersion = cinfo.firmware_version;
        info.keySlots = cinfo.key_slots;
        info.capabilities = cinfo.capabilities;

        return info;
    }

    DeviceStatus Device::status() const
    {
        ensureOpen();
        quac_device_status_t cstatus;
        int status = quac_get_device_status(handle_, &cstatus);
        if (status != QUAC_SUCCESS)
        {
            throw DeviceException(status, "Failed to get device status");
        }

        DeviceStatus devStatus;
        devStatus.temperature = cstatus.temperature;
        devStatus.entropyLevel = cstatus.entropy_level;
        devStatus.totalOperations = cstatus.total_operations;
        devStatus.totalErrors = 0; // Not in C struct, using 0
        devStatus.isHealthy = (cstatus.last_error == QUAC_SUCCESS);

        return devStatus;
    }

    void Device::selfTest()
    {
        ensureOpen();
        int status = quac_self_test(handle_);
        if (status != QUAC_SUCCESS)
        {
            throw DeviceException(status, "Self-test failed");
        }
    }

    void Device::reset()
    {
        ensureOpen();
        int status = quac_reset_device(handle_);
        if (status != QUAC_SUCCESS)
        {
            throw DeviceException(status, "Device reset failed");
        }
    }

    Kem &Device::kem()
    {
        ensureOpen();
        if (!kem_)
        {
            kem_ = new Kem(handle_);
        }
        return *kem_;
    }

    const Kem &Device::kem() const
    {
        ensureOpen();
        if (!kem_)
        {
            kem_ = new Kem(handle_);
        }
        return *kem_;
    }

    Sign &Device::sign()
    {
        ensureOpen();
        if (!sign_)
        {
            sign_ = new Sign(handle_);
        }
        return *sign_;
    }

    const Sign &Device::sign() const
    {
        ensureOpen();
        if (!sign_)
        {
            sign_ = new Sign(handle_);
        }
        return *sign_;
    }

    Random &Device::random()
    {
        ensureOpen();
        if (!random_)
        {
            random_ = new Random(handle_);
        }
        return *random_;
    }

    const Random &Device::random() const
    {
        ensureOpen();
        if (!random_)
        {
            random_ = new Random(handle_);
        }
        return *random_;
    }

    Hash &Device::hash()
    {
        ensureOpen();
        if (!hash_)
        {
            hash_ = new Hash(handle_);
        }
        return *hash_;
    }

    const Hash &Device::hash() const
    {
        ensureOpen();
        if (!hash_)
        {
            hash_ = new Hash(handle_);
        }
        return *hash_;
    }

    KeyStorage &Device::keys()
    {
        ensureOpen();
        if (!keys_)
        {
            keys_ = new KeyStorage(handle_);
        }
        return *keys_;
    }

    const KeyStorage &Device::keys() const
    {
        ensureOpen();
        if (!keys_)
        {
            keys_ = new KeyStorage(handle_);
        }
        return *keys_;
    }

    void Device::ensureOpen() const
    {
        if (!handle_)
        {
            throw DeviceException(ErrorCode::InvalidHandle, "Device not open");
        }
    }

    void Device::cleanup() noexcept
    {
        delete kem_;
        delete sign_;
        delete random_;
        delete hash_;
        delete keys_;

        kem_ = nullptr;
        sign_ = nullptr;
        random_ = nullptr;
        hash_ = nullptr;
        keys_ = nullptr;
    }

} // namespace quac100