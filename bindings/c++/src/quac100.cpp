/**
 * @file quac100.cpp
 * @brief QUAC 100 C++ SDK - Library Implementation
 * @copyright Copyright © 2025 Dyber, Inc. All Rights Reserved.
 */

#include "quac100/quac100.hpp"

extern "C"
{
#include <quac100/quac100.h>
#include <quac100/device.h>
}

namespace quac100
{

    Library::Library(uint32_t flags)
    {
        int status = quac_init(flags);
        if (status != QUAC_SUCCESS)
        {
            throw Exception(status, "Failed to initialize QUAC library");
        }
        initialized_ = true;
    }

    Library::~Library() noexcept
    {
        if (initialized_)
        {
            quac_cleanup();
        }
    }

    Library::Library(Library &&other) noexcept
        : initialized_(other.initialized_)
    {
        other.initialized_ = false;
    }

    Library &Library::operator=(Library &&other) noexcept
    {
        if (this != &other)
        {
            if (initialized_)
            {
                quac_cleanup();
            }
            initialized_ = other.initialized_;
            other.initialized_ = false;
        }
        return *this;
    }

    bool Library::isInitialized() const noexcept
    {
        return initialized_;
    }

    std::string Library::version()
    {
        const char *ver = quac_version();
        return ver ? ver : "";
    }

    Version Library::versionInfo()
    {
        Version v;
        quac_version_info(&v.major, &v.minor, &v.patch);
        return v;
    }

    std::string Library::buildInfo()
    {
        const char *info = quac_build_info();
        return info ? info : "";
    }

    std::vector<DeviceInfo> Library::enumerateDevices() const
    {
        std::vector<DeviceInfo> devices;

        quac_device_info_t cdevices[QUAC_MAX_DEVICES];
        int count = 0;
        int status = quac_enumerate_devices(cdevices, QUAC_MAX_DEVICES, &count);
        if (status != QUAC_SUCCESS)
        {
            throw DeviceException(status, "Failed to enumerate devices");
        }

        for (int i = 0; i < count; ++i)
        {
            DeviceInfo info;
            info.index = cdevices[i].device_index;
            info.modelName = cdevices[i].model_name;
            info.serialNumber = cdevices[i].serial_number;
            info.firmwareVersion = cdevices[i].firmware_version;
            info.keySlots = cdevices[i].key_slots;
            info.capabilities = cdevices[i].capabilities;
            devices.push_back(info);
        }

        return devices;
    }

    Device Library::openDevice(int index) const
    {
        quac_device_t handle = nullptr;
        int status = quac_open_device(index, QUAC_FLAG_DEFAULT, &handle);
        if (status != QUAC_SUCCESS)
        {
            throw DeviceException(status, "Failed to open device");
        }
        return Device(handle);
    }

    Device Library::openFirstDevice() const
    {
        return openDevice(0);
    }

} // namespace quac100