/**
 * @file basic_example.cpp
 * @brief QUAC 100 C++ SDK - Basic Example
 * @copyright Copyright © 2025 Dyber, Inc. All Rights Reserved.
 *
 * Demonstrates basic library initialization and device operations.
 */

#include <quac100/quac100.hpp>
#include <iostream>
#include <iomanip>

int main()
{
    std::cout << "QUAC 100 C++ SDK - Basic Example\n";
    std::cout << "================================\n\n";
    std::cout.flush();

    try
    {
        // Initialize library (RAII - automatically cleans up)
        std::cout << "Initializing library...\n";
        std::cout.flush();
        quac100::Library lib;

        std::cout << "Library Version: " << quac100::Library::version() << "\n";
        std::cout << "Build Info: " << quac100::Library::buildInfo() << "\n\n";
        std::cout.flush();

        // Enumerate devices
        auto devices = lib.enumerateDevices();
        std::cout << "Found " << devices.size() << " device(s)\n\n";
        std::cout.flush();

        for (const auto &info : devices)
        {
            std::cout << "Device " << info.index << ":\n";
            std::cout << "  Model: " << info.modelName << "\n";
            std::cout << "  Serial: " << info.serialNumber << "\n";
            std::cout << "  Firmware: " << info.firmwareVersion << "\n";
            std::cout << "  Key Slots: " << info.keySlots << "\n\n";
            std::cout.flush();
        }

        // Open first device
        std::cout << "Opening first device...\n";
        std::cout.flush();
        auto device = lib.openFirstDevice();
        std::cout << "Opened device successfully!\n\n";
        std::cout.flush();

        // Get device status
        auto status = device.status();
        std::cout << "Device Status:\n";
        std::cout << "  Temperature: " << status.temperature << " C\n";
        std::cout << "  Entropy Level: " << status.entropyLevel << "%\n";
        std::cout << "  Total Operations: " << status.totalOperations << "\n";
        std::cout << "  Health: " << (status.isHealthy ? "OK" : "WARNING") << "\n\n";
        std::cout.flush();

        // Run self-test
        std::cout << "Running self-test... ";
        std::cout.flush();
        device.selfTest();
        std::cout << "PASSED\n\n";
        std::cout.flush();

        // Generate some random bytes
        auto randomBytes = device.random().bytes(16);
        std::cout << "Random bytes: " << quac100::utils::toHex(randomBytes) << "\n";
        std::cout.flush();

        // Generate a UUID
        auto uuid = device.random().uuid();
        std::cout << "Random UUID: " << uuid << "\n\n";
        std::cout.flush();

        std::cout << "Basic example completed successfully!\n";
        std::cout.flush();
    }
    catch (const quac100::Exception &e)
    {
        std::cerr << "QUAC Error: " << e.what() << " (code: " << e.codeInt() << ")\n";
        std::cerr.flush();
        return 1;
    }
    catch (const std::exception &e)
    {
        std::cerr << "Standard exception: " << e.what() << "\n";
        std::cerr.flush();
        return 1;
    }

    return 0;
}