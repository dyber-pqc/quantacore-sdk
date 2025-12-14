/**
 * @file random_example.cpp
 * @brief QUAC 100 C++ SDK - Random Number Generation Example
 * @copyright Copyright © 2025 Dyber, Inc. All Rights Reserved.
 *
 * Demonstrates quantum random number generation (QRNG).
 */

#include <quac100/quac100.hpp>
#include <iostream>
#include <iomanip>
#include <map>
#include <chrono>

using namespace quac100;

int main()
{
    std::cout << "QUAC 100 C++ SDK - Random Number Generation Example\n";
    std::cout << "====================================================\n\n";
    std::cout.flush();

    try
    {
        std::cout << "Initializing library...\n";
        std::cout.flush();
        Library lib;

        std::cout << "Opening device...\n";
        std::cout.flush();
        auto device = lib.openFirstDevice();
        std::cout << "Device opened successfully.\n\n";
        std::cout.flush();

        // Check entropy status
        std::cout << "Entropy Status:\n";
        std::cout << "---------------\n";
        std::cout.flush();

        auto entropy = device.random().entropyStatus();
        std::cout << "  Level: " << entropy.level << "%\n";
        std::cout << "  Health: " << (entropy.healthOk ? "OK" : "WARNING") << "\n";
        std::cout << "  Bytes Generated: " << entropy.bytesGenerated << "\n";
        std::cout << "  Bit Rate: " << std::fixed << std::setprecision(2)
                  << entropy.bitRate << " bits/sec\n\n";
        std::cout.flush();

        // Generate random bytes
        std::cout << "Random Bytes Generation:\n";
        std::cout << "------------------------\n";
        std::cout.flush();

        auto bytes16 = device.random().bytes(16);
        std::cout << "16 bytes:  " << utils::toHex(bytes16) << "\n";
        std::cout.flush();

        auto bytes32 = device.random().bytes(32);
        std::cout << "32 bytes:  " << utils::toHex(bytes32) << "\n";
        std::cout.flush();

        auto bytes64 = device.random().bytes(64);
        std::cout << "64 bytes:  " << utils::toHex(Bytes(bytes64.begin(), bytes64.begin() + 32))
                  << "...\n\n";
        std::cout.flush();

        // Generate random integers
        std::cout << "Random Integers:\n";
        std::cout << "----------------\n";
        std::cout.flush();

        std::cout << "uint32: ";
        for (int i = 0; i < 5; ++i)
        {
            std::cout << device.random().uint32() << " ";
        }
        std::cout << "\n";
        std::cout.flush();

        std::cout << "uint64: ";
        for (int i = 0; i < 3; ++i)
        {
            std::cout << device.random().uint64() << " ";
        }
        std::cout << "\n";
        std::cout.flush();

        std::cout << "range(100): ";
        for (int i = 0; i < 10; ++i)
        {
            std::cout << device.random().range(100) << " ";
        }
        std::cout << "\n";
        std::cout.flush();

        std::cout << "range(10, 20): ";
        for (int i = 0; i < 10; ++i)
        {
            std::cout << device.random().range(10, 20) << " ";
        }
        std::cout << "\n\n";
        std::cout.flush();

        // Generate random doubles
        std::cout << "Random Doubles [0.0, 1.0):\n";
        std::cout << "--------------------------\n";
        std::cout.flush();
        for (int i = 0; i < 5; ++i)
        {
            std::cout << std::fixed << std::setprecision(6)
                      << device.random().uniform() << " ";
        }
        std::cout << "\n\n";
        std::cout.flush();

        // Generate UUIDs
        std::cout << "Random UUIDs:\n";
        std::cout << "-------------\n";
        std::cout.flush();
        for (int i = 0; i < 5; ++i)
        {
            std::cout << device.random().uuid() << "\n";
        }
        std::cout << "\n";
        std::cout.flush();

        // Shuffle demonstration (manual implementation)
        std::cout << "Shuffle Demonstration:\n";
        std::cout << "----------------------\n";
        std::cout.flush();

        std::vector<int> deck(52);
        for (int i = 0; i < 52; ++i)
            deck[i] = i;

        std::cout << "Original: ";
        for (int i = 0; i < 10; ++i)
            std::cout << deck[i] << " ";
        std::cout << "...\n";
        std::cout.flush();

        // Fisher-Yates shuffle using QRNG
        for (size_t i = deck.size() - 1; i > 0; --i)
        {
            uint32_t j = device.random().range(static_cast<uint32_t>(i + 1));
            std::swap(deck[i], deck[j]);
        }

        std::cout << "Shuffled: ";
        for (int i = 0; i < 10; ++i)
            std::cout << deck[i] << " ";
        std::cout << "...\n\n";
        std::cout.flush();

        // Random selection
        std::cout << "Random Selection:\n";
        std::cout << "-----------------\n";
        std::cout.flush();

        std::vector<std::string> colors = {"Red", "Green", "Blue", "Yellow", "Purple"};
        std::cout << "Colors: ";
        for (const auto &c : colors)
            std::cout << c << " ";
        std::cout << "\n";
        std::cout.flush();

        // Random choice
        uint32_t idx = device.random().range(static_cast<uint32_t>(colors.size()));
        std::cout << "Random choice: " << colors[idx] << "\n";
        std::cout.flush();

        // Random sample of 3
        std::cout << "Random sample(3): ";
        std::vector<std::string> colorsCopy = colors;
        for (int i = 0; i < 3 && !colorsCopy.empty(); ++i)
        {
            uint32_t pick = device.random().range(static_cast<uint32_t>(colorsCopy.size()));
            std::cout << colorsCopy[pick] << " ";
            colorsCopy.erase(colorsCopy.begin() + pick);
        }
        std::cout << "\n\n";
        std::cout.flush();

        // Distribution test
        std::cout << "Distribution Test (10000 samples in [0,10)):\n";
        std::cout << "---------------------------------------------\n";
        std::cout.flush();

        std::map<uint32_t, int> histogram;
        for (int i = 0; i < 10000; ++i)
        {
            histogram[device.random().range(10)]++;
        }

        for (uint32_t i = 0; i < 10; ++i)
        {
            std::cout << i << ": ";
            int bars = histogram[i] / 100;
            for (int j = 0; j < bars; ++j)
                std::cout << "#";
            std::cout << " (" << histogram[i] << ")\n";
        }
        std::cout << "\n";
        std::cout.flush();

        // Performance benchmark
        std::cout << "Performance Benchmark:\n";
        std::cout << "----------------------\n";
        std::cout.flush();

        const int iterations = 1000;
        const size_t blockSize = 1024;

        auto startTime = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < iterations; ++i)
        {
            device.random().bytes(blockSize);
        }
        auto endTime = std::chrono::high_resolution_clock::now();
        double totalMs = std::chrono::duration<double, std::milli>(endTime - startTime).count();
        double rate = (iterations * blockSize) / (totalMs / 1000.0);

        std::cout << "Throughput: " << std::fixed << std::setprecision(2)
                  << (rate / 1024.0 / 1024.0) << " MB/sec\n\n";
        std::cout.flush();

        std::cout << "Random example completed successfully!\n";
        std::cout.flush();
    }
    catch (const Exception &e)
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