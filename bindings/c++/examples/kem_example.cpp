/**
 * @file kem_example.cpp
 * @brief QUAC 100 C++ SDK - Key Encapsulation Mechanism (KEM) Example
 * @copyright Copyright © 2025 Dyber, Inc. All Rights Reserved.
 *
 * Demonstrates ML-KEM (Kyber) post-quantum key exchange.
 */

#include <quac100/quac100.hpp>
#include <iostream>
#include <iomanip>
#include <chrono>

using namespace quac100;

void printBytes(const std::string &label, const Bytes &data, size_t maxLen = 32)
{
    std::cout << label << " (" << data.size() << " bytes): ";
    std::cout << utils::toHex(Bytes(data.begin(),
                                    data.begin() + std::min(data.size(), maxLen)));
    if (data.size() > maxLen)
        std::cout << "...";
    std::cout << "\n";
    std::cout.flush();
}

std::string formatDuration(double ms)
{
    std::ostringstream oss;
    if (ms < 1.0)
    {
        oss << std::fixed << std::setprecision(2) << (ms * 1000.0) << " us";
    }
    else if (ms < 1000.0)
    {
        oss << std::fixed << std::setprecision(2) << ms << " ms";
    }
    else
    {
        oss << std::fixed << std::setprecision(2) << (ms / 1000.0) << " s";
    }
    return oss.str();
}

int main()
{
    std::cout << "QUAC 100 C++ SDK - KEM Example\n";
    std::cout << "==============================\n\n";
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

        // Get algorithm parameters (use instance method via device.kem())
        std::cout << "ML-KEM Algorithm Parameters:\n";
        std::cout << "----------------------------\n";
        std::cout.flush();

        for (auto alg : {KemAlgorithm::ML_KEM_512,
                         KemAlgorithm::ML_KEM_768,
                         KemAlgorithm::ML_KEM_1024})
        {
            auto params = device.kem().getParams(alg);
            std::cout << params.name << ":\n";
            std::cout << "  Public Key:    " << params.publicKeySize << " bytes\n";
            std::cout << "  Secret Key:    " << params.secretKeySize << " bytes\n";
            std::cout << "  Ciphertext:    " << params.ciphertextSize << " bytes\n";
            std::cout << "  Shared Secret: " << params.sharedSecretSize << " bytes\n";
            std::cout << "  Security:      Level " << params.securityLevel << "\n\n";
            std::cout.flush();
        }

        // Demonstrate ML-KEM-768 key exchange
        std::cout << "ML-KEM-768 Key Exchange Demo\n";
        std::cout << "----------------------------\n\n";
        std::cout.flush();

        // Alice generates a key pair
        std::cout << "Alice: Generating key pair...\n";
        std::cout.flush();
        auto startTime = std::chrono::high_resolution_clock::now();
        auto aliceKeys = device.kem().generateKeyPair(KemAlgorithm::ML_KEM_768);
        auto endTime = std::chrono::high_resolution_clock::now();
        double keygenMs = std::chrono::duration<double, std::milli>(endTime - startTime).count();
        std::cout << "Alice: Key generation took " << formatDuration(keygenMs) << "\n";
        printBytes("Alice Public Key", aliceKeys.publicKey);
        std::cout << "\n";
        std::cout.flush();

        // Alice sends her public key to Bob (simulated)
        std::cout << "Alice -> Bob: Sending public key...\n\n";
        std::cout.flush();

        // Bob encapsulates using Alice's public key
        std::cout << "Bob: Encapsulating shared secret...\n";
        std::cout.flush();
        startTime = std::chrono::high_resolution_clock::now();
        auto bobResult = device.kem().encapsulate(KemAlgorithm::ML_KEM_768, aliceKeys.publicKey);
        endTime = std::chrono::high_resolution_clock::now();
        double encapsMs = std::chrono::duration<double, std::milli>(endTime - startTime).count();
        std::cout << "Bob: Encapsulation took " << formatDuration(encapsMs) << "\n";
        printBytes("Bob Ciphertext", bobResult.ciphertext);
        printBytes("Bob Shared Secret", bobResult.sharedSecret);
        std::cout << "\n";
        std::cout.flush();

        // Bob sends ciphertext to Alice (simulated)
        std::cout << "Bob -> Alice: Sending ciphertext...\n\n";
        std::cout.flush();

        // Alice decapsulates to get the same shared secret
        std::cout << "Alice: Decapsulating shared secret...\n";
        std::cout.flush();
        startTime = std::chrono::high_resolution_clock::now();
        auto aliceSecret = device.kem().decapsulate(KemAlgorithm::ML_KEM_768,
                                                    aliceKeys.secretKey,
                                                    bobResult.ciphertext);
        endTime = std::chrono::high_resolution_clock::now();
        double decapsMs = std::chrono::duration<double, std::milli>(endTime - startTime).count();
        std::cout << "Alice: Decapsulation took " << formatDuration(decapsMs) << "\n";
        printBytes("Alice Shared Secret", aliceSecret);
        std::cout << "\n";
        std::cout.flush();

        // Verify shared secrets match
        if (bobResult.sharedSecret == aliceSecret)
        {
            std::cout << "[OK] SUCCESS: Shared secrets match!\n";
            std::cout << "  Both parties now have the same 32-byte key for symmetric encryption.\n\n";
        }
        else
        {
            std::cout << "[FAIL] FAILURE: Shared secrets don't match!\n";
            return 1;
        }
        std::cout.flush();

        // Benchmark
        std::cout << "Performance Benchmark (1000 operations):\n";
        std::cout << "----------------------------------------\n";
        std::cout.flush();

        const int iterations = 1000;

        // Keygen benchmark
        startTime = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < iterations; ++i)
        {
            device.kem().generateKeyPair(KemAlgorithm::ML_KEM_768);
        }
        endTime = std::chrono::high_resolution_clock::now();
        double totalMs = std::chrono::duration<double, std::milli>(endTime - startTime).count();
        double keygenRate = iterations / (totalMs / 1000.0);
        std::cout << "Key Generation: " << std::fixed << std::setprecision(0)
                  << keygenRate << " ops/sec\n";
        std::cout.flush();

        // Encaps benchmark
        startTime = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < iterations; ++i)
        {
            device.kem().encapsulate(KemAlgorithm::ML_KEM_768, aliceKeys.publicKey);
        }
        endTime = std::chrono::high_resolution_clock::now();
        totalMs = std::chrono::duration<double, std::milli>(endTime - startTime).count();
        double encapsRate = iterations / (totalMs / 1000.0);
        std::cout << "Encapsulation:  " << std::fixed << std::setprecision(0)
                  << encapsRate << " ops/sec\n";
        std::cout.flush();

        // Decaps benchmark
        startTime = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < iterations; ++i)
        {
            device.kem().decapsulate(KemAlgorithm::ML_KEM_768,
                                     aliceKeys.secretKey,
                                     bobResult.ciphertext);
        }
        endTime = std::chrono::high_resolution_clock::now();
        totalMs = std::chrono::duration<double, std::milli>(endTime - startTime).count();
        double decapsRate = iterations / (totalMs / 1000.0);
        std::cout << "Decapsulation:  " << std::fixed << std::setprecision(0)
                  << decapsRate << " ops/sec\n\n";
        std::cout.flush();

        std::cout << "KEM example completed successfully!\n";
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