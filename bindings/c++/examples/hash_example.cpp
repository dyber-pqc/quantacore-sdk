/**
 * @file hash_example.cpp
 * @brief QUAC 100 C++ SDK - Hash Operations Example
 * @copyright Copyright © 2025 Dyber, Inc. All Rights Reserved.
 *
 * Demonstrates hardware-accelerated hash functions.
 */

#include <quac100/quac100.hpp>
#include <iostream>
#include <iomanip>
#include <chrono>

using namespace quac100;

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
    std::cout << "QUAC 100 C++ SDK - Hash Operations Example\n";
    std::cout << "==========================================\n\n";
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

        std::string testData = "Hello, QUAC 100!";
        Bytes data(testData.begin(), testData.end());
        std::cout << "Test Data: \"" << testData << "\"\n\n";
        std::cout.flush();

        // SHA-2 family
        std::cout << "SHA-2 Family:\n";
        std::cout << "-------------\n";
        std::cout.flush();

        auto sha256 = device.hash().sha256(data);
        std::cout << "SHA-256:  " << utils::toHex(sha256) << "\n";
        std::cout.flush();

        auto sha384 = device.hash().sha384(data);
        std::cout << "SHA-384:  " << utils::toHex(sha384) << "\n";
        std::cout.flush();

        auto sha512 = device.hash().sha512(data);
        std::cout << "SHA-512:  " << utils::toHex(sha512) << "\n\n";
        std::cout.flush();

        // SHA-3 family
        std::cout << "SHA-3 Family:\n";
        std::cout << "-------------\n";
        std::cout.flush();

        auto sha3_256 = device.hash().sha3_256(data);
        std::cout << "SHA3-256: " << utils::toHex(sha3_256) << "\n";
        std::cout.flush();

        auto sha3_512 = device.hash().sha3_512(data);
        std::cout << "SHA3-512: " << utils::toHex(sha3_512) << "\n\n";
        std::cout.flush();

        // SHAKE (extendable output)
        std::cout << "SHAKE (Extendable Output):\n";
        std::cout << "--------------------------\n";
        std::cout.flush();

        auto shake128_32 = device.hash().shake128(data, 32);
        std::cout << "SHAKE128(32):  " << utils::toHex(shake128_32) << "\n";
        std::cout.flush();

        auto shake128_64 = device.hash().shake128(data, 64);
        std::cout << "SHAKE128(64):  " << utils::toHex(shake128_64) << "\n";
        std::cout.flush();

        auto shake256_32 = device.hash().shake256(data, 32);
        std::cout << "SHAKE256(32):  " << utils::toHex(shake256_32) << "\n";
        std::cout.flush();

        auto shake256_64 = device.hash().shake256(data, 64);
        std::cout << "SHAKE256(64):  " << utils::toHex(shake256_64) << "\n\n";
        std::cout.flush();

        // Incremental hashing
        std::cout << "Incremental Hashing:\n";
        std::cout << "--------------------\n";
        std::cout.flush();

        Bytes part1 = {'H', 'e', 'l', 'l', 'o', ',', ' '};
        Bytes part2 = {'Q', 'U', 'A', 'C', ' '};
        Bytes part3 = {'1', '0', '0', '!'};

        auto ctx = device.hash().createContext(HashAlgorithm::SHA256);
        ctx.update(part1);
        ctx.update(part2);
        ctx.update(part3);
        auto incrementalHash = ctx.finalize();

        std::cout << "Incremental: " << utils::toHex(incrementalHash) << "\n";
        std::cout << "One-shot:    " << utils::toHex(sha256) << "\n";
        std::cout << "Match: " << (incrementalHash == sha256 ? "YES" : "NO") << "\n\n";
        std::cout.flush();

        // HMAC
        std::cout << "HMAC:\n";
        std::cout << "-----\n";
        std::cout.flush();

        Bytes key = {'s', 'e', 'c', 'r', 'e', 't', '-', 'k', 'e', 'y'};

        auto hmacSha256 = device.hash().hmac(HashAlgorithm::SHA256, key, data);
        std::cout << "HMAC-SHA256: " << utils::toHex(hmacSha256) << "\n";
        std::cout.flush();

        auto hmacSha512 = device.hash().hmac(HashAlgorithm::SHA512, key, data);
        std::cout << "HMAC-SHA512: " << utils::toHex(hmacSha512) << "\n\n";
        std::cout.flush();

        // HKDF (Key Derivation)
        std::cout << "HKDF Key Derivation:\n";
        std::cout << "--------------------\n";
        std::cout.flush();

        Bytes ikm = device.random().bytes(32); // Input keying material
        Bytes salt = device.random().bytes(16);
        Bytes info = {'a', 'p', 'p', '-', 'k', 'e', 'y'};

        auto derivedKey = device.hash().hkdf(HashAlgorithm::SHA256, ikm, salt, info, 32);
        std::cout << "Derived Key (32 bytes): " << utils::toHex(derivedKey) << "\n";
        std::cout.flush();

        auto derivedKey64 = device.hash().hkdf(HashAlgorithm::SHA256, ikm, salt, info, 64);
        std::cout << "Derived Key (64 bytes): " << utils::toHex(derivedKey64) << "\n\n";
        std::cout.flush();

        // Hash verification example
        std::cout << "Hash Verification Example:\n";
        std::cout << "--------------------------\n";
        std::cout.flush();

        std::string password = "MySecurePassword123";
        Bytes passwordSalt = device.random().bytes(16);

        // Create password hash
        Bytes passwordData(password.begin(), password.end());
        passwordData.insert(passwordData.end(), passwordSalt.begin(), passwordSalt.end());
        auto passwordHash = device.hash().sha256(passwordData);

        std::cout << "Salt: " << utils::toHex(passwordSalt) << "\n";
        std::cout << "Hash: " << utils::toHex(passwordHash) << "\n";
        std::cout.flush();

        // Verify password
        std::string testPassword = "MySecurePassword123";
        Bytes testData2(testPassword.begin(), testPassword.end());
        testData2.insert(testData2.end(), passwordSalt.begin(), passwordSalt.end());
        auto testHash = device.hash().sha256(testData2);

        std::cout << "Verification: " << (testHash == passwordHash ? "MATCH" : "MISMATCH") << "\n\n";
        std::cout.flush();

        // Performance benchmark
        std::cout << "Performance Benchmark (10000 x 1KB):\n";
        std::cout << "------------------------------------\n";
        std::cout.flush();

        Bytes benchData(1024, 0x42);
        const int iterations = 10000;

        auto startTime = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < iterations; ++i)
        {
            device.hash().sha256(benchData);
        }
        auto endTime = std::chrono::high_resolution_clock::now();
        double totalMs = std::chrono::duration<double, std::milli>(endTime - startTime).count();
        double sha256Rate = (iterations * 1024.0) / (totalMs / 1000.0) / 1024.0 / 1024.0;
        std::cout << "SHA-256:  " << std::fixed << std::setprecision(2)
                  << sha256Rate << " MB/sec\n";
        std::cout.flush();

        startTime = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < iterations; ++i)
        {
            device.hash().sha3_256(benchData);
        }
        endTime = std::chrono::high_resolution_clock::now();
        totalMs = std::chrono::duration<double, std::milli>(endTime - startTime).count();
        double sha3Rate = (iterations * 1024.0) / (totalMs / 1000.0) / 1024.0 / 1024.0;
        std::cout << "SHA3-256: " << std::fixed << std::setprecision(2)
                  << sha3Rate << " MB/sec\n\n";
        std::cout.flush();

        std::cout << "Hash example completed successfully!\n";
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