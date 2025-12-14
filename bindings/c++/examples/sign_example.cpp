/**
 * @file sign_example.cpp
 * @brief QUAC 100 C++ SDK - Digital Signature Example
 * @copyright Copyright © 2025 Dyber, Inc. All Rights Reserved.
 *
 * Demonstrates ML-DSA (Dilithium) post-quantum digital signatures.
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
    std::cout << "QUAC 100 C++ SDK - Digital Signature Example\n";
    std::cout << "=============================================\n\n";
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

        // Get algorithm parameters (use instance method via device.sign())
        std::cout << "ML-DSA Algorithm Parameters:\n";
        std::cout << "----------------------------\n";
        std::cout.flush();

        for (auto alg : {SignAlgorithm::ML_DSA_44,
                         SignAlgorithm::ML_DSA_65,
                         SignAlgorithm::ML_DSA_87})
        {
            auto params = device.sign().getParams(alg);
            std::cout << params.name << ":\n";
            std::cout << "  Public Key:  " << params.publicKeySize << " bytes\n";
            std::cout << "  Secret Key:  " << params.secretKeySize << " bytes\n";
            std::cout << "  Signature:   " << params.signatureSize << " bytes\n";
            std::cout << "  Security:    Level " << params.securityLevel << "\n\n";
            std::cout.flush();
        }

        // Demonstrate ML-DSA-65 signing
        std::cout << "ML-DSA-65 Digital Signature Demo\n";
        std::cout << "---------------------------------\n\n";
        std::cout.flush();

        // Generate signing key pair
        std::cout << "Generating signing key pair...\n";
        std::cout.flush();
        auto startTime = std::chrono::high_resolution_clock::now();
        auto keys = device.sign().generateKeyPair(SignAlgorithm::ML_DSA_65);
        auto endTime = std::chrono::high_resolution_clock::now();
        double keygenMs = std::chrono::duration<double, std::milli>(endTime - startTime).count();
        std::cout << "Key generation took " << formatDuration(keygenMs) << "\n";
        printBytes("Public Key", keys.publicKey);
        std::cout << "\n";
        std::cout.flush();

        // Sign a message
        std::string messageStr = "This is an important document that needs to be signed.";
        Bytes message(messageStr.begin(), messageStr.end());
        std::cout << "Message: \"" << messageStr << "\"\n\n";
        std::cout.flush();

        std::cout << "Signing message...\n";
        std::cout.flush();
        startTime = std::chrono::high_resolution_clock::now();
        auto signature = device.sign().sign(SignAlgorithm::ML_DSA_65, keys.secretKey, message);
        endTime = std::chrono::high_resolution_clock::now();
        double signMs = std::chrono::duration<double, std::milli>(endTime - startTime).count();
        std::cout << "Signing took " << formatDuration(signMs) << "\n";
        printBytes("Signature", signature);
        std::cout << "\n";
        std::cout.flush();

        // Verify signature
        std::cout << "Verifying signature...\n";
        std::cout.flush();
        startTime = std::chrono::high_resolution_clock::now();
        bool valid = device.sign().verify(SignAlgorithm::ML_DSA_65,
                                          keys.publicKey, message, signature);
        endTime = std::chrono::high_resolution_clock::now();
        double verifyMs = std::chrono::duration<double, std::milli>(endTime - startTime).count();
        std::cout << "Verification took " << formatDuration(verifyMs) << "\n";
        std::cout.flush();

        if (valid)
        {
            std::cout << "[OK] Signature is VALID\n\n";
        }
        else
        {
            std::cout << "[FAIL] Signature is INVALID\n";
            return 1;
        }
        std::cout.flush();

        // Test tamper detection
        std::cout << "Testing Tamper Detection:\n";
        std::cout << "-------------------------\n";
        std::cout.flush();

        // Modify message
        std::string tamperedStr = "This is an important document that needs to be signed!";
        Bytes tamperedMessage(tamperedStr.begin(), tamperedStr.end());
        std::cout << "Tampered: \"" << tamperedStr << "\"\n";
        std::cout.flush();

        bool tamperedValid = false;
        try
        {
            tamperedValid = device.sign().verify(SignAlgorithm::ML_DSA_65,
                                                 keys.publicKey,
                                                 tamperedMessage,
                                                 signature);
        }
        catch (const VerificationException &)
        {
            tamperedValid = false;
        }

        if (!tamperedValid)
        {
            std::cout << "[OK] Tamper detected: Signature rejected for modified message\n\n";
        }
        else
        {
            std::cout << "[FAIL] SECURITY FAILURE: Tampered message accepted!\n";
            return 1;
        }
        std::cout.flush();

        // Batch signing example
        std::cout << "Batch Signing Example:\n";
        std::cout << "----------------------\n";
        std::cout.flush();

        std::vector<Bytes> messages = {
            {'M', 'e', 's', 's', 'a', 'g', 'e', ' ', '1'},
            {'M', 'e', 's', 's', 'a', 'g', 'e', ' ', '2'},
            {'M', 'e', 's', 's', 'a', 'g', 'e', ' ', '3'},
            {'M', 'e', 's', 's', 'a', 'g', 'e', ' ', '4'},
            {'M', 'e', 's', 's', 'a', 'g', 'e', ' ', '5'}};

        std::vector<Bytes> signatures;
        startTime = std::chrono::high_resolution_clock::now();
        for (const auto &msg : messages)
        {
            signatures.push_back(device.sign().sign(SignAlgorithm::ML_DSA_65,
                                                    keys.secretKey, msg));
        }
        endTime = std::chrono::high_resolution_clock::now();
        double batchSignMs = std::chrono::duration<double, std::milli>(endTime - startTime).count();
        std::cout << "Signed " << messages.size() << " messages in "
                  << formatDuration(batchSignMs) << "\n";
        std::cout.flush();

        int validCount = 0;
        startTime = std::chrono::high_resolution_clock::now();
        for (size_t i = 0; i < messages.size(); ++i)
        {
            try
            {
                if (device.sign().verify(SignAlgorithm::ML_DSA_65,
                                         keys.publicKey,
                                         messages[i],
                                         signatures[i]))
                {
                    validCount++;
                }
            }
            catch (...)
            {
            }
        }
        endTime = std::chrono::high_resolution_clock::now();
        double batchVerifyMs = std::chrono::duration<double, std::milli>(endTime - startTime).count();
        std::cout << "Verified " << messages.size() << " signatures in "
                  << formatDuration(batchVerifyMs) << "\n";
        std::cout << "Results: " << validCount << "/" << messages.size() << " valid\n\n";
        std::cout.flush();

        // Performance benchmark
        std::cout << "Performance Benchmark (100 operations):\n";
        std::cout << "---------------------------------------\n";
        std::cout.flush();

        const int iterations = 100;
        Bytes testMsg(256, 0x42);

        // Sign benchmark
        startTime = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < iterations; ++i)
        {
            device.sign().sign(SignAlgorithm::ML_DSA_65, keys.secretKey, testMsg);
        }
        endTime = std::chrono::high_resolution_clock::now();
        double totalMs = std::chrono::duration<double, std::milli>(endTime - startTime).count();
        double signRate = iterations / (totalMs / 1000.0);
        std::cout << "Signing:      " << std::fixed << std::setprecision(0)
                  << signRate << " ops/sec\n";
        std::cout.flush();

        // Verify benchmark
        auto testSig = device.sign().sign(SignAlgorithm::ML_DSA_65, keys.secretKey, testMsg);
        startTime = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < iterations; ++i)
        {
            device.sign().verify(SignAlgorithm::ML_DSA_65, keys.publicKey, testMsg, testSig);
        }
        endTime = std::chrono::high_resolution_clock::now();
        totalMs = std::chrono::duration<double, std::milli>(endTime - startTime).count();
        double verifyRate = iterations / (totalMs / 1000.0);
        std::cout << "Verification: " << std::fixed << std::setprecision(0)
                  << verifyRate << " ops/sec\n\n";
        std::cout.flush();

        std::cout << "Signature example completed successfully!\n";
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