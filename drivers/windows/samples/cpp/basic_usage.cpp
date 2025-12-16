/*++

    QUAC 100 C++ Sample - Basic Usage
    
    This sample demonstrates basic usage of the QUAC 100 driver
    including device initialization, KEM operations, signatures,
    and random number generation.
    
    Copyright (c) 2025 Dyber, Inc. All Rights Reserved.

--*/

#include <iostream>
#include <vector>
#include <iomanip>
#include <memory>
#include <stdexcept>

// Include the QUAC 100 library header
#include <quac100lib.h>

// Link against the library
#pragma comment(lib, "quac100.lib")

//
// Helper class for RAII device handle management
//
class Quac100Device {
public:
    Quac100Device() : m_handle(nullptr) {
        QUAC_STATUS status = Quac100_Open(&m_handle);
        if (status != QUAC_SUCCESS) {
            throw std::runtime_error("Failed to open QUAC 100 device");
        }
    }
    
    ~Quac100Device() {
        if (m_handle) {
            Quac100_Close(m_handle);
        }
    }
    
    // Disable copy
    Quac100Device(const Quac100Device&) = delete;
    Quac100Device& operator=(const Quac100Device&) = delete;
    
    // Enable move
    Quac100Device(Quac100Device&& other) noexcept : m_handle(other.m_handle) {
        other.m_handle = nullptr;
    }
    
    QUAC_HANDLE get() const { return m_handle; }
    operator QUAC_HANDLE() const { return m_handle; }
    
private:
    QUAC_HANDLE m_handle;
};

//
// Helper function to print bytes as hex
//
void PrintHex(const char* label, const uint8_t* data, size_t len, size_t maxDisplay = 32) {
    std::cout << label << " (" << len << " bytes): ";
    for (size_t i = 0; i < std::min(len, maxDisplay); i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') 
                  << static_cast<int>(data[i]);
    }
    if (len > maxDisplay) {
        std::cout << "...";
    }
    std::cout << std::dec << std::endl;
}

//
// Demonstrate KEM (Key Encapsulation Mechanism) operations
//
void DemoKEM(Quac100Device& device) {
    std::cout << "\n=== ML-KEM (Kyber) Demo ===" << std::endl;
    
    // Allocate buffers for Kyber-768
    std::vector<uint8_t> publicKey(KYBER768_PUBLIC_KEY_SIZE);
    std::vector<uint8_t> secretKey(KYBER768_SECRET_KEY_SIZE);
    std::vector<uint8_t> ciphertext(KYBER768_CIPHERTEXT_SIZE);
    std::vector<uint8_t> sharedSecret1(KYBER_SHARED_SECRET_SIZE);
    std::vector<uint8_t> sharedSecret2(KYBER_SHARED_SECRET_SIZE);
    
    // Generate key pair
    std::cout << "Generating ML-KEM-768 key pair..." << std::endl;
    QUAC_STATUS status = Quac100_KemKeyGen(
        device,
        QUAC_KEM_KYBER768,
        publicKey.data(),
        secretKey.data()
    );
    
    if (status != QUAC_SUCCESS) {
        throw std::runtime_error("KEM key generation failed");
    }
    
    PrintHex("Public Key", publicKey.data(), publicKey.size());
    
    // Encapsulate (sender side)
    std::cout << "\nEncapsulating shared secret..." << std::endl;
    status = Quac100_KemEncaps(
        device,
        QUAC_KEM_KYBER768,
        publicKey.data(),
        ciphertext.data(),
        sharedSecret1.data()
    );
    
    if (status != QUAC_SUCCESS) {
        throw std::runtime_error("KEM encapsulation failed");
    }
    
    PrintHex("Ciphertext", ciphertext.data(), ciphertext.size());
    PrintHex("Shared Secret (sender)", sharedSecret1.data(), sharedSecret1.size());
    
    // Decapsulate (receiver side)
    std::cout << "\nDecapsulating shared secret..." << std::endl;
    status = Quac100_KemDecaps(
        device,
        QUAC_KEM_KYBER768,
        secretKey.data(),
        ciphertext.data(),
        sharedSecret2.data()
    );
    
    if (status != QUAC_SUCCESS) {
        throw std::runtime_error("KEM decapsulation failed");
    }
    
    PrintHex("Shared Secret (receiver)", sharedSecret2.data(), sharedSecret2.size());
    
    // Verify shared secrets match
    if (sharedSecret1 == sharedSecret2) {
        std::cout << "\n✓ Shared secrets match!" << std::endl;
    } else {
        std::cout << "\n✗ ERROR: Shared secrets do not match!" << std::endl;
    }
}

//
// Demonstrate digital signature operations
//
void DemoSignature(Quac100Device& device) {
    std::cout << "\n=== ML-DSA (Dilithium) Demo ===" << std::endl;
    
    // Allocate buffers for Dilithium-3
    std::vector<uint8_t> publicKey(DILITHIUM3_PUBLIC_KEY_SIZE);
    std::vector<uint8_t> secretKey(DILITHIUM3_SECRET_KEY_SIZE);
    std::vector<uint8_t> signature(DILITHIUM3_SIGNATURE_SIZE);
    
    // Message to sign
    const char* message = "Hello, Post-Quantum World!";
    size_t messageLen = strlen(message);
    
    // Generate key pair
    std::cout << "Generating ML-DSA-65 key pair..." << std::endl;
    QUAC_STATUS status = Quac100_SignKeyGen(
        device,
        QUAC_SIGN_DILITHIUM3,
        publicKey.data(),
        secretKey.data()
    );
    
    if (status != QUAC_SUCCESS) {
        throw std::runtime_error("Signature key generation failed");
    }
    
    PrintHex("Public Key", publicKey.data(), publicKey.size());
    
    // Sign the message
    std::cout << "\nSigning message: \"" << message << "\"" << std::endl;
    uint32_t signatureLen = static_cast<uint32_t>(signature.size());
    status = Quac100_Sign(
        device,
        QUAC_SIGN_DILITHIUM3,
        secretKey.data(),
        reinterpret_cast<const uint8_t*>(message),
        static_cast<uint32_t>(messageLen),
        nullptr,  // No context
        0,
        signature.data(),
        &signatureLen
    );
    
    if (status != QUAC_SUCCESS) {
        throw std::runtime_error("Signing failed");
    }
    
    signature.resize(signatureLen);
    PrintHex("Signature", signature.data(), signature.size());
    
    // Verify the signature
    std::cout << "\nVerifying signature..." << std::endl;
    bool valid = false;
    status = Quac100_Verify(
        device,
        QUAC_SIGN_DILITHIUM3,
        publicKey.data(),
        reinterpret_cast<const uint8_t*>(message),
        static_cast<uint32_t>(messageLen),
        nullptr,
        0,
        signature.data(),
        signatureLen,
        &valid
    );
    
    if (status != QUAC_SUCCESS) {
        throw std::runtime_error("Verification failed");
    }
    
    if (valid) {
        std::cout << "✓ Signature is valid!" << std::endl;
    } else {
        std::cout << "✗ Signature is invalid!" << std::endl;
    }
    
    // Try to verify with modified message
    std::cout << "\nVerifying with modified message..." << std::endl;
    const char* modifiedMessage = "Hello, Post-Quantum World?";  // Changed ! to ?
    status = Quac100_Verify(
        device,
        QUAC_SIGN_DILITHIUM3,
        publicKey.data(),
        reinterpret_cast<const uint8_t*>(modifiedMessage),
        static_cast<uint32_t>(strlen(modifiedMessage)),
        nullptr,
        0,
        signature.data(),
        signatureLen,
        &valid
    );
    
    if (!valid) {
        std::cout << "✓ Modified message correctly rejected!" << std::endl;
    } else {
        std::cout << "✗ ERROR: Modified message incorrectly accepted!" << std::endl;
    }
}

//
// Demonstrate quantum random number generation
//
void DemoQRNG(Quac100Device& device) {
    std::cout << "\n=== QRNG Demo ===" << std::endl;
    
    // Generate random bytes
    std::vector<uint8_t> randomData(64);
    
    std::cout << "Generating 64 quantum random bytes..." << std::endl;
    QUAC_STATUS status = Quac100_Random(
        device,
        randomData.data(),
        static_cast<uint32_t>(randomData.size()),
        QUAC_RNG_QUALITY_HIGH
    );
    
    if (status != QUAC_SUCCESS) {
        throw std::runtime_error("Random generation failed");
    }
    
    PrintHex("Random Data", randomData.data(), randomData.size(), 64);
    
    // Check QRNG health
    std::cout << "\nChecking QRNG health..." << std::endl;
    QUAC_RNG_STATUS rngStatus;
    status = Quac100_GetRngStatus(device, &rngStatus);
    
    if (status == QUAC_SUCCESS) {
        std::cout << "  State: " << (rngStatus.State == QUAC_RNG_STATE_READY ? "Ready" : "Not Ready") << std::endl;
        std::cout << "  Health: " << (rngStatus.Health == QUAC_RNG_HEALTH_OK ? "OK" : "Degraded") << std::endl;
        std::cout << "  Entropy Available: " << rngStatus.EntropyBits << " bits" << std::endl;
        std::cout << "  Total Generated: " << rngStatus.TotalGenerated << " bytes" << std::endl;
    }
}

//
// Demonstrate device information retrieval
//
void DemoDeviceInfo(Quac100Device& device) {
    std::cout << "\n=== Device Information ===" << std::endl;
    
    // Get version info
    QUAC_VERSION_INFO version;
    QUAC_STATUS status = Quac100_GetVersion(device, &version);
    
    if (status == QUAC_SUCCESS) {
        std::cout << "Driver Version: " << version.DriverVersionString << std::endl;
        std::cout << "Firmware Version: " << version.FirmwareVersionString << std::endl;
        std::cout << "Hardware Revision: " << version.HardwareRevision << std::endl;
    }
    
    // Get device info
    QUAC_DEVICE_INFO info;
    status = Quac100_GetInfo(device, &info);
    
    if (status == QUAC_SUCCESS) {
        std::cout << "Device Name: " << info.DeviceName << std::endl;
        std::cout << "Serial Number: " << std::hex << info.SerialNumber << std::dec << std::endl;
        std::cout << "Temperature: " << info.TemperatureCelsius << " C" << std::endl;
        std::cout << "Power: " << info.PowerStateMilliwatts << " mW" << std::endl;
        
        std::cout << "Capabilities: ";
        if (info.Capabilities & QUAC_CAP_KEM_KYBER512) std::cout << "Kyber512 ";
        if (info.Capabilities & QUAC_CAP_KEM_KYBER768) std::cout << "Kyber768 ";
        if (info.Capabilities & QUAC_CAP_KEM_KYBER1024) std::cout << "Kyber1024 ";
        if (info.Capabilities & QUAC_CAP_SIGN_DILITHIUM2) std::cout << "Dilithium2 ";
        if (info.Capabilities & QUAC_CAP_SIGN_DILITHIUM3) std::cout << "Dilithium3 ";
        if (info.Capabilities & QUAC_CAP_SIGN_DILITHIUM5) std::cout << "Dilithium5 ";
        if (info.Capabilities & QUAC_CAP_SIGN_SPHINCS) std::cout << "SPHINCS+ ";
        if (info.Capabilities & QUAC_CAP_QRNG) std::cout << "QRNG ";
        std::cout << std::endl;
    }
}

//
// Main entry point
//
int main() {
    std::cout << "QUAC 100 C++ Sample - Basic Usage" << std::endl;
    std::cout << "==================================" << std::endl;
    
    try {
        // Open device
        std::cout << "\nOpening QUAC 100 device..." << std::endl;
        Quac100Device device;
        std::cout << "Device opened successfully!" << std::endl;
        
        // Run demos
        DemoDeviceInfo(device);
        DemoKEM(device);
        DemoSignature(device);
        DemoQRNG(device);
        
        std::cout << "\n=== All demos completed successfully! ===" << std::endl;
        return 0;
        
    } catch (const std::exception& e) {
        std::cerr << "\nError: " << e.what() << std::endl;
        return 1;
    }
}
