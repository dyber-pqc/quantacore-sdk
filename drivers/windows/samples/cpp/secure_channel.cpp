/*++

    QUAC 100 C++ Sample - Secure Channel
    
    This sample demonstrates how to establish a post-quantum secure
    channel using QUAC 100's ML-KEM for key exchange and ML-DSA
    for authentication.
    
    This is a simplified demonstration - a real implementation would
    include proper protocol framing, error handling, and integration
    with a transport layer.
    
    Copyright (c) 2025 Dyber, Inc. All Rights Reserved.

--*/

#include <iostream>
#include <vector>
#include <cstring>
#include <memory>
#include <random>

#include <quac100lib.h>
#include <windows.h>
#include <bcrypt.h>

#pragma comment(lib, "quac100.lib")
#pragma comment(lib, "bcrypt.lib")

//
// Simulated secure channel endpoint
//
class SecureEndpoint {
public:
    SecureEndpoint(QUAC_HANDLE device, const std::string& name)
        : m_device(device)
        , m_name(name)
        , m_hasSessionKey(false)
    {
        // Generate long-term identity key pair (for signing)
        m_signPublicKey.resize(DILITHIUM3_PUBLIC_KEY_SIZE);
        m_signSecretKey.resize(DILITHIUM3_SECRET_KEY_SIZE);
        
        QUAC_STATUS status = Quac100_SignKeyGen(
            m_device,
            QUAC_SIGN_DILITHIUM3,
            m_signPublicKey.data(),
            m_signSecretKey.data()
        );
        
        if (status != QUAC_SUCCESS) {
            throw std::runtime_error("Failed to generate identity key");
        }
        
        std::cout << "[" << m_name << "] Identity key generated" << std::endl;
    }
    
    //
    // Get our public identity key (for sharing with peers)
    //
    const std::vector<uint8_t>& GetIdentityPublicKey() const {
        return m_signPublicKey;
    }
    
    //
    // Set the peer's identity public key (received out-of-band)
    //
    void SetPeerIdentity(const std::vector<uint8_t>& peerPublicKey) {
        m_peerSignPublicKey = peerPublicKey;
        std::cout << "[" << m_name << "] Peer identity set" << std::endl;
    }
    
    //
    // Initiator: Start key exchange (generate ephemeral KEM keys)
    //
    std::vector<uint8_t> InitiateKeyExchange() {
        std::cout << "[" << m_name << "] Initiating key exchange..." << std::endl;
        
        // Generate ephemeral KEM key pair
        m_kemPublicKey.resize(KYBER768_PUBLIC_KEY_SIZE);
        m_kemSecretKey.resize(KYBER768_SECRET_KEY_SIZE);
        
        QUAC_STATUS status = Quac100_KemKeyGen(
            m_device,
            QUAC_KEM_KYBER768,
            m_kemPublicKey.data(),
            m_kemSecretKey.data()
        );
        
        if (status != QUAC_SUCCESS) {
            throw std::runtime_error("Failed to generate ephemeral KEM key");
        }
        
        // Sign the ephemeral public key
        std::vector<uint8_t> signature(DILITHIUM3_SIGNATURE_SIZE);
        uint32_t sigLen = static_cast<uint32_t>(signature.size());
        
        status = Quac100_Sign(
            m_device,
            QUAC_SIGN_DILITHIUM3,
            m_signSecretKey.data(),
            m_kemPublicKey.data(),
            static_cast<uint32_t>(m_kemPublicKey.size()),
            nullptr, 0,
            signature.data(),
            &sigLen
        );
        
        if (status != QUAC_SUCCESS) {
            throw std::runtime_error("Failed to sign ephemeral key");
        }
        signature.resize(sigLen);
        
        // Create message: ephemeral_public_key || signature
        std::vector<uint8_t> message;
        message.reserve(m_kemPublicKey.size() + signature.size());
        message.insert(message.end(), m_kemPublicKey.begin(), m_kemPublicKey.end());
        message.insert(message.end(), signature.begin(), signature.end());
        
        std::cout << "[" << m_name << "] Sent ephemeral public key with signature" << std::endl;
        return message;
    }
    
    //
    // Responder: Respond to key exchange (encapsulate and send ciphertext)
    //
    std::vector<uint8_t> RespondToKeyExchange(const std::vector<uint8_t>& initiatorMessage) {
        std::cout << "[" << m_name << "] Responding to key exchange..." << std::endl;
        
        // Parse initiator's message
        if (initiatorMessage.size() < KYBER768_PUBLIC_KEY_SIZE) {
            throw std::runtime_error("Invalid initiator message");
        }
        
        std::vector<uint8_t> peerKemPublicKey(
            initiatorMessage.begin(),
            initiatorMessage.begin() + KYBER768_PUBLIC_KEY_SIZE
        );
        
        std::vector<uint8_t> peerSignature(
            initiatorMessage.begin() + KYBER768_PUBLIC_KEY_SIZE,
            initiatorMessage.end()
        );
        
        // Verify initiator's signature on ephemeral key
        bool valid = false;
        QUAC_STATUS status = Quac100_Verify(
            m_device,
            QUAC_SIGN_DILITHIUM3,
            m_peerSignPublicKey.data(),
            peerKemPublicKey.data(),
            static_cast<uint32_t>(peerKemPublicKey.size()),
            nullptr, 0,
            peerSignature.data(),
            static_cast<uint32_t>(peerSignature.size()),
            &valid
        );
        
        if (status != QUAC_SUCCESS || !valid) {
            throw std::runtime_error("Peer signature verification failed!");
        }
        
        std::cout << "[" << m_name << "] Peer signature verified" << std::endl;
        
        // Encapsulate shared secret
        std::vector<uint8_t> ciphertext(KYBER768_CIPHERTEXT_SIZE);
        m_sessionKey.resize(KYBER_SHARED_SECRET_SIZE);
        
        status = Quac100_KemEncaps(
            m_device,
            QUAC_KEM_KYBER768,
            peerKemPublicKey.data(),
            ciphertext.data(),
            m_sessionKey.data()
        );
        
        if (status != QUAC_SUCCESS) {
            throw std::runtime_error("Encapsulation failed");
        }
        
        m_hasSessionKey = true;
        
        // Sign the ciphertext
        std::vector<uint8_t> signature(DILITHIUM3_SIGNATURE_SIZE);
        uint32_t sigLen = static_cast<uint32_t>(signature.size());
        
        status = Quac100_Sign(
            m_device,
            QUAC_SIGN_DILITHIUM3,
            m_signSecretKey.data(),
            ciphertext.data(),
            static_cast<uint32_t>(ciphertext.size()),
            nullptr, 0,
            signature.data(),
            &sigLen
        );
        
        if (status != QUAC_SUCCESS) {
            throw std::runtime_error("Failed to sign ciphertext");
        }
        signature.resize(sigLen);
        
        // Create response: ciphertext || signature
        std::vector<uint8_t> response;
        response.reserve(ciphertext.size() + signature.size());
        response.insert(response.end(), ciphertext.begin(), ciphertext.end());
        response.insert(response.end(), signature.begin(), signature.end());
        
        std::cout << "[" << m_name << "] Session key established, sent ciphertext" << std::endl;
        return response;
    }
    
    //
    // Initiator: Complete key exchange (decapsulate ciphertext)
    //
    void CompleteKeyExchange(const std::vector<uint8_t>& responderMessage) {
        std::cout << "[" << m_name << "] Completing key exchange..." << std::endl;
        
        // Parse responder's message
        if (responderMessage.size() < KYBER768_CIPHERTEXT_SIZE) {
            throw std::runtime_error("Invalid responder message");
        }
        
        std::vector<uint8_t> ciphertext(
            responderMessage.begin(),
            responderMessage.begin() + KYBER768_CIPHERTEXT_SIZE
        );
        
        std::vector<uint8_t> peerSignature(
            responderMessage.begin() + KYBER768_CIPHERTEXT_SIZE,
            responderMessage.end()
        );
        
        // Verify responder's signature on ciphertext
        bool valid = false;
        QUAC_STATUS status = Quac100_Verify(
            m_device,
            QUAC_SIGN_DILITHIUM3,
            m_peerSignPublicKey.data(),
            ciphertext.data(),
            static_cast<uint32_t>(ciphertext.size()),
            nullptr, 0,
            peerSignature.data(),
            static_cast<uint32_t>(peerSignature.size()),
            &valid
        );
        
        if (status != QUAC_SUCCESS || !valid) {
            throw std::runtime_error("Peer signature verification failed!");
        }
        
        std::cout << "[" << m_name << "] Peer signature verified" << std::endl;
        
        // Decapsulate to get shared secret
        m_sessionKey.resize(KYBER_SHARED_SECRET_SIZE);
        
        status = Quac100_KemDecaps(
            m_device,
            QUAC_KEM_KYBER768,
            m_kemSecretKey.data(),
            ciphertext.data(),
            m_sessionKey.data()
        );
        
        if (status != QUAC_SUCCESS) {
            throw std::runtime_error("Decapsulation failed");
        }
        
        m_hasSessionKey = true;
        
        // Clear ephemeral secret key
        SecureZeroMemory(m_kemSecretKey.data(), m_kemSecretKey.size());
        m_kemSecretKey.clear();
        
        std::cout << "[" << m_name << "] Session key established!" << std::endl;
    }
    
    //
    // Encrypt a message using the session key (using AES-GCM via BCrypt)
    //
    std::vector<uint8_t> Encrypt(const std::string& plaintext) {
        if (!m_hasSessionKey) {
            throw std::runtime_error("No session key established");
        }
        
        BCRYPT_ALG_HANDLE hAlg = nullptr;
        BCRYPT_KEY_HANDLE hKey = nullptr;
        NTSTATUS status;
        
        // Open AES algorithm
        status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
        if (!BCRYPT_SUCCESS(status)) {
            throw std::runtime_error("Failed to open AES provider");
        }
        
        // Set GCM mode
        status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
            (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
        
        // Generate key from session key (use first 32 bytes for AES-256)
        status = BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0,
            m_sessionKey.data(), 32, 0);
        
        if (!BCRYPT_SUCCESS(status)) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            throw std::runtime_error("Failed to create AES key");
        }
        
        // Generate random IV using QUAC QRNG
        std::vector<uint8_t> iv(12);  // GCM uses 12-byte IV
        Quac100_Random(m_device, iv.data(), 12, QUAC_RNG_QUALITY_HIGH);
        
        // Prepare auth info
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
        BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
        authInfo.pbNonce = iv.data();
        authInfo.cbNonce = static_cast<ULONG>(iv.size());
        authInfo.pbTag = nullptr;
        authInfo.cbTag = 16;  // GCM tag size
        
        // Get ciphertext size
        ULONG ciphertextLen = 0;
        status = BCryptEncrypt(hKey, (PUCHAR)plaintext.data(),
            static_cast<ULONG>(plaintext.size()), &authInfo,
            nullptr, 0, nullptr, 0, &ciphertextLen, 0);
        
        // Allocate output: IV || ciphertext || tag
        std::vector<uint8_t> output(12 + ciphertextLen + 16);
        memcpy(output.data(), iv.data(), 12);
        
        std::vector<uint8_t> tag(16);
        authInfo.pbTag = tag.data();
        
        // Encrypt
        status = BCryptEncrypt(hKey, (PUCHAR)plaintext.data(),
            static_cast<ULONG>(plaintext.size()), &authInfo,
            nullptr, 0, output.data() + 12, ciphertextLen, &ciphertextLen, 0);
        
        // Append tag
        memcpy(output.data() + 12 + ciphertextLen, tag.data(), 16);
        
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        
        if (!BCRYPT_SUCCESS(status)) {
            throw std::runtime_error("Encryption failed");
        }
        
        std::cout << "[" << m_name << "] Encrypted " << plaintext.size() << " bytes" << std::endl;
        return output;
    }
    
    //
    // Decrypt a message using the session key
    //
    std::string Decrypt(const std::vector<uint8_t>& ciphertext) {
        if (!m_hasSessionKey) {
            throw std::runtime_error("No session key established");
        }
        
        if (ciphertext.size() < 12 + 16) {  // IV + tag minimum
            throw std::runtime_error("Ciphertext too short");
        }
        
        BCRYPT_ALG_HANDLE hAlg = nullptr;
        BCRYPT_KEY_HANDLE hKey = nullptr;
        NTSTATUS status;
        
        status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
        status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
            (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
        status = BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0,
            m_sessionKey.data(), 32, 0);
        
        // Extract IV, ciphertext, tag
        std::vector<uint8_t> iv(ciphertext.begin(), ciphertext.begin() + 12);
        std::vector<uint8_t> tag(ciphertext.end() - 16, ciphertext.end());
        size_t encryptedLen = ciphertext.size() - 12 - 16;
        
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
        BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
        authInfo.pbNonce = iv.data();
        authInfo.cbNonce = static_cast<ULONG>(iv.size());
        authInfo.pbTag = tag.data();
        authInfo.cbTag = static_cast<ULONG>(tag.size());
        
        std::vector<uint8_t> plaintext(encryptedLen);
        ULONG plaintextLen = 0;
        
        status = BCryptDecrypt(hKey,
            (PUCHAR)(ciphertext.data() + 12), static_cast<ULONG>(encryptedLen),
            &authInfo, nullptr, 0,
            plaintext.data(), static_cast<ULONG>(plaintext.size()),
            &plaintextLen, 0);
        
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        
        if (!BCRYPT_SUCCESS(status)) {
            throw std::runtime_error("Decryption failed (authentication error)");
        }
        
        std::cout << "[" << m_name << "] Decrypted " << plaintextLen << " bytes" << std::endl;
        return std::string(plaintext.begin(), plaintext.begin() + plaintextLen);
    }
    
    //
    // Get session key fingerprint (for verification)
    //
    std::string GetSessionKeyFingerprint() const {
        if (!m_hasSessionKey) {
            return "(no session key)";
        }
        
        char hex[65];
        for (size_t i = 0; i < 32; i++) {
            sprintf_s(hex + i * 2, 3, "%02x", m_sessionKey[i]);
        }
        return std::string(hex, 16) + "...";  // First 8 bytes
    }
    
private:
    QUAC_HANDLE m_device;
    std::string m_name;
    
    // Long-term identity keys
    std::vector<uint8_t> m_signPublicKey;
    std::vector<uint8_t> m_signSecretKey;
    std::vector<uint8_t> m_peerSignPublicKey;
    
    // Ephemeral KEM keys
    std::vector<uint8_t> m_kemPublicKey;
    std::vector<uint8_t> m_kemSecretKey;
    
    // Session key
    std::vector<uint8_t> m_sessionKey;
    bool m_hasSessionKey;
};

//
// Main demo
//
int main() {
    std::cout << "QUAC 100 C++ Sample - Post-Quantum Secure Channel" << std::endl;
    std::cout << "==================================================" << std::endl;
    
    try {
        // Open device
        QUAC_HANDLE device;
        if (Quac100_Open(&device) != QUAC_SUCCESS) {
            throw std::runtime_error("Failed to open device");
        }
        
        std::cout << "\n--- Setting up endpoints ---\n" << std::endl;
        
        // Create two endpoints (simulating Alice and Bob)
        SecureEndpoint alice(device, "Alice");
        SecureEndpoint bob(device, "Bob");
        
        // Exchange identity keys (out-of-band in real implementation)
        alice.SetPeerIdentity(bob.GetIdentityPublicKey());
        bob.SetPeerIdentity(alice.GetIdentityPublicKey());
        
        std::cout << "\n--- Key Exchange Protocol ---\n" << std::endl;
        
        // Step 1: Alice initiates key exchange
        auto initMessage = alice.InitiateKeyExchange();
        
        // Step 2: Bob responds with encapsulated secret
        auto responseMessage = bob.RespondToKeyExchange(initMessage);
        
        // Step 3: Alice completes key exchange
        alice.CompleteKeyExchange(responseMessage);
        
        // Verify both have same session key
        std::cout << "\n--- Session Key Verification ---\n" << std::endl;
        std::cout << "Alice's session key: " << alice.GetSessionKeyFingerprint() << std::endl;
        std::cout << "Bob's session key:   " << bob.GetSessionKeyFingerprint() << std::endl;
        
        // Demo secure messaging
        std::cout << "\n--- Secure Messaging ---\n" << std::endl;
        
        std::string message1 = "Hello Bob! This is a secret post-quantum message.";
        auto encrypted1 = alice.Encrypt(message1);
        auto decrypted1 = bob.Decrypt(encrypted1);
        std::cout << "Alice -> Bob: \"" << decrypted1 << "\"" << std::endl;
        
        std::string message2 = "Hi Alice! The future of cryptography is quantum-safe!";
        auto encrypted2 = bob.Encrypt(message2);
        auto decrypted2 = alice.Decrypt(encrypted2);
        std::cout << "Bob -> Alice: \"" << decrypted2 << "\"" << std::endl;
        
        // Cleanup
        Quac100_Close(device);
        
        std::cout << "\n=== Secure channel demo complete! ===" << std::endl;
        return 0;
        
    } catch (const std::exception& e) {
        std::cerr << "\nError: " << e.what() << std::endl;
        return 1;
    }
}
