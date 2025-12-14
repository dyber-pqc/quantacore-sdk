/**
 * @file keys.cpp
 * @brief QUAC 100 C++ SDK - Key Storage Implementation
 * @copyright Copyright © 2025 Dyber, Inc. All Rights Reserved.
 */

#include "quac100/keys.hpp"

extern "C"
{
#include <quac100/quac100.h>
#include <quac100/keys.h>
}

namespace quac100
{

    KeyStorage::KeyStorage(quac_device_t device) : device_(device) {}

    void KeyStorage::store(int slot, const std::string &label, KeyType type, int algorithm,
                           const Bytes &keyData, KeyUsage usage, bool exportable)
    {
        (void)slot;       // C API assigns slot automatically
        (void)algorithm;  // Algorithm is inferred from key type in C API
        (void)exportable; // Not directly supported in C API store

        int assignedSlot = -1;

        int status = quac_key_store(
            device_,
            keyData.data(),
            keyData.size(),
            static_cast<quac_key_type_t>(type),
            label.c_str(),
            static_cast<uint32_t>(usage),
            &assignedSlot);

        if (status != QUAC_SUCCESS)
        {
            throw KeyStorageException(status, "Failed to store key");
        }
    }

    Bytes KeyStorage::load(int slot)
    {
        // First get key info to determine size
        quac_key_info_t cinfo;
        int status = quac_key_info(device_, slot, &cinfo);
        if (status != QUAC_SUCCESS)
        {
            throw KeyStorageException(status, "Failed to get key info");
        }

        Bytes key(cinfo.key_size);
        size_t keyLen = key.size();

        status = quac_key_load(device_, slot, key.data(), &keyLen);
        if (status != QUAC_SUCCESS)
        {
            throw KeyStorageException(status, "Failed to load key");
        }

        key.resize(keyLen);
        return key;
    }

    void KeyStorage::remove(int slot)
    {
        int status = quac_key_delete(device_, slot);
        if (status != QUAC_SUCCESS)
        {
            throw KeyStorageException(status, "Failed to delete key");
        }
    }

    bool KeyStorage::exists(int slot)
    {
        quac_key_info_t cinfo;
        int status = quac_key_info(device_, slot, &cinfo);
        return status == QUAC_SUCCESS;
    }

    std::optional<KeyInfo> KeyStorage::info(int slot)
    {
        quac_key_info_t cinfo;
        int status = quac_key_info(device_, slot, &cinfo);

        if (status == QUAC_ERROR_KEY_NOT_FOUND)
        {
            return std::nullopt;
        }

        if (status != QUAC_SUCCESS)
        {
            throw KeyStorageException(status, "Failed to get key info");
        }

        KeyInfo info;
        info.slot = cinfo.slot;
        info.label = cinfo.label;
        info.type = static_cast<KeyType>(cinfo.type);
        info.algorithm = cinfo.algorithm;
        info.usage = static_cast<KeyUsage>(cinfo.usage);
        info.exportable = cinfo.extractable;
        info.createdAt = cinfo.created_time;

        return info;
    }

    std::vector<KeyInfo> KeyStorage::list()
    {
        std::vector<KeyInfo> keys;

        int slots[QUAC_MAX_KEY_SLOTS];
        int count = 0;

        int status = quac_key_list(device_, slots, QUAC_MAX_KEY_SLOTS, &count);
        if (status != QUAC_SUCCESS)
        {
            throw KeyStorageException(status, "Failed to list keys");
        }

        for (int i = 0; i < count; ++i)
        {
            auto keyInfo = info(slots[i]);
            if (keyInfo)
            {
                keys.push_back(*keyInfo);
            }
        }

        return keys;
    }

    int KeyStorage::findByLabel(const std::string &label)
    {
        int slot = -1;
        int status = quac_key_find(device_, label.c_str(), &slot);

        if (status == QUAC_ERROR_KEY_NOT_FOUND)
        {
            return -1;
        }

        if (status != QUAC_SUCCESS)
        {
            throw KeyStorageException(status, "Failed to find key by label");
        }

        return slot;
    }

    int KeyStorage::slotCount()
    {
        int total = 0, used = 0;
        int status = quac_key_slot_count(device_, &total, &used);
        if (status != QUAC_SUCCESS)
        {
            throw KeyStorageException(status, "Failed to get slot count");
        }
        return total;
    }

    int KeyStorage::usedSlots()
    {
        int total = 0, used = 0;
        int status = quac_key_slot_count(device_, &total, &used);
        if (status != QUAC_SUCCESS)
        {
            throw KeyStorageException(status, "Failed to get used slot count");
        }
        return used;
    }

    int KeyStorage::freeSlots()
    {
        int total = 0, used = 0;
        int status = quac_key_slot_count(device_, &total, &used);
        if (status != QUAC_SUCCESS)
        {
            throw KeyStorageException(status, "Failed to get free slot count");
        }
        return total - used;
    }

    EncapsResult KeyStorage::encapsulateWithStored(int slot)
    {
        EncapsResult result;

        // Allocate maximum possible sizes
        result.ciphertext.resize(QUAC_ML_KEM_1024_CIPHERTEXT_SIZE);
        result.sharedSecret.resize(QUAC_ML_KEM_SHARED_SECRET_SIZE);

        size_t ctLen = result.ciphertext.size();
        size_t ssLen = result.sharedSecret.size();

        int status = quac_kem_encaps_stored(
            device_,
            slot,
            result.ciphertext.data(),
            &ctLen,
            result.sharedSecret.data(),
            &ssLen);

        if (status != QUAC_SUCCESS)
        {
            throw KeyStorageException(status, "Encapsulation with stored key failed");
        }

        result.ciphertext.resize(ctLen);
        result.sharedSecret.resize(ssLen);
        return result;
    }

    Bytes KeyStorage::decapsulateWithStored(int slot, const Bytes &ciphertext)
    {
        Bytes sharedSecret(QUAC_ML_KEM_SHARED_SECRET_SIZE);
        size_t ssLen = sharedSecret.size();

        int status = quac_kem_decaps_stored(
            device_,
            slot,
            ciphertext.data(),
            ciphertext.size(),
            sharedSecret.data(),
            &ssLen);

        if (status != QUAC_SUCCESS)
        {
            throw KeyStorageException(status, "Decapsulation with stored key failed");
        }

        sharedSecret.resize(ssLen);
        return sharedSecret;
    }

    Bytes KeyStorage::signWithStored(int slot, const Bytes &message)
    {
        // Allocate maximum possible signature size
        Bytes signature(QUAC_ML_DSA_87_SIGNATURE_SIZE);
        size_t sigLen = signature.size();

        int status = quac_sign_stored(
            device_,
            slot,
            message.data(),
            message.size(),
            signature.data(),
            &sigLen);

        if (status != QUAC_SUCCESS)
        {
            throw KeyStorageException(status, "Signing with stored key failed");
        }

        signature.resize(sigLen);
        return signature;
    }

    bool KeyStorage::verifyWithStored(int slot, const Bytes &message, const Bytes &signature)
    {
        int status = quac_verify_stored(
            device_,
            slot,
            message.data(),
            message.size(),
            signature.data(),
            signature.size());

        return status == QUAC_SUCCESS;
    }

} // namespace quac100