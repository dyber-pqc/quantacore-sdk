/**
 * @file keys.hpp
 * @brief QUAC 100 C++ SDK - Key Storage (HSM)
 * @copyright Copyright © 2025 Dyber, Inc. All Rights Reserved.
 */

#ifndef QUAC100_KEYS_HPP
#define QUAC100_KEYS_HPP

#include "types.hpp"
#include "exception.hpp"
#include <optional>

// Forward declare C types
extern "C"
{
    typedef struct quac_device_handle *quac_device_t;
}

namespace quac100
{

    /**
     * @brief HSM Key Storage operations
     */
    class KeyStorage
    {
    public:
        explicit KeyStorage(quac_device_t device);
        ~KeyStorage() = default;

        // Non-copyable but movable
        KeyStorage(const KeyStorage &) = delete;
        KeyStorage &operator=(const KeyStorage &) = delete;
        KeyStorage(KeyStorage &&) = default;
        KeyStorage &operator=(KeyStorage &&) = default;

        /*========================================================================
         * Key Management
         *========================================================================*/

        /**
         * @brief Store a key in the HSM
         */
        void store(int slot, const std::string &label, KeyType type, int algorithm,
                   const Bytes &keyData, KeyUsage usage = KeyUsage::All,
                   bool exportable = false);

        /**
         * @brief Load a key from the HSM
         */
        Bytes load(int slot);

        /**
         * @brief Remove a key from the HSM
         */
        void remove(int slot);

        /**
         * @brief Check if a slot contains a key
         */
        bool exists(int slot);

        /**
         * @brief Get information about a stored key
         */
        std::optional<KeyInfo> info(int slot);

        /**
         * @brief List all stored keys
         */
        std::vector<KeyInfo> list();

        /**
         * @brief Find key by label
         * @return Slot number or -1 if not found
         */
        int findByLabel(const std::string &label);

        /**
         * @brief Get total number of key slots
         */
        int slotCount();

        /**
         * @brief Get number of used slots
         */
        int usedSlots();

        /**
         * @brief Get number of free slots
         */
        int freeSlots();

        /*========================================================================
         * Operations with Stored Keys
         *========================================================================*/

        /**
         * @brief Encapsulate using a stored public key
         */
        EncapsResult encapsulateWithStored(int slot);

        /**
         * @brief Decapsulate using a stored secret key
         */
        Bytes decapsulateWithStored(int slot, const Bytes &ciphertext);

        /**
         * @brief Sign using a stored secret key
         */
        Bytes signWithStored(int slot, const Bytes &message);

        /**
         * @brief Verify using a stored public key
         */
        bool verifyWithStored(int slot, const Bytes &message, const Bytes &signature);

    private:
        quac_device_t device_;
    };

} // namespace quac100

#endif // QUAC100_KEYS_HPP