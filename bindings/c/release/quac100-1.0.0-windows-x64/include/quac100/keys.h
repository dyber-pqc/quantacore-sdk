/**
 * @file keys.h
 * @brief QUAC 100 SDK - Key Storage and Management API
 * @copyright Copyright © 2025 Dyber, Inc. All Rights Reserved.
 */

#ifndef QUAC100_KEYS_H
#define QUAC100_KEYS_H

#include "types.h"

#ifdef __cplusplus
extern "C"
{
#endif

    /**
     * @defgroup Keys Key Management
     * @brief Secure key storage and management operations
     * @{
     */

    /**
     * @brief Store a key in device secure storage
     *
     * @param[in] device Device handle
     * @param[in] key Key data
     * @param[in] key_len Key length
     * @param[in] key_type Key type
     * @param[in] label Key label (max 63 chars)
     * @param[in] usage Key usage flags
     * @param[out] slot Assigned slot number
     * @return QUAC_SUCCESS on success, error code on failure
     *
     * @code
     * int slot;
     * quac_status_t status = quac_key_store(device, sk, sk_len,
     *                                        QUAC_KEY_TYPE_ML_KEM_SECRET,
     *                                        "my-kem-key",
     *                                        QUAC_KEY_USAGE_ALL_KEM,
     *                                        &slot);
     * @endcode
     */
    QUAC_API quac_status_t quac_key_store(
        quac_device_t device,
        const uint8_t *key,
        size_t key_len,
        quac_key_type_t key_type,
        const char *label,
        uint32_t usage,
        int *slot);

    /**
     * @brief Load a key from device secure storage
     *
     * @param[in] device Device handle
     * @param[in] slot Key slot number
     * @param[out] key Buffer for key data
     * @param[in,out] key_len Key buffer size / actual size
     * @return QUAC_SUCCESS on success, error code on failure
     */
    QUAC_API quac_status_t quac_key_load(
        quac_device_t device,
        int slot,
        uint8_t *key,
        size_t *key_len);

    /**
     * @brief Delete a key from device secure storage
     *
     * @param[in] device Device handle
     * @param[in] slot Key slot number
     * @return QUAC_SUCCESS on success, error code on failure
     */
    QUAC_API quac_status_t quac_key_delete(
        quac_device_t device,
        int slot);

    /**
     * @brief Get information about a stored key
     *
     * @param[in] device Device handle
     * @param[in] slot Key slot number
     * @param[out] info Key information
     * @return QUAC_SUCCESS on success, error code on failure
     */
    QUAC_API quac_status_t quac_key_info(
        quac_device_t device,
        int slot,
        quac_key_info_t *info);

    /**
     * @brief List all stored keys
     *
     * @param[in] device Device handle
     * @param[out] slots Array to store slot numbers
     * @param[in] max_slots Maximum slots to return
     * @param[out] count Number of keys found
     * @return QUAC_SUCCESS on success, error code on failure
     */
    QUAC_API quac_status_t quac_key_list(
        quac_device_t device,
        int *slots,
        int max_slots,
        int *count);

    /**
     * @brief Find a key by label
     *
     * @param[in] device Device handle
     * @param[in] label Key label to find
     * @param[out] slot Key slot number
     * @return QUAC_SUCCESS on success, QUAC_ERROR_KEY_NOT_FOUND if not found
     */
    QUAC_API quac_status_t quac_key_find(
        quac_device_t device,
        const char *label,
        int *slot);

    /**
     * @brief Get count of available key slots
     *
     * @param[in] device Device handle
     * @param[out] total Total key slots
     * @param[out] used Used key slots
     * @return QUAC_SUCCESS on success, error code on failure
     */
    QUAC_API quac_status_t quac_key_slot_count(
        quac_device_t device,
        int *total,
        int *used);

    /**
     * @brief Modify key attributes
     *
     * @param[in] device Device handle
     * @param[in] slot Key slot number
     * @param[in] new_label New label (NULL to keep current)
     * @param[in] new_usage New usage flags (0 to keep current)
     * @return QUAC_SUCCESS on success, error code on failure
     */
    QUAC_API quac_status_t quac_key_modify(
        quac_device_t device,
        int slot,
        const char *new_label,
        uint32_t new_usage);

    /**
     * @brief Export a key (if extractable)
     *
     * @param[in] device Device handle
     * @param[in] slot Key slot number
     * @param[out] key Buffer for key data
     * @param[in,out] key_len Key buffer size / actual size
     * @return QUAC_SUCCESS on success, error code on failure
     */
    QUAC_API quac_status_t quac_key_export(
        quac_device_t device,
        int slot,
        uint8_t *key,
        size_t *key_len);

    /**
     * @brief Import a key to a specific slot
     *
     * @param[in] device Device handle
     * @param[in] slot Target slot number
     * @param[in] key Key data
     * @param[in] key_len Key length
     * @param[in] key_type Key type
     * @param[in] label Key label
     * @param[in] usage Key usage flags
     * @param[in] overwrite Allow overwriting existing key
     * @return QUAC_SUCCESS on success, error code on failure
     */
    QUAC_API quac_status_t quac_key_import(
        quac_device_t device,
        int slot,
        const uint8_t *key,
        size_t key_len,
        quac_key_type_t key_type,
        const char *label,
        uint32_t usage,
        bool overwrite);

    /**
     * @brief Generate key pair in secure storage
     *
     * Generates a key pair directly in secure storage without
     * exposing the secret key.
     *
     * @param[in] device Device handle
     * @param[in] algorithm Algorithm (KEM or signature)
     * @param[in] label Key label
     * @param[in] usage Key usage flags
     * @param[out] public_slot Slot for public key
     * @param[out] secret_slot Slot for secret key
     * @param[out] public_key Buffer for public key (optional, can be NULL)
     * @param[in,out] public_key_len Public key buffer size / actual size
     * @return QUAC_SUCCESS on success, error code on failure
     */
    QUAC_API quac_status_t quac_key_generate_stored(
        quac_device_t device,
        int algorithm,
        const char *label,
        uint32_t usage,
        int *public_slot,
        int *secret_slot,
        uint8_t *public_key,
        size_t *public_key_len);

    /**
     * @brief Wrap a key for export
     *
     * @param[in] device Device handle
     * @param[in] key_slot Slot of key to wrap
     * @param[in] wrapping_key_slot Slot of wrapping key
     * @param[out] wrapped_key Buffer for wrapped key
     * @param[in,out] wrapped_len Wrapped key buffer size / actual size
     * @return QUAC_SUCCESS on success, error code on failure
     */
    QUAC_API quac_status_t quac_key_wrap(
        quac_device_t device,
        int key_slot,
        int wrapping_key_slot,
        uint8_t *wrapped_key,
        size_t *wrapped_len);

    /**
     * @brief Unwrap and import a key
     *
     * @param[in] device Device handle
     * @param[in] wrapped_key Wrapped key data
     * @param[in] wrapped_len Wrapped key length
     * @param[in] wrapping_key_slot Slot of wrapping key
     * @param[in] key_type Type of wrapped key
     * @param[in] label Label for imported key
     * @param[in] usage Usage flags for imported key
     * @param[out] slot Assigned slot for imported key
     * @return QUAC_SUCCESS on success, error code on failure
     */
    QUAC_API quac_status_t quac_key_unwrap(
        quac_device_t device,
        const uint8_t *wrapped_key,
        size_t wrapped_len,
        int wrapping_key_slot,
        quac_key_type_t key_type,
        const char *label,
        uint32_t usage,
        int *slot);

    /**
     * @brief Perform KEM operation using stored key
     *
     * @param[in] device Device handle
     * @param[in] public_key_slot Slot of public key
     * @param[out] ciphertext Buffer for ciphertext
     * @param[in,out] ciphertext_len Ciphertext buffer size / actual size
     * @param[out] shared_secret Buffer for shared secret
     * @param[in,out] shared_secret_len Shared secret buffer size / actual size
     * @return QUAC_SUCCESS on success, error code on failure
     */
    QUAC_API quac_status_t quac_kem_encaps_stored(
        quac_device_t device,
        int public_key_slot,
        uint8_t *ciphertext,
        size_t *ciphertext_len,
        uint8_t *shared_secret,
        size_t *shared_secret_len);

    /**
     * @brief Perform KEM decapsulation using stored key
     *
     * @param[in] device Device handle
     * @param[in] secret_key_slot Slot of secret key
     * @param[in] ciphertext Ciphertext
     * @param[in] ciphertext_len Ciphertext length
     * @param[out] shared_secret Buffer for shared secret
     * @param[in,out] shared_secret_len Shared secret buffer size / actual size
     * @return QUAC_SUCCESS on success, error code on failure
     */
    QUAC_API quac_status_t quac_kem_decaps_stored(
        quac_device_t device,
        int secret_key_slot,
        const uint8_t *ciphertext,
        size_t ciphertext_len,
        uint8_t *shared_secret,
        size_t *shared_secret_len);

    /**
     * @brief Sign using stored key
     *
     * @param[in] device Device handle
     * @param[in] secret_key_slot Slot of secret key
     * @param[in] message Message to sign
     * @param[in] message_len Message length
     * @param[out] signature Buffer for signature
     * @param[in,out] signature_len Signature buffer size / actual size
     * @return QUAC_SUCCESS on success, error code on failure
     */
    QUAC_API quac_status_t quac_sign_stored(
        quac_device_t device,
        int secret_key_slot,
        const uint8_t *message,
        size_t message_len,
        uint8_t *signature,
        size_t *signature_len);

    /**
     * @brief Verify using stored key
     *
     * @param[in] device Device handle
     * @param[in] public_key_slot Slot of public key
     * @param[in] message Message that was signed
     * @param[in] message_len Message length
     * @param[in] signature Signature to verify
     * @param[in] signature_len Signature length
     * @return QUAC_SUCCESS if valid, QUAC_ERROR_VERIFY_FAILED if invalid
     */
    QUAC_API quac_status_t quac_verify_stored(
        quac_device_t device,
        int public_key_slot,
        const uint8_t *message,
        size_t message_len,
        const uint8_t *signature,
        size_t signature_len);

    /** @} */ /* end of Keys group */

#ifdef __cplusplus
}
#endif

#endif /* QUAC100_KEYS_H */