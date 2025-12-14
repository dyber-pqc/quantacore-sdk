/**
 * @file keys.c
 * @brief QUAC 100 SDK - Key Storage and Management Implementation
 * @copyright Copyright © 2025 Dyber, Inc. All Rights Reserved.
 */

#include "quac100/quac100.h"
#include "internal.h"

#include <stdlib.h>
#include <string.h>

/*============================================================================
 * Key Storage Operations
 *============================================================================*/

QUAC_API quac_status_t quac_key_store(
    quac_device_t device,
    const uint8_t *key,
    size_t key_len,
    quac_key_type_t key_type,
    const char *label,
    uint32_t usage,
    int *slot)
{
    QUAC_CHECK_INIT();
    QUAC_CHECK_DEVICE(device);
    QUAC_CHECK_PARAM(key != NULL);
    QUAC_CHECK_PARAM(key_len > 0);
    QUAC_CHECK_PARAM(slot != NULL);

    if (label && strlen(label) > QUAC_MAX_LABEL_LENGTH)
    {
        return QUAC_ERROR_INVALID_PARAM;
    }

    quac_device_handle_impl *handle = (quac_device_handle_impl *)device;

    /* Build command payload */
    size_t payload_size = 4 + 4 + 4 + 64 + key_len; /* type + usage + key_len + label + key */
    uint8_t *payload = (uint8_t *)malloc(payload_size);
    if (!payload)
    {
        return QUAC_ERROR_OUT_OF_MEMORY;
    }

    size_t offset = 0;
    memcpy(payload + offset, &key_type, 4);
    offset += 4;
    memcpy(payload + offset, &usage, 4);
    offset += 4;

    uint32_t len32 = (uint32_t)key_len;
    memcpy(payload + offset, &len32, 4);
    offset += 4;

    memset(payload + offset, 0, 64);
    if (label)
    {
        strncpy((char *)(payload + offset), label, 63);
    }
    offset += 64;

    memcpy(payload + offset, key, key_len);

    quac_device_lock_internal(handle);

    uint8_t response[4];
    size_t response_len = sizeof(response);

    quac_status_t status = quac_hal_send_command(handle, 0x20,
                                                 payload, payload_size,
                                                 response, &response_len);

    quac_device_unlock_internal(handle);

    /* Secure cleanup */
    quac_secure_zero(payload, payload_size);
    free(payload);

    if (status == QUAC_SUCCESS && response_len >= 4)
    {
        memcpy(slot, response, 4);
    }

    return status;
}

QUAC_API quac_status_t quac_key_load(
    quac_device_t device,
    int slot,
    uint8_t *key,
    size_t *key_len)
{
    QUAC_CHECK_INIT();
    QUAC_CHECK_DEVICE(device);
    QUAC_CHECK_PARAM(key != NULL);
    QUAC_CHECK_PARAM(key_len != NULL);
    QUAC_CHECK_PARAM(slot >= 0 && slot < QUAC_MAX_KEY_SLOTS);

    quac_device_handle_impl *handle = (quac_device_handle_impl *)device;

    quac_device_lock_internal(handle);

    int32_t slot32 = slot;
    quac_status_t status = quac_hal_send_command(handle, 0x21,
                                                 &slot32, sizeof(slot32),
                                                 key, key_len);

    quac_device_unlock_internal(handle);

    return status;
}

QUAC_API quac_status_t quac_key_delete(
    quac_device_t device,
    int slot)
{
    QUAC_CHECK_INIT();
    QUAC_CHECK_DEVICE(device);
    QUAC_CHECK_PARAM(slot >= 0 && slot < QUAC_MAX_KEY_SLOTS);

    quac_device_handle_impl *handle = (quac_device_handle_impl *)device;

    quac_device_lock_internal(handle);

    int32_t slot32 = slot;
    quac_status_t status = quac_hal_send_command(handle, 0x22,
                                                 &slot32, sizeof(slot32),
                                                 NULL, NULL);

    quac_device_unlock_internal(handle);

    return status;
}

QUAC_API quac_status_t quac_key_info(
    quac_device_t device,
    int slot,
    quac_key_info_t *info)
{
    QUAC_CHECK_INIT();
    QUAC_CHECK_DEVICE(device);
    QUAC_CHECK_PARAM(info != NULL);
    QUAC_CHECK_PARAM(slot >= 0 && slot < QUAC_MAX_KEY_SLOTS);

    quac_device_handle_impl *handle = (quac_device_handle_impl *)device;

    quac_device_lock_internal(handle);

    int32_t slot32 = slot;
    uint8_t response[128];
    size_t response_len = sizeof(response);

    quac_status_t status = quac_hal_send_command(handle, 0x23,
                                                 &slot32, sizeof(slot32),
                                                 response, &response_len);

    quac_device_unlock_internal(handle);

    if (status == QUAC_SUCCESS && response_len >= 96)
    {
        info->slot = slot;
        memcpy(&info->type, response, 4);
        memcpy(&info->algorithm, response + 4, 4);
        memcpy(&info->key_size, response + 8, 8);
        memcpy(info->label, response + 16, 64);
        info->label[63] = '\0';
        memcpy(&info->usage, response + 80, 4);
        memcpy(&info->storage, response + 84, 4);
        memcpy(&info->created_time, response + 88, 8);
        info->extractable = response[96] != 0;
    }

    return status;
}

QUAC_API quac_status_t quac_key_list(
    quac_device_t device,
    int *slots,
    int max_slots,
    int *count)
{
    QUAC_CHECK_INIT();
    QUAC_CHECK_DEVICE(device);
    QUAC_CHECK_PARAM(slots != NULL);
    QUAC_CHECK_PARAM(count != NULL);
    QUAC_CHECK_PARAM(max_slots > 0);

    quac_device_handle_impl *handle = (quac_device_handle_impl *)device;

    quac_device_lock_internal(handle);

    size_t response_len = max_slots * sizeof(int32_t) + 4;
    uint8_t *response = (uint8_t *)malloc(response_len);
    if (!response)
    {
        quac_device_unlock_internal(handle);
        return QUAC_ERROR_OUT_OF_MEMORY;
    }

    quac_status_t status = quac_hal_send_command(handle, 0x24,
                                                 NULL, 0,
                                                 response, &response_len);

    quac_device_unlock_internal(handle);

    if (status == QUAC_SUCCESS && response_len >= 4)
    {
        int32_t total;
        memcpy(&total, response, 4);
        *count = (total < max_slots) ? total : max_slots;

        for (int i = 0; i < *count; i++)
        {
            memcpy(&slots[i], response + 4 + i * 4, 4);
        }
    }

    free(response);
    return status;
}

QUAC_API quac_status_t quac_key_find(
    quac_device_t device,
    const char *label,
    int *slot)
{
    QUAC_CHECK_INIT();
    QUAC_CHECK_DEVICE(device);
    QUAC_CHECK_PARAM(label != NULL);
    QUAC_CHECK_PARAM(slot != NULL);

    quac_device_handle_impl *handle = (quac_device_handle_impl *)device;

    char label_buf[64] = {0};
    strncpy(label_buf, label, 63);

    quac_device_lock_internal(handle);

    uint8_t response[4];
    size_t response_len = sizeof(response);

    quac_status_t status = quac_hal_send_command(handle, 0x25,
                                                 label_buf, 64,
                                                 response, &response_len);

    quac_device_unlock_internal(handle);

    if (status == QUAC_SUCCESS && response_len >= 4)
    {
        memcpy(slot, response, 4);
    }

    return status;
}

QUAC_API quac_status_t quac_key_slot_count(
    quac_device_t device,
    int *total,
    int *used)
{
    QUAC_CHECK_INIT();
    QUAC_CHECK_DEVICE(device);
    QUAC_CHECK_PARAM(total != NULL);
    QUAC_CHECK_PARAM(used != NULL);

    quac_device_handle_impl *handle = (quac_device_handle_impl *)device;

    quac_device_lock_internal(handle);

    uint8_t response[8];
    size_t response_len = sizeof(response);

    quac_status_t status = quac_hal_send_command(handle, 0x26,
                                                 NULL, 0,
                                                 response, &response_len);

    quac_device_unlock_internal(handle);

    if (status == QUAC_SUCCESS && response_len >= 8)
    {
        memcpy(total, response, 4);
        memcpy(used, response + 4, 4);
    }

    return status;
}

QUAC_API quac_status_t quac_key_modify(
    quac_device_t device,
    int slot,
    const char *new_label,
    uint32_t new_usage)
{
    QUAC_CHECK_INIT();
    QUAC_CHECK_DEVICE(device);
    QUAC_CHECK_PARAM(slot >= 0 && slot < QUAC_MAX_KEY_SLOTS);

    if (new_label && strlen(new_label) > QUAC_MAX_LABEL_LENGTH)
    {
        return QUAC_ERROR_INVALID_PARAM;
    }

    quac_device_handle_impl *handle = (quac_device_handle_impl *)device;

    uint8_t payload[72] = {0}; /* slot + usage + label */
    int32_t slot32 = slot;
    memcpy(payload, &slot32, 4);
    memcpy(payload + 4, &new_usage, 4);
    if (new_label)
    {
        strncpy((char *)(payload + 8), new_label, 63);
    }

    quac_device_lock_internal(handle);

    quac_status_t status = quac_hal_send_command(handle, 0x27,
                                                 payload, sizeof(payload),
                                                 NULL, NULL);

    quac_device_unlock_internal(handle);

    return status;
}

QUAC_API quac_status_t quac_key_export(
    quac_device_t device,
    int slot,
    uint8_t *key,
    size_t *key_len)
{
    return quac_key_load(device, slot, key, key_len);
}

QUAC_API quac_status_t quac_key_import(
    quac_device_t device,
    int slot,
    const uint8_t *key,
    size_t key_len,
    quac_key_type_t key_type,
    const char *label,
    uint32_t usage,
    bool overwrite)
{
    QUAC_CHECK_INIT();
    QUAC_CHECK_DEVICE(device);
    QUAC_CHECK_PARAM(key != NULL);
    QUAC_CHECK_PARAM(key_len > 0);
    QUAC_CHECK_PARAM(slot >= 0 && slot < QUAC_MAX_KEY_SLOTS);

    /* Check if slot is occupied */
    if (!overwrite)
    {
        quac_key_info_t info;
        quac_status_t status = quac_key_info(device, slot, &info);
        if (status == QUAC_SUCCESS)
        {
            return QUAC_ERROR_INVALID_PARAM; /* Slot occupied */
        }
    }

    int assigned_slot;
    quac_status_t status = quac_key_store(device, key, key_len, key_type,
                                          label, usage, &assigned_slot);

    return status;
}

QUAC_API quac_status_t quac_key_generate_stored(
    quac_device_t device,
    int algorithm,
    const char *label,
    uint32_t usage,
    int *public_slot,
    int *secret_slot,
    uint8_t *public_key,
    size_t *public_key_len)
{
    QUAC_CHECK_INIT();
    QUAC_CHECK_DEVICE(device);
    QUAC_CHECK_PARAM(public_slot != NULL);
    QUAC_CHECK_PARAM(secret_slot != NULL);

    /* Determine if KEM or signature algorithm */
    if (quac_is_kem_algorithm(algorithm))
    {
        quac_kem_params_t params;
        quac_status_t status = quac_kem_get_params((quac_kem_algorithm_t)algorithm, &params);
        if (status != QUAC_SUCCESS)
            return status;

        /* Generate key pair */
        uint8_t *pk = (uint8_t *)malloc(params.public_key_size);
        uint8_t *sk = (uint8_t *)malloc(params.secret_key_size);
        if (!pk || !sk)
        {
            free(pk);
            free(sk);
            return QUAC_ERROR_OUT_OF_MEMORY;
        }

        size_t pk_len = params.public_key_size;
        size_t sk_len = params.secret_key_size;

        status = quac_kem_keygen(device, (quac_kem_algorithm_t)algorithm,
                                 pk, &pk_len, sk, &sk_len);

        if (status == QUAC_SUCCESS)
        {
            /* Store keys */
            char pk_label[64], sk_label[64];
            snprintf(pk_label, sizeof(pk_label), "%s-pub", label ? label : "key");
            snprintf(sk_label, sizeof(sk_label), "%s-sec", label ? label : "key");

            status = quac_key_store(device, pk, pk_len, QUAC_KEY_TYPE_ML_KEM_PUBLIC,
                                    pk_label, usage & QUAC_KEY_USAGE_ENCAPSULATE, public_slot);

            if (status == QUAC_SUCCESS)
            {
                status = quac_key_store(device, sk, sk_len, QUAC_KEY_TYPE_ML_KEM_SECRET,
                                        sk_label, usage & QUAC_KEY_USAGE_DECAPSULATE, secret_slot);
            }

            /* Copy public key if requested */
            if (status == QUAC_SUCCESS && public_key && public_key_len)
            {
                if (*public_key_len >= pk_len)
                {
                    memcpy(public_key, pk, pk_len);
                    *public_key_len = pk_len;
                }
                else
                {
                    *public_key_len = pk_len;
                }
            }
        }

        quac_secure_zero(sk, params.secret_key_size);
        free(pk);
        free(sk);

        return status;
    }
    else if (quac_is_sign_algorithm(algorithm))
    {
        quac_sign_params_t params;
        quac_status_t status = quac_sign_get_params((quac_sign_algorithm_t)algorithm, &params);
        if (status != QUAC_SUCCESS)
            return status;

        uint8_t *pk = (uint8_t *)malloc(params.public_key_size);
        uint8_t *sk = (uint8_t *)malloc(params.secret_key_size);
        if (!pk || !sk)
        {
            free(pk);
            free(sk);
            return QUAC_ERROR_OUT_OF_MEMORY;
        }

        size_t pk_len = params.public_key_size;
        size_t sk_len = params.secret_key_size;

        status = quac_sign_keygen(device, (quac_sign_algorithm_t)algorithm,
                                  pk, &pk_len, sk, &sk_len);

        if (status == QUAC_SUCCESS)
        {
            char pk_label[64], sk_label[64];
            snprintf(pk_label, sizeof(pk_label), "%s-pub", label ? label : "key");
            snprintf(sk_label, sizeof(sk_label), "%s-sec", label ? label : "key");

            status = quac_key_store(device, pk, pk_len, QUAC_KEY_TYPE_ML_DSA_PUBLIC,
                                    pk_label, usage & QUAC_KEY_USAGE_VERIFY, public_slot);

            if (status == QUAC_SUCCESS)
            {
                status = quac_key_store(device, sk, sk_len, QUAC_KEY_TYPE_ML_DSA_SECRET,
                                        sk_label, usage & QUAC_KEY_USAGE_SIGN, secret_slot);
            }

            if (status == QUAC_SUCCESS && public_key && public_key_len)
            {
                if (*public_key_len >= pk_len)
                {
                    memcpy(public_key, pk, pk_len);
                    *public_key_len = pk_len;
                }
                else
                {
                    *public_key_len = pk_len;
                }
            }
        }

        quac_secure_zero(sk, params.secret_key_size);
        free(pk);
        free(sk);

        return status;
    }

    return QUAC_ERROR_NOT_SUPPORTED;
}

/*============================================================================
 * Key Wrapping (Stubs)
 *============================================================================*/

QUAC_API quac_status_t quac_key_wrap(
    quac_device_t device,
    int key_slot,
    int wrapping_key_slot,
    uint8_t *wrapped_key,
    size_t *wrapped_len)
{
    (void)device;
    (void)key_slot;
    (void)wrapping_key_slot;
    (void)wrapped_key;
    (void)wrapped_len;
    return QUAC_ERROR_NOT_SUPPORTED; /* TODO: Implement */
}

QUAC_API quac_status_t quac_key_unwrap(
    quac_device_t device,
    const uint8_t *wrapped_key,
    size_t wrapped_len,
    int wrapping_key_slot,
    quac_key_type_t key_type,
    const char *label,
    uint32_t usage,
    int *slot)
{
    (void)device;
    (void)wrapped_key;
    (void)wrapped_len;
    (void)wrapping_key_slot;
    (void)key_type;
    (void)label;
    (void)usage;
    (void)slot;
    return QUAC_ERROR_NOT_SUPPORTED; /* TODO: Implement */
}

/*============================================================================
 * Operations with Stored Keys
 *============================================================================*/

QUAC_API quac_status_t quac_kem_encaps_stored(
    quac_device_t device,
    int public_key_slot,
    uint8_t *ciphertext,
    size_t *ciphertext_len,
    uint8_t *shared_secret,
    size_t *shared_secret_len)
{
    QUAC_CHECK_INIT();
    QUAC_CHECK_DEVICE(device);
    QUAC_CHECK_PARAM(ciphertext != NULL);
    QUAC_CHECK_PARAM(ciphertext_len != NULL);
    QUAC_CHECK_PARAM(shared_secret != NULL);
    QUAC_CHECK_PARAM(shared_secret_len != NULL);

    /* Get key info to determine algorithm */
    quac_key_info_t info;
    quac_status_t status = quac_key_info(device, public_key_slot, &info);
    if (status != QUAC_SUCCESS)
        return status;

    if (info.type != QUAC_KEY_TYPE_ML_KEM_PUBLIC)
    {
        return QUAC_ERROR_INVALID_KEY;
    }

    /* Load key */
    uint8_t pk[QUAC_ML_KEM_1024_PUBLIC_KEY_SIZE];
    size_t pk_len = sizeof(pk);

    status = quac_key_load(device, public_key_slot, pk, &pk_len);
    if (status != QUAC_SUCCESS)
        return status;

    /* Perform encapsulation */
    return quac_kem_encaps(device, (quac_kem_algorithm_t)info.algorithm,
                           pk, pk_len, ciphertext, ciphertext_len,
                           shared_secret, shared_secret_len);
}

QUAC_API quac_status_t quac_kem_decaps_stored(
    quac_device_t device,
    int secret_key_slot,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    uint8_t *shared_secret,
    size_t *shared_secret_len)
{
    QUAC_CHECK_INIT();
    QUAC_CHECK_DEVICE(device);
    QUAC_CHECK_PARAM(ciphertext != NULL);
    QUAC_CHECK_PARAM(shared_secret != NULL);
    QUAC_CHECK_PARAM(shared_secret_len != NULL);

    quac_key_info_t info;
    quac_status_t status = quac_key_info(device, secret_key_slot, &info);
    if (status != QUAC_SUCCESS)
        return status;

    if (info.type != QUAC_KEY_TYPE_ML_KEM_SECRET)
    {
        return QUAC_ERROR_INVALID_KEY;
    }

    uint8_t sk[QUAC_ML_KEM_1024_SECRET_KEY_SIZE];
    size_t sk_len = sizeof(sk);

    status = quac_key_load(device, secret_key_slot, sk, &sk_len);
    if (status != QUAC_SUCCESS)
        return status;

    status = quac_kem_decaps(device, (quac_kem_algorithm_t)info.algorithm,
                             sk, sk_len, ciphertext, ciphertext_len,
                             shared_secret, shared_secret_len);

    quac_secure_zero(sk, sk_len);
    return status;
}

QUAC_API quac_status_t quac_sign_stored(
    quac_device_t device,
    int secret_key_slot,
    const uint8_t *message,
    size_t message_len,
    uint8_t *signature,
    size_t *signature_len)
{
    QUAC_CHECK_INIT();
    QUAC_CHECK_DEVICE(device);
    QUAC_CHECK_PARAM(signature != NULL);
    QUAC_CHECK_PARAM(signature_len != NULL);

    quac_key_info_t info;
    quac_status_t status = quac_key_info(device, secret_key_slot, &info);
    if (status != QUAC_SUCCESS)
        return status;

    if (info.type != QUAC_KEY_TYPE_ML_DSA_SECRET &&
        info.type != QUAC_KEY_TYPE_SLH_DSA_SECRET)
    {
        return QUAC_ERROR_INVALID_KEY;
    }

    uint8_t sk[QUAC_ML_DSA_87_SECRET_KEY_SIZE];
    size_t sk_len = sizeof(sk);

    status = quac_key_load(device, secret_key_slot, sk, &sk_len);
    if (status != QUAC_SUCCESS)
        return status;

    status = quac_sign(device, (quac_sign_algorithm_t)info.algorithm,
                       sk, sk_len, message, message_len, signature, signature_len);

    quac_secure_zero(sk, sk_len);
    return status;
}

QUAC_API quac_status_t quac_verify_stored(
    quac_device_t device,
    int public_key_slot,
    const uint8_t *message,
    size_t message_len,
    const uint8_t *signature,
    size_t signature_len)
{
    QUAC_CHECK_INIT();
    QUAC_CHECK_DEVICE(device);
    QUAC_CHECK_PARAM(signature != NULL);

    quac_key_info_t info;
    quac_status_t status = quac_key_info(device, public_key_slot, &info);
    if (status != QUAC_SUCCESS)
        return status;

    if (info.type != QUAC_KEY_TYPE_ML_DSA_PUBLIC &&
        info.type != QUAC_KEY_TYPE_SLH_DSA_PUBLIC)
    {
        return QUAC_ERROR_INVALID_KEY;
    }

    uint8_t pk[QUAC_ML_DSA_87_PUBLIC_KEY_SIZE];
    size_t pk_len = sizeof(pk);

    status = quac_key_load(device, public_key_slot, pk, &pk_len);
    if (status != QUAC_SUCCESS)
        return status;

    return quac_verify(device, (quac_sign_algorithm_t)info.algorithm,
                       pk, pk_len, message, message_len, signature, signature_len);
}