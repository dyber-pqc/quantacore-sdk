/**
 * @file quac100_pkcs11_slot.c
 * @brief QUAC 100 PKCS#11 Module - Slot and Token Management
 *
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include <string.h>
#include <stdlib.h>

#include "quac100_pkcs11.h"
#include "quac100_pkcs11_internal.h"

/* ==========================================================================
 * Slot Management
 * ========================================================================== */

CK_RV quac_slot_init(quac_slot_t *slot, CK_SLOT_ID slotID)
{
    if (slot == NULL)
        return CKR_ARGUMENTS_BAD;

    memset(slot, 0, sizeof(quac_slot_t));

    slot->slotID = slotID;
    slot->tokenPresent = CK_FALSE;
    slot->hardwareSlot = CK_FALSE;

    /* Set slot description */
    char desc[65];
    snprintf(desc, sizeof(desc), "QUAC 100 PQC Accelerator Slot %lu", (unsigned long)slotID);
    quac_pad_string(slot->description, desc, sizeof(slot->description));

    quac_pad_string(slot->manufacturerID, QUAC_MANUFACTURER, sizeof(slot->manufacturerID));

    slot->hardwareVersion.major = 1;
    slot->hardwareVersion.minor = 0;
    slot->firmwareVersion.major = 1;
    slot->firmwareVersion.minor = 0;

    /* Initialize token */
    quac_token_init(&slot->token, (CK_UTF8CHAR_PTR)QUAC_TOKEN_LABEL);
    slot->tokenPresent = CK_TRUE;

    return CKR_OK;
}

CK_RV quac_slot_cleanup(quac_slot_t *slot)
{
    if (slot == NULL)
        return CKR_ARGUMENTS_BAD;

    quac_token_cleanup(&slot->token);

#ifdef QUAC_HAS_HARDWARE
    if (slot->device != NULL)
    {
        quac_close_device(slot->device);
        slot->device = NULL;
    }
#endif

    slot->tokenPresent = CK_FALSE;

    return CKR_OK;
}

quac_slot_t *quac_get_slot(CK_SLOT_ID slotID)
{
    if (slotID >= g_module.numSlots)
        return NULL;

    return &g_module.slots[slotID];
}

/* ==========================================================================
 * Token Management
 * ========================================================================== */

CK_RV quac_token_init(quac_token_t *token, CK_UTF8CHAR_PTR pLabel)
{
    if (token == NULL)
        return CKR_ARGUMENTS_BAD;

    memset(token, 0, sizeof(quac_token_t));

    /* Set label */
    if (pLabel != NULL)
    {
        memcpy(token->label, pLabel, 32);
    }
    else
    {
        quac_pad_string(token->label, QUAC_TOKEN_LABEL, sizeof(token->label));
    }

    /* Set default PINs for testing */
    memcpy(token->soPin, QUAC_DEFAULT_SO_PIN, strlen(QUAC_DEFAULT_SO_PIN));
    token->soPinLen = strlen(QUAC_DEFAULT_SO_PIN);
    token->soPinSet = CK_TRUE;

    memcpy(token->userPin, QUAC_DEFAULT_USER_PIN, strlen(QUAC_DEFAULT_USER_PIN));
    token->userPinLen = strlen(QUAC_DEFAULT_USER_PIN);
    token->userPinSet = CK_TRUE;

    token->initialized = CK_TRUE;
    token->userLoggedIn = CK_FALSE;
    token->soLoggedIn = CK_FALSE;

    /* Memory allocation */
    token->totalPublicMemory = 1024 * 1024; /* 1 MB */
    token->freePublicMemory = 1024 * 1024;
    token->totalPrivateMemory = 1024 * 1024; /* 1 MB */
    token->freePrivateMemory = 1024 * 1024;

    token->numObjects = 0;
    token->nextObjectHandle = 1;

    return CKR_OK;
}

CK_RV quac_token_cleanup(quac_token_t *token)
{
    if (token == NULL)
        return CKR_ARGUMENTS_BAD;

    /* Securely clear all objects */
    for (CK_ULONG i = 0; i < token->numObjects; i++)
    {
        quac_object_t *obj = &token->objects[i];

        if (obj->publicKey != NULL)
        {
            quac_secure_zero(obj->publicKey, obj->publicKeyLen);
            free(obj->publicKey);
        }

        if (obj->secretKey != NULL)
        {
            quac_secure_zero(obj->secretKey, obj->secretKeyLen);
            free(obj->secretKey);
        }

        if (obj->attributes != NULL)
        {
            for (CK_ULONG j = 0; j < obj->numAttributes; j++)
            {
                if (obj->attributes[j].pValue != NULL)
                {
                    quac_secure_zero(obj->attributes[j].pValue, obj->attributes[j].ulValueLen);
                    free(obj->attributes[j].pValue);
                }
            }
            free(obj->attributes);
        }
    }

    /* Clear PINs */
    quac_secure_zero(token->userPin, sizeof(token->userPin));
    quac_secure_zero(token->soPin, sizeof(token->soPin));

    memset(token, 0, sizeof(quac_token_t));

    return CKR_OK;
}