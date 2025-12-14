/**
 * @file quac100_pkcs11.c
 * @brief QUAC 100 PKCS#11 Module - Core Implementation
 *
 * Main PKCS#11 entry points and function list.
 *
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#define QUAC_PKCS11_EXPORTS

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "quac100_pkcs11.h"
#include "quac100_pkcs11_internal.h"

#ifdef QUAC_HAS_HARDWARE
#include <quac100/quac.h>
#endif

/* ==========================================================================
 * Global State
 * ========================================================================== */

quac_module_t g_module = {
    .initialized = CK_FALSE,
    .numSlots = 0,
    .nextSessionHandle = 1,
};

/* ==========================================================================
 * Mechanism Table
 * ========================================================================== */

const quac_mechanism_info_t g_mechanisms[] = {
    /* ML-KEM Key Generation */
    {CKM_ML_KEM_512_KEY_PAIR_GEN, 512, 512, CKF_GENERATE_KEY_PAIR | CKF_HW},
    {CKM_ML_KEM_768_KEY_PAIR_GEN, 768, 768, CKF_GENERATE_KEY_PAIR | CKF_HW},
    {CKM_ML_KEM_1024_KEY_PAIR_GEN, 1024, 1024, CKF_GENERATE_KEY_PAIR | CKF_HW},

    /* ML-KEM Encapsulation */
    {CKM_ML_KEM_512_ENCAPS, 512, 512, CKF_DERIVE | CKF_HW},
    {CKM_ML_KEM_768_ENCAPS, 768, 768, CKF_DERIVE | CKF_HW},
    {CKM_ML_KEM_1024_ENCAPS, 1024, 1024, CKF_DERIVE | CKF_HW},

    /* ML-KEM Decapsulation */
    {CKM_ML_KEM_512_DECAPS, 512, 512, CKF_DERIVE | CKF_HW},
    {CKM_ML_KEM_768_DECAPS, 768, 768, CKF_DERIVE | CKF_HW},
    {CKM_ML_KEM_1024_DECAPS, 1024, 1024, CKF_DERIVE | CKF_HW},

    /* ML-DSA Key Generation */
    {CKM_ML_DSA_44_KEY_PAIR_GEN, 44, 44, CKF_GENERATE_KEY_PAIR | CKF_HW},
    {CKM_ML_DSA_65_KEY_PAIR_GEN, 65, 65, CKF_GENERATE_KEY_PAIR | CKF_HW},
    {CKM_ML_DSA_87_KEY_PAIR_GEN, 87, 87, CKF_GENERATE_KEY_PAIR | CKF_HW},

    /* ML-DSA Signing/Verification */
    {CKM_ML_DSA_44, 44, 44, CKF_SIGN | CKF_VERIFY | CKF_HW},
    {CKM_ML_DSA_65, 65, 65, CKF_SIGN | CKF_VERIFY | CKF_HW},
    {CKM_ML_DSA_87, 87, 87, CKF_SIGN | CKF_VERIFY | CKF_HW},

    /* QRNG */
    {CKM_QUAC_QRNG, 0, 0, CKF_HW},

    /* SHA hashes */
    {CKM_SHA256, 0, 0, CKF_DIGEST},
    {CKM_SHA384, 0, 0, CKF_DIGEST},
    {CKM_SHA512, 0, 0, CKF_DIGEST},
    {CKM_SHA3_256, 0, 0, CKF_DIGEST},
    {CKM_SHA3_384, 0, 0, CKF_DIGEST},
    {CKM_SHA3_512, 0, 0, CKF_DIGEST},
};

const CK_ULONG g_num_mechanisms = sizeof(g_mechanisms) / sizeof(g_mechanisms[0]);

/* ==========================================================================
 * Function List
 * ========================================================================== */

static CK_FUNCTION_LIST g_function_list = {
    .version = {2, 40},
    .C_Initialize = C_Initialize,
    .C_Finalize = C_Finalize,
    .C_GetInfo = C_GetInfo,
    .C_GetFunctionList = C_GetFunctionList,
    .C_GetSlotList = C_GetSlotList,
    .C_GetSlotInfo = C_GetSlotInfo,
    .C_GetTokenInfo = C_GetTokenInfo,
    .C_GetMechanismList = C_GetMechanismList,
    .C_GetMechanismInfo = C_GetMechanismInfo,
    .C_InitToken = C_InitToken,
    .C_InitPIN = C_InitPIN,
    .C_SetPIN = C_SetPIN,
    .C_OpenSession = C_OpenSession,
    .C_CloseSession = C_CloseSession,
    .C_CloseAllSessions = C_CloseAllSessions,
    .C_GetSessionInfo = C_GetSessionInfo,
    .C_GetOperationState = C_GetOperationState,
    .C_SetOperationState = C_SetOperationState,
    .C_Login = C_Login,
    .C_Logout = C_Logout,
    .C_CreateObject = C_CreateObject,
    .C_CopyObject = C_CopyObject,
    .C_DestroyObject = C_DestroyObject,
    .C_GetObjectSize = C_GetObjectSize,
    .C_GetAttributeValue = C_GetAttributeValue,
    .C_SetAttributeValue = C_SetAttributeValue,
    .C_FindObjectsInit = C_FindObjectsInit,
    .C_FindObjects = C_FindObjects,
    .C_FindObjectsFinal = C_FindObjectsFinal,
    .C_EncryptInit = C_EncryptInit,
    .C_Encrypt = C_Encrypt,
    .C_EncryptUpdate = C_EncryptUpdate,
    .C_EncryptFinal = C_EncryptFinal,
    .C_DecryptInit = C_DecryptInit,
    .C_Decrypt = C_Decrypt,
    .C_DecryptUpdate = C_DecryptUpdate,
    .C_DecryptFinal = C_DecryptFinal,
    .C_DigestInit = C_DigestInit,
    .C_Digest = C_Digest,
    .C_DigestUpdate = C_DigestUpdate,
    .C_DigestKey = C_DigestKey,
    .C_DigestFinal = C_DigestFinal,
    .C_SignInit = C_SignInit,
    .C_Sign = C_Sign,
    .C_SignUpdate = C_SignUpdate,
    .C_SignFinal = C_SignFinal,
    .C_SignRecoverInit = C_SignRecoverInit,
    .C_SignRecover = C_SignRecover,
    .C_VerifyInit = C_VerifyInit,
    .C_Verify = C_Verify,
    .C_VerifyUpdate = C_VerifyUpdate,
    .C_VerifyFinal = C_VerifyFinal,
    .C_VerifyRecoverInit = C_VerifyRecoverInit,
    .C_VerifyRecover = C_VerifyRecover,
    .C_DigestEncryptUpdate = C_DigestEncryptUpdate,
    .C_DecryptDigestUpdate = C_DecryptDigestUpdate,
    .C_SignEncryptUpdate = C_SignEncryptUpdate,
    .C_DecryptVerifyUpdate = C_DecryptVerifyUpdate,
    .C_GenerateKey = C_GenerateKey,
    .C_GenerateKeyPair = C_GenerateKeyPair,
    .C_WrapKey = C_WrapKey,
    .C_UnwrapKey = C_UnwrapKey,
    .C_DeriveKey = C_DeriveKey,
    .C_SeedRandom = C_SeedRandom,
    .C_GenerateRandom = C_GenerateRandom,
    .C_GetFunctionStatus = C_GetFunctionStatus,
    .C_CancelFunction = C_CancelFunction,
    .C_WaitForSlotEvent = C_WaitForSlotEvent,
};

/* ==========================================================================
 * Utility Functions
 * ========================================================================== */

void quac_lock(void)
{
    pthread_mutex_lock(&g_module.mutex);
}

void quac_unlock(void)
{
    pthread_mutex_unlock(&g_module.mutex);
}

void quac_secure_zero(void *ptr, size_t size)
{
    volatile unsigned char *p = ptr;
    while (size--)
    {
        *p++ = 0;
    }
}

void quac_pad_string(CK_UTF8CHAR_PTR dest, const char *src, CK_ULONG len)
{
    size_t src_len = strlen(src);
    if (src_len > len)
        src_len = len;
    memcpy(dest, src, src_len);
    memset(dest + src_len, ' ', len - src_len);
}

/* ==========================================================================
 * General-Purpose Functions
 * ========================================================================== */

CK_RV CK_CALL_SPEC C_Initialize(CK_VOID_PTR pInitArgs)
{
    CK_C_INITIALIZE_ARGS_PTR args = (CK_C_INITIALIZE_ARGS_PTR)pInitArgs;

    if (g_module.initialized)
        return CKR_CRYPTOKI_ALREADY_INITIALIZED;

    /* Initialize mutex */
    pthread_mutex_init(&g_module.mutex, NULL);

    /* Process initialization arguments */
    if (args != NULL)
    {
        if (args->flags & CKF_OS_LOCKING_OK)
        {
            g_module.useOsLocking = CK_TRUE;
        }

        if (args->CreateMutex && args->DestroyMutex &&
            args->LockMutex && args->UnlockMutex)
        {
            g_module.createMutex = args->CreateMutex;
            g_module.destroyMutex = args->DestroyMutex;
            g_module.lockMutex = args->LockMutex;
            g_module.unlockMutex = args->UnlockMutex;
        }
    }

    /* Initialize hardware */
#ifdef QUAC_HAS_HARDWARE
    if (quac_init() == 0)
    {
        int device_count = quac_get_device_count();
        for (int i = 0; i < device_count && g_module.numSlots < QUAC_MAX_SLOTS; i++)
        {
            quac_slot_init(&g_module.slots[g_module.numSlots], g_module.numSlots);
            g_module.slots[g_module.numSlots].hardwareSlot = CK_TRUE;
            g_module.slots[g_module.numSlots].tokenPresent = CK_TRUE;
            g_module.numSlots++;
        }
    }
#endif

    /* Create at least one software slot */
    if (g_module.numSlots == 0)
    {
        quac_slot_init(&g_module.slots[0], 0);
        g_module.slots[0].hardwareSlot = CK_FALSE;
        g_module.slots[0].tokenPresent = CK_TRUE;
        g_module.numSlots = 1;
    }

    /* Initialize sessions array */
    memset(g_module.sessions, 0, sizeof(g_module.sessions));
    g_module.nextSessionHandle = 1;

    g_module.initialized = CK_TRUE;

    return CKR_OK;
}

CK_RV CK_CALL_SPEC C_Finalize(CK_VOID_PTR pReserved)
{
    (void)pReserved;

    if (!g_module.initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    quac_lock();

    /* Close all sessions */
    for (CK_ULONG i = 0; i < QUAC_MAX_SESSIONS; i++)
    {
        if (g_module.sessions[i].isOpen)
        {
            quac_session_destroy(g_module.sessions[i].handle);
        }
    }

    /* Cleanup slots */
    for (CK_ULONG i = 0; i < g_module.numSlots; i++)
    {
        quac_slot_cleanup(&g_module.slots[i]);
    }

#ifdef QUAC_HAS_HARDWARE
    quac_cleanup();
#endif

    g_module.initialized = CK_FALSE;
    g_module.numSlots = 0;

    quac_unlock();

    pthread_mutex_destroy(&g_module.mutex);

    return CKR_OK;
}

CK_RV CK_CALL_SPEC C_GetInfo(CK_INFO_PTR pInfo)
{
    if (!g_module.initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (pInfo == NULL)
        return CKR_ARGUMENTS_BAD;

    pInfo->cryptokiVersion.major = 2;
    pInfo->cryptokiVersion.minor = 40;

    quac_pad_string(pInfo->manufacturerID, QUAC_MANUFACTURER, sizeof(pInfo->manufacturerID));

    pInfo->flags = 0;

    quac_pad_string(pInfo->libraryDescription, "QUAC 100 PQC PKCS#11", sizeof(pInfo->libraryDescription));

    pInfo->libraryVersion.major = 1;
    pInfo->libraryVersion.minor = 0;

    return CKR_OK;
}

CK_RV CK_CALL_SPEC C_GetFunctionList(CK_VOID_PTR_PTR ppFunctionList)
{
    if (ppFunctionList == NULL)
        return CKR_ARGUMENTS_BAD;

    *ppFunctionList = (CK_VOID_PTR)&g_function_list;

    return CKR_OK;
}

/* ==========================================================================
 * Slot and Token Management
 * ========================================================================== */

CK_RV CK_CALL_SPEC C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount)
{
    CK_ULONG count = 0;

    if (!g_module.initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (pulCount == NULL)
        return CKR_ARGUMENTS_BAD;

    /* Count matching slots */
    for (CK_ULONG i = 0; i < g_module.numSlots; i++)
    {
        if (!tokenPresent || g_module.slots[i].tokenPresent)
        {
            if (pSlotList != NULL && count < *pulCount)
            {
                pSlotList[count] = g_module.slots[i].slotID;
            }
            count++;
        }
    }

    if (pSlotList == NULL)
    {
        *pulCount = count;
        return CKR_OK;
    }

    if (count > *pulCount)
    {
        *pulCount = count;
        return CKR_BUFFER_TOO_SMALL;
    }

    *pulCount = count;
    return CKR_OK;
}

CK_RV CK_CALL_SPEC C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
    quac_slot_t *slot;

    if (!g_module.initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (pInfo == NULL)
        return CKR_ARGUMENTS_BAD;

    slot = quac_get_slot(slotID);
    if (slot == NULL)
        return CKR_SLOT_ID_INVALID;

    memcpy(pInfo->slotDescription, slot->description, sizeof(pInfo->slotDescription));
    memcpy(pInfo->manufacturerID, slot->manufacturerID, sizeof(pInfo->manufacturerID));

    pInfo->flags = 0;
    if (slot->tokenPresent)
        pInfo->flags |= CKF_TOKEN_PRESENT;
    if (slot->hardwareSlot)
        pInfo->flags |= CKF_HW_SLOT;

    pInfo->hardwareVersion = slot->hardwareVersion;
    pInfo->firmwareVersion = slot->firmwareVersion;

    return CKR_OK;
}

CK_RV CK_CALL_SPEC C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
    quac_slot_t *slot;
    quac_token_t *token;

    if (!g_module.initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (pInfo == NULL)
        return CKR_ARGUMENTS_BAD;

    slot = quac_get_slot(slotID);
    if (slot == NULL)
        return CKR_SLOT_ID_INVALID;

    if (!slot->tokenPresent)
        return CKR_TOKEN_NOT_PRESENT;

    token = &slot->token;

    memcpy(pInfo->label, token->label, sizeof(pInfo->label));
    quac_pad_string(pInfo->manufacturerID, QUAC_MANUFACTURER, sizeof(pInfo->manufacturerID));
    quac_pad_string(pInfo->model, QUAC_MODEL, sizeof(pInfo->model));
    quac_pad_string((CK_UTF8CHAR_PTR)pInfo->serialNumber, QUAC_SERIAL_NUMBER, sizeof(pInfo->serialNumber));

    pInfo->flags = CKF_RNG | CKF_LOGIN_REQUIRED;
    if (token->initialized)
        pInfo->flags |= CKF_TOKEN_INITIALIZED;
    if (token->userPinSet)
        pInfo->flags |= CKF_USER_PIN_INITIALIZED;

    pInfo->ulMaxSessionCount = QUAC_MAX_SESSIONS;
    pInfo->ulSessionCount = 0; /* Would count active sessions */
    pInfo->ulMaxRwSessionCount = QUAC_MAX_SESSIONS;
    pInfo->ulRwSessionCount = 0;
    pInfo->ulMaxPinLen = QUAC_MAX_PIN_LEN;
    pInfo->ulMinPinLen = QUAC_MIN_PIN_LEN;
    pInfo->ulTotalPublicMemory = token->totalPublicMemory;
    pInfo->ulFreePublicMemory = token->freePublicMemory;
    pInfo->ulTotalPrivateMemory = token->totalPrivateMemory;
    pInfo->ulFreePrivateMemory = token->freePrivateMemory;

    pInfo->hardwareVersion.major = 1;
    pInfo->hardwareVersion.minor = 0;
    pInfo->firmwareVersion.major = 1;
    pInfo->firmwareVersion.minor = 0;

    memset(pInfo->utcTime, ' ', sizeof(pInfo->utcTime));

    return CKR_OK;
}

CK_RV CK_CALL_SPEC C_GetMechanismList(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount)
{
    quac_slot_t *slot;

    if (!g_module.initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (pulCount == NULL)
        return CKR_ARGUMENTS_BAD;

    slot = quac_get_slot(slotID);
    if (slot == NULL)
        return CKR_SLOT_ID_INVALID;

    if (pMechanismList == NULL)
    {
        *pulCount = g_num_mechanisms;
        return CKR_OK;
    }

    if (*pulCount < g_num_mechanisms)
    {
        *pulCount = g_num_mechanisms;
        return CKR_BUFFER_TOO_SMALL;
    }

    for (CK_ULONG i = 0; i < g_num_mechanisms; i++)
    {
        pMechanismList[i] = g_mechanisms[i].type;
    }

    *pulCount = g_num_mechanisms;
    return CKR_OK;
}

CK_RV CK_CALL_SPEC C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo)
{
    quac_slot_t *slot;

    if (!g_module.initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (pInfo == NULL)
        return CKR_ARGUMENTS_BAD;

    slot = quac_get_slot(slotID);
    if (slot == NULL)
        return CKR_SLOT_ID_INVALID;

    for (CK_ULONG i = 0; i < g_num_mechanisms; i++)
    {
        if (g_mechanisms[i].type == type)
        {
            pInfo->ulMinKeySize = g_mechanisms[i].minKeySize;
            pInfo->ulMaxKeySize = g_mechanisms[i].maxKeySize;
            pInfo->flags = g_mechanisms[i].flags;
            return CKR_OK;
        }
    }

    return CKR_MECHANISM_INVALID;
}

CK_RV CK_CALL_SPEC C_InitToken(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel)
{
    quac_slot_t *slot;
    quac_token_t *token;

    if (!g_module.initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (pPin == NULL || pLabel == NULL)
        return CKR_ARGUMENTS_BAD;

    if (ulPinLen < QUAC_MIN_PIN_LEN || ulPinLen > QUAC_MAX_PIN_LEN)
        return CKR_PIN_LEN_RANGE;

    slot = quac_get_slot(slotID);
    if (slot == NULL)
        return CKR_SLOT_ID_INVALID;

    if (!slot->tokenPresent)
        return CKR_TOKEN_NOT_PRESENT;

    quac_lock();

    token = &slot->token;

    /* Clear existing token data */
    quac_token_cleanup(token);

    /* Initialize token */
    quac_token_init(token, pLabel);

    /* Set SO PIN */
    memcpy(token->soPin, pPin, ulPinLen);
    token->soPinLen = ulPinLen;
    token->soPinSet = CK_TRUE;
    token->initialized = CK_TRUE;

    quac_unlock();

    return CKR_OK;
}

CK_RV CK_CALL_SPEC C_InitPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
    quac_session_t *session;
    quac_slot_t *slot;
    quac_token_t *token;

    if (!g_module.initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (pPin == NULL)
        return CKR_ARGUMENTS_BAD;

    if (ulPinLen < QUAC_MIN_PIN_LEN || ulPinLen > QUAC_MAX_PIN_LEN)
        return CKR_PIN_LEN_RANGE;

    quac_lock();

    session = quac_get_session(hSession);
    if (session == NULL)
    {
        quac_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }

    /* Must be logged in as SO */
    if (session->state != CKS_RW_SO_FUNCTIONS)
    {
        quac_unlock();
        return CKR_USER_NOT_LOGGED_IN;
    }

    slot = quac_get_slot(session->slotID);
    token = &slot->token;

    memcpy(token->userPin, pPin, ulPinLen);
    token->userPinLen = ulPinLen;
    token->userPinSet = CK_TRUE;

    quac_unlock();

    return CKR_OK;
}

CK_RV CK_CALL_SPEC C_SetPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen)
{
    quac_session_t *session;
    quac_slot_t *slot;
    quac_token_t *token;

    if (!g_module.initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (pOldPin == NULL || pNewPin == NULL)
        return CKR_ARGUMENTS_BAD;

    if (ulNewLen < QUAC_MIN_PIN_LEN || ulNewLen > QUAC_MAX_PIN_LEN)
        return CKR_PIN_LEN_RANGE;

    quac_lock();

    session = quac_get_session(hSession);
    if (session == NULL)
    {
        quac_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }

    slot = quac_get_slot(session->slotID);
    token = &slot->token;

    /* Check which PIN we're changing based on login state */
    if (token->soLoggedIn)
    {
        if (token->soPinLen != ulOldLen || memcmp(token->soPin, pOldPin, ulOldLen) != 0)
        {
            quac_unlock();
            return CKR_PIN_INCORRECT;
        }
        memcpy(token->soPin, pNewPin, ulNewLen);
        token->soPinLen = ulNewLen;
    }
    else if (token->userLoggedIn)
    {
        if (token->userPinLen != ulOldLen || memcmp(token->userPin, pOldPin, ulOldLen) != 0)
        {
            quac_unlock();
            return CKR_PIN_INCORRECT;
        }
        memcpy(token->userPin, pNewPin, ulNewLen);
        token->userPinLen = ulNewLen;
    }
    else
    {
        quac_unlock();
        return CKR_USER_NOT_LOGGED_IN;
    }

    quac_unlock();

    return CKR_OK;
}

CK_RV CK_CALL_SPEC C_WaitForSlotEvent(CK_ULONG flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved)
{
    (void)flags;
    (void)pSlot;
    (void)pReserved;

    if (!g_module.initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    /* Hot-plug not supported */
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* ==========================================================================
 * Session Management
 * ========================================================================== */

CK_RV CK_CALL_SPEC C_OpenSession(CK_SLOT_ID slotID, CK_ULONG flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession)
{
    if (!g_module.initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (phSession == NULL)
        return CKR_ARGUMENTS_BAD;

    if (!(flags & CKF_SERIAL_SESSION))
        return CKR_SESSION_PARALLEL_NOT_SUPPORTED;

    return quac_session_create(slotID, flags, Notify, pApplication, phSession);
}

CK_RV CK_CALL_SPEC C_CloseSession(CK_SESSION_HANDLE hSession)
{
    if (!g_module.initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    return quac_session_destroy(hSession);
}

CK_RV CK_CALL_SPEC C_CloseAllSessions(CK_SLOT_ID slotID)
{
    quac_slot_t *slot;

    if (!g_module.initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    slot = quac_get_slot(slotID);
    if (slot == NULL)
        return CKR_SLOT_ID_INVALID;

    quac_lock();

    for (CK_ULONG i = 0; i < QUAC_MAX_SESSIONS; i++)
    {
        if (g_module.sessions[i].isOpen && g_module.sessions[i].slotID == slotID)
        {
            quac_session_destroy(g_module.sessions[i].handle);
        }
    }

    quac_unlock();

    return CKR_OK;
}

CK_RV CK_CALL_SPEC C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
    quac_session_t *session;

    if (!g_module.initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (pInfo == NULL)
        return CKR_ARGUMENTS_BAD;

    quac_lock();

    session = quac_get_session(hSession);
    if (session == NULL)
    {
        quac_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }

    pInfo->slotID = session->slotID;
    pInfo->state = session->state;
    pInfo->flags = session->flags;
    pInfo->ulDeviceError = 0;

    quac_unlock();

    return CKR_OK;
}

CK_RV CK_CALL_SPEC C_GetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen)
{
    (void)hSession;
    (void)pOperationState;
    (void)pulOperationStateLen;

    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_CALL_SPEC C_SetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey)
{
    (void)hSession;
    (void)pOperationState;
    (void)ulOperationStateLen;
    (void)hEncryptionKey;
    (void)hAuthenticationKey;

    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_CALL_SPEC C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
    quac_session_t *session;
    quac_slot_t *slot;
    quac_token_t *token;

    if (!g_module.initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (pPin == NULL)
        return CKR_ARGUMENTS_BAD;

    quac_lock();

    session = quac_get_session(hSession);
    if (session == NULL)
    {
        quac_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }

    slot = quac_get_slot(session->slotID);
    token = &slot->token;

    if (!token->initialized)
    {
        quac_unlock();
        return CKR_USER_PIN_NOT_INITIALIZED;
    }

    if (userType == CKU_SO)
    {
        if (token->userLoggedIn)
        {
            quac_unlock();
            return CKR_USER_ANOTHER_ALREADY_LOGGED_IN;
        }

        if (token->soPinLen != ulPinLen || memcmp(token->soPin, pPin, ulPinLen) != 0)
        {
            quac_unlock();
            return CKR_PIN_INCORRECT;
        }

        token->soLoggedIn = CK_TRUE;
        session->state = CKS_RW_SO_FUNCTIONS;
    }
    else if (userType == CKU_USER)
    {
        if (token->soLoggedIn)
        {
            quac_unlock();
            return CKR_USER_ANOTHER_ALREADY_LOGGED_IN;
        }

        if (!token->userPinSet)
        {
            quac_unlock();
            return CKR_USER_PIN_NOT_INITIALIZED;
        }

        if (token->userPinLen != ulPinLen || memcmp(token->userPin, pPin, ulPinLen) != 0)
        {
            quac_unlock();
            return CKR_PIN_INCORRECT;
        }

        token->userLoggedIn = CK_TRUE;

        if (session->flags & CKF_RW_SESSION)
            session->state = CKS_RW_USER_FUNCTIONS;
        else
            session->state = CKS_RO_USER_FUNCTIONS;
    }
    else
    {
        quac_unlock();
        return CKR_USER_TYPE_INVALID;
    }

    quac_unlock();

    return CKR_OK;
}

CK_RV CK_CALL_SPEC C_Logout(CK_SESSION_HANDLE hSession)
{
    quac_session_t *session;
    quac_slot_t *slot;
    quac_token_t *token;

    if (!g_module.initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    quac_lock();

    session = quac_get_session(hSession);
    if (session == NULL)
    {
        quac_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }

    slot = quac_get_slot(session->slotID);
    token = &slot->token;

    token->userLoggedIn = CK_FALSE;
    token->soLoggedIn = CK_FALSE;

    if (session->flags & CKF_RW_SESSION)
        session->state = CKS_RW_PUBLIC_SESSION;
    else
        session->state = CKS_RO_PUBLIC_SESSION;

    quac_unlock();

    return CKR_OK;
}

/* Stub implementations for remaining functions... */

CK_RV CK_CALL_SPEC C_CreateObject(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject)
{
    quac_session_t *session;
    quac_slot_t *slot;

    if (!g_module.initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (pTemplate == NULL || phObject == NULL)
        return CKR_ARGUMENTS_BAD;

    quac_lock();

    session = quac_get_session(hSession);
    if (session == NULL)
    {
        quac_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }

    slot = quac_get_slot(session->slotID);
    CK_RV rv = quac_object_create(&slot->token, pTemplate, ulCount, phObject);

    quac_unlock();

    return rv;
}

CK_RV CK_CALL_SPEC C_CopyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject)
{
    (void)hSession;
    (void)hObject;
    (void)pTemplate;
    (void)ulCount;
    (void)phNewObject;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_CALL_SPEC C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{
    quac_session_t *session;
    quac_slot_t *slot;

    if (!g_module.initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    quac_lock();

    session = quac_get_session(hSession);
    if (session == NULL)
    {
        quac_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }

    slot = quac_get_slot(session->slotID);
    CK_RV rv = quac_object_destroy(&slot->token, hObject);

    quac_unlock();

    return rv;
}

CK_RV CK_CALL_SPEC C_GetObjectSize(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize)
{
    (void)hSession;
    (void)hObject;
    (void)pulSize;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_CALL_SPEC C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    quac_session_t *session;
    quac_slot_t *slot;
    quac_object_t *obj;
    CK_RV rv = CKR_OK;

    if (!g_module.initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (pTemplate == NULL)
        return CKR_ARGUMENTS_BAD;

    quac_lock();

    session = quac_get_session(hSession);
    if (session == NULL)
    {
        quac_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }

    slot = quac_get_slot(session->slotID);
    obj = quac_get_object(&slot->token, hObject);

    if (obj == NULL)
    {
        quac_unlock();
        return CKR_OBJECT_HANDLE_INVALID;
    }

    for (CK_ULONG i = 0; i < ulCount; i++)
    {
        CK_RV attr_rv = quac_object_get_attribute(obj, pTemplate[i].type,
                                                  pTemplate[i].pValue,
                                                  &pTemplate[i].ulValueLen);
        if (attr_rv != CKR_OK)
            rv = attr_rv;
    }

    quac_unlock();

    return rv;
}

CK_RV CK_CALL_SPEC C_SetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    (void)hSession;
    (void)hObject;
    (void)pTemplate;
    (void)ulCount;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_CALL_SPEC C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    quac_session_t *session;
    quac_slot_t *slot;
    quac_token_t *token;

    if (!g_module.initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    quac_lock();

    session = quac_get_session(hSession);
    if (session == NULL)
    {
        quac_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }

    if (session->findCtx.active)
    {
        quac_unlock();
        return CKR_OPERATION_ACTIVE;
    }

    slot = quac_get_slot(session->slotID);
    token = &slot->token;

    /* Find matching objects */
    session->findCtx.numResults = 0;
    session->findCtx.currentIndex = 0;

    for (CK_ULONG i = 0; i < token->numObjects && session->findCtx.numResults < QUAC_MAX_FIND_RESULTS; i++)
    {
        if (token->objects[i].inUse && quac_object_match(&token->objects[i], pTemplate, ulCount))
        {
            session->findCtx.results[session->findCtx.numResults++] = token->objects[i].handle;
        }
    }

    session->findCtx.active = CK_TRUE;

    quac_unlock();

    return CKR_OK;
}

CK_RV CK_CALL_SPEC C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount)
{
    quac_session_t *session;

    if (!g_module.initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (phObject == NULL || pulObjectCount == NULL)
        return CKR_ARGUMENTS_BAD;

    quac_lock();

    session = quac_get_session(hSession);
    if (session == NULL)
    {
        quac_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }

    if (!session->findCtx.active)
    {
        quac_unlock();
        return CKR_OPERATION_NOT_INITIALIZED;
    }

    *pulObjectCount = 0;

    while (session->findCtx.currentIndex < session->findCtx.numResults &&
           *pulObjectCount < ulMaxObjectCount)
    {
        phObject[(*pulObjectCount)++] = session->findCtx.results[session->findCtx.currentIndex++];
    }

    quac_unlock();

    return CKR_OK;
}

CK_RV CK_CALL_SPEC C_FindObjectsFinal(CK_SESSION_HANDLE hSession)
{
    quac_session_t *session;

    if (!g_module.initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    quac_lock();

    session = quac_get_session(hSession);
    if (session == NULL)
    {
        quac_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }

    session->findCtx.active = CK_FALSE;
    session->findCtx.numResults = 0;
    session->findCtx.currentIndex = 0;

    quac_unlock();

    return CKR_OK;
}

/* Encryption - Not applicable for ML-KEM (use DeriveKey for KEM) */
CK_RV CK_CALL_SPEC C_EncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    (void)hSession;
    (void)pMechanism;
    (void)hKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_CALL_SPEC C_Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{
    (void)hSession;
    (void)pData;
    (void)ulDataLen;
    (void)pEncryptedData;
    (void)pulEncryptedDataLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_CALL_SPEC C_EncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
    (void)hSession;
    (void)pPart;
    (void)ulPartLen;
    (void)pEncryptedPart;
    (void)pulEncryptedPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_CALL_SPEC C_EncryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPartLen)
{
    (void)hSession;
    (void)pLastEncryptedPart;
    (void)pulLastEncryptedPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_CALL_SPEC C_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    (void)hSession;
    (void)pMechanism;
    (void)hKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_CALL_SPEC C_Decrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
    (void)hSession;
    (void)pEncryptedData;
    (void)ulEncryptedDataLen;
    (void)pData;
    (void)pulDataLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_CALL_SPEC C_DecryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
    (void)hSession;
    (void)pEncryptedPart;
    (void)ulEncryptedPartLen;
    (void)pPart;
    (void)pulPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_CALL_SPEC C_DecryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen)
{
    (void)hSession;
    (void)pLastPart;
    (void)pulLastPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* Digest */
CK_RV CK_CALL_SPEC C_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism)
{
    (void)hSession;
    (void)pMechanism;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_CALL_SPEC C_Digest(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
    (void)hSession;
    (void)pData;
    (void)ulDataLen;
    (void)pDigest;
    (void)pulDigestLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_CALL_SPEC C_DigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
    (void)hSession;
    (void)pPart;
    (void)ulPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_CALL_SPEC C_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey)
{
    (void)hSession;
    (void)hKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_CALL_SPEC C_DigestFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
    (void)hSession;
    (void)pDigest;
    (void)pulDigestLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* Signing - ML-DSA */
CK_RV CK_CALL_SPEC C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    quac_session_t *session;

    if (!g_module.initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (pMechanism == NULL)
        return CKR_ARGUMENTS_BAD;

    quac_lock();

    session = quac_get_session(hSession);
    if (session == NULL)
    {
        quac_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }

    CK_RV rv = quac_sign_init(session, pMechanism, hKey);

    quac_unlock();

    return rv;
}

CK_RV CK_CALL_SPEC C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
    quac_session_t *session;

    if (!g_module.initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (pData == NULL || pulSignatureLen == NULL)
        return CKR_ARGUMENTS_BAD;

    quac_lock();

    session = quac_get_session(hSession);
    if (session == NULL)
    {
        quac_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }

    CK_RV rv = quac_sign(session, pData, ulDataLen, pSignature, pulSignatureLen);

    quac_unlock();

    return rv;
}

CK_RV CK_CALL_SPEC C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
    (void)hSession;
    (void)pPart;
    (void)ulPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_CALL_SPEC C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
    (void)hSession;
    (void)pSignature;
    (void)pulSignatureLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_CALL_SPEC C_SignRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    (void)hSession;
    (void)pMechanism;
    (void)hKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_CALL_SPEC C_SignRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
    (void)hSession;
    (void)pData;
    (void)ulDataLen;
    (void)pSignature;
    (void)pulSignatureLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* Verification - ML-DSA */
CK_RV CK_CALL_SPEC C_VerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    quac_session_t *session;

    if (!g_module.initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (pMechanism == NULL)
        return CKR_ARGUMENTS_BAD;

    quac_lock();

    session = quac_get_session(hSession);
    if (session == NULL)
    {
        quac_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }

    CK_RV rv = quac_verify_init(session, pMechanism, hKey);

    quac_unlock();

    return rv;
}

CK_RV CK_CALL_SPEC C_Verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
    quac_session_t *session;

    if (!g_module.initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (pData == NULL || pSignature == NULL)
        return CKR_ARGUMENTS_BAD;

    quac_lock();

    session = quac_get_session(hSession);
    if (session == NULL)
    {
        quac_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }

    CK_RV rv = quac_verify(session, pData, ulDataLen, pSignature, ulSignatureLen);

    quac_unlock();

    return rv;
}

CK_RV CK_CALL_SPEC C_VerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
    (void)hSession;
    (void)pPart;
    (void)ulPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_CALL_SPEC C_VerifyFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
    (void)hSession;
    (void)pSignature;
    (void)ulSignatureLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_CALL_SPEC C_VerifyRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    (void)hSession;
    (void)pMechanism;
    (void)hKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_CALL_SPEC C_VerifyRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
    (void)hSession;
    (void)pSignature;
    (void)ulSignatureLen;
    (void)pData;
    (void)pulDataLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* Dual-function */
CK_RV CK_CALL_SPEC C_DigestEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
    (void)hSession;
    (void)pPart;
    (void)ulPartLen;
    (void)pEncryptedPart;
    (void)pulEncryptedPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_CALL_SPEC C_DecryptDigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
    (void)hSession;
    (void)pEncryptedPart;
    (void)ulEncryptedPartLen;
    (void)pPart;
    (void)pulPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_CALL_SPEC C_SignEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
    (void)hSession;
    (void)pPart;
    (void)ulPartLen;
    (void)pEncryptedPart;
    (void)pulEncryptedPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_CALL_SPEC C_DecryptVerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
    (void)hSession;
    (void)pEncryptedPart;
    (void)ulEncryptedPartLen;
    (void)pPart;
    (void)pulPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* Key Management */
CK_RV CK_CALL_SPEC C_GenerateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey)
{
    (void)hSession;
    (void)pMechanism;
    (void)pTemplate;
    (void)ulCount;
    (void)phKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_CALL_SPEC C_GenerateKeyPair(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey)
{
    quac_session_t *session;
    quac_slot_t *slot;
    CK_KEY_TYPE keyType;

    if (!g_module.initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (pMechanism == NULL || pPublicKeyTemplate == NULL || pPrivateKeyTemplate == NULL ||
        phPublicKey == NULL || phPrivateKey == NULL)
        return CKR_ARGUMENTS_BAD;

    quac_lock();

    session = quac_get_session(hSession);
    if (session == NULL)
    {
        quac_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }

    slot = quac_get_slot(session->slotID);

    CK_RV rv;

    switch (pMechanism->mechanism)
    {
    case CKM_ML_KEM_512_KEY_PAIR_GEN:
        keyType = CKK_ML_KEM_512;
        rv = quac_generate_keypair_mlkem(&slot->token, keyType,
                                         pPublicKeyTemplate, ulPublicKeyAttributeCount,
                                         pPrivateKeyTemplate, ulPrivateKeyAttributeCount,
                                         phPublicKey, phPrivateKey);
        break;

    case CKM_ML_KEM_768_KEY_PAIR_GEN:
        keyType = CKK_ML_KEM_768;
        rv = quac_generate_keypair_mlkem(&slot->token, keyType,
                                         pPublicKeyTemplate, ulPublicKeyAttributeCount,
                                         pPrivateKeyTemplate, ulPrivateKeyAttributeCount,
                                         phPublicKey, phPrivateKey);
        break;

    case CKM_ML_KEM_1024_KEY_PAIR_GEN:
        keyType = CKK_ML_KEM_1024;
        rv = quac_generate_keypair_mlkem(&slot->token, keyType,
                                         pPublicKeyTemplate, ulPublicKeyAttributeCount,
                                         pPrivateKeyTemplate, ulPrivateKeyAttributeCount,
                                         phPublicKey, phPrivateKey);
        break;

    case CKM_ML_DSA_44_KEY_PAIR_GEN:
        keyType = CKK_ML_DSA_44;
        rv = quac_generate_keypair_mldsa(&slot->token, keyType,
                                         pPublicKeyTemplate, ulPublicKeyAttributeCount,
                                         pPrivateKeyTemplate, ulPrivateKeyAttributeCount,
                                         phPublicKey, phPrivateKey);
        break;

    case CKM_ML_DSA_65_KEY_PAIR_GEN:
        keyType = CKK_ML_DSA_65;
        rv = quac_generate_keypair_mldsa(&slot->token, keyType,
                                         pPublicKeyTemplate, ulPublicKeyAttributeCount,
                                         pPrivateKeyTemplate, ulPrivateKeyAttributeCount,
                                         phPublicKey, phPrivateKey);
        break;

    case CKM_ML_DSA_87_KEY_PAIR_GEN:
        keyType = CKK_ML_DSA_87;
        rv = quac_generate_keypair_mldsa(&slot->token, keyType,
                                         pPublicKeyTemplate, ulPublicKeyAttributeCount,
                                         pPrivateKeyTemplate, ulPrivateKeyAttributeCount,
                                         phPublicKey, phPrivateKey);
        break;

    default:
        rv = CKR_MECHANISM_INVALID;
    }

    quac_unlock();

    return rv;
}

CK_RV CK_CALL_SPEC C_WrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen)
{
    (void)hSession;
    (void)pMechanism;
    (void)hWrappingKey;
    (void)hKey;
    (void)pWrappedKey;
    (void)pulWrappedKeyLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_CALL_SPEC C_UnwrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
    (void)hSession;
    (void)pMechanism;
    (void)hUnwrappingKey;
    (void)pWrappedKey;
    (void)ulWrappedKeyLen;
    (void)pTemplate;
    (void)ulAttributeCount;
    (void)phKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CK_CALL_SPEC C_DeriveKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
    /* ML-KEM encaps/decaps would be implemented here */
    (void)hSession;
    (void)pMechanism;
    (void)hBaseKey;
    (void)pTemplate;
    (void)ulAttributeCount;
    (void)phKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* Random Number Generation */
CK_RV CK_CALL_SPEC C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen)
{
    quac_session_t *session;

    if (!g_module.initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (pSeed == NULL)
        return CKR_ARGUMENTS_BAD;

    quac_lock();

    session = quac_get_session(hSession);
    if (session == NULL)
    {
        quac_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }

    /* QRNG doesn't need seeding, but we accept it */
    (void)ulSeedLen;

    quac_unlock();

    return CKR_OK;
}

CK_RV CK_CALL_SPEC C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData, CK_ULONG ulRandomLen)
{
    quac_session_t *session;

    if (!g_module.initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (pRandomData == NULL)
        return CKR_ARGUMENTS_BAD;

    quac_lock();

    session = quac_get_session(hSession);
    if (session == NULL)
    {
        quac_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }

    CK_RV rv = quac_generate_random(pRandomData, ulRandomLen);

    quac_unlock();

    return rv;
}

/* Parallel function management */
CK_RV CK_CALL_SPEC C_GetFunctionStatus(CK_SESSION_HANDLE hSession)
{
    (void)hSession;
    return CKR_FUNCTION_NOT_PARALLEL;
}

CK_RV CK_CALL_SPEC C_CancelFunction(CK_SESSION_HANDLE hSession)
{
    (void)hSession;
    return CKR_FUNCTION_NOT_PARALLEL;
}