/**
 * @file quac100_pkcs11_internal.h
 * @brief QUAC 100 PKCS#11 Module - Internal Definitions
 *
 * Internal structures and functions not exposed in public API.
 *
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#ifndef QUAC100_PKCS11_INTERNAL_H
#define QUAC100_PKCS11_INTERNAL_H

#include "quac100_pkcs11.h"
#include <pthread.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

    /* ==========================================================================
     * Configuration Constants
     * ========================================================================== */

#define QUAC_MAX_SLOTS 4
#define QUAC_MAX_SESSIONS 256
#define QUAC_MAX_OBJECTS 4096
#define QUAC_MAX_FIND_RESULTS 256
#define QUAC_MAX_PIN_LEN 64
#define QUAC_MIN_PIN_LEN 4
#define QUAC_DEFAULT_SO_PIN "12345678"
#define QUAC_DEFAULT_USER_PIN "1234"
#define QUAC_TOKEN_LABEL "QUAC 100 PQC Token"
#define QUAC_MANUFACTURER "Dyber, Inc."
#define QUAC_MODEL "QUAC-100"
#define QUAC_SERIAL_NUMBER "0001"

/* PQC Key Sizes */
#define ML_KEM_512_PUBLIC_KEY_LEN 800
#define ML_KEM_512_SECRET_KEY_LEN 1632
#define ML_KEM_512_CIPHERTEXT_LEN 768
#define ML_KEM_768_PUBLIC_KEY_LEN 1184
#define ML_KEM_768_SECRET_KEY_LEN 2400
#define ML_KEM_768_CIPHERTEXT_LEN 1088
#define ML_KEM_1024_PUBLIC_KEY_LEN 1568
#define ML_KEM_1024_SECRET_KEY_LEN 3168
#define ML_KEM_1024_CIPHERTEXT_LEN 1568
#define ML_KEM_SHARED_SECRET_LEN 32

#define ML_DSA_44_PUBLIC_KEY_LEN 1312
#define ML_DSA_44_SECRET_KEY_LEN 2560
#define ML_DSA_44_SIGNATURE_LEN 2420
#define ML_DSA_65_PUBLIC_KEY_LEN 1952
#define ML_DSA_65_SECRET_KEY_LEN 4032
#define ML_DSA_65_SIGNATURE_LEN 3309
#define ML_DSA_87_PUBLIC_KEY_LEN 2592
#define ML_DSA_87_SECRET_KEY_LEN 4896
#define ML_DSA_87_SIGNATURE_LEN 4627

    /* ==========================================================================
     * Internal Structures
     * ========================================================================== */

    /**
     * @brief Object attribute storage
     */
    typedef struct quac_attribute
    {
        CK_ATTRIBUTE_TYPE type;
        CK_BYTE *pValue;
        CK_ULONG ulValueLen;
    } quac_attribute_t;

    /**
     * @brief PKCS#11 object
     */
    typedef struct quac_object
    {
        CK_OBJECT_HANDLE handle;
        CK_OBJECT_CLASS objClass;
        CK_KEY_TYPE keyType;
        CK_BBOOL isToken;       /* Token object (persistent) */
        CK_BBOOL isPrivate;     /* Private object (needs login) */
        CK_BBOOL isSensitive;   /* Cannot export value */
        CK_BBOOL isExtractable; /* Can be wrapped */
        CK_BBOOL isLocal;       /* Generated locally */

        /* Attributes */
        quac_attribute_t *attributes;
        CK_ULONG numAttributes;

        /* Key data */
        CK_BYTE *publicKey;
        CK_ULONG publicKeyLen;
        CK_BYTE *secretKey;
        CK_ULONG secretKeyLen;

        /* Label and ID */
        CK_BYTE label[64];
        CK_ULONG labelLen;
        CK_BYTE id[64];
        CK_ULONG idLen;

        /* Capabilities */
        CK_BBOOL canSign;
        CK_BBOOL canVerify;
        CK_BBOOL canEncrypt;
        CK_BBOOL canDecrypt;
        CK_BBOOL canDerive;
        CK_BBOOL canWrap;
        CK_BBOOL canUnwrap;

        /* In use flag */
        CK_BBOOL inUse;
    } quac_object_t;

    /**
     * @brief Find objects context
     */
    typedef struct quac_find_ctx
    {
        CK_OBJECT_HANDLE results[QUAC_MAX_FIND_RESULTS];
        CK_ULONG numResults;
        CK_ULONG currentIndex;
        CK_BBOOL active;
    } quac_find_ctx_t;

    /**
     * @brief Cryptographic operation context
     */
    typedef struct quac_crypto_ctx
    {
        CK_MECHANISM_TYPE mechanism;
        CK_OBJECT_HANDLE keyHandle;
        CK_BBOOL active;

        /* For multi-part operations */
        CK_BYTE *buffer;
        CK_ULONG bufferLen;
        CK_ULONG bufferUsed;
    } quac_crypto_ctx_t;

    /**
     * @brief Session state
     */
    typedef struct quac_session
    {
        CK_SESSION_HANDLE handle;
        CK_SLOT_ID slotID;
        CK_ULONG state;
        CK_ULONG flags;
        CK_BBOOL isOpen;

        /* Application callback */
        CK_NOTIFY notify;
        CK_VOID_PTR pApplication;

        /* Operation contexts */
        quac_crypto_ctx_t signCtx;
        quac_crypto_ctx_t verifyCtx;
        quac_crypto_ctx_t encryptCtx;
        quac_crypto_ctx_t decryptCtx;
        quac_crypto_ctx_t digestCtx;

        /* Find context */
        quac_find_ctx_t findCtx;

        /* Session objects (non-token) */
        CK_OBJECT_HANDLE sessionObjects[QUAC_MAX_OBJECTS];
        CK_ULONG numSessionObjects;
    } quac_session_t;

    /**
     * @brief Token state
     */
    typedef struct quac_token
    {
        CK_BBOOL initialized;
        CK_BBOOL userPinSet;
        CK_BBOOL soPinSet;
        CK_BBOOL userLoggedIn;
        CK_BBOOL soLoggedIn;

        /* PIN storage (in production, would be hashed) */
        CK_BYTE userPin[QUAC_MAX_PIN_LEN];
        CK_ULONG userPinLen;
        CK_BYTE soPin[QUAC_MAX_PIN_LEN];
        CK_ULONG soPinLen;

        /* Label */
        CK_UTF8CHAR label[32];

        /* Token objects */
        quac_object_t objects[QUAC_MAX_OBJECTS];
        CK_ULONG numObjects;
        CK_OBJECT_HANDLE nextObjectHandle;

        /* Statistics */
        CK_ULONG totalPublicMemory;
        CK_ULONG freePublicMemory;
        CK_ULONG totalPrivateMemory;
        CK_ULONG freePrivateMemory;
    } quac_token_t;

    /**
     * @brief Slot state
     */
    typedef struct quac_slot
    {
        CK_SLOT_ID slotID;
        CK_BBOOL tokenPresent;
        CK_BBOOL hardwareSlot;

        /* Slot info */
        CK_UTF8CHAR description[64];
        CK_UTF8CHAR manufacturerID[32];
        CK_VERSION hardwareVersion;
        CK_VERSION firmwareVersion;

        /* Token */
        quac_token_t token;

        /* Hardware device (if present) */
#ifdef QUAC_HAS_HARDWARE
        void *device;
#endif
    } quac_slot_t;

    /**
     * @brief Global module state
     */
    typedef struct quac_module
    {
        CK_BBOOL initialized;
        pthread_mutex_t mutex;

        /* Slots */
        quac_slot_t slots[QUAC_MAX_SLOTS];
        CK_ULONG numSlots;

        /* Sessions */
        quac_session_t sessions[QUAC_MAX_SESSIONS];
        CK_SESSION_HANDLE nextSessionHandle;

        /* Threading */
        CK_BBOOL useOsLocking;
        CK_CREATEMUTEX createMutex;
        CK_DESTROYMUTEX destroyMutex;
        CK_LOCKMUTEX lockMutex;
        CK_UNLOCKMUTEX unlockMutex;
    } quac_module_t;

    /* ==========================================================================
     * Global State
     * ========================================================================== */

    extern quac_module_t g_module;

    /* ==========================================================================
     * Internal Functions - Slot/Token
     * ========================================================================== */

    CK_RV quac_slot_init(quac_slot_t *slot, CK_SLOT_ID slotID);
    CK_RV quac_slot_cleanup(quac_slot_t *slot);
    quac_slot_t *quac_get_slot(CK_SLOT_ID slotID);
    CK_RV quac_token_init(quac_token_t *token, CK_UTF8CHAR_PTR pLabel);
    CK_RV quac_token_cleanup(quac_token_t *token);

    /* ==========================================================================
     * Internal Functions - Session
     * ========================================================================== */

    CK_RV quac_session_create(CK_SLOT_ID slotID, CK_ULONG flags,
                              CK_NOTIFY notify, CK_VOID_PTR pApplication,
                              CK_SESSION_HANDLE_PTR phSession);
    CK_RV quac_session_destroy(CK_SESSION_HANDLE hSession);
    quac_session_t *quac_get_session(CK_SESSION_HANDLE hSession);
    CK_RV quac_session_check_state(quac_session_t *session, CK_BBOOL needLogin, CK_BBOOL needRW);

    /* ==========================================================================
     * Internal Functions - Object
     * ========================================================================== */

    CK_RV quac_object_create(quac_token_t *token, CK_ATTRIBUTE_PTR pTemplate,
                             CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject);
    CK_RV quac_object_destroy(quac_token_t *token, CK_OBJECT_HANDLE hObject);
    quac_object_t *quac_get_object(quac_token_t *token, CK_OBJECT_HANDLE hObject);
    CK_RV quac_object_get_attribute(quac_object_t *obj, CK_ATTRIBUTE_TYPE type,
                                    CK_VOID_PTR pValue, CK_ULONG_PTR pulValueLen);
    CK_RV quac_object_set_attribute(quac_object_t *obj, CK_ATTRIBUTE_TYPE type,
                                    CK_VOID_PTR pValue, CK_ULONG ulValueLen);
    CK_BBOOL quac_object_match(quac_object_t *obj, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);

    /* ==========================================================================
     * Internal Functions - Cryptography
     * ========================================================================== */

    CK_RV quac_generate_keypair_mlkem(quac_token_t *token, CK_KEY_TYPE keyType,
                                      CK_ATTRIBUTE_PTR pPubTemplate, CK_ULONG ulPubCount,
                                      CK_ATTRIBUTE_PTR pPrivTemplate, CK_ULONG ulPrivCount,
                                      CK_OBJECT_HANDLE_PTR phPubKey, CK_OBJECT_HANDLE_PTR phPrivKey);

    CK_RV quac_generate_keypair_mldsa(quac_token_t *token, CK_KEY_TYPE keyType,
                                      CK_ATTRIBUTE_PTR pPubTemplate, CK_ULONG ulPubCount,
                                      CK_ATTRIBUTE_PTR pPrivTemplate, CK_ULONG ulPrivCount,
                                      CK_OBJECT_HANDLE_PTR phPubKey, CK_OBJECT_HANDLE_PTR phPrivKey);

    CK_RV quac_sign_init(quac_session_t *session, CK_MECHANISM_PTR pMechanism,
                         CK_OBJECT_HANDLE hKey);
    CK_RV quac_sign(quac_session_t *session, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                    CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
    CK_RV quac_verify_init(quac_session_t *session, CK_MECHANISM_PTR pMechanism,
                           CK_OBJECT_HANDLE hKey);
    CK_RV quac_verify(quac_session_t *session, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                      CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen);

    CK_RV quac_encaps(quac_session_t *session, CK_OBJECT_HANDLE hPubKey,
                      CK_BYTE_PTR pCiphertext, CK_ULONG_PTR pulCiphertextLen,
                      CK_BYTE_PTR pSharedSecret, CK_ULONG_PTR pulSharedSecretLen);
    CK_RV quac_decaps(quac_session_t *session, CK_OBJECT_HANDLE hPrivKey,
                      CK_BYTE_PTR pCiphertext, CK_ULONG ulCiphertextLen,
                      CK_BYTE_PTR pSharedSecret, CK_ULONG_PTR pulSharedSecretLen);

    CK_RV quac_generate_random(CK_BYTE_PTR pData, CK_ULONG ulLen);

    /* ==========================================================================
     * Internal Functions - Utility
     * ========================================================================== */

    void quac_lock(void);
    void quac_unlock(void);
    void quac_secure_zero(void *ptr, size_t size);
    CK_RV quac_copy_attribute(CK_ATTRIBUTE_PTR pDest, CK_ATTRIBUTE_PTR pSrc);
    void quac_pad_string(CK_UTF8CHAR_PTR dest, const char *src, CK_ULONG len);

    /* ==========================================================================
     * Mechanism Information
     * ========================================================================== */

    typedef struct quac_mechanism_info
    {
        CK_MECHANISM_TYPE type;
        CK_ULONG minKeySize;
        CK_ULONG maxKeySize;
        CK_ULONG flags;
    } quac_mechanism_info_t;

    extern const quac_mechanism_info_t g_mechanisms[];
    extern const CK_ULONG g_num_mechanisms;

    CK_RV quac_get_mechanism_info(CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo);

#ifdef __cplusplus
}
#endif

#endif /* QUAC100_PKCS11_INTERNAL_H */