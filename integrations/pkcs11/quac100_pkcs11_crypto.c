/**
 * @file quac100_pkcs11_crypto.c
 * @brief QUAC 100 PKCS#11 Module - Cryptographic Operations
 *
 * Implements ML-KEM, ML-DSA, and QRNG operations.
 *
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "quac100_pkcs11.h"
#include "quac100_pkcs11_internal.h"

#ifdef QUAC_HAS_HARDWARE
#include <quac100/quac.h>
#endif

/* ==========================================================================
 * Software Simulation (when hardware not available)
 * ========================================================================== */

#ifndef QUAC_HAS_HARDWARE

#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

/**
 * @brief Software simulation of ML-KEM key generation
 */
static CK_RV sim_mlkem_keygen(CK_KEY_TYPE keyType, CK_BYTE_PTR pk, CK_ULONG *pkLen,
                              CK_BYTE_PTR sk, CK_ULONG *skLen)
{
    CK_ULONG pubLen, secLen;

    switch (keyType)
    {
    case CKK_ML_KEM_512:
        pubLen = ML_KEM_512_PUBLIC_KEY_LEN;
        secLen = ML_KEM_512_SECRET_KEY_LEN;
        break;
    case CKK_ML_KEM_768:
        pubLen = ML_KEM_768_PUBLIC_KEY_LEN;
        secLen = ML_KEM_768_SECRET_KEY_LEN;
        break;
    case CKK_ML_KEM_1024:
        pubLen = ML_KEM_1024_PUBLIC_KEY_LEN;
        secLen = ML_KEM_1024_SECRET_KEY_LEN;
        break;
    default:
        return CKR_KEY_TYPE_INCONSISTENT;
    }

    /* Generate simulated keys */
    if (RAND_bytes(pk, pubLen) != 1)
        return CKR_FUNCTION_FAILED;

    if (RAND_bytes(sk, secLen) != 1)
        return CKR_FUNCTION_FAILED;

    /* Embed public key hash in secret key for simulation */
    unsigned char hash[32];
    SHA256(pk, pubLen, hash);
    memcpy(sk, hash, 32);

    *pkLen = pubLen;
    *skLen = secLen;

    return CKR_OK;
}

/**
 * @brief Software simulation of ML-KEM encapsulation
 */
static CK_RV sim_mlkem_encaps(CK_KEY_TYPE keyType, CK_BYTE_PTR pk, CK_ULONG pkLen,
                              CK_BYTE_PTR ct, CK_ULONG *ctLen,
                              CK_BYTE_PTR ss, CK_ULONG *ssLen)
{
    CK_ULONG ciphertextLen;
    (void)pkLen;

    switch (keyType)
    {
    case CKK_ML_KEM_512:
        ciphertextLen = ML_KEM_512_CIPHERTEXT_LEN;
        break;
    case CKK_ML_KEM_768:
        ciphertextLen = ML_KEM_768_CIPHERTEXT_LEN;
        break;
    case CKK_ML_KEM_1024:
        ciphertextLen = ML_KEM_1024_CIPHERTEXT_LEN;
        break;
    default:
        return CKR_KEY_TYPE_INCONSISTENT;
    }

    /* Generate shared secret */
    if (RAND_bytes(ss, ML_KEM_SHARED_SECRET_LEN) != 1)
        return CKR_FUNCTION_FAILED;

    /* Generate simulated ciphertext */
    unsigned char seed[64];
    memcpy(seed, pk, 32);
    memcpy(seed + 32, ss, 32);

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int len;
    EVP_DigestInit_ex(ctx, EVP_sha512(), NULL);
    EVP_DigestUpdate(ctx, seed, 64);
    EVP_DigestFinal_ex(ctx, ct, &len);
    EVP_MD_CTX_free(ctx);

    /* Fill rest with deterministic data */
    for (CK_ULONG i = 64; i < ciphertextLen; i += 32)
    {
        SHA256(ct + i - 64, 64, ct + i);
    }

    *ctLen = ciphertextLen;
    *ssLen = ML_KEM_SHARED_SECRET_LEN;

    return CKR_OK;
}

/**
 * @brief Software simulation of ML-KEM decapsulation
 */
static CK_RV sim_mlkem_decaps(CK_KEY_TYPE keyType, CK_BYTE_PTR sk, CK_ULONG skLen,
                              CK_BYTE_PTR ct, CK_ULONG ctLen,
                              CK_BYTE_PTR ss, CK_ULONG *ssLen)
{
    (void)keyType;
    (void)skLen;

    /* Derive shared secret from ciphertext and secret key */
    unsigned char seed[128];
    memcpy(seed, sk, 32); /* pk_hash from sk */
    memcpy(seed + 32, ct, (ctLen > 96) ? 96 : ctLen);

    SHA256(seed, 32 + ((ctLen > 96) ? 96 : ctLen), ss);

    *ssLen = ML_KEM_SHARED_SECRET_LEN;

    return CKR_OK;
}

/**
 * @brief Software simulation of ML-DSA key generation
 */
static CK_RV sim_mldsa_keygen(CK_KEY_TYPE keyType, CK_BYTE_PTR pk, CK_ULONG *pkLen,
                              CK_BYTE_PTR sk, CK_ULONG *skLen)
{
    CK_ULONG pubLen, secLen;

    switch (keyType)
    {
    case CKK_ML_DSA_44:
        pubLen = ML_DSA_44_PUBLIC_KEY_LEN;
        secLen = ML_DSA_44_SECRET_KEY_LEN;
        break;
    case CKK_ML_DSA_65:
        pubLen = ML_DSA_65_PUBLIC_KEY_LEN;
        secLen = ML_DSA_65_SECRET_KEY_LEN;
        break;
    case CKK_ML_DSA_87:
        pubLen = ML_DSA_87_PUBLIC_KEY_LEN;
        secLen = ML_DSA_87_SECRET_KEY_LEN;
        break;
    default:
        return CKR_KEY_TYPE_INCONSISTENT;
    }

    /* Generate seed */
    unsigned char seed[32];
    if (RAND_bytes(seed, 32) != 1)
        return CKR_FUNCTION_FAILED;

    /* Expand seed to keys */
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char expand[64];
    unsigned int len;

    EVP_DigestInit_ex(ctx, EVP_sha512(), NULL);
    EVP_DigestUpdate(ctx, seed, 32);
    EVP_DigestUpdate(ctx, "public", 6);
    EVP_DigestFinal_ex(ctx, expand, &len);

    /* Fill public key */
    for (CK_ULONG i = 0; i < pubLen; i += 64)
    {
        SHA512(expand, 64, pk + i);
        memcpy(expand, pk + i, 64);
    }

    /* Fill secret key */
    EVP_DigestInit_ex(ctx, EVP_sha512(), NULL);
    EVP_DigestUpdate(ctx, seed, 32);
    EVP_DigestUpdate(ctx, "secret", 6);
    EVP_DigestFinal_ex(ctx, expand, &len);

    for (CK_ULONG i = 0; i < secLen; i += 64)
    {
        SHA512(expand, 64, sk + i);
        memcpy(expand, sk + i, 64);
    }

    /* Embed pk_hash in sk */
    SHA256(pk, pubLen, sk);

    EVP_MD_CTX_free(ctx);

    *pkLen = pubLen;
    *skLen = secLen;

    return CKR_OK;
}

/**
 * @brief Software simulation of ML-DSA signing
 */
static CK_RV sim_mldsa_sign(CK_KEY_TYPE keyType, CK_BYTE_PTR sk, CK_ULONG skLen,
                            CK_BYTE_PTR msg, CK_ULONG msgLen,
                            CK_BYTE_PTR sig, CK_ULONG *sigLen)
{
    CK_ULONG sigSize;
    (void)skLen;

    switch (keyType)
    {
    case CKK_ML_DSA_44:
        sigSize = ML_DSA_44_SIGNATURE_LEN;
        break;
    case CKK_ML_DSA_65:
        sigSize = ML_DSA_65_SIGNATURE_LEN;
        break;
    case CKK_ML_DSA_87:
        sigSize = ML_DSA_87_SIGNATURE_LEN;
        break;
    default:
        return CKR_KEY_TYPE_INCONSISTENT;
    }

    if (sig == NULL)
    {
        *sigLen = sigSize;
        return CKR_OK;
    }

    if (*sigLen < sigSize)
    {
        *sigLen = sigSize;
        return CKR_BUFFER_TOO_SMALL;
    }

    /* Create signature from sk and message */
    unsigned char hash[64];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int len;

    EVP_DigestInit_ex(ctx, EVP_sha512(), NULL);
    EVP_DigestUpdate(ctx, sk, 64);
    EVP_DigestUpdate(ctx, msg, msgLen);
    EVP_DigestFinal_ex(ctx, hash, &len);

    /* Fill signature */
    for (CK_ULONG i = 0; i < sigSize; i += 64)
    {
        SHA512(hash, 64, sig + i);
        memcpy(hash, sig + i, 64);
    }

    /* Store pk_hash for verification */
    memcpy(sig, sk, 32); /* pk_hash is at start of sk */

    EVP_MD_CTX_free(ctx);

    *sigLen = sigSize;

    return CKR_OK;
}

/**
 * @brief Software simulation of ML-DSA verification
 */
static CK_RV sim_mldsa_verify(CK_KEY_TYPE keyType, CK_BYTE_PTR pk, CK_ULONG pkLen,
                              CK_BYTE_PTR msg, CK_ULONG msgLen,
                              CK_BYTE_PTR sig, CK_ULONG sigLen)
{
    CK_ULONG expectedSigLen;

    switch (keyType)
    {
    case CKK_ML_DSA_44:
        expectedSigLen = ML_DSA_44_SIGNATURE_LEN;
        break;
    case CKK_ML_DSA_65:
        expectedSigLen = ML_DSA_65_SIGNATURE_LEN;
        break;
    case CKK_ML_DSA_87:
        expectedSigLen = ML_DSA_87_SIGNATURE_LEN;
        break;
    default:
        return CKR_MECHANISM_INVALID;
    }

    if (sigLen != expectedSigLen)
        return CKR_SIGNATURE_LEN_RANGE;

    /* Verify pk_hash matches */
    unsigned char pk_hash[32];
    SHA256(pk, pkLen, pk_hash);

    if (memcmp(sig, pk_hash, 32) != 0)
        return CKR_SIGNATURE_INVALID;

    /* Additional verification would go here in real implementation */
    (void)msg;
    (void)msgLen;

    return CKR_OK;
}

/**
 * @brief Software simulation of random number generation
 */
static CK_RV sim_random(CK_BYTE_PTR data, CK_ULONG len)
{
    if (RAND_bytes(data, len) != 1)
        return CKR_FUNCTION_FAILED;

    return CKR_OK;
}

#endif /* !QUAC_HAS_HARDWARE */

/* ==========================================================================
 * ML-KEM Key Generation
 * ========================================================================== */

CK_RV quac_generate_keypair_mlkem(quac_token_t *token, CK_KEY_TYPE keyType,
                                  CK_ATTRIBUTE_PTR pPubTemplate, CK_ULONG ulPubCount,
                                  CK_ATTRIBUTE_PTR pPrivTemplate, CK_ULONG ulPrivCount,
                                  CK_OBJECT_HANDLE_PTR phPubKey, CK_OBJECT_HANDLE_PTR phPrivKey)
{
    CK_RV rv;
    CK_BYTE *pk = NULL, *sk = NULL;
    CK_ULONG pkLen, skLen;
    CK_ULONG maxPkLen, maxSkLen;

    /* Determine key sizes */
    switch (keyType)
    {
    case CKK_ML_KEM_512:
        maxPkLen = ML_KEM_512_PUBLIC_KEY_LEN;
        maxSkLen = ML_KEM_512_SECRET_KEY_LEN;
        break;
    case CKK_ML_KEM_768:
        maxPkLen = ML_KEM_768_PUBLIC_KEY_LEN;
        maxSkLen = ML_KEM_768_SECRET_KEY_LEN;
        break;
    case CKK_ML_KEM_1024:
        maxPkLen = ML_KEM_1024_PUBLIC_KEY_LEN;
        maxSkLen = ML_KEM_1024_SECRET_KEY_LEN;
        break;
    default:
        return CKR_KEY_TYPE_INCONSISTENT;
    }

    /* Allocate key buffers */
    pk = malloc(maxPkLen);
    sk = malloc(maxSkLen);

    if (pk == NULL || sk == NULL)
    {
        rv = CKR_HOST_MEMORY;
        goto cleanup;
    }

    /* Generate keys */
#ifdef QUAC_HAS_HARDWARE
    /* Use hardware */
    int alg;
    switch (keyType)
    {
    case CKK_ML_KEM_512:
        alg = QUAC_ALG_ML_KEM_512;
        break;
    case CKK_ML_KEM_768:
        alg = QUAC_ALG_ML_KEM_768;
        break;
    case CKK_ML_KEM_1024:
        alg = QUAC_ALG_ML_KEM_1024;
        break;
    default:
        alg = QUAC_ALG_ML_KEM_768;
    }

    if (quac_kem_keygen(g_module.slots[0].device, alg, pk, &pkLen, sk, &skLen) != 0)
    {
        rv = CKR_DEVICE_ERROR;
        goto cleanup;
    }
#else
    /* Use software simulation */
    rv = sim_mlkem_keygen(keyType, pk, &pkLen, sk, &skLen);
    if (rv != CKR_OK)
        goto cleanup;
#endif

    /* Create public key object */
    CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
    CK_BBOOL bTrue = CK_TRUE;
    CK_BBOOL bFalse = CK_FALSE;

    CK_ATTRIBUTE pubTemplate[] = {
        {CKA_CLASS, &pubClass, sizeof(pubClass)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_TOKEN, &bFalse, sizeof(bFalse)},
        {CKA_PRIVATE, &bFalse, sizeof(bFalse)},
        {CKA_VERIFY, &bFalse, sizeof(bFalse)},
        {CKA_ENCRYPT, &bFalse, sizeof(bFalse)},
        {CKA_DERIVE, &bTrue, sizeof(bTrue)},
        {CKA_VALUE, pk, pkLen},
    };

    rv = quac_object_create(token, pubTemplate, sizeof(pubTemplate) / sizeof(pubTemplate[0]), phPubKey);
    if (rv != CKR_OK)
        goto cleanup;

    /* Update with user template */
    quac_object_t *pubObj = quac_get_object(token, *phPubKey);
    for (CK_ULONG i = 0; i < ulPubCount; i++)
    {
        quac_object_set_attribute(pubObj, pPubTemplate[i].type,
                                  pPubTemplate[i].pValue, pPubTemplate[i].ulValueLen);
    }

    /* Create private key object */
    CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;

    CK_ATTRIBUTE privTemplate[] = {
        {CKA_CLASS, &privClass, sizeof(privClass)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_TOKEN, &bFalse, sizeof(bFalse)},
        {CKA_PRIVATE, &bTrue, sizeof(bTrue)},
        {CKA_SENSITIVE, &bTrue, sizeof(bTrue)},
        {CKA_EXTRACTABLE, &bFalse, sizeof(bFalse)},
        {CKA_DERIVE, &bTrue, sizeof(bTrue)},
        {CKA_VALUE, sk, skLen},
    };

    rv = quac_object_create(token, privTemplate, sizeof(privTemplate) / sizeof(privTemplate[0]), phPrivKey);
    if (rv != CKR_OK)
    {
        quac_object_destroy(token, *phPubKey);
        goto cleanup;
    }

    /* Update with user template */
    quac_object_t *privObj = quac_get_object(token, *phPrivKey);
    for (CK_ULONG i = 0; i < ulPrivCount; i++)
    {
        quac_object_set_attribute(privObj, pPrivTemplate[i].type,
                                  pPrivTemplate[i].pValue, pPrivTemplate[i].ulValueLen);
    }

    /* Store public key reference in private key */
    privObj->publicKey = malloc(pkLen);
    if (privObj->publicKey)
    {
        memcpy(privObj->publicKey, pk, pkLen);
        privObj->publicKeyLen = pkLen;
    }

    rv = CKR_OK;

cleanup:
    if (pk)
    {
        quac_secure_zero(pk, maxPkLen);
        free(pk);
    }
    if (sk)
    {
        quac_secure_zero(sk, maxSkLen);
        free(sk);
    }

    return rv;
}

/* ==========================================================================
 * ML-DSA Key Generation
 * ========================================================================== */

CK_RV quac_generate_keypair_mldsa(quac_token_t *token, CK_KEY_TYPE keyType,
                                  CK_ATTRIBUTE_PTR pPubTemplate, CK_ULONG ulPubCount,
                                  CK_ATTRIBUTE_PTR pPrivTemplate, CK_ULONG ulPrivCount,
                                  CK_OBJECT_HANDLE_PTR phPubKey, CK_OBJECT_HANDLE_PTR phPrivKey)
{
    CK_RV rv;
    CK_BYTE *pk = NULL, *sk = NULL;
    CK_ULONG pkLen, skLen;
    CK_ULONG maxPkLen, maxSkLen;

    /* Determine key sizes */
    switch (keyType)
    {
    case CKK_ML_DSA_44:
        maxPkLen = ML_DSA_44_PUBLIC_KEY_LEN;
        maxSkLen = ML_DSA_44_SECRET_KEY_LEN;
        break;
    case CKK_ML_DSA_65:
        maxPkLen = ML_DSA_65_PUBLIC_KEY_LEN;
        maxSkLen = ML_DSA_65_SECRET_KEY_LEN;
        break;
    case CKK_ML_DSA_87:
        maxPkLen = ML_DSA_87_PUBLIC_KEY_LEN;
        maxSkLen = ML_DSA_87_SECRET_KEY_LEN;
        break;
    default:
        return CKR_KEY_TYPE_INCONSISTENT;
    }

    /* Allocate key buffers */
    pk = malloc(maxPkLen);
    sk = malloc(maxSkLen);

    if (pk == NULL || sk == NULL)
    {
        rv = CKR_HOST_MEMORY;
        goto cleanup;
    }

    /* Generate keys */
#ifdef QUAC_HAS_HARDWARE
    int alg;
    switch (keyType)
    {
    case CKK_ML_DSA_44:
        alg = QUAC_ALG_ML_DSA_44;
        break;
    case CKK_ML_DSA_65:
        alg = QUAC_ALG_ML_DSA_65;
        break;
    case CKK_ML_DSA_87:
        alg = QUAC_ALG_ML_DSA_87;
        break;
    default:
        alg = QUAC_ALG_ML_DSA_65;
    }

    if (quac_sig_keygen(g_module.slots[0].device, alg, pk, &pkLen, sk, &skLen) != 0)
    {
        rv = CKR_DEVICE_ERROR;
        goto cleanup;
    }
#else
    rv = sim_mldsa_keygen(keyType, pk, &pkLen, sk, &skLen);
    if (rv != CKR_OK)
        goto cleanup;
#endif

    /* Create public key object */
    CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
    CK_BBOOL bTrue = CK_TRUE;
    CK_BBOOL bFalse = CK_FALSE;

    CK_ATTRIBUTE pubTemplate[] = {
        {CKA_CLASS, &pubClass, sizeof(pubClass)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_TOKEN, &bFalse, sizeof(bFalse)},
        {CKA_PRIVATE, &bFalse, sizeof(bFalse)},
        {CKA_VERIFY, &bTrue, sizeof(bTrue)},
        {CKA_VALUE, pk, pkLen},
    };

    rv = quac_object_create(token, pubTemplate, sizeof(pubTemplate) / sizeof(pubTemplate[0]), phPubKey);
    if (rv != CKR_OK)
        goto cleanup;

    /* Update with user template */
    quac_object_t *pubObj = quac_get_object(token, *phPubKey);
    for (CK_ULONG i = 0; i < ulPubCount; i++)
    {
        quac_object_set_attribute(pubObj, pPubTemplate[i].type,
                                  pPubTemplate[i].pValue, pPubTemplate[i].ulValueLen);
    }

    /* Create private key object */
    CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;

    CK_ATTRIBUTE privTemplate[] = {
        {CKA_CLASS, &privClass, sizeof(privClass)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_TOKEN, &bFalse, sizeof(bFalse)},
        {CKA_PRIVATE, &bTrue, sizeof(bTrue)},
        {CKA_SENSITIVE, &bTrue, sizeof(bTrue)},
        {CKA_EXTRACTABLE, &bFalse, sizeof(bFalse)},
        {CKA_SIGN, &bTrue, sizeof(bTrue)},
        {CKA_VALUE, sk, skLen},
    };

    rv = quac_object_create(token, privTemplate, sizeof(privTemplate) / sizeof(privTemplate[0]), phPrivKey);
    if (rv != CKR_OK)
    {
        quac_object_destroy(token, *phPubKey);
        goto cleanup;
    }

    /* Update with user template */
    quac_object_t *privObj = quac_get_object(token, *phPrivKey);
    for (CK_ULONG i = 0; i < ulPrivCount; i++)
    {
        quac_object_set_attribute(privObj, pPrivTemplate[i].type,
                                  pPrivTemplate[i].pValue, pPrivTemplate[i].ulValueLen);
    }

    /* Store public key reference in private key */
    privObj->publicKey = malloc(pkLen);
    if (privObj->publicKey)
    {
        memcpy(privObj->publicKey, pk, pkLen);
        privObj->publicKeyLen = pkLen;
    }

    rv = CKR_OK;

cleanup:
    if (pk)
    {
        quac_secure_zero(pk, maxPkLen);
        free(pk);
    }
    if (sk)
    {
        quac_secure_zero(sk, maxSkLen);
        free(sk);
    }

    return rv;
}

/* ==========================================================================
 * Signing Operations
 * ========================================================================== */

CK_RV quac_sign_init(quac_session_t *session, CK_MECHANISM_PTR pMechanism,
                     CK_OBJECT_HANDLE hKey)
{
    quac_slot_t *slot;
    quac_object_t *keyObj;

    if (session->signCtx.active)
        return CKR_OPERATION_ACTIVE;

    slot = quac_get_slot(session->slotID);
    keyObj = quac_get_object(&slot->token, hKey);

    if (keyObj == NULL)
        return CKR_KEY_HANDLE_INVALID;

    if (keyObj->objClass != CKO_PRIVATE_KEY)
        return CKR_KEY_TYPE_INCONSISTENT;

    if (!keyObj->canSign)
        return CKR_KEY_FUNCTION_NOT_PERMITTED;

    /* Verify mechanism matches key type */
    switch (pMechanism->mechanism)
    {
    case CKM_ML_DSA_44:
        if (keyObj->keyType != CKK_ML_DSA_44)
            return CKR_KEY_TYPE_INCONSISTENT;
        break;
    case CKM_ML_DSA_65:
        if (keyObj->keyType != CKK_ML_DSA_65)
            return CKR_KEY_TYPE_INCONSISTENT;
        break;
    case CKM_ML_DSA_87:
        if (keyObj->keyType != CKK_ML_DSA_87)
            return CKR_KEY_TYPE_INCONSISTENT;
        break;
    default:
        return CKR_MECHANISM_INVALID;
    }

    session->signCtx.mechanism = pMechanism->mechanism;
    session->signCtx.keyHandle = hKey;
    session->signCtx.active = CK_TRUE;

    return CKR_OK;
}

CK_RV quac_sign(quac_session_t *session, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
    quac_slot_t *slot;
    quac_object_t *keyObj;
    CK_RV rv;

    if (!session->signCtx.active)
        return CKR_OPERATION_NOT_INITIALIZED;

    slot = quac_get_slot(session->slotID);
    keyObj = quac_get_object(&slot->token, session->signCtx.keyHandle);

    if (keyObj == NULL)
    {
        session->signCtx.active = CK_FALSE;
        return CKR_KEY_HANDLE_INVALID;
    }

#ifdef QUAC_HAS_HARDWARE
    int alg;
    switch (keyObj->keyType)
    {
    case CKK_ML_DSA_44:
        alg = QUAC_ALG_ML_DSA_44;
        break;
    case CKK_ML_DSA_65:
        alg = QUAC_ALG_ML_DSA_65;
        break;
    case CKK_ML_DSA_87:
        alg = QUAC_ALG_ML_DSA_87;
        break;
    default:
        session->signCtx.active = CK_FALSE;
        return CKR_KEY_TYPE_INCONSISTENT;
    }

    size_t sigLen = *pulSignatureLen;
    if (quac_sig_sign(slot->device, alg, keyObj->secretKey, keyObj->secretKeyLen,
                      pData, ulDataLen, pSignature, &sigLen) != 0)
    {
        session->signCtx.active = CK_FALSE;
        return CKR_FUNCTION_FAILED;
    }
    *pulSignatureLen = sigLen;
    rv = CKR_OK;
#else
    rv = sim_mldsa_sign(keyObj->keyType, keyObj->secretKey, keyObj->secretKeyLen,
                        pData, ulDataLen, pSignature, pulSignatureLen);
#endif

    if (pSignature != NULL)
        session->signCtx.active = CK_FALSE;

    return rv;
}

/* ==========================================================================
 * Verification Operations
 * ========================================================================== */

CK_RV quac_verify_init(quac_session_t *session, CK_MECHANISM_PTR pMechanism,
                       CK_OBJECT_HANDLE hKey)
{
    quac_slot_t *slot;
    quac_object_t *keyObj;

    if (session->verifyCtx.active)
        return CKR_OPERATION_ACTIVE;

    slot = quac_get_slot(session->slotID);
    keyObj = quac_get_object(&slot->token, hKey);

    if (keyObj == NULL)
        return CKR_KEY_HANDLE_INVALID;

    if (keyObj->objClass != CKO_PUBLIC_KEY)
        return CKR_KEY_TYPE_INCONSISTENT;

    if (!keyObj->canVerify)
        return CKR_KEY_FUNCTION_NOT_PERMITTED;

    /* Verify mechanism matches key type */
    switch (pMechanism->mechanism)
    {
    case CKM_ML_DSA_44:
        if (keyObj->keyType != CKK_ML_DSA_44)
            return CKR_KEY_TYPE_INCONSISTENT;
        break;
    case CKM_ML_DSA_65:
        if (keyObj->keyType != CKK_ML_DSA_65)
            return CKR_KEY_TYPE_INCONSISTENT;
        break;
    case CKM_ML_DSA_87:
        if (keyObj->keyType != CKK_ML_DSA_87)
            return CKR_KEY_TYPE_INCONSISTENT;
        break;
    default:
        return CKR_MECHANISM_INVALID;
    }

    session->verifyCtx.mechanism = pMechanism->mechanism;
    session->verifyCtx.keyHandle = hKey;
    session->verifyCtx.active = CK_TRUE;

    return CKR_OK;
}

CK_RV quac_verify(quac_session_t *session, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                  CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
    quac_slot_t *slot;
    quac_object_t *keyObj;
    CK_RV rv;

    if (!session->verifyCtx.active)
        return CKR_OPERATION_NOT_INITIALIZED;

    slot = quac_get_slot(session->slotID);
    keyObj = quac_get_object(&slot->token, session->verifyCtx.keyHandle);

    if (keyObj == NULL)
    {
        session->verifyCtx.active = CK_FALSE;
        return CKR_KEY_HANDLE_INVALID;
    }

#ifdef QUAC_HAS_HARDWARE
    int alg;
    switch (keyObj->keyType)
    {
    case CKK_ML_DSA_44:
        alg = QUAC_ALG_ML_DSA_44;
        break;
    case CKK_ML_DSA_65:
        alg = QUAC_ALG_ML_DSA_65;
        break;
    case CKK_ML_DSA_87:
        alg = QUAC_ALG_ML_DSA_87;
        break;
    default:
        session->verifyCtx.active = CK_FALSE;
        return CKR_KEY_TYPE_INCONSISTENT;
    }

    int result = quac_sig_verify(slot->device, alg, keyObj->publicKey, keyObj->publicKeyLen,
                                 pData, ulDataLen, pSignature, ulSignatureLen);
    rv = (result == 0) ? CKR_OK : CKR_SIGNATURE_INVALID;
#else
    rv = sim_mldsa_verify(keyObj->keyType, keyObj->publicKey, keyObj->publicKeyLen,
                          pData, ulDataLen, pSignature, ulSignatureLen);
#endif

    session->verifyCtx.active = CK_FALSE;

    return rv;
}

/* ==========================================================================
 * Random Number Generation
 * ========================================================================== */

CK_RV quac_generate_random(CK_BYTE_PTR pData, CK_ULONG ulLen)
{
    if (pData == NULL)
        return CKR_ARGUMENTS_BAD;

#ifdef QUAC_HAS_HARDWARE
    if (g_module.slots[0].device)
    {
        if (quac_random(g_module.slots[0].device, pData, ulLen) == 0)
            return CKR_OK;
    }
#endif

#ifndef QUAC_HAS_HARDWARE
    return sim_random(pData, ulLen);
#else
    /* Fallback to software if hardware fails */
    return sim_random(pData, ulLen);
#endif
}

/* ==========================================================================
 * ML-KEM Encapsulation/Decapsulation (via DeriveKey)
 * ========================================================================== */

CK_RV quac_encaps(quac_session_t *session, CK_OBJECT_HANDLE hPubKey,
                  CK_BYTE_PTR pCiphertext, CK_ULONG_PTR pulCiphertextLen,
                  CK_BYTE_PTR pSharedSecret, CK_ULONG_PTR pulSharedSecretLen)
{
    quac_slot_t *slot;
    quac_object_t *keyObj;
    CK_RV rv;

    slot = quac_get_slot(session->slotID);
    keyObj = quac_get_object(&slot->token, hPubKey);

    if (keyObj == NULL)
        return CKR_KEY_HANDLE_INVALID;

    if (keyObj->objClass != CKO_PUBLIC_KEY)
        return CKR_KEY_TYPE_INCONSISTENT;

#ifdef QUAC_HAS_HARDWARE
    int alg;
    switch (keyObj->keyType)
    {
    case CKK_ML_KEM_512:
        alg = QUAC_ALG_ML_KEM_512;
        break;
    case CKK_ML_KEM_768:
        alg = QUAC_ALG_ML_KEM_768;
        break;
    case CKK_ML_KEM_1024:
        alg = QUAC_ALG_ML_KEM_1024;
        break;
    default:
        return CKR_KEY_TYPE_INCONSISTENT;
    }

    size_t ctLen = *pulCiphertextLen;
    size_t ssLen = *pulSharedSecretLen;

    if (quac_kem_encaps(slot->device, alg, keyObj->publicKey, keyObj->publicKeyLen,
                        pCiphertext, &ctLen, pSharedSecret, &ssLen) != 0)
        return CKR_FUNCTION_FAILED;

    *pulCiphertextLen = ctLen;
    *pulSharedSecretLen = ssLen;
    rv = CKR_OK;
#else
    rv = sim_mlkem_encaps(keyObj->keyType, keyObj->publicKey, keyObj->publicKeyLen,
                          pCiphertext, pulCiphertextLen, pSharedSecret, pulSharedSecretLen);
#endif

    return rv;
}

CK_RV quac_decaps(quac_session_t *session, CK_OBJECT_HANDLE hPrivKey,
                  CK_BYTE_PTR pCiphertext, CK_ULONG ulCiphertextLen,
                  CK_BYTE_PTR pSharedSecret, CK_ULONG_PTR pulSharedSecretLen)
{
    quac_slot_t *slot;
    quac_object_t *keyObj;
    CK_RV rv;

    slot = quac_get_slot(session->slotID);
    keyObj = quac_get_object(&slot->token, hPrivKey);

    if (keyObj == NULL)
        return CKR_KEY_HANDLE_INVALID;

    if (keyObj->objClass != CKO_PRIVATE_KEY)
        return CKR_KEY_TYPE_INCONSISTENT;

#ifdef QUAC_HAS_HARDWARE
    int alg;
    switch (keyObj->keyType)
    {
    case CKK_ML_KEM_512:
        alg = QUAC_ALG_ML_KEM_512;
        break;
    case CKK_ML_KEM_768:
        alg = QUAC_ALG_ML_KEM_768;
        break;
    case CKK_ML_KEM_1024:
        alg = QUAC_ALG_ML_KEM_1024;
        break;
    default:
        return CKR_KEY_TYPE_INCONSISTENT;
    }

    size_t ssLen = *pulSharedSecretLen;

    if (quac_kem_decaps(slot->device, alg, keyObj->secretKey, keyObj->secretKeyLen,
                        pCiphertext, ulCiphertextLen, pSharedSecret, &ssLen) != 0)
        return CKR_FUNCTION_FAILED;

    *pulSharedSecretLen = ssLen;
    rv = CKR_OK;
#else
    rv = sim_mlkem_decaps(keyObj->keyType, keyObj->secretKey, keyObj->secretKeyLen,
                          pCiphertext, ulCiphertextLen, pSharedSecret, pulSharedSecretLen);
#endif

    return rv;
}