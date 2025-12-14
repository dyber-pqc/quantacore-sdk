/**
 * @file quac100_pkcs11.h
 * @brief QUAC 100 PKCS#11 Module - Public Header
 *
 * PKCS#11 (Cryptoki) interface for the QUAC 100 post-quantum cryptographic
 * accelerator. Implements PKCS#11 v2.40 with extensions for:
 * - ML-KEM (FIPS 203) key encapsulation
 * - ML-DSA (FIPS 204) digital signatures
 * - QRNG hardware random number generation
 *
 * Standard Compliance:
 * - PKCS#11 Cryptographic Token Interface Standard v2.40
 * - OASIS PKCS#11 Cryptographic Token Interface Base Specification v3.0
 * - NIST FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA)
 *
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#ifndef QUAC100_PKCS11_H
#define QUAC100_PKCS11_H

#ifdef __cplusplus
extern "C"
{
#endif

/* ==========================================================================
 * PKCS#11 Platform Configuration
 * ========================================================================== */

/* Specifies that the function is a DLL entry point */
#ifdef _WIN32
#define CK_IMPORT_SPEC __declspec(dllimport)
#define CK_EXPORT_SPEC __declspec(dllexport)
#define CK_CALL_SPEC __cdecl
#else
#define CK_IMPORT_SPEC
#define CK_EXPORT_SPEC __attribute__((visibility("default")))
#define CK_CALL_SPEC
#endif

#ifdef QUAC_PKCS11_EXPORTS
#define CK_SPEC CK_EXPORT_SPEC
#else
#define CK_SPEC CK_IMPORT_SPEC
#endif

/* Packing for structures */
#pragma pack(push, 1)

    /* ==========================================================================
     * PKCS#11 Basic Types
     * ========================================================================== */

    typedef unsigned char CK_BYTE;
    typedef CK_BYTE *CK_BYTE_PTR;
    typedef unsigned char CK_CHAR;
    typedef CK_CHAR *CK_CHAR_PTR;
    typedef unsigned char CK_UTF8CHAR;
    typedef CK_UTF8CHAR *CK_UTF8CHAR_PTR;
    typedef unsigned char CK_BBOOL;
    typedef unsigned long CK_ULONG;
    typedef CK_ULONG *CK_ULONG_PTR;
    typedef long CK_LONG;
    typedef CK_BYTE *CK_VOID_PTR;
    typedef CK_VOID_PTR *CK_VOID_PTR_PTR;

#define CK_FALSE 0
#define CK_TRUE 1

#ifndef NULL_PTR
#define NULL_PTR ((CK_VOID_PTR)0)
#endif

    /* ==========================================================================
     * PKCS#11 Handle Types
     * ========================================================================== */

    typedef CK_ULONG CK_SLOT_ID;
    typedef CK_SLOT_ID *CK_SLOT_ID_PTR;
    typedef CK_ULONG CK_SESSION_HANDLE;
    typedef CK_SESSION_HANDLE *CK_SESSION_HANDLE_PTR;
    typedef CK_ULONG CK_OBJECT_HANDLE;
    typedef CK_OBJECT_HANDLE *CK_OBJECT_HANDLE_PTR;
    typedef CK_ULONG CK_MECHANISM_TYPE;
    typedef CK_MECHANISM_TYPE *CK_MECHANISM_TYPE_PTR;

#define CK_INVALID_HANDLE 0UL

    /* ==========================================================================
     * Return Values (CK_RV)
     * ========================================================================== */

    typedef CK_ULONG CK_RV;

#define CKR_OK 0x00000000UL
#define CKR_CANCEL 0x00000001UL
#define CKR_HOST_MEMORY 0x00000002UL
#define CKR_SLOT_ID_INVALID 0x00000003UL
#define CKR_GENERAL_ERROR 0x00000005UL
#define CKR_FUNCTION_FAILED 0x00000006UL
#define CKR_ARGUMENTS_BAD 0x00000007UL
#define CKR_NO_EVENT 0x00000008UL
#define CKR_NEED_TO_CREATE_THREADS 0x00000009UL
#define CKR_CANT_LOCK 0x0000000AUL
#define CKR_ATTRIBUTE_READ_ONLY 0x00000010UL
#define CKR_ATTRIBUTE_SENSITIVE 0x00000011UL
#define CKR_ATTRIBUTE_TYPE_INVALID 0x00000012UL
#define CKR_ATTRIBUTE_VALUE_INVALID 0x00000013UL
#define CKR_ACTION_PROHIBITED 0x0000001BUL
#define CKR_DATA_INVALID 0x00000020UL
#define CKR_DATA_LEN_RANGE 0x00000021UL
#define CKR_DEVICE_ERROR 0x00000030UL
#define CKR_DEVICE_MEMORY 0x00000031UL
#define CKR_DEVICE_REMOVED 0x00000032UL
#define CKR_ENCRYPTED_DATA_INVALID 0x00000040UL
#define CKR_ENCRYPTED_DATA_LEN_RANGE 0x00000041UL
#define CKR_FUNCTION_CANCELED 0x00000050UL
#define CKR_FUNCTION_NOT_PARALLEL 0x00000051UL
#define CKR_FUNCTION_NOT_SUPPORTED 0x00000054UL
#define CKR_KEY_HANDLE_INVALID 0x00000060UL
#define CKR_KEY_SIZE_RANGE 0x00000062UL
#define CKR_KEY_TYPE_INCONSISTENT 0x00000063UL
#define CKR_KEY_NOT_NEEDED 0x00000064UL
#define CKR_KEY_CHANGED 0x00000065UL
#define CKR_KEY_NEEDED 0x00000066UL
#define CKR_KEY_INDIGESTIBLE 0x00000067UL
#define CKR_KEY_FUNCTION_NOT_PERMITTED 0x00000068UL
#define CKR_KEY_NOT_WRAPPABLE 0x00000069UL
#define CKR_KEY_UNEXTRACTABLE 0x0000006AUL
#define CKR_MECHANISM_INVALID 0x00000070UL
#define CKR_MECHANISM_PARAM_INVALID 0x00000071UL
#define CKR_OBJECT_HANDLE_INVALID 0x00000082UL
#define CKR_OPERATION_ACTIVE 0x00000090UL
#define CKR_OPERATION_NOT_INITIALIZED 0x00000091UL
#define CKR_PIN_INCORRECT 0x000000A0UL
#define CKR_PIN_INVALID 0x000000A1UL
#define CKR_PIN_LEN_RANGE 0x000000A2UL
#define CKR_PIN_EXPIRED 0x000000A3UL
#define CKR_PIN_LOCKED 0x000000A4UL
#define CKR_SESSION_CLOSED 0x000000B0UL
#define CKR_SESSION_COUNT 0x000000B1UL
#define CKR_SESSION_HANDLE_INVALID 0x000000B3UL
#define CKR_SESSION_PARALLEL_NOT_SUPPORTED 0x000000B4UL
#define CKR_SESSION_READ_ONLY 0x000000B5UL
#define CKR_SESSION_EXISTS 0x000000B6UL
#define CKR_SESSION_READ_ONLY_EXISTS 0x000000B7UL
#define CKR_SESSION_READ_WRITE_SO_EXISTS 0x000000B8UL
#define CKR_SIGNATURE_INVALID 0x000000C0UL
#define CKR_SIGNATURE_LEN_RANGE 0x000000C1UL
#define CKR_TEMPLATE_INCOMPLETE 0x000000D0UL
#define CKR_TEMPLATE_INCONSISTENT 0x000000D1UL
#define CKR_TOKEN_NOT_PRESENT 0x000000E0UL
#define CKR_TOKEN_NOT_RECOGNIZED 0x000000E1UL
#define CKR_TOKEN_WRITE_PROTECTED 0x000000E2UL
#define CKR_UNWRAPPING_KEY_HANDLE_INVALID 0x000000F0UL
#define CKR_UNWRAPPING_KEY_SIZE_RANGE 0x000000F1UL
#define CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT 0x000000F2UL
#define CKR_USER_ALREADY_LOGGED_IN 0x00000100UL
#define CKR_USER_NOT_LOGGED_IN 0x00000101UL
#define CKR_USER_PIN_NOT_INITIALIZED 0x00000102UL
#define CKR_USER_TYPE_INVALID 0x00000103UL
#define CKR_USER_ANOTHER_ALREADY_LOGGED_IN 0x00000104UL
#define CKR_USER_TOO_MANY_TYPES 0x00000105UL
#define CKR_WRAPPED_KEY_INVALID 0x00000110UL
#define CKR_WRAPPED_KEY_LEN_RANGE 0x00000112UL
#define CKR_WRAPPING_KEY_HANDLE_INVALID 0x00000113UL
#define CKR_WRAPPING_KEY_SIZE_RANGE 0x00000114UL
#define CKR_WRAPPING_KEY_TYPE_INCONSISTENT 0x00000115UL
#define CKR_RANDOM_SEED_NOT_SUPPORTED 0x00000120UL
#define CKR_RANDOM_NO_RNG 0x00000121UL
#define CKR_DOMAIN_PARAMS_INVALID 0x00000130UL
#define CKR_CURVE_NOT_SUPPORTED 0x00000140UL
#define CKR_BUFFER_TOO_SMALL 0x00000150UL
#define CKR_SAVED_STATE_INVALID 0x00000160UL
#define CKR_INFORMATION_SENSITIVE 0x00000170UL
#define CKR_STATE_UNSAVEABLE 0x00000180UL
#define CKR_CRYPTOKI_NOT_INITIALIZED 0x00000190UL
#define CKR_CRYPTOKI_ALREADY_INITIALIZED 0x00000191UL
#define CKR_MUTEX_BAD 0x000001A0UL
#define CKR_MUTEX_NOT_LOCKED 0x000001A1UL
#define CKR_FUNCTION_REJECTED 0x00000200UL
#define CKR_VENDOR_DEFINED 0x80000000UL

    /* ==========================================================================
     * Attribute Types
     * ========================================================================== */

    typedef CK_ULONG CK_ATTRIBUTE_TYPE;

#define CKA_CLASS 0x00000000UL
#define CKA_TOKEN 0x00000001UL
#define CKA_PRIVATE 0x00000002UL
#define CKA_LABEL 0x00000003UL
#define CKA_APPLICATION 0x00000010UL
#define CKA_VALUE 0x00000011UL
#define CKA_OBJECT_ID 0x00000012UL
#define CKA_CERTIFICATE_TYPE 0x00000080UL
#define CKA_ISSUER 0x00000081UL
#define CKA_SERIAL_NUMBER 0x00000082UL
#define CKA_AC_ISSUER 0x00000083UL
#define CKA_OWNER 0x00000084UL
#define CKA_ATTR_TYPES 0x00000085UL
#define CKA_TRUSTED 0x00000086UL
#define CKA_CERTIFICATE_CATEGORY 0x00000087UL
#define CKA_JAVA_MIDP_SECURITY_DOMAIN 0x00000088UL
#define CKA_URL 0x00000089UL
#define CKA_HASH_OF_SUBJECT_PUBLIC_KEY 0x0000008AUL
#define CKA_HASH_OF_ISSUER_PUBLIC_KEY 0x0000008BUL
#define CKA_CHECK_VALUE 0x00000090UL
#define CKA_KEY_TYPE 0x00000100UL
#define CKA_SUBJECT 0x00000101UL
#define CKA_ID 0x00000102UL
#define CKA_SENSITIVE 0x00000103UL
#define CKA_ENCRYPT 0x00000104UL
#define CKA_DECRYPT 0x00000105UL
#define CKA_WRAP 0x00000106UL
#define CKA_UNWRAP 0x00000107UL
#define CKA_SIGN 0x00000108UL
#define CKA_SIGN_RECOVER 0x00000109UL
#define CKA_VERIFY 0x0000010AUL
#define CKA_VERIFY_RECOVER 0x0000010BUL
#define CKA_DERIVE 0x0000010CUL
#define CKA_START_DATE 0x00000110UL
#define CKA_END_DATE 0x00000111UL
#define CKA_MODULUS 0x00000120UL
#define CKA_MODULUS_BITS 0x00000121UL
#define CKA_PUBLIC_EXPONENT 0x00000122UL
#define CKA_PRIVATE_EXPONENT 0x00000123UL
#define CKA_PRIME_1 0x00000124UL
#define CKA_PRIME_2 0x00000125UL
#define CKA_EXPONENT_1 0x00000126UL
#define CKA_EXPONENT_2 0x00000127UL
#define CKA_COEFFICIENT 0x00000128UL
#define CKA_PUBLIC_KEY_INFO 0x00000129UL
#define CKA_PRIME 0x00000130UL
#define CKA_SUBPRIME 0x00000131UL
#define CKA_BASE 0x00000132UL
#define CKA_PRIME_BITS 0x00000133UL
#define CKA_SUBPRIME_BITS 0x00000134UL
#define CKA_VALUE_BITS 0x00000160UL
#define CKA_VALUE_LEN 0x00000161UL
#define CKA_EXTRACTABLE 0x00000162UL
#define CKA_LOCAL 0x00000163UL
#define CKA_NEVER_EXTRACTABLE 0x00000164UL
#define CKA_ALWAYS_SENSITIVE 0x00000165UL
#define CKA_KEY_GEN_MECHANISM 0x00000166UL
#define CKA_MODIFIABLE 0x00000170UL
#define CKA_COPYABLE 0x00000171UL
#define CKA_DESTROYABLE 0x00000172UL
#define CKA_EC_PARAMS 0x00000180UL
#define CKA_EC_POINT 0x00000181UL
#define CKA_ALWAYS_AUTHENTICATE 0x00000202UL
#define CKA_WRAP_WITH_TRUSTED 0x00000210UL
#define CKA_WRAP_TEMPLATE 0x00000211UL
#define CKA_UNWRAP_TEMPLATE 0x00000212UL
#define CKA_DERIVE_TEMPLATE 0x00000213UL
#define CKA_ALLOWED_MECHANISMS 0x00000600UL

#define CKA_VENDOR_DEFINED 0x80000000UL

/* QUAC PQC-specific attributes */
#define CKA_QUAC_ML_KEM_PARAMS (CKA_VENDOR_DEFINED | 0x00000001UL)
#define CKA_QUAC_ML_DSA_PARAMS (CKA_VENDOR_DEFINED | 0x00000002UL)
#define CKA_QUAC_PUBLIC_KEY (CKA_VENDOR_DEFINED | 0x00000003UL)
#define CKA_QUAC_SECRET_KEY (CKA_VENDOR_DEFINED | 0x00000004UL)

    /* ==========================================================================
     * Object Classes
     * ========================================================================== */

    typedef CK_ULONG CK_OBJECT_CLASS;

#define CKO_DATA 0x00000000UL
#define CKO_CERTIFICATE 0x00000001UL
#define CKO_PUBLIC_KEY 0x00000002UL
#define CKO_PRIVATE_KEY 0x00000003UL
#define CKO_SECRET_KEY 0x00000004UL
#define CKO_HW_FEATURE 0x00000005UL
#define CKO_DOMAIN_PARAMETERS 0x00000006UL
#define CKO_MECHANISM 0x00000007UL
#define CKO_VENDOR_DEFINED 0x80000000UL

    /* ==========================================================================
     * Key Types
     * ========================================================================== */

    typedef CK_ULONG CK_KEY_TYPE;

#define CKK_RSA 0x00000000UL
#define CKK_DSA 0x00000001UL
#define CKK_DH 0x00000002UL
#define CKK_EC 0x00000003UL
#define CKK_X9_42_DH 0x00000004UL
#define CKK_KEA 0x00000005UL
#define CKK_GENERIC_SECRET 0x00000010UL
#define CKK_RC2 0x00000011UL
#define CKK_RC4 0x00000012UL
#define CKK_DES 0x00000013UL
#define CKK_DES2 0x00000014UL
#define CKK_DES3 0x00000015UL
#define CKK_CAST 0x00000016UL
#define CKK_CAST3 0x00000017UL
#define CKK_CAST128 0x00000018UL
#define CKK_RC5 0x00000019UL
#define CKK_IDEA 0x0000001AUL
#define CKK_SKIPJACK 0x0000001BUL
#define CKK_BATON 0x0000001CUL
#define CKK_JUNIPER 0x0000001DUL
#define CKK_CDMF 0x0000001EUL
#define CKK_AES 0x0000001FUL
#define CKK_BLOWFISH 0x00000020UL
#define CKK_TWOFISH 0x00000021UL
#define CKK_SECURID 0x00000022UL
#define CKK_HOTP 0x00000023UL
#define CKK_ACTI 0x00000024UL
#define CKK_CAMELLIA 0x00000025UL
#define CKK_ARIA 0x00000026UL
#define CKK_SHA512_224_HMAC 0x00000027UL
#define CKK_SHA512_256_HMAC 0x00000028UL
#define CKK_SHA512_T_HMAC 0x00000029UL
#define CKK_VENDOR_DEFINED 0x80000000UL

/* QUAC PQC Key Types */
#define CKK_ML_KEM_512 (CKK_VENDOR_DEFINED | 0x00000001UL)
#define CKK_ML_KEM_768 (CKK_VENDOR_DEFINED | 0x00000002UL)
#define CKK_ML_KEM_1024 (CKK_VENDOR_DEFINED | 0x00000003UL)
#define CKK_ML_DSA_44 (CKK_VENDOR_DEFINED | 0x00000004UL)
#define CKK_ML_DSA_65 (CKK_VENDOR_DEFINED | 0x00000005UL)
#define CKK_ML_DSA_87 (CKK_VENDOR_DEFINED | 0x00000006UL)

    /* ==========================================================================
     * Mechanism Types
     * ========================================================================== */

#define CKM_RSA_PKCS_KEY_PAIR_GEN 0x00000000UL
#define CKM_RSA_PKCS 0x00000001UL
#define CKM_RSA_9796 0x00000002UL
#define CKM_RSA_X_509 0x00000003UL
#define CKM_SHA1_RSA_PKCS 0x00000006UL
#define CKM_SHA256_RSA_PKCS 0x00000040UL
#define CKM_SHA384_RSA_PKCS 0x00000041UL
#define CKM_SHA512_RSA_PKCS 0x00000042UL
#define CKM_DSA_KEY_PAIR_GEN 0x00000010UL
#define CKM_DSA 0x00000011UL
#define CKM_DSA_SHA1 0x00000012UL
#define CKM_DSA_SHA224 0x00000013UL
#define CKM_DSA_SHA256 0x00000014UL
#define CKM_DH_PKCS_KEY_PAIR_GEN 0x00000020UL
#define CKM_DH_PKCS_DERIVE 0x00000021UL
#define CKM_EC_KEY_PAIR_GEN 0x00001040UL
#define CKM_ECDSA 0x00001041UL
#define CKM_ECDSA_SHA1 0x00001042UL
#define CKM_ECDSA_SHA224 0x00001043UL
#define CKM_ECDSA_SHA256 0x00001044UL
#define CKM_ECDSA_SHA384 0x00001045UL
#define CKM_ECDSA_SHA512 0x00001046UL
#define CKM_ECDH1_DERIVE 0x00001050UL
#define CKM_ECDH1_COFACTOR_DERIVE 0x00001051UL
#define CKM_AES_KEY_GEN 0x00001080UL
#define CKM_AES_ECB 0x00001081UL
#define CKM_AES_CBC 0x00001082UL
#define CKM_AES_MAC 0x00001083UL
#define CKM_AES_MAC_GENERAL 0x00001084UL
#define CKM_AES_CBC_PAD 0x00001085UL
#define CKM_AES_CTR 0x00001086UL
#define CKM_AES_GCM 0x00001087UL
#define CKM_AES_CCM 0x00001088UL
#define CKM_AES_KEY_WRAP 0x00002109UL
#define CKM_AES_KEY_WRAP_PAD 0x0000210AUL
#define CKM_SHA_1 0x00000220UL
#define CKM_SHA_1_HMAC 0x00000221UL
#define CKM_SHA256 0x00000250UL
#define CKM_SHA256_HMAC 0x00000251UL
#define CKM_SHA384 0x00000260UL
#define CKM_SHA384_HMAC 0x00000261UL
#define CKM_SHA512 0x00000270UL
#define CKM_SHA512_HMAC 0x00000271UL
#define CKM_SHA3_256 0x000002B0UL
#define CKM_SHA3_384 0x000002C0UL
#define CKM_SHA3_512 0x000002D0UL
#define CKM_VENDOR_DEFINED 0x80000000UL

/* QUAC PQC Mechanism Types */
#define CKM_ML_KEM_512_KEY_PAIR_GEN (CKM_VENDOR_DEFINED | 0x00000001UL)
#define CKM_ML_KEM_768_KEY_PAIR_GEN (CKM_VENDOR_DEFINED | 0x00000002UL)
#define CKM_ML_KEM_1024_KEY_PAIR_GEN (CKM_VENDOR_DEFINED | 0x00000003UL)
#define CKM_ML_KEM_512_ENCAPS (CKM_VENDOR_DEFINED | 0x00000004UL)
#define CKM_ML_KEM_768_ENCAPS (CKM_VENDOR_DEFINED | 0x00000005UL)
#define CKM_ML_KEM_1024_ENCAPS (CKM_VENDOR_DEFINED | 0x00000006UL)
#define CKM_ML_KEM_512_DECAPS (CKM_VENDOR_DEFINED | 0x00000007UL)
#define CKM_ML_KEM_768_DECAPS (CKM_VENDOR_DEFINED | 0x00000008UL)
#define CKM_ML_KEM_1024_DECAPS (CKM_VENDOR_DEFINED | 0x00000009UL)
#define CKM_ML_DSA_44_KEY_PAIR_GEN (CKM_VENDOR_DEFINED | 0x0000000AUL)
#define CKM_ML_DSA_65_KEY_PAIR_GEN (CKM_VENDOR_DEFINED | 0x0000000BUL)
#define CKM_ML_DSA_87_KEY_PAIR_GEN (CKM_VENDOR_DEFINED | 0x0000000CUL)
#define CKM_ML_DSA_44 (CKM_VENDOR_DEFINED | 0x0000000DUL)
#define CKM_ML_DSA_65 (CKM_VENDOR_DEFINED | 0x0000000EUL)
#define CKM_ML_DSA_87 (CKM_VENDOR_DEFINED | 0x0000000FUL)
#define CKM_QUAC_QRNG (CKM_VENDOR_DEFINED | 0x00000010UL)

    /* ==========================================================================
     * Structures
     * ========================================================================== */

    typedef struct CK_VERSION
    {
        CK_BYTE major;
        CK_BYTE minor;
    } CK_VERSION;

    typedef CK_VERSION *CK_VERSION_PTR;

    typedef struct CK_INFO
    {
        CK_VERSION cryptokiVersion;
        CK_UTF8CHAR manufacturerID[32];
        CK_ULONG flags;
        CK_UTF8CHAR libraryDescription[32];
        CK_VERSION libraryVersion;
    } CK_INFO;

    typedef CK_INFO *CK_INFO_PTR;

    typedef struct CK_SLOT_INFO
    {
        CK_UTF8CHAR slotDescription[64];
        CK_UTF8CHAR manufacturerID[32];
        CK_ULONG flags;
        CK_VERSION hardwareVersion;
        CK_VERSION firmwareVersion;
    } CK_SLOT_INFO;

    typedef CK_SLOT_INFO *CK_SLOT_INFO_PTR;

#define CKF_TOKEN_PRESENT 0x00000001UL
#define CKF_REMOVABLE_DEVICE 0x00000002UL
#define CKF_HW_SLOT 0x00000004UL

    typedef struct CK_TOKEN_INFO
    {
        CK_UTF8CHAR label[32];
        CK_UTF8CHAR manufacturerID[32];
        CK_UTF8CHAR model[16];
        CK_CHAR serialNumber[16];
        CK_ULONG flags;
        CK_ULONG ulMaxSessionCount;
        CK_ULONG ulSessionCount;
        CK_ULONG ulMaxRwSessionCount;
        CK_ULONG ulRwSessionCount;
        CK_ULONG ulMaxPinLen;
        CK_ULONG ulMinPinLen;
        CK_ULONG ulTotalPublicMemory;
        CK_ULONG ulFreePublicMemory;
        CK_ULONG ulTotalPrivateMemory;
        CK_ULONG ulFreePrivateMemory;
        CK_VERSION hardwareVersion;
        CK_VERSION firmwareVersion;
        CK_CHAR utcTime[16];
    } CK_TOKEN_INFO;

    typedef CK_TOKEN_INFO *CK_TOKEN_INFO_PTR;

#define CKF_RNG 0x00000001UL
#define CKF_WRITE_PROTECTED 0x00000002UL
#define CKF_LOGIN_REQUIRED 0x00000004UL
#define CKF_USER_PIN_INITIALIZED 0x00000008UL
#define CKF_RESTORE_KEY_NOT_NEEDED 0x00000020UL
#define CKF_CLOCK_ON_TOKEN 0x00000040UL
#define CKF_PROTECTED_AUTHENTICATION_PATH 0x00000100UL
#define CKF_DUAL_CRYPTO_OPERATIONS 0x00000200UL
#define CKF_TOKEN_INITIALIZED 0x00000400UL
#define CKF_SECONDARY_AUTHENTICATION 0x00000800UL
#define CKF_USER_PIN_COUNT_LOW 0x00010000UL
#define CKF_USER_PIN_FINAL_TRY 0x00020000UL
#define CKF_USER_PIN_LOCKED 0x00040000UL
#define CKF_USER_PIN_TO_BE_CHANGED 0x00080000UL
#define CKF_SO_PIN_COUNT_LOW 0x00100000UL
#define CKF_SO_PIN_FINAL_TRY 0x00200000UL
#define CKF_SO_PIN_LOCKED 0x00400000UL
#define CKF_SO_PIN_TO_BE_CHANGED 0x00800000UL
#define CKF_ERROR_STATE 0x01000000UL

    typedef struct CK_SESSION_INFO
    {
        CK_SLOT_ID slotID;
        CK_ULONG state;
        CK_ULONG flags;
        CK_ULONG ulDeviceError;
    } CK_SESSION_INFO;

    typedef CK_SESSION_INFO *CK_SESSION_INFO_PTR;

#define CKS_RO_PUBLIC_SESSION 0UL
#define CKS_RO_USER_FUNCTIONS 1UL
#define CKS_RW_PUBLIC_SESSION 2UL
#define CKS_RW_USER_FUNCTIONS 3UL
#define CKS_RW_SO_FUNCTIONS 4UL

#define CKF_RW_SESSION 0x00000002UL
#define CKF_SERIAL_SESSION 0x00000004UL

    typedef CK_ULONG CK_USER_TYPE;

#define CKU_SO 0UL
#define CKU_USER 1UL
#define CKU_CONTEXT_SPECIFIC 2UL

    typedef struct CK_ATTRIBUTE
    {
        CK_ATTRIBUTE_TYPE type;
        CK_VOID_PTR pValue;
        CK_ULONG ulValueLen;
    } CK_ATTRIBUTE;

    typedef CK_ATTRIBUTE *CK_ATTRIBUTE_PTR;

    typedef struct CK_MECHANISM
    {
        CK_MECHANISM_TYPE mechanism;
        CK_VOID_PTR pParameter;
        CK_ULONG ulParameterLen;
    } CK_MECHANISM;

    typedef CK_MECHANISM *CK_MECHANISM_PTR;

    typedef struct CK_MECHANISM_INFO
    {
        CK_ULONG ulMinKeySize;
        CK_ULONG ulMaxKeySize;
        CK_ULONG flags;
    } CK_MECHANISM_INFO;

    typedef CK_MECHANISM_INFO *CK_MECHANISM_INFO_PTR;

#define CKF_HW 0x00000001UL
#define CKF_ENCRYPT 0x00000100UL
#define CKF_DECRYPT 0x00000200UL
#define CKF_DIGEST 0x00000400UL
#define CKF_SIGN 0x00000800UL
#define CKF_SIGN_RECOVER 0x00001000UL
#define CKF_VERIFY 0x00002000UL
#define CKF_VERIFY_RECOVER 0x00004000UL
#define CKF_GENERATE 0x00008000UL
#define CKF_GENERATE_KEY_PAIR 0x00010000UL
#define CKF_WRAP 0x00020000UL
#define CKF_UNWRAP 0x00040000UL
#define CKF_DERIVE 0x00080000UL

    /* Callback types */
    typedef CK_RV (*CK_NOTIFY)(CK_SESSION_HANDLE hSession, CK_ULONG event, CK_VOID_PTR pApplication);
    typedef CK_RV (*CK_CREATEMUTEX)(CK_VOID_PTR_PTR ppMutex);
    typedef CK_RV (*CK_DESTROYMUTEX)(CK_VOID_PTR pMutex);
    typedef CK_RV (*CK_LOCKMUTEX)(CK_VOID_PTR pMutex);
    typedef CK_RV (*CK_UNLOCKMUTEX)(CK_VOID_PTR pMutex);

    typedef struct CK_C_INITIALIZE_ARGS
    {
        CK_CREATEMUTEX CreateMutex;
        CK_DESTROYMUTEX DestroyMutex;
        CK_LOCKMUTEX LockMutex;
        CK_UNLOCKMUTEX UnlockMutex;
        CK_ULONG flags;
        CK_VOID_PTR pReserved;
    } CK_C_INITIALIZE_ARGS;

    typedef CK_C_INITIALIZE_ARGS *CK_C_INITIALIZE_ARGS_PTR;

#define CKF_LIBRARY_CANT_CREATE_OS_THREADS 0x00000001UL
#define CKF_OS_LOCKING_OK 0x00000002UL

#pragma pack(pop)

    /* ==========================================================================
     * PKCS#11 Function Declarations
     * ========================================================================== */

    /* General-purpose functions */
    CK_SPEC CK_RV CK_CALL_SPEC C_Initialize(CK_VOID_PTR pInitArgs);
    CK_SPEC CK_RV CK_CALL_SPEC C_Finalize(CK_VOID_PTR pReserved);
    CK_SPEC CK_RV CK_CALL_SPEC C_GetInfo(CK_INFO_PTR pInfo);
    CK_SPEC CK_RV CK_CALL_SPEC C_GetFunctionList(CK_VOID_PTR_PTR ppFunctionList);

    /* Slot and token management functions */
    CK_SPEC CK_RV CK_CALL_SPEC C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount);
    CK_SPEC CK_RV CK_CALL_SPEC C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo);
    CK_SPEC CK_RV CK_CALL_SPEC C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo);
    CK_SPEC CK_RV CK_CALL_SPEC C_WaitForSlotEvent(CK_ULONG flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved);
    CK_SPEC CK_RV CK_CALL_SPEC C_GetMechanismList(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount);
    CK_SPEC CK_RV CK_CALL_SPEC C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo);
    CK_SPEC CK_RV CK_CALL_SPEC C_InitToken(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel);
    CK_SPEC CK_RV CK_CALL_SPEC C_InitPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen);
    CK_SPEC CK_RV CK_CALL_SPEC C_SetPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen);

    /* Session management functions */
    CK_SPEC CK_RV CK_CALL_SPEC C_OpenSession(CK_SLOT_ID slotID, CK_ULONG flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession);
    CK_SPEC CK_RV CK_CALL_SPEC C_CloseSession(CK_SESSION_HANDLE hSession);
    CK_SPEC CK_RV CK_CALL_SPEC C_CloseAllSessions(CK_SLOT_ID slotID);
    CK_SPEC CK_RV CK_CALL_SPEC C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo);
    CK_SPEC CK_RV CK_CALL_SPEC C_GetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen);
    CK_SPEC CK_RV CK_CALL_SPEC C_SetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey);
    CK_SPEC CK_RV CK_CALL_SPEC C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen);
    CK_SPEC CK_RV CK_CALL_SPEC C_Logout(CK_SESSION_HANDLE hSession);

    /* Object management functions */
    CK_SPEC CK_RV CK_CALL_SPEC C_CreateObject(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject);
    CK_SPEC CK_RV CK_CALL_SPEC C_CopyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject);
    CK_SPEC CK_RV CK_CALL_SPEC C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject);
    CK_SPEC CK_RV CK_CALL_SPEC C_GetObjectSize(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize);
    CK_SPEC CK_RV CK_CALL_SPEC C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
    CK_SPEC CK_RV CK_CALL_SPEC C_SetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
    CK_SPEC CK_RV CK_CALL_SPEC C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
    CK_SPEC CK_RV CK_CALL_SPEC C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount);
    CK_SPEC CK_RV CK_CALL_SPEC C_FindObjectsFinal(CK_SESSION_HANDLE hSession);

    /* Encryption functions */
    CK_SPEC CK_RV CK_CALL_SPEC C_EncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
    CK_SPEC CK_RV CK_CALL_SPEC C_Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen);
    CK_SPEC CK_RV CK_CALL_SPEC C_EncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen);
    CK_SPEC CK_RV CK_CALL_SPEC C_EncryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPartLen);

    /* Decryption functions */
    CK_SPEC CK_RV CK_CALL_SPEC C_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
    CK_SPEC CK_RV CK_CALL_SPEC C_Decrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen);
    CK_SPEC CK_RV CK_CALL_SPEC C_DecryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen);
    CK_SPEC CK_RV CK_CALL_SPEC C_DecryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen);

    /* Message digesting functions */
    CK_SPEC CK_RV CK_CALL_SPEC C_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism);
    CK_SPEC CK_RV CK_CALL_SPEC C_Digest(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen);
    CK_SPEC CK_RV CK_CALL_SPEC C_DigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen);
    CK_SPEC CK_RV CK_CALL_SPEC C_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey);
    CK_SPEC CK_RV CK_CALL_SPEC C_DigestFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen);

    /* Signing and MACing functions */
    CK_SPEC CK_RV CK_CALL_SPEC C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
    CK_SPEC CK_RV CK_CALL_SPEC C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
    CK_SPEC CK_RV CK_CALL_SPEC C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen);
    CK_SPEC CK_RV CK_CALL_SPEC C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
    CK_SPEC CK_RV CK_CALL_SPEC C_SignRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
    CK_SPEC CK_RV CK_CALL_SPEC C_SignRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);

    /* Verification functions */
    CK_SPEC CK_RV CK_CALL_SPEC C_VerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
    CK_SPEC CK_RV CK_CALL_SPEC C_Verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen);
    CK_SPEC CK_RV CK_CALL_SPEC C_VerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen);
    CK_SPEC CK_RV CK_CALL_SPEC C_VerifyFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen);
    CK_SPEC CK_RV CK_CALL_SPEC C_VerifyRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
    CK_SPEC CK_RV CK_CALL_SPEC C_VerifyRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen);

    /* Dual-function cryptographic functions */
    CK_SPEC CK_RV CK_CALL_SPEC C_DigestEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen);
    CK_SPEC CK_RV CK_CALL_SPEC C_DecryptDigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen);
    CK_SPEC CK_RV CK_CALL_SPEC C_SignEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen);
    CK_SPEC CK_RV CK_CALL_SPEC C_DecryptVerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen);

    /* Key management functions */
    CK_SPEC CK_RV CK_CALL_SPEC C_GenerateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey);
    CK_SPEC CK_RV CK_CALL_SPEC C_GenerateKeyPair(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey);
    CK_SPEC CK_RV CK_CALL_SPEC C_WrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen);
    CK_SPEC CK_RV CK_CALL_SPEC C_UnwrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey);
    CK_SPEC CK_RV CK_CALL_SPEC C_DeriveKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey);

    /* Random number generation functions */
    CK_SPEC CK_RV CK_CALL_SPEC C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen);
    CK_SPEC CK_RV CK_CALL_SPEC C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData, CK_ULONG ulRandomLen);

    /* Parallel function management */
    CK_SPEC CK_RV CK_CALL_SPEC C_GetFunctionStatus(CK_SESSION_HANDLE hSession);
    CK_SPEC CK_RV CK_CALL_SPEC C_CancelFunction(CK_SESSION_HANDLE hSession);

    /* ==========================================================================
     * Function List Structure
     * ========================================================================== */

    typedef struct CK_FUNCTION_LIST CK_FUNCTION_LIST;
    typedef CK_FUNCTION_LIST *CK_FUNCTION_LIST_PTR;
    typedef CK_FUNCTION_LIST_PTR *CK_FUNCTION_LIST_PTR_PTR;

    struct CK_FUNCTION_LIST
    {
        CK_VERSION version;
        CK_RV(CK_CALL_SPEC *C_Initialize)(CK_VOID_PTR pInitArgs);
        CK_RV(CK_CALL_SPEC *C_Finalize)(CK_VOID_PTR pReserved);
        CK_RV(CK_CALL_SPEC *C_GetInfo)(CK_INFO_PTR pInfo);
        CK_RV(CK_CALL_SPEC *C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR ppFunctionList);
        CK_RV(CK_CALL_SPEC *C_GetSlotList)(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount);
        CK_RV(CK_CALL_SPEC *C_GetSlotInfo)(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo);
        CK_RV(CK_CALL_SPEC *C_GetTokenInfo)(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo);
        CK_RV(CK_CALL_SPEC *C_GetMechanismList)(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount);
        CK_RV(CK_CALL_SPEC *C_GetMechanismInfo)(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo);
        CK_RV(CK_CALL_SPEC *C_InitToken)(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel);
        CK_RV(CK_CALL_SPEC *C_InitPIN)(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen);
        CK_RV(CK_CALL_SPEC *C_SetPIN)(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen);
        CK_RV(CK_CALL_SPEC *C_OpenSession)(CK_SLOT_ID slotID, CK_ULONG flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession);
        CK_RV(CK_CALL_SPEC *C_CloseSession)(CK_SESSION_HANDLE hSession);
        CK_RV(CK_CALL_SPEC *C_CloseAllSessions)(CK_SLOT_ID slotID);
        CK_RV(CK_CALL_SPEC *C_GetSessionInfo)(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo);
        CK_RV(CK_CALL_SPEC *C_GetOperationState)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen);
        CK_RV(CK_CALL_SPEC *C_SetOperationState)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey);
        CK_RV(CK_CALL_SPEC *C_Login)(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen);
        CK_RV(CK_CALL_SPEC *C_Logout)(CK_SESSION_HANDLE hSession);
        CK_RV(CK_CALL_SPEC *C_CreateObject)(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject);
        CK_RV(CK_CALL_SPEC *C_CopyObject)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject);
        CK_RV(CK_CALL_SPEC *C_DestroyObject)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject);
        CK_RV(CK_CALL_SPEC *C_GetObjectSize)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize);
        CK_RV(CK_CALL_SPEC *C_GetAttributeValue)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
        CK_RV(CK_CALL_SPEC *C_SetAttributeValue)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
        CK_RV(CK_CALL_SPEC *C_FindObjectsInit)(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
        CK_RV(CK_CALL_SPEC *C_FindObjects)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount);
        CK_RV(CK_CALL_SPEC *C_FindObjectsFinal)(CK_SESSION_HANDLE hSession);
        CK_RV(CK_CALL_SPEC *C_EncryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
        CK_RV(CK_CALL_SPEC *C_Encrypt)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen);
        CK_RV(CK_CALL_SPEC *C_EncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen);
        CK_RV(CK_CALL_SPEC *C_EncryptFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPartLen);
        CK_RV(CK_CALL_SPEC *C_DecryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
        CK_RV(CK_CALL_SPEC *C_Decrypt)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen);
        CK_RV(CK_CALL_SPEC *C_DecryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen);
        CK_RV(CK_CALL_SPEC *C_DecryptFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen);
        CK_RV(CK_CALL_SPEC *C_DigestInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism);
        CK_RV(CK_CALL_SPEC *C_Digest)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen);
        CK_RV(CK_CALL_SPEC *C_DigestUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen);
        CK_RV(CK_CALL_SPEC *C_DigestKey)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey);
        CK_RV(CK_CALL_SPEC *C_DigestFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen);
        CK_RV(CK_CALL_SPEC *C_SignInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
        CK_RV(CK_CALL_SPEC *C_Sign)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
        CK_RV(CK_CALL_SPEC *C_SignUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen);
        CK_RV(CK_CALL_SPEC *C_SignFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
        CK_RV(CK_CALL_SPEC *C_SignRecoverInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
        CK_RV(CK_CALL_SPEC *C_SignRecover)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
        CK_RV(CK_CALL_SPEC *C_VerifyInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
        CK_RV(CK_CALL_SPEC *C_Verify)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen);
        CK_RV(CK_CALL_SPEC *C_VerifyUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen);
        CK_RV(CK_CALL_SPEC *C_VerifyFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen);
        CK_RV(CK_CALL_SPEC *C_VerifyRecoverInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
        CK_RV(CK_CALL_SPEC *C_VerifyRecover)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen);
        CK_RV(CK_CALL_SPEC *C_DigestEncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen);
        CK_RV(CK_CALL_SPEC *C_DecryptDigestUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen);
        CK_RV(CK_CALL_SPEC *C_SignEncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen);
        CK_RV(CK_CALL_SPEC *C_DecryptVerifyUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen);
        CK_RV(CK_CALL_SPEC *C_GenerateKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey);
        CK_RV(CK_CALL_SPEC *C_GenerateKeyPair)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey);
        CK_RV(CK_CALL_SPEC *C_WrapKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen);
        CK_RV(CK_CALL_SPEC *C_UnwrapKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey);
        CK_RV(CK_CALL_SPEC *C_DeriveKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey);
        CK_RV(CK_CALL_SPEC *C_SeedRandom)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen);
        CK_RV(CK_CALL_SPEC *C_GenerateRandom)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData, CK_ULONG ulRandomLen);
        CK_RV(CK_CALL_SPEC *C_GetFunctionStatus)(CK_SESSION_HANDLE hSession);
        CK_RV(CK_CALL_SPEC *C_CancelFunction)(CK_SESSION_HANDLE hSession);
        CK_RV(CK_CALL_SPEC *C_WaitForSlotEvent)(CK_ULONG flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved);
    };

#ifdef __cplusplus
}
#endif

#endif /* QUAC100_PKCS11_H */