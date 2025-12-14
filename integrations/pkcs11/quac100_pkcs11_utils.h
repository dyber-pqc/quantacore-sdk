/**
 * @file D:\quantacore-sdk\integrations\pkcs11\quac100_pkcs11_utils.h
 * @brief QUAC 100 PKCS#11 Utility Functions
 *
 * Helper functions for PKCS#11 operations, error handling, and debugging.
 *
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#ifndef QUAC100_PKCS11_UTILS_H
#define QUAC100_PKCS11_UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

/* PKCS#11 definitions */
#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType(*name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType(*name)
#ifndef NULL_PTR
#define NULL_PTR NULL
#endif

#include "pkcs11.h"

#ifdef __cplusplus
extern "C"
{
#endif

/* ==========================================================================
 * QUAC 100 Vendor Extensions
 * ========================================================================== */

/* Key Types */
#define CKK_QUAC_ML_KEM_512 0x80000001UL
#define CKK_QUAC_ML_KEM_768 0x80000002UL
#define CKK_QUAC_ML_KEM_1024 0x80000003UL
#define CKK_QUAC_ML_DSA_44 0x80000011UL
#define CKK_QUAC_ML_DSA_65 0x80000012UL
#define CKK_QUAC_ML_DSA_87 0x80000013UL
#define CKK_QUAC_SLH_DSA_128S 0x80000021UL
#define CKK_QUAC_SLH_DSA_128F 0x80000022UL
#define CKK_QUAC_SLH_DSA_192S 0x80000023UL
#define CKK_QUAC_SLH_DSA_192F 0x80000024UL
#define CKK_QUAC_SLH_DSA_256S 0x80000025UL
#define CKK_QUAC_SLH_DSA_256F 0x80000026UL

/* Mechanisms - Key Generation */
#define CKM_QUAC_ML_KEM_512_KEYGEN 0x80001001UL
#define CKM_QUAC_ML_KEM_768_KEYGEN 0x80001002UL
#define CKM_QUAC_ML_KEM_1024_KEYGEN 0x80001003UL
#define CKM_QUAC_ML_DSA_44_KEYGEN 0x80002001UL
#define CKM_QUAC_ML_DSA_65_KEYGEN 0x80002002UL
#define CKM_QUAC_ML_DSA_87_KEYGEN 0x80002003UL

/* Mechanisms - Operations */
#define CKM_QUAC_ML_KEM_512_ENCAPS 0x80001011UL
#define CKM_QUAC_ML_KEM_768_ENCAPS 0x80001012UL
#define CKM_QUAC_ML_KEM_1024_ENCAPS 0x80001013UL
#define CKM_QUAC_ML_KEM_512_DECAPS 0x80001021UL
#define CKM_QUAC_ML_KEM_768_DECAPS 0x80001022UL
#define CKM_QUAC_ML_KEM_1024_DECAPS 0x80001023UL
#define CKM_QUAC_ML_DSA_44 0x80002011UL
#define CKM_QUAC_ML_DSA_65 0x80002012UL
#define CKM_QUAC_ML_DSA_87 0x80002013UL

/* Hybrid Mechanisms */
#define CKM_QUAC_X25519_ML_KEM_768 0x80003001UL
#define CKM_QUAC_P256_ML_KEM_768 0x80003002UL
#define CKM_QUAC_P384_ML_KEM_1024 0x80003003UL
#define CKM_QUAC_ED25519_ML_DSA_65 0x80003011UL
#define CKM_QUAC_P256_ML_DSA_65 0x80003012UL
#define CKM_QUAC_P384_ML_DSA_87 0x80003013UL

/* Vendor Attributes */
#define CKA_QUAC_ALGORITHM_OID 0x80000001UL
#define CKA_QUAC_HARDWARE_BACKED 0x80000002UL
#define CKA_QUAC_CREATION_TIME 0x80000003UL
#define CKA_QUAC_USAGE_COUNT 0x80000004UL

    /* ==========================================================================
     * Algorithm Sizes
     * ========================================================================== */

    typedef struct
    {
        CK_KEY_TYPE key_type;
        const char *name;
        CK_ULONG pk_size;
        CK_ULONG sk_size;
        CK_ULONG sig_size; /* For signatures */
        CK_ULONG ct_size;  /* For KEM */
        CK_ULONG ss_size;  /* Shared secret */
    } quac_alg_info_t;

    static const quac_alg_info_t QUAC_ALGORITHMS[] = {
        /* ML-KEM */
        {CKK_QUAC_ML_KEM_512, "ML-KEM-512", 800, 1632, 0, 768, 32},
        {CKK_QUAC_ML_KEM_768, "ML-KEM-768", 1184, 2400, 0, 1088, 32},
        {CKK_QUAC_ML_KEM_1024, "ML-KEM-1024", 1568, 3168, 0, 1568, 32},
        /* ML-DSA */
        {CKK_QUAC_ML_DSA_44, "ML-DSA-44", 1312, 2560, 2420, 0, 0},
        {CKK_QUAC_ML_DSA_65, "ML-DSA-65", 1952, 4032, 3309, 0, 0},
        {CKK_QUAC_ML_DSA_87, "ML-DSA-87", 2592, 4896, 4627, 0, 0},
        /* End marker */
        {0, NULL, 0, 0, 0, 0, 0}};

    static inline const quac_alg_info_t *quac_get_alg_info(CK_KEY_TYPE key_type)
    {
        for (int i = 0; QUAC_ALGORITHMS[i].name != NULL; i++)
        {
            if (QUAC_ALGORITHMS[i].key_type == key_type)
            {
                return &QUAC_ALGORITHMS[i];
            }
        }
        return NULL;
    }

    static inline const quac_alg_info_t *quac_get_alg_by_name(const char *name)
    {
        for (int i = 0; QUAC_ALGORITHMS[i].name != NULL; i++)
        {
            if (strcasecmp(QUAC_ALGORITHMS[i].name, name) == 0)
            {
                return &QUAC_ALGORITHMS[i];
            }
        }
        return NULL;
    }

    /* ==========================================================================
     * Error Handling
     * ========================================================================== */

    static inline const char *quac_ck_rv_str(CK_RV rv)
    {
        switch (rv)
        {
        case CKR_OK:
            return "CKR_OK";
        case CKR_CANCEL:
            return "CKR_CANCEL";
        case CKR_HOST_MEMORY:
            return "CKR_HOST_MEMORY";
        case CKR_SLOT_ID_INVALID:
            return "CKR_SLOT_ID_INVALID";
        case CKR_GENERAL_ERROR:
            return "CKR_GENERAL_ERROR";
        case CKR_FUNCTION_FAILED:
            return "CKR_FUNCTION_FAILED";
        case CKR_ARGUMENTS_BAD:
            return "CKR_ARGUMENTS_BAD";
        case CKR_NO_EVENT:
            return "CKR_NO_EVENT";
        case CKR_NEED_TO_CREATE_THREADS:
            return "CKR_NEED_TO_CREATE_THREADS";
        case CKR_CANT_LOCK:
            return "CKR_CANT_LOCK";
        case CKR_ATTRIBUTE_READ_ONLY:
            return "CKR_ATTRIBUTE_READ_ONLY";
        case CKR_ATTRIBUTE_SENSITIVE:
            return "CKR_ATTRIBUTE_SENSITIVE";
        case CKR_ATTRIBUTE_TYPE_INVALID:
            return "CKR_ATTRIBUTE_TYPE_INVALID";
        case CKR_ATTRIBUTE_VALUE_INVALID:
            return "CKR_ATTRIBUTE_VALUE_INVALID";
        case CKR_DATA_INVALID:
            return "CKR_DATA_INVALID";
        case CKR_DATA_LEN_RANGE:
            return "CKR_DATA_LEN_RANGE";
        case CKR_DEVICE_ERROR:
            return "CKR_DEVICE_ERROR";
        case CKR_DEVICE_MEMORY:
            return "CKR_DEVICE_MEMORY";
        case CKR_DEVICE_REMOVED:
            return "CKR_DEVICE_REMOVED";
        case CKR_ENCRYPTED_DATA_INVALID:
            return "CKR_ENCRYPTED_DATA_INVALID";
        case CKR_ENCRYPTED_DATA_LEN_RANGE:
            return "CKR_ENCRYPTED_DATA_LEN_RANGE";
        case CKR_FUNCTION_CANCELED:
            return "CKR_FUNCTION_CANCELED";
        case CKR_FUNCTION_NOT_PARALLEL:
            return "CKR_FUNCTION_NOT_PARALLEL";
        case CKR_FUNCTION_NOT_SUPPORTED:
            return "CKR_FUNCTION_NOT_SUPPORTED";
        case CKR_KEY_HANDLE_INVALID:
            return "CKR_KEY_HANDLE_INVALID";
        case CKR_KEY_SIZE_RANGE:
            return "CKR_KEY_SIZE_RANGE";
        case CKR_KEY_TYPE_INCONSISTENT:
            return "CKR_KEY_TYPE_INCONSISTENT";
        case CKR_KEY_NOT_NEEDED:
            return "CKR_KEY_NOT_NEEDED";
        case CKR_KEY_CHANGED:
            return "CKR_KEY_CHANGED";
        case CKR_KEY_NEEDED:
            return "CKR_KEY_NEEDED";
        case CKR_KEY_INDIGESTIBLE:
            return "CKR_KEY_INDIGESTIBLE";
        case CKR_KEY_FUNCTION_NOT_PERMITTED:
            return "CKR_KEY_FUNCTION_NOT_PERMITTED";
        case CKR_KEY_NOT_WRAPPABLE:
            return "CKR_KEY_NOT_WRAPPABLE";
        case CKR_KEY_UNEXTRACTABLE:
            return "CKR_KEY_UNEXTRACTABLE";
        case CKR_MECHANISM_INVALID:
            return "CKR_MECHANISM_INVALID";
        case CKR_MECHANISM_PARAM_INVALID:
            return "CKR_MECHANISM_PARAM_INVALID";
        case CKR_OBJECT_HANDLE_INVALID:
            return "CKR_OBJECT_HANDLE_INVALID";
        case CKR_OPERATION_ACTIVE:
            return "CKR_OPERATION_ACTIVE";
        case CKR_OPERATION_NOT_INITIALIZED:
            return "CKR_OPERATION_NOT_INITIALIZED";
        case CKR_PIN_INCORRECT:
            return "CKR_PIN_INCORRECT";
        case CKR_PIN_INVALID:
            return "CKR_PIN_INVALID";
        case CKR_PIN_LEN_RANGE:
            return "CKR_PIN_LEN_RANGE";
        case CKR_PIN_EXPIRED:
            return "CKR_PIN_EXPIRED";
        case CKR_PIN_LOCKED:
            return "CKR_PIN_LOCKED";
        case CKR_SESSION_CLOSED:
            return "CKR_SESSION_CLOSED";
        case CKR_SESSION_COUNT:
            return "CKR_SESSION_COUNT";
        case CKR_SESSION_HANDLE_INVALID:
            return "CKR_SESSION_HANDLE_INVALID";
        case CKR_SESSION_PARALLEL_NOT_SUPPORTED:
            return "CKR_SESSION_PARALLEL_NOT_SUPPORTED";
        case CKR_SESSION_READ_ONLY:
            return "CKR_SESSION_READ_ONLY";
        case CKR_SESSION_EXISTS:
            return "CKR_SESSION_EXISTS";
        case CKR_SESSION_READ_ONLY_EXISTS:
            return "CKR_SESSION_READ_ONLY_EXISTS";
        case CKR_SESSION_READ_WRITE_SO_EXISTS:
            return "CKR_SESSION_READ_WRITE_SO_EXISTS";
        case CKR_SIGNATURE_INVALID:
            return "CKR_SIGNATURE_INVALID";
        case CKR_SIGNATURE_LEN_RANGE:
            return "CKR_SIGNATURE_LEN_RANGE";
        case CKR_TEMPLATE_INCOMPLETE:
            return "CKR_TEMPLATE_INCOMPLETE";
        case CKR_TEMPLATE_INCONSISTENT:
            return "CKR_TEMPLATE_INCONSISTENT";
        case CKR_TOKEN_NOT_PRESENT:
            return "CKR_TOKEN_NOT_PRESENT";
        case CKR_TOKEN_NOT_RECOGNIZED:
            return "CKR_TOKEN_NOT_RECOGNIZED";
        case CKR_TOKEN_WRITE_PROTECTED:
            return "CKR_TOKEN_WRITE_PROTECTED";
        case CKR_UNWRAPPING_KEY_HANDLE_INVALID:
            return "CKR_UNWRAPPING_KEY_HANDLE_INVALID";
        case CKR_UNWRAPPING_KEY_SIZE_RANGE:
            return "CKR_UNWRAPPING_KEY_SIZE_RANGE";
        case CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT:
            return "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT";
        case CKR_USER_ALREADY_LOGGED_IN:
            return "CKR_USER_ALREADY_LOGGED_IN";
        case CKR_USER_NOT_LOGGED_IN:
            return "CKR_USER_NOT_LOGGED_IN";
        case CKR_USER_PIN_NOT_INITIALIZED:
            return "CKR_USER_PIN_NOT_INITIALIZED";
        case CKR_USER_TYPE_INVALID:
            return "CKR_USER_TYPE_INVALID";
        case CKR_USER_ANOTHER_ALREADY_LOGGED_IN:
            return "CKR_USER_ANOTHER_ALREADY_LOGGED_IN";
        case CKR_USER_TOO_MANY_TYPES:
            return "CKR_USER_TOO_MANY_TYPES";
        case CKR_WRAPPED_KEY_INVALID:
            return "CKR_WRAPPED_KEY_INVALID";
        case CKR_WRAPPED_KEY_LEN_RANGE:
            return "CKR_WRAPPED_KEY_LEN_RANGE";
        case CKR_WRAPPING_KEY_HANDLE_INVALID:
            return "CKR_WRAPPING_KEY_HANDLE_INVALID";
        case CKR_WRAPPING_KEY_SIZE_RANGE:
            return "CKR_WRAPPING_KEY_SIZE_RANGE";
        case CKR_WRAPPING_KEY_TYPE_INCONSISTENT:
            return "CKR_WRAPPING_KEY_TYPE_INCONSISTENT";
        case CKR_RANDOM_SEED_NOT_SUPPORTED:
            return "CKR_RANDOM_SEED_NOT_SUPPORTED";
        case CKR_RANDOM_NO_RNG:
            return "CKR_RANDOM_NO_RNG";
        case CKR_DOMAIN_PARAMS_INVALID:
            return "CKR_DOMAIN_PARAMS_INVALID";
        case CKR_BUFFER_TOO_SMALL:
            return "CKR_BUFFER_TOO_SMALL";
        case CKR_SAVED_STATE_INVALID:
            return "CKR_SAVED_STATE_INVALID";
        case CKR_INFORMATION_SENSITIVE:
            return "CKR_INFORMATION_SENSITIVE";
        case CKR_STATE_UNSAVEABLE:
            return "CKR_STATE_UNSAVEABLE";
        case CKR_CRYPTOKI_NOT_INITIALIZED:
            return "CKR_CRYPTOKI_NOT_INITIALIZED";
        case CKR_CRYPTOKI_ALREADY_INITIALIZED:
            return "CKR_CRYPTOKI_ALREADY_INITIALIZED";
        case CKR_MUTEX_BAD:
            return "CKR_MUTEX_BAD";
        case CKR_MUTEX_NOT_LOCKED:
            return "CKR_MUTEX_NOT_LOCKED";
        default:
            return "Unknown";
        }
    }

    /* ==========================================================================
     * Module Loading
     * ========================================================================== */

    typedef struct
    {
        void *handle;
        CK_FUNCTION_LIST_PTR p11;
    } quac_p11_module_t;

    static inline int quac_load_module(const char *path, quac_p11_module_t *mod)
    {
        CK_RV rv;
        CK_C_GetFunctionList pGetFunctionList;

        if (!path || !mod)
            return -1;

        memset(mod, 0, sizeof(*mod));

#ifdef _WIN32
        mod->handle = LoadLibraryA(path);
        if (!mod->handle)
            return -1;
        pGetFunctionList = (CK_C_GetFunctionList)GetProcAddress(mod->handle, "C_GetFunctionList");
#else
    mod->handle = dlopen(path, RTLD_NOW);
    if (!mod->handle)
        return -1;
    pGetFunctionList = (CK_C_GetFunctionList)dlsym(mod->handle, "C_GetFunctionList");
#endif

        if (!pGetFunctionList)
        {
#ifdef _WIN32
            FreeLibrary(mod->handle);
#else
        dlclose(mod->handle);
#endif
            return -1;
        }

        rv = pGetFunctionList(&mod->p11);
        if (rv != CKR_OK)
        {
#ifdef _WIN32
            FreeLibrary(mod->handle);
#else
        dlclose(mod->handle);
#endif
            return -1;
        }

        rv = mod->p11->C_Initialize(NULL);
        if (rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED)
        {
#ifdef _WIN32
            FreeLibrary(mod->handle);
#else
        dlclose(mod->handle);
#endif
            return -1;
        }

        return 0;
    }

    static inline void quac_unload_module(quac_p11_module_t *mod)
    {
        if (!mod)
            return;

        if (mod->p11)
        {
            mod->p11->C_Finalize(NULL);
            mod->p11 = NULL;
        }

        if (mod->handle)
        {
#ifdef _WIN32
            FreeLibrary(mod->handle);
#else
        dlclose(mod->handle);
#endif
            mod->handle = NULL;
        }
    }

    /* ==========================================================================
     * Convenience Functions
     * ========================================================================== */

    static inline CK_OBJECT_HANDLE quac_find_key(
        CK_FUNCTION_LIST_PTR p11,
        CK_SESSION_HANDLE session,
        CK_OBJECT_CLASS cls,
        const char *label)
    {
        CK_RV rv;
        CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
        CK_ULONG count;

        CK_ATTRIBUTE template[] = {
            {CKA_CLASS, &cls, sizeof(cls)},
            {CKA_LABEL, (void *)label, strlen(label)}};

        rv = p11->C_FindObjectsInit(session, template, 2);
        if (rv != CKR_OK)
            return CK_INVALID_HANDLE;

        rv = p11->C_FindObjects(session, &key, 1, &count);
        p11->C_FindObjectsFinal(session);

        return (rv == CKR_OK && count > 0) ? key : CK_INVALID_HANDLE;
    }

    static inline void quac_print_hex(const unsigned char *data, size_t len)
    {
        for (size_t i = 0; i < len; i++)
        {
            printf("%02x", data[i]);
        }
    }

    static inline char *quac_trim_string(char *str, size_t len)
    {
        while (len > 0 && str[len - 1] == ' ')
            len--;
        str[len] = '\0';
        return str;
    }

#ifdef __cplusplus
}
#endif

#endif /* QUAC100_PKCS11_UTILS_H */