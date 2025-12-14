/**
 * @file D:\quantacore-sdk\integrations\pkcs11\tools\quac100_p11tool.c
 * @brief QUAC 100 PKCS#11 Management Tool
 *
 * Comprehensive tool for managing QUAC 100 PKCS#11 tokens, keys, and objects.
 *
 * Usage:
 *   quac100_p11tool --list-slots
 *   quac100_p11tool --list-objects --slot 0 --pin 1234
 *   quac100_p11tool --generate-keypair --slot 0 --pin 1234 --algorithm ML-DSA-65
 *
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#ifdef _WIN32
#include <windows.h>
#define LOAD_LIBRARY(path) LoadLibraryA(path)
#define GET_PROC(lib, name) GetProcAddress(lib, name)
#define CLOSE_LIBRARY(lib) FreeLibrary(lib)
typedef HMODULE lib_handle_t;
#else
#include <dlfcn.h>
#define LOAD_LIBRARY(path) dlopen(path, RTLD_NOW)
#define GET_PROC(lib, name) dlsym(lib, name)
#define CLOSE_LIBRARY(lib) dlclose(lib)
typedef void *lib_handle_t;
#endif

/* PKCS#11 header */
#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType(*name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType(*name)
#ifndef NULL_PTR
#define NULL_PTR NULL
#endif

#include "pkcs11.h"

/* ==========================================================================
 * Global State
 * ========================================================================== */

static lib_handle_t g_module = NULL;
static CK_FUNCTION_LIST_PTR g_p11 = NULL;
static const char *g_module_path = NULL;
static CK_SLOT_ID g_slot = 0;
static const char *g_pin = NULL;
static int g_verbose = 0;

/* Algorithm definitions */
#define CKK_ML_KEM_512 0x80000001UL
#define CKK_ML_KEM_768 0x80000002UL
#define CKK_ML_KEM_1024 0x80000003UL
#define CKK_ML_DSA_44 0x80000011UL
#define CKK_ML_DSA_65 0x80000012UL
#define CKK_ML_DSA_87 0x80000013UL

#define CKM_ML_KEM_512_KEYGEN 0x80001001UL
#define CKM_ML_KEM_768_KEYGEN 0x80001002UL
#define CKM_ML_KEM_1024_KEYGEN 0x80001003UL
#define CKM_ML_DSA_44_KEYGEN 0x80002001UL
#define CKM_ML_DSA_65_KEYGEN 0x80002002UL
#define CKM_ML_DSA_87_KEYGEN 0x80002003UL

/* ==========================================================================
 * Utility Functions
 * ========================================================================== */

static const char *ck_rv_str(CK_RV rv)
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
    case CKR_ATTRIBUTE_READ_ONLY:
        return "CKR_ATTRIBUTE_READ_ONLY";
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
    case CKR_ENCRYPTED_DATA_INVALID:
        return "CKR_ENCRYPTED_DATA_INVALID";
    case CKR_ENCRYPTED_DATA_LEN_RANGE:
        return "CKR_ENCRYPTED_DATA_LEN_RANGE";
    case CKR_KEY_HANDLE_INVALID:
        return "CKR_KEY_HANDLE_INVALID";
    case CKR_KEY_SIZE_RANGE:
        return "CKR_KEY_SIZE_RANGE";
    case CKR_KEY_TYPE_INCONSISTENT:
        return "CKR_KEY_TYPE_INCONSISTENT";
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
    case CKR_SESSION_CLOSED:
        return "CKR_SESSION_CLOSED";
    case CKR_SESSION_COUNT:
        return "CKR_SESSION_COUNT";
    case CKR_SESSION_HANDLE_INVALID:
        return "CKR_SESSION_HANDLE_INVALID";
    case CKR_SESSION_READ_ONLY:
        return "CKR_SESSION_READ_ONLY";
    case CKR_SIGNATURE_INVALID:
        return "CKR_SIGNATURE_INVALID";
    case CKR_SIGNATURE_LEN_RANGE:
        return "CKR_SIGNATURE_LEN_RANGE";
    case CKR_TOKEN_NOT_PRESENT:
        return "CKR_TOKEN_NOT_PRESENT";
    case CKR_TOKEN_NOT_RECOGNIZED:
        return "CKR_TOKEN_NOT_RECOGNIZED";
    case CKR_TOKEN_WRITE_PROTECTED:
        return "CKR_TOKEN_WRITE_PROTECTED";
    case CKR_USER_ALREADY_LOGGED_IN:
        return "CKR_USER_ALREADY_LOGGED_IN";
    case CKR_USER_NOT_LOGGED_IN:
        return "CKR_USER_NOT_LOGGED_IN";
    case CKR_USER_PIN_NOT_INITIALIZED:
        return "CKR_USER_PIN_NOT_INITIALIZED";
    case CKR_USER_TYPE_INVALID:
        return "CKR_USER_TYPE_INVALID";
    default:
        return "Unknown";
    }
}

static const char *key_type_str(CK_KEY_TYPE type)
{
    switch (type)
    {
    case CKK_RSA:
        return "RSA";
    case CKK_DSA:
        return "DSA";
    case CKK_EC:
        return "EC";
    case CKK_AES:
        return "AES";
    case CKK_ML_KEM_512:
        return "ML-KEM-512";
    case CKK_ML_KEM_768:
        return "ML-KEM-768";
    case CKK_ML_KEM_1024:
        return "ML-KEM-1024";
    case CKK_ML_DSA_44:
        return "ML-DSA-44";
    case CKK_ML_DSA_65:
        return "ML-DSA-65";
    case CKK_ML_DSA_87:
        return "ML-DSA-87";
    default:
        return "Unknown";
    }
}

static const char *object_class_str(CK_OBJECT_CLASS cls)
{
    switch (cls)
    {
    case CKO_DATA:
        return "Data";
    case CKO_CERTIFICATE:
        return "Certificate";
    case CKO_PUBLIC_KEY:
        return "Public Key";
    case CKO_PRIVATE_KEY:
        return "Private Key";
    case CKO_SECRET_KEY:
        return "Secret Key";
    default:
        return "Unknown";
    }
}

static void print_hex(const unsigned char *data, size_t len, int max)
{
    for (size_t i = 0; i < len && (max == 0 || i < (size_t)max); i++)
    {
        printf("%02x", data[i]);
    }
    if (max > 0 && len > (size_t)max)
        printf("...");
}

static char *trim_string(char *str, size_t len)
{
    while (len > 0 && str[len - 1] == ' ')
        len--;
    str[len] = '\0';
    return str;
}

/* ==========================================================================
 * Module Management
 * ========================================================================== */

static int load_module(void)
{
    CK_RV rv;
    CK_C_GetFunctionList pGetFunctionList;

    if (!g_module_path)
    {
#ifdef _WIN32
        g_module_path = "quac100_pkcs11.dll";
#else
        g_module_path = "libquac100_pkcs11.so";
#endif
    }

    g_module = LOAD_LIBRARY(g_module_path);
    if (!g_module)
    {
        fprintf(stderr, "Failed to load module: %s\n", g_module_path);
        return -1;
    }

    pGetFunctionList = (CK_C_GetFunctionList)GET_PROC(g_module, "C_GetFunctionList");
    if (!pGetFunctionList)
    {
        fprintf(stderr, "Failed to get C_GetFunctionList\n");
        CLOSE_LIBRARY(g_module);
        return -1;
    }

    rv = pGetFunctionList(&g_p11);
    if (rv != CKR_OK)
    {
        fprintf(stderr, "C_GetFunctionList failed: %s\n", ck_rv_str(rv));
        CLOSE_LIBRARY(g_module);
        return -1;
    }

    rv = g_p11->C_Initialize(NULL);
    if (rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED)
    {
        fprintf(stderr, "C_Initialize failed: %s\n", ck_rv_str(rv));
        CLOSE_LIBRARY(g_module);
        return -1;
    }

    return 0;
}

static void unload_module(void)
{
    if (g_p11)
    {
        g_p11->C_Finalize(NULL);
        g_p11 = NULL;
    }
    if (g_module)
    {
        CLOSE_LIBRARY(g_module);
        g_module = NULL;
    }
}

/* ==========================================================================
 * Commands
 * ========================================================================== */

static int cmd_list_slots(void)
{
    CK_RV rv;
    CK_SLOT_ID slots[16];
    CK_ULONG slot_count = 16;

    rv = g_p11->C_GetSlotList(CK_FALSE, slots, &slot_count);
    if (rv != CKR_OK)
    {
        fprintf(stderr, "C_GetSlotList failed: %s\n", ck_rv_str(rv));
        return -1;
    }

    printf("Available Slots (%lu):\n", slot_count);
    printf("================================================================================\n");

    for (CK_ULONG i = 0; i < slot_count; i++)
    {
        CK_SLOT_INFO slot_info;
        CK_TOKEN_INFO token_info;

        rv = g_p11->C_GetSlotInfo(slots[i], &slot_info);
        if (rv != CKR_OK)
            continue;

        printf("\nSlot %lu: %s\n", slots[i],
               trim_string((char *)slot_info.slotDescription, sizeof(slot_info.slotDescription)));
        printf("  Manufacturer: %s\n",
               trim_string((char *)slot_info.manufacturerID, sizeof(slot_info.manufacturerID)));
        printf("  Flags: 0x%08lx", slot_info.flags);
        if (slot_info.flags & CKF_TOKEN_PRESENT)
            printf(" [TOKEN_PRESENT]");
        if (slot_info.flags & CKF_HW_SLOT)
            printf(" [HW_SLOT]");
        printf("\n");

        if (slot_info.flags & CKF_TOKEN_PRESENT)
        {
            rv = g_p11->C_GetTokenInfo(slots[i], &token_info);
            if (rv == CKR_OK)
            {
                printf("  Token:\n");
                printf("    Label: %s\n",
                       trim_string((char *)token_info.label, sizeof(token_info.label)));
                printf("    Manufacturer: %s\n",
                       trim_string((char *)token_info.manufacturerID, sizeof(token_info.manufacturerID)));
                printf("    Model: %s\n",
                       trim_string((char *)token_info.model, sizeof(token_info.model)));
                printf("    Serial: %s\n",
                       trim_string((char *)token_info.serialNumber, sizeof(token_info.serialNumber)));
                printf("    Flags: 0x%08lx", token_info.flags);
                if (token_info.flags & CKF_RNG)
                    printf(" [RNG]");
                if (token_info.flags & CKF_TOKEN_INITIALIZED)
                    printf(" [INITIALIZED]");
                if (token_info.flags & CKF_USER_PIN_INITIALIZED)
                    printf(" [PIN_INIT]");
                if (token_info.flags & CKF_LOGIN_REQUIRED)
                    printf(" [LOGIN_REQ]");
                printf("\n");
                printf("    Sessions: %lu/%lu (R/W: %lu/%lu)\n",
                       token_info.ulSessionCount, token_info.ulMaxSessionCount,
                       token_info.ulRwSessionCount, token_info.ulMaxRwSessionCount);
                printf("    Memory: Public %lu, Private %lu\n",
                       token_info.ulFreePublicMemory, token_info.ulFreePrivateMemory);
            }
        }
    }

    return 0;
}

static int cmd_list_mechanisms(void)
{
    CK_RV rv;
    CK_MECHANISM_TYPE mechs[64];
    CK_ULONG mech_count = 64;

    rv = g_p11->C_GetMechanismList(g_slot, mechs, &mech_count);
    if (rv != CKR_OK)
    {
        fprintf(stderr, "C_GetMechanismList failed: %s\n", ck_rv_str(rv));
        return -1;
    }

    printf("Mechanisms for Slot %lu (%lu):\n", g_slot, mech_count);
    printf("================================================================================\n");

    for (CK_ULONG i = 0; i < mech_count; i++)
    {
        CK_MECHANISM_INFO info;
        const char *name;

        switch (mechs[i])
        {
        case CKM_ML_KEM_512_KEYGEN:
            name = "ML-KEM-512 KeyGen";
            break;
        case CKM_ML_KEM_768_KEYGEN:
            name = "ML-KEM-768 KeyGen";
            break;
        case CKM_ML_KEM_1024_KEYGEN:
            name = "ML-KEM-1024 KeyGen";
            break;
        case CKM_ML_DSA_44_KEYGEN:
            name = "ML-DSA-44 KeyGen";
            break;
        case CKM_ML_DSA_65_KEYGEN:
            name = "ML-DSA-65 KeyGen";
            break;
        case CKM_ML_DSA_87_KEYGEN:
            name = "ML-DSA-87 KeyGen";
            break;
        case CKM_RSA_PKCS_KEY_PAIR_GEN:
            name = "RSA KeyGen";
            break;
        case CKM_EC_KEY_PAIR_GEN:
            name = "EC KeyGen";
            break;
        case CKM_AES_KEY_GEN:
            name = "AES KeyGen";
            break;
        default:
            name = "Unknown";
            break;
        }

        rv = g_p11->C_GetMechanismInfo(g_slot, mechs[i], &info);
        if (rv == CKR_OK)
        {
            printf("  0x%08lx  %-25s  KeySize: %lu-%lu  Flags: 0x%08lx\n",
                   mechs[i], name, info.ulMinKeySize, info.ulMaxKeySize, info.flags);
        }
        else
        {
            printf("  0x%08lx  %-25s\n", mechs[i], name);
        }
    }

    return 0;
}

static int cmd_list_objects(void)
{
    CK_RV rv;
    CK_SESSION_HANDLE session;
    CK_OBJECT_HANDLE objects[256];
    CK_ULONG obj_count;

    /* Open session */
    rv = g_p11->C_OpenSession(g_slot, CKF_SERIAL_SESSION, NULL, NULL, &session);
    if (rv != CKR_OK)
    {
        fprintf(stderr, "C_OpenSession failed: %s\n", ck_rv_str(rv));
        return -1;
    }

    /* Login if PIN provided */
    if (g_pin)
    {
        rv = g_p11->C_Login(session, CKU_USER, (CK_UTF8CHAR_PTR)g_pin, strlen(g_pin));
        if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN)
        {
            fprintf(stderr, "C_Login failed: %s\n", ck_rv_str(rv));
            g_p11->C_CloseSession(session);
            return -1;
        }
    }

    /* Find all objects */
    rv = g_p11->C_FindObjectsInit(session, NULL, 0);
    if (rv != CKR_OK)
    {
        fprintf(stderr, "C_FindObjectsInit failed: %s\n", ck_rv_str(rv));
        g_p11->C_CloseSession(session);
        return -1;
    }

    rv = g_p11->C_FindObjects(session, objects, 256, &obj_count);
    g_p11->C_FindObjectsFinal(session);

    printf("Objects in Slot %lu (%lu):\n", g_slot, obj_count);
    printf("================================================================================\n");

    for (CK_ULONG i = 0; i < obj_count; i++)
    {
        CK_OBJECT_CLASS obj_class;
        CK_KEY_TYPE key_type = 0;
        CK_BYTE label[256] = {0};
        CK_BYTE id[64] = {0};
        CK_ULONG key_size = 0;

        CK_ATTRIBUTE attrs[] = {
            {CKA_CLASS, &obj_class, sizeof(obj_class)},
            {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
            {CKA_LABEL, label, sizeof(label) - 1},
            {CKA_ID, id, sizeof(id)},
            {CKA_VALUE_LEN, &key_size, sizeof(key_size)}};

        rv = g_p11->C_GetAttributeValue(session, objects[i], attrs, 5);

        printf("\n  Handle: 0x%08lx\n", objects[i]);
        printf("    Class: %s\n", object_class_str(obj_class));
        if (obj_class == CKO_PUBLIC_KEY || obj_class == CKO_PRIVATE_KEY || obj_class == CKO_SECRET_KEY)
        {
            printf("    Type: %s\n", key_type_str(key_type));
        }
        if (attrs[2].ulValueLen > 0 && attrs[2].ulValueLen != (CK_ULONG)-1)
        {
            printf("    Label: %s\n", label);
        }
        if (attrs[3].ulValueLen > 0 && attrs[3].ulValueLen != (CK_ULONG)-1)
        {
            printf("    ID: ");
            print_hex(id, attrs[3].ulValueLen, 32);
            printf("\n");
        }
        if (key_size > 0)
        {
            printf("    Size: %lu bytes\n", key_size);
        }
    }

    g_p11->C_Logout(session);
    g_p11->C_CloseSession(session);
    return 0;
}

static int cmd_generate_keypair(const char *algorithm, const char *label)
{
    CK_RV rv;
    CK_SESSION_HANDLE session;
    CK_OBJECT_HANDLE pub_key, priv_key;
    CK_MECHANISM mech = {0, NULL, 0};
    CK_KEY_TYPE key_type;

    /* Parse algorithm */
    if (strcasecmp(algorithm, "ML-DSA-44") == 0)
    {
        mech.mechanism = CKM_ML_DSA_44_KEYGEN;
        key_type = CKK_ML_DSA_44;
    }
    else if (strcasecmp(algorithm, "ML-DSA-65") == 0)
    {
        mech.mechanism = CKM_ML_DSA_65_KEYGEN;
        key_type = CKK_ML_DSA_65;
    }
    else if (strcasecmp(algorithm, "ML-DSA-87") == 0)
    {
        mech.mechanism = CKM_ML_DSA_87_KEYGEN;
        key_type = CKK_ML_DSA_87;
    }
    else if (strcasecmp(algorithm, "ML-KEM-512") == 0)
    {
        mech.mechanism = CKM_ML_KEM_512_KEYGEN;
        key_type = CKK_ML_KEM_512;
    }
    else if (strcasecmp(algorithm, "ML-KEM-768") == 0)
    {
        mech.mechanism = CKM_ML_KEM_768_KEYGEN;
        key_type = CKK_ML_KEM_768;
    }
    else if (strcasecmp(algorithm, "ML-KEM-1024") == 0)
    {
        mech.mechanism = CKM_ML_KEM_1024_KEYGEN;
        key_type = CKK_ML_KEM_1024;
    }
    else
    {
        fprintf(stderr, "Unknown algorithm: %s\n", algorithm);
        fprintf(stderr, "Supported: ML-DSA-44, ML-DSA-65, ML-DSA-87, ML-KEM-512, ML-KEM-768, ML-KEM-1024\n");
        return -1;
    }

    /* Open R/W session */
    rv = g_p11->C_OpenSession(g_slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session);
    if (rv != CKR_OK)
    {
        fprintf(stderr, "C_OpenSession failed: %s\n", ck_rv_str(rv));
        return -1;
    }

    /* Login */
    if (!g_pin)
    {
        fprintf(stderr, "PIN required for key generation\n");
        g_p11->C_CloseSession(session);
        return -1;
    }

    rv = g_p11->C_Login(session, CKU_USER, (CK_UTF8CHAR_PTR)g_pin, strlen(g_pin));
    if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN)
    {
        fprintf(stderr, "C_Login failed: %s\n", ck_rv_str(rv));
        g_p11->C_CloseSession(session);
        return -1;
    }

    /* Set up key generation ID */
    CK_BYTE key_id[8];
    for (int i = 0; i < 8; i++)
        key_id[i] = rand() & 0xFF;

    CK_BBOOL ck_true = CK_TRUE;
    CK_BBOOL ck_false = CK_FALSE;

    CK_ATTRIBUTE pub_attrs[] = {
        {CKA_TOKEN, &ck_true, sizeof(ck_true)},
        {CKA_PRIVATE, &ck_false, sizeof(ck_false)},
        {CKA_LABEL, (void *)label, strlen(label)},
        {CKA_ID, key_id, sizeof(key_id)},
        {CKA_VERIFY, &ck_true, sizeof(ck_true)},
        {CKA_ENCRYPT, &ck_true, sizeof(ck_true)}};

    CK_ATTRIBUTE priv_attrs[] = {
        {CKA_TOKEN, &ck_true, sizeof(ck_true)},
        {CKA_PRIVATE, &ck_true, sizeof(ck_true)},
        {CKA_LABEL, (void *)label, strlen(label)},
        {CKA_ID, key_id, sizeof(key_id)},
        {CKA_SENSITIVE, &ck_true, sizeof(ck_true)},
        {CKA_SIGN, &ck_true, sizeof(ck_true)},
        {CKA_DECRYPT, &ck_true, sizeof(ck_true)}};

    printf("Generating %s keypair...\n", algorithm);

    rv = g_p11->C_GenerateKeyPair(session, &mech,
                                  pub_attrs, 6,
                                  priv_attrs, 7,
                                  &pub_key, &priv_key);
    if (rv != CKR_OK)
    {
        fprintf(stderr, "C_GenerateKeyPair failed: %s\n", ck_rv_str(rv));
        g_p11->C_Logout(session);
        g_p11->C_CloseSession(session);
        return -1;
    }

    printf("Key pair generated successfully!\n");
    printf("  Algorithm: %s\n", algorithm);
    printf("  Label: %s\n", label);
    printf("  Public Key Handle: 0x%08lx\n", pub_key);
    printf("  Private Key Handle: 0x%08lx\n", priv_key);
    printf("  Key ID: ");
    print_hex(key_id, sizeof(key_id), 0);
    printf("\n");

    g_p11->C_Logout(session);
    g_p11->C_CloseSession(session);
    return 0;
}

static int cmd_delete_object(CK_OBJECT_HANDLE handle)
{
    CK_RV rv;
    CK_SESSION_HANDLE session;

    rv = g_p11->C_OpenSession(g_slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session);
    if (rv != CKR_OK)
    {
        fprintf(stderr, "C_OpenSession failed: %s\n", ck_rv_str(rv));
        return -1;
    }

    if (g_pin)
    {
        rv = g_p11->C_Login(session, CKU_USER, (CK_UTF8CHAR_PTR)g_pin, strlen(g_pin));
        if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN)
        {
            fprintf(stderr, "C_Login failed: %s\n", ck_rv_str(rv));
            g_p11->C_CloseSession(session);
            return -1;
        }
    }

    rv = g_p11->C_DestroyObject(session, handle);
    if (rv != CKR_OK)
    {
        fprintf(stderr, "C_DestroyObject failed: %s\n", ck_rv_str(rv));
        g_p11->C_Logout(session);
        g_p11->C_CloseSession(session);
        return -1;
    }

    printf("Object 0x%08lx deleted\n", handle);

    g_p11->C_Logout(session);
    g_p11->C_CloseSession(session);
    return 0;
}

static int cmd_init_token(const char *label, const char *so_pin)
{
    CK_RV rv;

    if (!so_pin)
    {
        fprintf(stderr, "SO PIN required for token initialization\n");
        return -1;
    }

    char padded_label[32];
    memset(padded_label, ' ', sizeof(padded_label));
    size_t len = strlen(label);
    if (len > 32)
        len = 32;
    memcpy(padded_label, label, len);

    rv = g_p11->C_InitToken(g_slot, (CK_UTF8CHAR_PTR)so_pin, strlen(so_pin),
                            (CK_UTF8CHAR_PTR)padded_label);
    if (rv != CKR_OK)
    {
        fprintf(stderr, "C_InitToken failed: %s\n", ck_rv_str(rv));
        return -1;
    }

    printf("Token initialized with label: %s\n", label);
    return 0;
}

static int cmd_init_pin(const char *new_pin)
{
    CK_RV rv;
    CK_SESSION_HANDLE session;

    if (!g_pin || !new_pin)
    {
        fprintf(stderr, "SO PIN (-p) and new user PIN (--new-pin) required\n");
        return -1;
    }

    rv = g_p11->C_OpenSession(g_slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session);
    if (rv != CKR_OK)
    {
        fprintf(stderr, "C_OpenSession failed: %s\n", ck_rv_str(rv));
        return -1;
    }

    rv = g_p11->C_Login(session, CKU_SO, (CK_UTF8CHAR_PTR)g_pin, strlen(g_pin));
    if (rv != CKR_OK)
    {
        fprintf(stderr, "SO Login failed: %s\n", ck_rv_str(rv));
        g_p11->C_CloseSession(session);
        return -1;
    }

    rv = g_p11->C_InitPIN(session, (CK_UTF8CHAR_PTR)new_pin, strlen(new_pin));
    if (rv != CKR_OK)
    {
        fprintf(stderr, "C_InitPIN failed: %s\n", ck_rv_str(rv));
        g_p11->C_Logout(session);
        g_p11->C_CloseSession(session);
        return -1;
    }

    printf("User PIN initialized\n");

    g_p11->C_Logout(session);
    g_p11->C_CloseSession(session);
    return 0;
}

/* ==========================================================================
 * Main
 * ========================================================================== */

static void usage(const char *prog)
{
    printf("QUAC 100 PKCS#11 Management Tool\n\n");
    printf("Usage: %s <command> [options]\n\n", prog);
    printf("Commands:\n");
    printf("  --list-slots            List available slots and tokens\n");
    printf("  --list-mechanisms       List mechanisms for a slot\n");
    printf("  --list-objects          List objects in a token\n");
    printf("  --generate-keypair      Generate a key pair\n");
    printf("  --delete-object <h>     Delete object by handle\n");
    printf("  --init-token            Initialize token\n");
    printf("  --init-pin              Initialize user PIN\n");
    printf("\n");
    printf("Options:\n");
    printf("  -m, --module <path>     PKCS#11 module path\n");
    printf("  -s, --slot <num>        Slot number (default: 0)\n");
    printf("  -p, --pin <pin>         User PIN (or SO PIN for init)\n");
    printf("  -a, --algorithm <alg>   Algorithm for keygen\n");
    printf("  -l, --label <label>     Label for keys/token\n");
    printf("  --new-pin <pin>         New PIN for --init-pin\n");
    printf("  -v, --verbose           Verbose output\n");
    printf("  -h, --help              Show this help\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s --list-slots\n", prog);
    printf("  %s --list-objects -s 0 -p 1234\n", prog);
    printf("  %s --generate-keypair -s 0 -p 1234 -a ML-DSA-65 -l mykey\n", prog);
    printf("  %s --init-token -s 0 -p SO_PIN -l \"QUAC 100\"\n", prog);
}

int main(int argc, char *argv[])
{
    int opt;
    int cmd = 0;
    const char *algorithm = "ML-DSA-65";
    const char *label = "pqc-key";
    const char *new_pin = NULL;
    CK_OBJECT_HANDLE delete_handle = 0;

    enum
    {
        CMD_NONE = 0,
        CMD_LIST_SLOTS,
        CMD_LIST_MECHANISMS,
        CMD_LIST_OBJECTS,
        CMD_GENERATE_KEYPAIR,
        CMD_DELETE_OBJECT,
        CMD_INIT_TOKEN,
        CMD_INIT_PIN
    };

    static struct option long_opts[] = {
        {"list-slots", no_argument, 0, 'S'},
        {"list-mechanisms", no_argument, 0, 'M'},
        {"list-objects", no_argument, 0, 'O'},
        {"generate-keypair", no_argument, 0, 'G'},
        {"delete-object", required_argument, 0, 'D'},
        {"init-token", no_argument, 0, 'T'},
        {"init-pin", no_argument, 0, 'I'},
        {"module", required_argument, 0, 'm'},
        {"slot", required_argument, 0, 's'},
        {"pin", required_argument, 0, 'p'},
        {"algorithm", required_argument, 0, 'a'},
        {"label", required_argument, 0, 'l'},
        {"new-pin", required_argument, 0, 'n'},
        {"verbose", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}};

    while ((opt = getopt_long(argc, argv, "SMOGTIm:s:p:a:l:n:vh", long_opts, NULL)) != -1)
    {
        switch (opt)
        {
        case 'S':
            cmd = CMD_LIST_SLOTS;
            break;
        case 'M':
            cmd = CMD_LIST_MECHANISMS;
            break;
        case 'O':
            cmd = CMD_LIST_OBJECTS;
            break;
        case 'G':
            cmd = CMD_GENERATE_KEYPAIR;
            break;
        case 'D':
            cmd = CMD_DELETE_OBJECT;
            delete_handle = strtoul(optarg, NULL, 0);
            break;
        case 'T':
            cmd = CMD_INIT_TOKEN;
            break;
        case 'I':
            cmd = CMD_INIT_PIN;
            break;
        case 'm':
            g_module_path = optarg;
            break;
        case 's':
            g_slot = atoi(optarg);
            break;
        case 'p':
            g_pin = optarg;
            break;
        case 'a':
            algorithm = optarg;
            break;
        case 'l':
            label = optarg;
            break;
        case 'n':
            new_pin = optarg;
            break;
        case 'v':
            g_verbose = 1;
            break;
        case 'h':
            usage(argv[0]);
            return 0;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    if (cmd == CMD_NONE)
    {
        fprintf(stderr, "Error: Command required\n\n");
        usage(argv[0]);
        return 1;
    }

    if (load_module() != 0)
    {
        return 1;
    }

    int ret;
    switch (cmd)
    {
    case CMD_LIST_SLOTS:
        ret = cmd_list_slots();
        break;
    case CMD_LIST_MECHANISMS:
        ret = cmd_list_mechanisms();
        break;
    case CMD_LIST_OBJECTS:
        ret = cmd_list_objects();
        break;
    case CMD_GENERATE_KEYPAIR:
        ret = cmd_generate_keypair(algorithm, label);
        break;
    case CMD_DELETE_OBJECT:
        ret = cmd_delete_object(delete_handle);
        break;
    case CMD_INIT_TOKEN:
        ret = cmd_init_token(label, g_pin);
        break;
    case CMD_INIT_PIN:
        ret = cmd_init_pin(new_pin);
        break;
    default:
        ret = -1;
    }

    unload_module();
    return ret == 0 ? 0 : 1;
}