/**
 * @file D:\quantacore-sdk\integrations\pkcs11\examples\p11_sign_verify.c
 * @brief QUAC 100 PKCS#11 - Sign and Verify Example
 *
 * Demonstrates ML-DSA signing and verification through PKCS#11.
 *
 * Usage:
 *   p11_sign_verify --sign --key-label mykey --pin 1234 --input file.txt
 *   p11_sign_verify --verify --key-label mykey --input file.txt --sig file.sig
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
 * Mechanism Definitions
 * ========================================================================== */

#define CKM_ML_DSA_44 0x80002011UL
#define CKM_ML_DSA_65 0x80002012UL
#define CKM_ML_DSA_87 0x80002013UL

#define CKK_ML_DSA_44 0x80000011UL
#define CKK_ML_DSA_65 0x80000012UL
#define CKK_ML_DSA_87 0x80000013UL

/* ==========================================================================
 * Global State
 * ========================================================================== */

static lib_handle_t g_module = NULL;
static CK_FUNCTION_LIST_PTR g_p11 = NULL;
static const char *g_module_path = NULL;
static CK_SLOT_ID g_slot = 0;
static const char *g_pin = NULL;
static const char *g_key_label = NULL;
static const char *g_input_file = NULL;
static const char *g_sig_file = "signature.bin";
static int g_verbose = 0;

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
        fprintf(stderr, "C_GetFunctionList failed\n");
        CLOSE_LIBRARY(g_module);
        return -1;
    }

    rv = g_p11->C_Initialize(NULL);
    if (rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED)
    {
        fprintf(stderr, "C_Initialize failed\n");
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
 * Key Finding
 * ========================================================================== */

static CK_OBJECT_HANDLE find_key(CK_SESSION_HANDLE session, CK_OBJECT_CLASS cls,
                                 const char *label)
{
    CK_RV rv;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_ULONG count;

    CK_ATTRIBUTE template[] = {
        {CKA_CLASS, &cls, sizeof(cls)},
        {CKA_LABEL, (void *)label, strlen(label)}};

    rv = g_p11->C_FindObjectsInit(session, template, 2);
    if (rv != CKR_OK)
    {
        fprintf(stderr, "C_FindObjectsInit failed\n");
        return CK_INVALID_HANDLE;
    }

    rv = g_p11->C_FindObjects(session, &key, 1, &count);
    g_p11->C_FindObjectsFinal(session);

    if (rv != CKR_OK || count == 0)
    {
        return CK_INVALID_HANDLE;
    }

    return key;
}

static CK_MECHANISM_TYPE get_sign_mechanism(CK_SESSION_HANDLE session,
                                            CK_OBJECT_HANDLE key)
{
    CK_RV rv;
    CK_KEY_TYPE key_type;
    CK_ATTRIBUTE attr = {CKA_KEY_TYPE, &key_type, sizeof(key_type)};

    rv = g_p11->C_GetAttributeValue(session, key, &attr, 1);
    if (rv != CKR_OK)
    {
        return 0;
    }

    switch (key_type)
    {
    case CKK_ML_DSA_44:
        return CKM_ML_DSA_44;
    case CKK_ML_DSA_65:
        return CKM_ML_DSA_65;
    case CKK_ML_DSA_87:
        return CKM_ML_DSA_87;
    default:
        return 0;
    }
}

/* ==========================================================================
 * Signing
 * ========================================================================== */

static int do_sign(void)
{
    CK_RV rv;
    CK_SESSION_HANDLE session;
    CK_OBJECT_HANDLE priv_key;
    CK_MECHANISM mech;
    unsigned char *data = NULL;
    unsigned char *signature = NULL;
    CK_ULONG sig_len;
    long data_len;
    FILE *f;
    int ret = -1;

    if (!g_key_label)
    {
        fprintf(stderr, "Key label required (--key-label)\n");
        return -1;
    }
    if (!g_input_file)
    {
        fprintf(stderr, "Input file required (--input)\n");
        return -1;
    }

    /* Open session and login */
    rv = g_p11->C_OpenSession(g_slot, CKF_SERIAL_SESSION, NULL, NULL, &session);
    if (rv != CKR_OK)
    {
        fprintf(stderr, "C_OpenSession failed\n");
        return -1;
    }

    if (g_pin)
    {
        rv = g_p11->C_Login(session, CKU_USER, (CK_UTF8CHAR_PTR)g_pin, strlen(g_pin));
        if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN)
        {
            fprintf(stderr, "C_Login failed\n");
            g_p11->C_CloseSession(session);
            return -1;
        }
    }

    /* Find private key */
    priv_key = find_key(session, CKO_PRIVATE_KEY, g_key_label);
    if (priv_key == CK_INVALID_HANDLE)
    {
        fprintf(stderr, "Private key '%s' not found\n", g_key_label);
        goto cleanup;
    }

    if (g_verbose)
    {
        printf("Found private key: handle 0x%08lx\n", priv_key);
    }

    /* Get mechanism */
    mech.mechanism = get_sign_mechanism(session, priv_key);
    mech.pParameter = NULL;
    mech.ulParameterLen = 0;

    if (mech.mechanism == 0)
    {
        fprintf(stderr, "Unknown key type\n");
        goto cleanup;
    }

    /* Read input file */
    f = fopen(g_input_file, "rb");
    if (!f)
    {
        perror(g_input_file);
        goto cleanup;
    }

    fseek(f, 0, SEEK_END);
    data_len = ftell(f);
    fseek(f, 0, SEEK_SET);

    data = malloc(data_len);
    if (!data || fread(data, 1, data_len, f) != (size_t)data_len)
    {
        fprintf(stderr, "Failed to read input file\n");
        fclose(f);
        goto cleanup;
    }
    fclose(f);

    if (g_verbose)
    {
        printf("Input: %ld bytes\n", data_len);
    }

    /* Initialize signing */
    rv = g_p11->C_SignInit(session, &mech, priv_key);
    if (rv != CKR_OK)
    {
        fprintf(stderr, "C_SignInit failed\n");
        goto cleanup;
    }

    /* Get signature length */
    rv = g_p11->C_Sign(session, data, data_len, NULL, &sig_len);
    if (rv != CKR_OK)
    {
        fprintf(stderr, "C_Sign (get length) failed\n");
        goto cleanup;
    }

    signature = malloc(sig_len);
    if (!signature)
    {
        fprintf(stderr, "Memory allocation failed\n");
        goto cleanup;
    }

    /* Sign */
    rv = g_p11->C_Sign(session, data, data_len, signature, &sig_len);
    if (rv != CKR_OK)
    {
        fprintf(stderr, "C_Sign failed\n");
        goto cleanup;
    }

    if (g_verbose)
    {
        printf("Signature: %lu bytes\n", sig_len);
    }

    /* Write signature */
    f = fopen(g_sig_file, "wb");
    if (!f)
    {
        perror(g_sig_file);
        goto cleanup;
    }

    if (fwrite(signature, 1, sig_len, f) != sig_len)
    {
        fprintf(stderr, "Failed to write signature\n");
        fclose(f);
        goto cleanup;
    }
    fclose(f);

    printf("Signature written to %s (%lu bytes)\n", g_sig_file, sig_len);
    ret = 0;

cleanup:
    free(data);
    free(signature);
    g_p11->C_Logout(session);
    g_p11->C_CloseSession(session);
    return ret;
}

/* ==========================================================================
 * Verification
 * ========================================================================== */

static int do_verify(void)
{
    CK_RV rv;
    CK_SESSION_HANDLE session;
    CK_OBJECT_HANDLE pub_key;
    CK_MECHANISM mech;
    unsigned char *data = NULL;
    unsigned char *signature = NULL;
    long data_len, sig_len;
    FILE *f;
    int ret = -1;

    if (!g_key_label)
    {
        fprintf(stderr, "Key label required (--key-label)\n");
        return -1;
    }
    if (!g_input_file)
    {
        fprintf(stderr, "Input file required (--input)\n");
        return -1;
    }

    /* Open session */
    rv = g_p11->C_OpenSession(g_slot, CKF_SERIAL_SESSION, NULL, NULL, &session);
    if (rv != CKR_OK)
    {
        fprintf(stderr, "C_OpenSession failed\n");
        return -1;
    }

    /* Find public key */
    pub_key = find_key(session, CKO_PUBLIC_KEY, g_key_label);
    if (pub_key == CK_INVALID_HANDLE)
    {
        fprintf(stderr, "Public key '%s' not found\n", g_key_label);
        g_p11->C_CloseSession(session);
        return -1;
    }

    if (g_verbose)
    {
        printf("Found public key: handle 0x%08lx\n", pub_key);
    }

    /* Get mechanism */
    mech.mechanism = get_sign_mechanism(session, pub_key);
    mech.pParameter = NULL;
    mech.ulParameterLen = 0;

    if (mech.mechanism == 0)
    {
        fprintf(stderr, "Unknown key type\n");
        goto cleanup;
    }

    /* Read input file */
    f = fopen(g_input_file, "rb");
    if (!f)
    {
        perror(g_input_file);
        goto cleanup;
    }

    fseek(f, 0, SEEK_END);
    data_len = ftell(f);
    fseek(f, 0, SEEK_SET);

    data = malloc(data_len);
    if (!data || fread(data, 1, data_len, f) != (size_t)data_len)
    {
        fprintf(stderr, "Failed to read input file\n");
        fclose(f);
        goto cleanup;
    }
    fclose(f);

    /* Read signature */
    f = fopen(g_sig_file, "rb");
    if (!f)
    {
        perror(g_sig_file);
        goto cleanup;
    }

    fseek(f, 0, SEEK_END);
    sig_len = ftell(f);
    fseek(f, 0, SEEK_SET);

    signature = malloc(sig_len);
    if (!signature || fread(signature, 1, sig_len, f) != (size_t)sig_len)
    {
        fprintf(stderr, "Failed to read signature\n");
        fclose(f);
        goto cleanup;
    }
    fclose(f);

    if (g_verbose)
    {
        printf("Data: %ld bytes, Signature: %ld bytes\n", data_len, sig_len);
    }

    /* Initialize verification */
    rv = g_p11->C_VerifyInit(session, &mech, pub_key);
    if (rv != CKR_OK)
    {
        fprintf(stderr, "C_VerifyInit failed\n");
        goto cleanup;
    }

    /* Verify */
    rv = g_p11->C_Verify(session, data, data_len, signature, sig_len);

    if (rv == CKR_OK)
    {
        printf("Signature VALID ✓\n");
        ret = 0;
    }
    else if (rv == CKR_SIGNATURE_INVALID)
    {
        printf("Signature INVALID ✗\n");
        ret = 1;
    }
    else
    {
        fprintf(stderr, "C_Verify failed\n");
        ret = -1;
    }

cleanup:
    free(data);
    free(signature);
    g_p11->C_CloseSession(session);
    return ret;
}

/* ==========================================================================
 * Demo Mode
 * ========================================================================== */

static int do_demo(void)
{
    CK_RV rv;
    CK_SESSION_HANDLE session;
    CK_OBJECT_HANDLE pub_key, priv_key;
    CK_MECHANISM keygen_mech = {0x80002002, NULL, 0}; /* ML-DSA-65 KeyGen */
    CK_MECHANISM sign_mech = {CKM_ML_DSA_65, NULL, 0};
    CK_BYTE data[] = "Hello, Post-Quantum Cryptography!";
    CK_ULONG data_len = sizeof(data) - 1;
    CK_BYTE signature[4096];
    CK_ULONG sig_len = sizeof(signature);
    int ret = -1;

    printf("=== PKCS#11 ML-DSA Sign/Verify Demo ===\n\n");

    /* Open session */
    rv = g_p11->C_OpenSession(g_slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session);
    if (rv != CKR_OK)
    {
        fprintf(stderr, "C_OpenSession failed\n");
        return -1;
    }

    /* Login */
    if (g_pin)
    {
        rv = g_p11->C_Login(session, CKU_USER, (CK_UTF8CHAR_PTR)g_pin, strlen(g_pin));
        if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN)
        {
            fprintf(stderr, "C_Login failed\n");
            g_p11->C_CloseSession(session);
            return -1;
        }
    }

    /* Generate key pair */
    printf("1. Generating ML-DSA-65 key pair...\n");

    CK_BBOOL ck_true = CK_TRUE;
    CK_ATTRIBUTE pub_attrs[] = {
        {CKA_TOKEN, &ck_true, sizeof(ck_true)},
        {CKA_VERIFY, &ck_true, sizeof(ck_true)},
        {CKA_LABEL, "demo-key", 8}};
    CK_ATTRIBUTE priv_attrs[] = {
        {CKA_TOKEN, &ck_true, sizeof(ck_true)},
        {CKA_SIGN, &ck_true, sizeof(ck_true)},
        {CKA_SENSITIVE, &ck_true, sizeof(ck_true)},
        {CKA_LABEL, "demo-key", 8}};

    rv = g_p11->C_GenerateKeyPair(session, &keygen_mech,
                                  pub_attrs, 3, priv_attrs, 4,
                                  &pub_key, &priv_key);
    if (rv != CKR_OK)
    {
        fprintf(stderr, "C_GenerateKeyPair failed\n");
        goto cleanup;
    }
    printf("   Key pair generated (pub: 0x%08lx, priv: 0x%08lx)\n\n", pub_key, priv_key);

    /* Sign */
    printf("2. Signing message: \"%s\"\n", data);

    rv = g_p11->C_SignInit(session, &sign_mech, priv_key);
    if (rv != CKR_OK)
    {
        fprintf(stderr, "C_SignInit failed\n");
        goto cleanup;
    }

    rv = g_p11->C_Sign(session, data, data_len, signature, &sig_len);
    if (rv != CKR_OK)
    {
        fprintf(stderr, "C_Sign failed\n");
        goto cleanup;
    }
    printf("   Signature: %lu bytes\n\n", sig_len);

    /* Verify */
    printf("3. Verifying signature...\n");

    rv = g_p11->C_VerifyInit(session, &sign_mech, pub_key);
    if (rv != CKR_OK)
    {
        fprintf(stderr, "C_VerifyInit failed\n");
        goto cleanup;
    }

    rv = g_p11->C_Verify(session, data, data_len, signature, sig_len);
    if (rv == CKR_OK)
    {
        printf("   Verification: PASSED ✓\n\n");
    }
    else
    {
        printf("   Verification: FAILED ✗\n\n");
        goto cleanup;
    }

    /* Test with modified data */
    printf("4. Testing with tampered message...\n");
    data[0] ^= 0xFF;

    rv = g_p11->C_VerifyInit(session, &sign_mech, pub_key);
    rv = g_p11->C_Verify(session, data, data_len, signature, sig_len);
    if (rv == CKR_SIGNATURE_INVALID)
    {
        printf("   Verification correctly rejected tampered data ✓\n\n");
    }
    else
    {
        printf("   Unexpected result\n\n");
    }

    printf("Demo completed successfully!\n");
    ret = 0;

cleanup:
    /* Delete demo keys */
    g_p11->C_DestroyObject(session, pub_key);
    g_p11->C_DestroyObject(session, priv_key);
    g_p11->C_Logout(session);
    g_p11->C_CloseSession(session);
    return ret;
}

/* ==========================================================================
 * Main
 * ========================================================================== */

static void usage(const char *prog)
{
    printf("QUAC 100 PKCS#11 Sign/Verify Example\n\n");
    printf("Usage: %s <mode> [options]\n\n", prog);
    printf("Modes:\n");
    printf("  --sign              Sign a file\n");
    printf("  --verify            Verify a signature\n");
    printf("  --demo              Run full demo (keygen + sign + verify)\n");
    printf("\n");
    printf("Options:\n");
    printf("  -m, --module <path>     PKCS#11 module path\n");
    printf("  -s, --slot <num>        Slot number (default: 0)\n");
    printf("  -p, --pin <pin>         User PIN\n");
    printf("  -k, --key-label <label> Key label to use\n");
    printf("  -i, --input <file>      Input file to sign/verify\n");
    printf("  -S, --signature <file>  Signature file (default: signature.bin)\n");
    printf("  -v, --verbose           Verbose output\n");
    printf("  -h, --help              Show this help\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s --sign -k mykey -p 1234 -i document.pdf\n", prog);
    printf("  %s --verify -k mykey -i document.pdf -S signature.bin\n", prog);
    printf("  %s --demo -p 1234\n", prog);
}

int main(int argc, char *argv[])
{
    int opt;
    int mode = 0; /* 1=sign, 2=verify, 3=demo */

    static struct option long_opts[] = {
        {"sign", no_argument, 0, 'g'},
        {"verify", no_argument, 0, 'V'},
        {"demo", no_argument, 0, 'D'},
        {"module", required_argument, 0, 'm'},
        {"slot", required_argument, 0, 's'},
        {"pin", required_argument, 0, 'p'},
        {"key-label", required_argument, 0, 'k'},
        {"input", required_argument, 0, 'i'},
        {"signature", required_argument, 0, 'S'},
        {"verbose", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}};

    while ((opt = getopt_long(argc, argv, "gVDm:s:p:k:i:S:vh", long_opts, NULL)) != -1)
    {
        switch (opt)
        {
        case 'g':
            mode = 1;
            break;
        case 'V':
            mode = 2;
            break;
        case 'D':
            mode = 3;
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
        case 'k':
            g_key_label = optarg;
            break;
        case 'i':
            g_input_file = optarg;
            break;
        case 'S':
            g_sig_file = optarg;
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

    if (mode == 0)
    {
        fprintf(stderr, "Error: Mode required (--sign, --verify, or --demo)\n\n");
        usage(argv[0]);
        return 1;
    }

    if (load_module() != 0)
    {
        return 1;
    }

    int ret;
    switch (mode)
    {
    case 1:
        ret = do_sign();
        break;
    case 2:
        ret = do_verify();
        break;
    case 3:
        ret = do_demo();
        break;
    default:
        ret = -1;
    }

    unload_module();
    return ret == 0 ? 0 : (ret == 1 ? 1 : 2);
}