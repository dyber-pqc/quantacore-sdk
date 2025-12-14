/**
 * @file D:\quantacore-sdk\integrations\pkcs11\tools\quac100_keytool.c
 * @brief QUAC 100 PKCS#11 Key Import/Export Tool
 *
 * Tool for importing and exporting keys to/from PKCS#11 tokens.
 *
 * Usage:
 *   quac100_keytool --export -k label -o key.pem -p 1234
 *   quac100_keytool --import -i key.pem -l newlabel -p 1234
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
 * Constants
 * ========================================================================== */

#define CKK_ML_KEM_512 0x80000001UL
#define CKK_ML_KEM_768 0x80000002UL
#define CKK_ML_KEM_1024 0x80000003UL
#define CKK_ML_DSA_44 0x80000011UL
#define CKK_ML_DSA_65 0x80000012UL
#define CKK_ML_DSA_87 0x80000013UL

/* Base64 encoding table */
static const char BASE64_TABLE[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* ==========================================================================
 * Global State
 * ========================================================================== */

static lib_handle_t g_module = NULL;
static CK_FUNCTION_LIST_PTR g_p11 = NULL;
static const char *g_module_path = NULL;
static CK_SLOT_ID g_slot = 0;
static const char *g_pin = NULL;
static int g_verbose = 0;

/* ==========================================================================
 * Base64 Encoding/Decoding
 * ========================================================================== */

static size_t base64_encode(const unsigned char *in, size_t in_len, char *out)
{
    size_t out_len = 0;
    int i;

    for (i = 0; i < (int)in_len - 2; i += 3)
    {
        out[out_len++] = BASE64_TABLE[(in[i] >> 2) & 0x3F];
        out[out_len++] = BASE64_TABLE[((in[i] & 0x3) << 4) | ((in[i + 1] >> 4) & 0xF)];
        out[out_len++] = BASE64_TABLE[((in[i + 1] & 0xF) << 2) | ((in[i + 2] >> 6) & 0x3)];
        out[out_len++] = BASE64_TABLE[in[i + 2] & 0x3F];
    }

    if (i < (int)in_len)
    {
        out[out_len++] = BASE64_TABLE[(in[i] >> 2) & 0x3F];
        if (i == (int)in_len - 1)
        {
            out[out_len++] = BASE64_TABLE[(in[i] & 0x3) << 4];
            out[out_len++] = '=';
        }
        else
        {
            out[out_len++] = BASE64_TABLE[((in[i] & 0x3) << 4) | ((in[i + 1] >> 4) & 0xF)];
            out[out_len++] = BASE64_TABLE[(in[i + 1] & 0xF) << 2];
        }
        out[out_len++] = '=';
    }

    out[out_len] = '\0';
    return out_len;
}

static int base64_decode_char(char c)
{
    if (c >= 'A' && c <= 'Z')
        return c - 'A';
    if (c >= 'a' && c <= 'z')
        return c - 'a' + 26;
    if (c >= '0' && c <= '9')
        return c - '0' + 52;
    if (c == '+')
        return 62;
    if (c == '/')
        return 63;
    return -1;
}

static size_t base64_decode(const char *in, unsigned char *out)
{
    size_t out_len = 0;
    int vals[4];
    int i = 0;

    while (*in)
    {
        if (*in == '\n' || *in == '\r' || *in == ' ')
        {
            in++;
            continue;
        }
        if (*in == '=')
            break;

        vals[i] = base64_decode_char(*in);
        if (vals[i] < 0)
        {
            in++;
            continue;
        }

        i++;
        if (i == 4)
        {
            out[out_len++] = (vals[0] << 2) | (vals[1] >> 4);
            out[out_len++] = (vals[1] << 4) | (vals[2] >> 2);
            out[out_len++] = (vals[2] << 6) | vals[3];
            i = 0;
        }
        in++;
    }

    if (i >= 2)
    {
        out[out_len++] = (vals[0] << 2) | (vals[1] >> 4);
        if (i >= 3)
        {
            out[out_len++] = (vals[1] << 4) | (vals[2] >> 2);
        }
    }

    return out_len;
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
    }
    if (g_module)
    {
        CLOSE_LIBRARY(g_module);
    }
}

/* ==========================================================================
 * Key Operations
 * ========================================================================== */

static const char *key_type_name(CK_KEY_TYPE type)
{
    switch (type)
    {
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
    case CKK_RSA:
        return "RSA";
    case CKK_EC:
        return "EC";
    default:
        return "UNKNOWN";
    }
}

static const char *key_type_pem_header(CK_KEY_TYPE type, CK_OBJECT_CLASS cls)
{
    const char *prefix = (cls == CKO_PRIVATE_KEY) ? "PRIVATE" : "PUBLIC";

    switch (type)
    {
    case CKK_ML_KEM_512:
    case CKK_ML_KEM_768:
    case CKK_ML_KEM_1024:
        return (cls == CKO_PRIVATE_KEY) ? "ML-KEM PRIVATE KEY" : "ML-KEM PUBLIC KEY";
    case CKK_ML_DSA_44:
    case CKK_ML_DSA_65:
    case CKK_ML_DSA_87:
        return (cls == CKO_PRIVATE_KEY) ? "ML-DSA PRIVATE KEY" : "ML-DSA PUBLIC KEY";
    default:
        return (cls == CKO_PRIVATE_KEY) ? "PRIVATE KEY" : "PUBLIC KEY";
    }
}

static int export_key(const char *label, const char *output_file, int export_private)
{
    CK_RV rv;
    CK_SESSION_HANDLE session;
    CK_OBJECT_HANDLE key;
    CK_OBJECT_CLASS cls = export_private ? CKO_PRIVATE_KEY : CKO_PUBLIC_KEY;
    CK_ULONG count;
    FILE *f;
    int ret = -1;

    /* Open session */
    rv = g_p11->C_OpenSession(g_slot, CKF_SERIAL_SESSION, NULL, NULL, &session);
    if (rv != CKR_OK)
    {
        fprintf(stderr, "C_OpenSession failed\n");
        return -1;
    }

    /* Login for private key access */
    if (export_private && g_pin)
    {
        rv = g_p11->C_Login(session, CKU_USER, (CK_UTF8CHAR_PTR)g_pin, strlen(g_pin));
        if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN)
        {
            fprintf(stderr, "C_Login failed\n");
            g_p11->C_CloseSession(session);
            return -1;
        }
    }

    /* Find key by label */
    CK_ATTRIBUTE find_attrs[] = {
        {CKA_CLASS, &cls, sizeof(cls)},
        {CKA_LABEL, (void *)label, strlen(label)}};

    rv = g_p11->C_FindObjectsInit(session, find_attrs, 2);
    if (rv != CKR_OK)
    {
        fprintf(stderr, "C_FindObjectsInit failed\n");
        goto cleanup;
    }

    rv = g_p11->C_FindObjects(session, &key, 1, &count);
    g_p11->C_FindObjectsFinal(session);

    if (rv != CKR_OK || count == 0)
    {
        fprintf(stderr, "Key '%s' not found\n", label);
        goto cleanup;
    }

    /* Get key type and value */
    CK_KEY_TYPE key_type;
    CK_BYTE value[8192];
    CK_BBOOL extractable = CK_FALSE;

    CK_ATTRIBUTE get_attrs[] = {
        {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
        {CKA_VALUE, value, sizeof(value)},
        {CKA_EXTRACTABLE, &extractable, sizeof(extractable)}};

    rv = g_p11->C_GetAttributeValue(session, key, get_attrs, 3);

    if (export_private && !extractable)
    {
        fprintf(stderr, "Key is not extractable\n");
        goto cleanup;
    }

    if (get_attrs[1].ulValueLen == (CK_ULONG)-1)
    {
        fprintf(stderr, "Cannot extract key value (sensitive or not extractable)\n");
        goto cleanup;
    }

    /* Write PEM file */
    f = fopen(output_file, "w");
    if (!f)
    {
        perror(output_file);
        goto cleanup;
    }

    const char *header = key_type_pem_header(key_type, cls);
    char *b64 = malloc(get_attrs[1].ulValueLen * 2);
    if (!b64)
    {
        fclose(f);
        goto cleanup;
    }

    base64_encode(value, get_attrs[1].ulValueLen, b64);

    fprintf(f, "-----BEGIN %s-----\n", header);

    /* Write base64 in 64-char lines */
    size_t b64_len = strlen(b64);
    for (size_t i = 0; i < b64_len; i += 64)
    {
        size_t chunk = (b64_len - i > 64) ? 64 : (b64_len - i);
        fprintf(f, "%.*s\n", (int)chunk, b64 + i);
    }

    fprintf(f, "-----END %s-----\n", header);

    fclose(f);
    free(b64);

    printf("Exported %s key '%s' to %s\n",
           export_private ? "private" : "public", label, output_file);
    printf("  Algorithm: %s\n", key_type_name(key_type));
    printf("  Size: %lu bytes\n", get_attrs[1].ulValueLen);

    ret = 0;

cleanup:
    if (export_private)
        g_p11->C_Logout(session);
    g_p11->C_CloseSession(session);
    return ret;
}

static int import_key(const char *input_file, const char *label, const char *algorithm)
{
    CK_RV rv;
    CK_SESSION_HANDLE session;
    CK_OBJECT_HANDLE key;
    FILE *f;
    char *pem_data = NULL;
    unsigned char *key_data = NULL;
    size_t key_len;
    long file_size;
    int ret = -1;
    int is_private = 0;
    CK_KEY_TYPE key_type;

    /* Parse algorithm */
    if (strcasecmp(algorithm, "ML-KEM-512") == 0)
    {
        key_type = CKK_ML_KEM_512;
    }
    else if (strcasecmp(algorithm, "ML-KEM-768") == 0)
    {
        key_type = CKK_ML_KEM_768;
    }
    else if (strcasecmp(algorithm, "ML-KEM-1024") == 0)
    {
        key_type = CKK_ML_KEM_1024;
    }
    else if (strcasecmp(algorithm, "ML-DSA-44") == 0)
    {
        key_type = CKK_ML_DSA_44;
    }
    else if (strcasecmp(algorithm, "ML-DSA-65") == 0)
    {
        key_type = CKK_ML_DSA_65;
    }
    else if (strcasecmp(algorithm, "ML-DSA-87") == 0)
    {
        key_type = CKK_ML_DSA_87;
    }
    else
    {
        fprintf(stderr, "Unknown algorithm: %s\n", algorithm);
        return -1;
    }

    /* Read PEM file */
    f = fopen(input_file, "r");
    if (!f)
    {
        perror(input_file);
        return -1;
    }

    fseek(f, 0, SEEK_END);
    file_size = ftell(f);
    fseek(f, 0, SEEK_SET);

    pem_data = malloc(file_size + 1);
    if (!pem_data || fread(pem_data, 1, file_size, f) != (size_t)file_size)
    {
        fprintf(stderr, "Failed to read file\n");
        fclose(f);
        goto cleanup;
    }
    pem_data[file_size] = '\0';
    fclose(f);

    /* Check if private key */
    is_private = (strstr(pem_data, "PRIVATE KEY") != NULL);

    /* Find base64 data */
    char *start = strstr(pem_data, "-----BEGIN");
    if (start)
    {
        start = strchr(start, '\n');
        if (start)
            start++;
    }
    char *end = strstr(pem_data, "-----END");

    if (!start || !end || end <= start)
    {
        fprintf(stderr, "Invalid PEM format\n");
        goto cleanup;
    }

    /* Decode base64 */
    key_data = malloc(end - start);
    if (!key_data)
    {
        fprintf(stderr, "Memory allocation failed\n");
        goto cleanup;
    }

    key_len = base64_decode(start, key_data);
    if (key_len == 0)
    {
        fprintf(stderr, "Base64 decode failed\n");
        goto cleanup;
    }

    /* Open session */
    rv = g_p11->C_OpenSession(g_slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                              NULL, NULL, &session);
    if (rv != CKR_OK)
    {
        fprintf(stderr, "C_OpenSession failed\n");
        goto cleanup;
    }

    /* Login */
    if (g_pin)
    {
        rv = g_p11->C_Login(session, CKU_USER, (CK_UTF8CHAR_PTR)g_pin, strlen(g_pin));
        if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN)
        {
            fprintf(stderr, "C_Login failed\n");
            g_p11->C_CloseSession(session);
            goto cleanup;
        }
    }

    /* Create object */
    CK_OBJECT_CLASS cls = is_private ? CKO_PRIVATE_KEY : CKO_PUBLIC_KEY;
    CK_BBOOL ck_true = CK_TRUE;
    CK_BBOOL ck_false = CK_FALSE;

    CK_ATTRIBUTE attrs[] = {
        {CKA_CLASS, &cls, sizeof(cls)},
        {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
        {CKA_TOKEN, &ck_true, sizeof(ck_true)},
        {CKA_LABEL, (void *)label, strlen(label)},
        {CKA_VALUE, key_data, key_len},
        {CKA_PRIVATE, is_private ? &ck_true : &ck_false, sizeof(CK_BBOOL)},
        {CKA_SENSITIVE, is_private ? &ck_true : &ck_false, sizeof(CK_BBOOL)},
        {CKA_SIGN, is_private ? &ck_true : &ck_false, sizeof(CK_BBOOL)},
        {CKA_VERIFY, is_private ? &ck_false : &ck_true, sizeof(CK_BBOOL)}};

    rv = g_p11->C_CreateObject(session, attrs, 9, &key);
    if (rv != CKR_OK)
    {
        fprintf(stderr, "C_CreateObject failed: 0x%08lx\n", rv);
        g_p11->C_Logout(session);
        g_p11->C_CloseSession(session);
        goto cleanup;
    }

    printf("Imported %s key from %s\n", is_private ? "private" : "public", input_file);
    printf("  Label: %s\n", label);
    printf("  Algorithm: %s\n", algorithm);
    printf("  Handle: 0x%08lx\n", key);
    printf("  Size: %zu bytes\n", key_len);

    g_p11->C_Logout(session);
    g_p11->C_CloseSession(session);
    ret = 0;

cleanup:
    free(pem_data);
    free(key_data);
    return ret;
}

static int list_keys(void)
{
    CK_RV rv;
    CK_SESSION_HANDLE session;
    CK_OBJECT_HANDLE objects[256];
    CK_ULONG obj_count;

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

    /* Find all key objects */
    rv = g_p11->C_FindObjectsInit(session, NULL, 0);
    if (rv != CKR_OK)
    {
        g_p11->C_CloseSession(session);
        return -1;
    }

    rv = g_p11->C_FindObjects(session, objects, 256, &obj_count);
    g_p11->C_FindObjectsFinal(session);

    printf("Keys in Slot %lu:\n", g_slot);
    printf("================================================================================\n");
    printf("%-12s %-10s %-15s %-12s %s\n",
           "Handle", "Class", "Type", "Extractable", "Label");
    printf("--------------------------------------------------------------------------------\n");

    for (CK_ULONG i = 0; i < obj_count; i++)
    {
        CK_OBJECT_CLASS cls;
        CK_KEY_TYPE key_type = 0;
        CK_BYTE label[256] = {0};
        CK_BBOOL extractable = CK_FALSE;

        CK_ATTRIBUTE attrs[] = {
            {CKA_CLASS, &cls, sizeof(cls)},
            {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
            {CKA_LABEL, label, sizeof(label) - 1},
            {CKA_EXTRACTABLE, &extractable, sizeof(extractable)}};

        rv = g_p11->C_GetAttributeValue(session, objects[i], attrs, 4);
        if (rv != CKR_OK)
            continue;

        /* Only show keys */
        if (cls != CKO_PUBLIC_KEY && cls != CKO_PRIVATE_KEY && cls != CKO_SECRET_KEY)
        {
            continue;
        }

        const char *cls_name = (cls == CKO_PUBLIC_KEY) ? "Public" : (cls == CKO_PRIVATE_KEY) ? "Private"
                                                                                             : "Secret";

        printf("0x%08lx   %-10s %-15s %-12s %s\n",
               objects[i], cls_name, key_type_name(key_type),
               extractable ? "Yes" : "No",
               (char *)label);
    }

    g_p11->C_Logout(session);
    g_p11->C_CloseSession(session);
    return 0;
}

/* ==========================================================================
 * Main
 * ========================================================================== */

static void usage(const char *prog)
{
    printf("QUAC 100 PKCS#11 Key Import/Export Tool\n\n");
    printf("Usage: %s <command> [options]\n\n", prog);
    printf("Commands:\n");
    printf("  --export            Export a key to PEM file\n");
    printf("  --export-private    Export a private key (requires PIN)\n");
    printf("  --import            Import a key from PEM file\n");
    printf("  --list              List all keys\n");
    printf("\n");
    printf("Options:\n");
    printf("  -m, --module <path>     PKCS#11 module path\n");
    printf("  -s, --slot <num>        Slot number (default: 0)\n");
    printf("  -p, --pin <pin>         User PIN\n");
    printf("  -k, --key-label <label> Key label (for export)\n");
    printf("  -l, --label <label>     New key label (for import)\n");
    printf("  -a, --algorithm <alg>   Algorithm (for import)\n");
    printf("  -i, --input <file>      Input file (for import)\n");
    printf("  -o, --output <file>     Output file (for export)\n");
    printf("  -v, --verbose           Verbose output\n");
    printf("  -h, --help              Show this help\n");
    printf("\n");
    printf("Algorithms: ML-KEM-512, ML-KEM-768, ML-KEM-1024, ML-DSA-44, ML-DSA-65, ML-DSA-87\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s --list -p 1234\n", prog);
    printf("  %s --export -k mykey -o pubkey.pem\n", prog);
    printf("  %s --export-private -k mykey -o privkey.pem -p 1234\n", prog);
    printf("  %s --import -i key.pem -l imported -a ML-DSA-65 -p 1234\n", prog);
}

int main(int argc, char *argv[])
{
    int opt;
    int cmd = 0; /* 1=export, 2=export-private, 3=import, 4=list */
    const char *key_label = NULL;
    const char *new_label = NULL;
    const char *algorithm = "ML-DSA-65";
    const char *input_file = NULL;
    const char *output_file = NULL;

    static struct option long_opts[] = {
        {"export", no_argument, 0, 'E'},
        {"export-private", no_argument, 0, 'P'},
        {"import", no_argument, 0, 'I'},
        {"list", no_argument, 0, 'L'},
        {"module", required_argument, 0, 'm'},
        {"slot", required_argument, 0, 's'},
        {"pin", required_argument, 0, 'p'},
        {"key-label", required_argument, 0, 'k'},
        {"label", required_argument, 0, 'l'},
        {"algorithm", required_argument, 0, 'a'},
        {"input", required_argument, 0, 'i'},
        {"output", required_argument, 0, 'o'},
        {"verbose", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}};

    while ((opt = getopt_long(argc, argv, "EPILm:s:p:k:l:a:i:o:vh", long_opts, NULL)) != -1)
    {
        switch (opt)
        {
        case 'E':
            cmd = 1;
            break;
        case 'P':
            cmd = 2;
            break;
        case 'I':
            cmd = 3;
            break;
        case 'L':
            cmd = 4;
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
            key_label = optarg;
            break;
        case 'l':
            new_label = optarg;
            break;
        case 'a':
            algorithm = optarg;
            break;
        case 'i':
            input_file = optarg;
            break;
        case 'o':
            output_file = optarg;
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

    if (cmd == 0)
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
    case 1: /* export public */
        if (!key_label || !output_file)
        {
            fprintf(stderr, "Key label (-k) and output file (-o) required\n");
            ret = 1;
        }
        else
        {
            ret = export_key(key_label, output_file, 0);
        }
        break;
    case 2: /* export private */
        if (!key_label || !output_file)
        {
            fprintf(stderr, "Key label (-k) and output file (-o) required\n");
            ret = 1;
        }
        else if (!g_pin)
        {
            fprintf(stderr, "PIN required for private key export\n");
            ret = 1;
        }
        else
        {
            ret = export_key(key_label, output_file, 1);
        }
        break;
    case 3: /* import */
        if (!input_file || !new_label)
        {
            fprintf(stderr, "Input file (-i) and label (-l) required\n");
            ret = 1;
        }
        else
        {
            ret = import_key(input_file, new_label, algorithm);
        }
        break;
    case 4: /* list */
        ret = list_keys();
        break;
    default:
        ret = 1;
    }

    unload_module();
    return ret == 0 ? 0 : 1;
}