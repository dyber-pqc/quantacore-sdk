/**
 * @file D:\quantacore-sdk\integrations\pkcs11\examples\p11_random.c
 * @brief QUAC 100 PKCS#11 - Random Number Generation Example
 *
 * Demonstrates quantum random number generation through PKCS#11.
 *
 * Usage:
 *   p11_random --bytes 32
 *   p11_random --bytes 1024 --output random.bin
 *   p11_random --seed random_seed.bin
 *
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
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
    }
    if (g_module)
    {
        CLOSE_LIBRARY(g_module);
    }
}

/* ==========================================================================
 * Random Operations
 * ========================================================================== */

static int check_rng_support(void)
{
    CK_RV rv;
    CK_TOKEN_INFO token_info;

    rv = g_p11->C_GetTokenInfo(g_slot, &token_info);
    if (rv != CKR_OK)
    {
        fprintf(stderr, "C_GetTokenInfo failed\n");
        return 0;
    }

    if (!(token_info.flags & CKF_RNG))
    {
        fprintf(stderr, "Token does not support random number generation\n");
        return 0;
    }

    if (g_verbose)
    {
        char label[33];
        memcpy(label, token_info.label, 32);
        label[32] = '\0';
        /* Trim trailing spaces */
        for (int i = 31; i >= 0 && label[i] == ' '; i--)
        {
            label[i] = '\0';
        }
        printf("Token: %s\n", label);
        printf("RNG supported: Yes\n\n");
    }

    return 1;
}

static int generate_random(size_t num_bytes, const char *output_file, int hex_output)
{
    CK_RV rv;
    CK_SESSION_HANDLE session;
    unsigned char *buffer;
    FILE *f = NULL;
    int ret = -1;
    size_t chunk_size = 4096;
    size_t remaining = num_bytes;
    size_t offset = 0;

    if (!check_rng_support())
    {
        return -1;
    }

    buffer = malloc(num_bytes);
    if (!buffer)
    {
        fprintf(stderr, "Memory allocation failed\n");
        return -1;
    }

    rv = g_p11->C_OpenSession(g_slot, CKF_SERIAL_SESSION, NULL, NULL, &session);
    if (rv != CKR_OK)
    {
        fprintf(stderr, "C_OpenSession failed\n");
        free(buffer);
        return -1;
    }

    if (g_verbose)
    {
        printf("Generating %zu bytes of random data...\n", num_bytes);
    }

    /* Generate in chunks for large requests */
    while (remaining > 0)
    {
        size_t to_generate = (remaining > chunk_size) ? chunk_size : remaining;

        rv = g_p11->C_GenerateRandom(session, buffer + offset, to_generate);
        if (rv != CKR_OK)
        {
            fprintf(stderr, "C_GenerateRandom failed\n");
            goto cleanup;
        }

        offset += to_generate;
        remaining -= to_generate;

        if (g_verbose && num_bytes > chunk_size)
        {
            printf("\r  Progress: %zu / %zu bytes", offset, num_bytes);
            fflush(stdout);
        }
    }

    if (g_verbose && num_bytes > chunk_size)
    {
        printf("\n");
    }

    /* Output */
    if (output_file)
    {
        f = fopen(output_file, "wb");
        if (!f)
        {
            perror(output_file);
            goto cleanup;
        }
        if (fwrite(buffer, 1, num_bytes, f) != num_bytes)
        {
            fprintf(stderr, "Failed to write output\n");
            fclose(f);
            goto cleanup;
        }
        fclose(f);
        printf("Wrote %zu bytes to %s\n", num_bytes, output_file);
    }
    else if (hex_output)
    {
        for (size_t i = 0; i < num_bytes; i++)
        {
            printf("%02x", buffer[i]);
            if ((i + 1) % 32 == 0)
                printf("\n");
        }
        if (num_bytes % 32 != 0)
            printf("\n");
    }
    else
    {
        /* Binary to stdout - be careful */
        if (fwrite(buffer, 1, num_bytes, stdout) != num_bytes)
        {
            fprintf(stderr, "Failed to write output\n");
            goto cleanup;
        }
    }

    ret = 0;

cleanup:
    /* Secure cleanup */
    memset(buffer, 0, num_bytes);
    free(buffer);
    g_p11->C_CloseSession(session);
    return ret;
}

static int seed_random(const char *seed_file)
{
    CK_RV rv;
    CK_SESSION_HANDLE session;
    FILE *f;
    unsigned char seed[256];
    size_t seed_len;
    int ret = -1;

    f = fopen(seed_file, "rb");
    if (!f)
    {
        perror(seed_file);
        return -1;
    }

    seed_len = fread(seed, 1, sizeof(seed), f);
    fclose(f);

    if (seed_len == 0)
    {
        fprintf(stderr, "Empty seed file\n");
        return -1;
    }

    rv = g_p11->C_OpenSession(g_slot, CKF_SERIAL_SESSION, NULL, NULL, &session);
    if (rv != CKR_OK)
    {
        fprintf(stderr, "C_OpenSession failed\n");
        return -1;
    }

    if (g_verbose)
    {
        printf("Seeding RNG with %zu bytes...\n", seed_len);
    }

    rv = g_p11->C_SeedRandom(session, seed, seed_len);
    if (rv == CKR_RANDOM_SEED_NOT_SUPPORTED)
    {
        printf("Note: Token RNG does not accept external seed (uses hardware entropy)\n");
        ret = 0; /* Not an error for hardware RNG */
    }
    else if (rv != CKR_OK)
    {
        fprintf(stderr, "C_SeedRandom failed\n");
    }
    else
    {
        printf("RNG seeded successfully\n");
        ret = 0;
    }

    /* Secure cleanup */
    memset(seed, 0, sizeof(seed));
    g_p11->C_CloseSession(session);
    return ret;
}

static int benchmark_random(size_t total_bytes, size_t chunk_size)
{
    CK_RV rv;
    CK_SESSION_HANDLE session;
    unsigned char *buffer;
    clock_t start, end;
    double elapsed;
    size_t generated = 0;
    int ret = -1;

    if (!check_rng_support())
    {
        return -1;
    }

    buffer = malloc(chunk_size);
    if (!buffer)
    {
        fprintf(stderr, "Memory allocation failed\n");
        return -1;
    }

    rv = g_p11->C_OpenSession(g_slot, CKF_SERIAL_SESSION, NULL, NULL, &session);
    if (rv != CKR_OK)
    {
        fprintf(stderr, "C_OpenSession failed\n");
        free(buffer);
        return -1;
    }

    printf("Benchmarking RNG...\n");
    printf("  Total: %zu bytes\n", total_bytes);
    printf("  Chunk: %zu bytes\n\n", chunk_size);

    start = clock();

    while (generated < total_bytes)
    {
        size_t to_generate = ((total_bytes - generated) > chunk_size) ? chunk_size : (total_bytes - generated);

        rv = g_p11->C_GenerateRandom(session, buffer, to_generate);
        if (rv != CKR_OK)
        {
            fprintf(stderr, "C_GenerateRandom failed\n");
            goto cleanup;
        }

        generated += to_generate;
    }

    end = clock();
    elapsed = (double)(end - start) / CLOCKS_PER_SEC;

    printf("Results:\n");
    printf("  Time: %.3f seconds\n", elapsed);
    printf("  Throughput: %.2f MB/s\n", (total_bytes / (1024.0 * 1024.0)) / elapsed);
    printf("  Throughput: %.2f Mbit/s\n", (total_bytes * 8.0 / (1024.0 * 1024.0)) / elapsed);

    ret = 0;

cleanup:
    memset(buffer, 0, chunk_size);
    free(buffer);
    g_p11->C_CloseSession(session);
    return ret;
}

static int entropy_test(size_t num_bytes)
{
    CK_RV rv;
    CK_SESSION_HANDLE session;
    unsigned char *buffer;
    unsigned long counts[256] = {0};
    double expected, chi_square = 0;
    int ret = -1;

    if (num_bytes < 256)
    {
        fprintf(stderr, "Need at least 256 bytes for entropy test\n");
        return -1;
    }

    if (!check_rng_support())
    {
        return -1;
    }

    buffer = malloc(num_bytes);
    if (!buffer)
    {
        fprintf(stderr, "Memory allocation failed\n");
        return -1;
    }

    rv = g_p11->C_OpenSession(g_slot, CKF_SERIAL_SESSION, NULL, NULL, &session);
    if (rv != CKR_OK)
    {
        fprintf(stderr, "C_OpenSession failed\n");
        free(buffer);
        return -1;
    }

    printf("Running entropy test with %zu bytes...\n\n", num_bytes);

    rv = g_p11->C_GenerateRandom(session, buffer, num_bytes);
    if (rv != CKR_OK)
    {
        fprintf(stderr, "C_GenerateRandom failed\n");
        goto cleanup;
    }

    /* Count byte frequencies */
    for (size_t i = 0; i < num_bytes; i++)
    {
        counts[buffer[i]]++;
    }

    /* Chi-square test */
    expected = num_bytes / 256.0;
    for (int i = 0; i < 256; i++)
    {
        double diff = counts[i] - expected;
        chi_square += (diff * diff) / expected;
    }

    /* Calculate entropy estimate */
    double entropy = 0;
    for (int i = 0; i < 256; i++)
    {
        if (counts[i] > 0)
        {
            double p = counts[i] / (double)num_bytes;
            entropy -= p * log2(p);
        }
    }

    printf("Entropy Analysis:\n");
    printf("  Sample size: %zu bytes\n", num_bytes);
    printf("  Chi-square: %.2f (expected ~255 for uniform)\n", chi_square);
    printf("  Entropy: %.4f bits/byte (ideal: 8.0)\n", entropy);
    printf("  Compression estimate: %.1f%%\n", (1.0 - entropy / 8.0) * 100);
    printf("\n");

    /* Simple assessment */
    if (chi_square < 200 || chi_square > 330)
    {
        printf("⚠ Chi-square outside expected range (may indicate non-random data)\n");
    }
    else
    {
        printf("✓ Chi-square within normal range\n");
    }

    if (entropy < 7.9)
    {
        printf("⚠ Entropy below optimal (%.4f < 7.9)\n", entropy);
    }
    else
    {
        printf("✓ Entropy is excellent (%.4f ≈ 8.0)\n", entropy);
    }

    ret = 0;

cleanup:
    memset(buffer, 0, num_bytes);
    free(buffer);
    g_p11->C_CloseSession(session);
    return ret;
}

/* ==========================================================================
 * Main
 * ========================================================================== */

static void usage(const char *prog)
{
    printf("QUAC 100 PKCS#11 Random Number Generator\n\n");
    printf("Usage: %s [command] [options]\n\n", prog);
    printf("Commands:\n");
    printf("  --generate            Generate random bytes (default)\n");
    printf("  --seed <file>         Seed the RNG from file\n");
    printf("  --benchmark           Benchmark RNG throughput\n");
    printf("  --entropy-test        Test RNG entropy quality\n");
    printf("\n");
    printf("Options:\n");
    printf("  -m, --module <path>   PKCS#11 module path\n");
    printf("  -s, --slot <num>      Slot number (default: 0)\n");
    printf("  -n, --bytes <num>     Number of bytes (default: 32)\n");
    printf("  -o, --output <file>   Output file (binary)\n");
    printf("  -x, --hex             Output as hexadecimal\n");
    printf("  -c, --chunk <size>    Chunk size for benchmark (default: 4096)\n");
    printf("  -v, --verbose         Verbose output\n");
    printf("  -h, --help            Show this help\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s -n 64 -x                    # 64 bytes, hex output\n", prog);
    printf("  %s -n 1048576 -o random.bin    # 1MB to file\n", prog);
    printf("  %s --benchmark -n 10485760     # Benchmark 10MB\n", prog);
    printf("  %s --entropy-test -n 100000    # Test 100KB\n", prog);
}

#include <math.h>

int main(int argc, char *argv[])
{
    int opt;
    int mode = 0; /* 0=generate, 1=seed, 2=benchmark, 3=entropy */
    size_t num_bytes = 32;
    size_t chunk_size = 4096;
    const char *output_file = NULL;
    const char *seed_file = NULL;
    int hex_output = 0;

    static struct option long_opts[] = {
        {"generate", no_argument, 0, 'G'},
        {"seed", required_argument, 0, 'S'},
        {"benchmark", no_argument, 0, 'B'},
        {"entropy-test", no_argument, 0, 'E'},
        {"module", required_argument, 0, 'm'},
        {"slot", required_argument, 0, 's'},
        {"bytes", required_argument, 0, 'n'},
        {"output", required_argument, 0, 'o'},
        {"hex", no_argument, 0, 'x'},
        {"chunk", required_argument, 0, 'c'},
        {"verbose", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}};

    while ((opt = getopt_long(argc, argv, "GS:BEm:s:n:o:xc:vh", long_opts, NULL)) != -1)
    {
        switch (opt)
        {
        case 'G':
            mode = 0;
            break;
        case 'S':
            mode = 1;
            seed_file = optarg;
            break;
        case 'B':
            mode = 2;
            break;
        case 'E':
            mode = 3;
            break;
        case 'm':
            g_module_path = optarg;
            break;
        case 's':
            g_slot = atoi(optarg);
            break;
        case 'n':
            num_bytes = strtoul(optarg, NULL, 0);
            break;
        case 'o':
            output_file = optarg;
            break;
        case 'x':
            hex_output = 1;
            break;
        case 'c':
            chunk_size = strtoul(optarg, NULL, 0);
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

    if (num_bytes == 0)
    {
        fprintf(stderr, "Invalid byte count\n");
        return 1;
    }

    if (load_module() != 0)
    {
        return 1;
    }

    int ret;
    switch (mode)
    {
    case 0:
        ret = generate_random(num_bytes, output_file, hex_output);
        break;
    case 1:
        ret = seed_random(seed_file);
        break;
    case 2:
        ret = benchmark_random(num_bytes, chunk_size);
        break;
    case 3:
        ret = entropy_test(num_bytes);
        break;
    default:
        ret = -1;
    }

    unload_module();
    return ret == 0 ? 0 : 1;
}