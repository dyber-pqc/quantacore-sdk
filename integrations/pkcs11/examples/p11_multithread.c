/**
 * @file D:\quantacore-sdk\integrations\pkcs11\examples\p11_multithread.c
 * @brief QUAC 100 PKCS#11 - Multi-threaded Operations Example
 *
 * Demonstrates concurrent PKCS#11 operations across multiple threads.
 *
 * Usage:
 *   p11_multithread --threads 8 --iterations 100 -p 1234
 *
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
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
 * Mechanism Definitions
 * ========================================================================== */

#define CKM_ML_DSA_65_KEYGEN 0x80002002UL
#define CKM_ML_DSA_65 0x80002012UL
#define CKK_ML_DSA_65 0x80000012UL

/* ==========================================================================
 * Global State
 * ========================================================================== */

static lib_handle_t g_module = NULL;
static CK_FUNCTION_LIST_PTR g_p11 = NULL;
static const char *g_module_path = NULL;
static CK_SLOT_ID g_slot = 0;
static const char *g_pin = NULL;
static int g_num_threads = 4;
static int g_iterations = 100;
static int g_verbose = 0;

/* Shared key handles (protected by mutex) */
static CK_OBJECT_HANDLE g_pub_key = CK_INVALID_HANDLE;
static CK_OBJECT_HANDLE g_priv_key = CK_INVALID_HANDLE;
static pthread_mutex_t g_key_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Statistics */
typedef struct
{
    int thread_id;
    int sign_count;
    int verify_count;
    int error_count;
    double total_sign_time;
    double total_verify_time;
} thread_stats_t;

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

    /* Initialize with locking callbacks for thread safety */
    CK_C_INITIALIZE_ARGS init_args;
    memset(&init_args, 0, sizeof(init_args));
    init_args.flags = CKF_OS_LOCKING_OK;

    rv = g_p11->C_Initialize(&init_args);
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
 * Timing
 * ========================================================================== */

static double get_time(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

/* ==========================================================================
 * Worker Thread
 * ========================================================================== */

static void *worker_thread(void *arg)
{
    thread_stats_t *stats = (thread_stats_t *)arg;
    CK_RV rv;
    CK_SESSION_HANDLE session;
    CK_MECHANISM mech = {CKM_ML_DSA_65, NULL, 0};
    CK_BYTE data[32];
    CK_BYTE signature[4096];
    CK_ULONG sig_len;
    double t0, t1;

    /* Each thread gets its own session */
    rv = g_p11->C_OpenSession(g_slot, CKF_SERIAL_SESSION, NULL, NULL, &session);
    if (rv != CKR_OK)
    {
        fprintf(stderr, "Thread %d: C_OpenSession failed\n", stats->thread_id);
        stats->error_count++;
        return NULL;
    }

    /* Login (each session needs to login independently or share) */
    if (g_pin)
    {
        rv = g_p11->C_Login(session, CKU_USER, (CK_UTF8CHAR_PTR)g_pin, strlen(g_pin));
        if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN)
        {
            fprintf(stderr, "Thread %d: C_Login failed\n", stats->thread_id);
            g_p11->C_CloseSession(session);
            stats->error_count++;
            return NULL;
        }
    }

    /* Run iterations */
    for (int i = 0; i < g_iterations; i++)
    {
        /* Generate random data to sign */
        rv = g_p11->C_GenerateRandom(session, data, sizeof(data));
        if (rv != CKR_OK)
        {
            if (g_verbose)
            {
                fprintf(stderr, "Thread %d: C_GenerateRandom failed\n", stats->thread_id);
            }
            /* Use pseudo-random as fallback */
            for (int j = 0; j < (int)sizeof(data); j++)
            {
                data[j] = rand() & 0xFF;
            }
        }

        /* Sign */
        t0 = get_time();

        rv = g_p11->C_SignInit(session, &mech, g_priv_key);
        if (rv != CKR_OK)
        {
            stats->error_count++;
            continue;
        }

        sig_len = sizeof(signature);
        rv = g_p11->C_Sign(session, data, sizeof(data), signature, &sig_len);
        if (rv != CKR_OK)
        {
            stats->error_count++;
            continue;
        }

        t1 = get_time();
        stats->total_sign_time += (t1 - t0);
        stats->sign_count++;

        /* Verify */
        t0 = get_time();

        rv = g_p11->C_VerifyInit(session, &mech, g_pub_key);
        if (rv != CKR_OK)
        {
            stats->error_count++;
            continue;
        }

        rv = g_p11->C_Verify(session, data, sizeof(data), signature, sig_len);
        if (rv != CKR_OK)
        {
            if (g_verbose)
            {
                fprintf(stderr, "Thread %d: Verify failed (iteration %d)\n",
                        stats->thread_id, i);
            }
            stats->error_count++;
            continue;
        }

        t1 = get_time();
        stats->total_verify_time += (t1 - t0);
        stats->verify_count++;

        if (g_verbose && (i + 1) % 10 == 0)
        {
            printf("Thread %d: Completed %d iterations\n", stats->thread_id, i + 1);
        }
    }

    g_p11->C_CloseSession(session);
    return NULL;
}

/* ==========================================================================
 * Main
 * ========================================================================== */

static void usage(const char *prog)
{
    printf("QUAC 100 PKCS#11 Multi-threaded Example\n\n");
    printf("Usage: %s [options]\n\n", prog);
    printf("Options:\n");
    printf("  -m, --module <path>      PKCS#11 module path\n");
    printf("  -s, --slot <num>         Slot number (default: 0)\n");
    printf("  -p, --pin <pin>          User PIN\n");
    printf("  -t, --threads <num>      Number of threads (default: 4)\n");
    printf("  -n, --iterations <num>   Iterations per thread (default: 100)\n");
    printf("  -v, --verbose            Verbose output\n");
    printf("  -h, --help               Show this help\n");
    printf("\n");
    printf("Example:\n");
    printf("  %s -t 8 -n 1000 -p 1234\n", prog);
}

int main(int argc, char *argv[])
{
    int opt;
    pthread_t *threads = NULL;
    thread_stats_t *stats = NULL;
    CK_RV rv;
    CK_SESSION_HANDLE session;
    CK_MECHANISM keygen_mech = {CKM_ML_DSA_65_KEYGEN, NULL, 0};
    double start_time, end_time;
    int ret = -1;

    static struct option long_opts[] = {
        {"module", required_argument, 0, 'm'},
        {"slot", required_argument, 0, 's'},
        {"pin", required_argument, 0, 'p'},
        {"threads", required_argument, 0, 't'},
        {"iterations", required_argument, 0, 'n'},
        {"verbose", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}};

    while ((opt = getopt_long(argc, argv, "m:s:p:t:n:vh", long_opts, NULL)) != -1)
    {
        switch (opt)
        {
        case 'm':
            g_module_path = optarg;
            break;
        case 's':
            g_slot = atoi(optarg);
            break;
        case 'p':
            g_pin = optarg;
            break;
        case 't':
            g_num_threads = atoi(optarg);
            break;
        case 'n':
            g_iterations = atoi(optarg);
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

    if (g_num_threads < 1 || g_num_threads > 64)
    {
        fprintf(stderr, "Invalid thread count (1-64)\n");
        return 1;
    }

    if (g_iterations < 1)
    {
        fprintf(stderr, "Invalid iteration count\n");
        return 1;
    }

    printf("=== PKCS#11 Multi-threaded Test ===\n\n");
    printf("Configuration:\n");
    printf("  Threads: %d\n", g_num_threads);
    printf("  Iterations per thread: %d\n", g_iterations);
    printf("  Total operations: %d sign + %d verify\n\n",
           g_num_threads * g_iterations, g_num_threads * g_iterations);

    /* Load module */
    if (load_module() != 0)
    {
        return 1;
    }

    /* Open session for key generation */
    rv = g_p11->C_OpenSession(g_slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                              NULL, NULL, &session);
    if (rv != CKR_OK)
    {
        fprintf(stderr, "C_OpenSession failed\n");
        goto cleanup;
    }

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

    /* Generate shared key pair */
    printf("Generating ML-DSA-65 key pair...\n");

    CK_BBOOL ck_true = CK_TRUE;
    CK_ATTRIBUTE pub_attrs[] = {
        {CKA_TOKEN, &ck_true, sizeof(ck_true)},
        {CKA_VERIFY, &ck_true, sizeof(ck_true)},
        {CKA_LABEL, "mt-test-key", 11}};
    CK_ATTRIBUTE priv_attrs[] = {
        {CKA_TOKEN, &ck_true, sizeof(ck_true)},
        {CKA_SIGN, &ck_true, sizeof(ck_true)},
        {CKA_SENSITIVE, &ck_true, sizeof(ck_true)},
        {CKA_LABEL, "mt-test-key", 11}};

    rv = g_p11->C_GenerateKeyPair(session, &keygen_mech,
                                  pub_attrs, 3, priv_attrs, 4,
                                  &g_pub_key, &g_priv_key);
    if (rv != CKR_OK)
    {
        fprintf(stderr, "C_GenerateKeyPair failed\n");
        g_p11->C_CloseSession(session);
        goto cleanup;
    }

    printf("Key pair generated (pub: 0x%08lx, priv: 0x%08lx)\n\n", g_pub_key, g_priv_key);

    g_p11->C_CloseSession(session);

    /* Allocate threads and stats */
    threads = calloc(g_num_threads, sizeof(pthread_t));
    stats = calloc(g_num_threads, sizeof(thread_stats_t));
    if (!threads || !stats)
    {
        fprintf(stderr, "Memory allocation failed\n");
        goto cleanup;
    }

    /* Start worker threads */
    printf("Starting %d worker threads...\n\n", g_num_threads);
    start_time = get_time();

    for (int i = 0; i < g_num_threads; i++)
    {
        stats[i].thread_id = i;
        if (pthread_create(&threads[i], NULL, worker_thread, &stats[i]) != 0)
        {
            fprintf(stderr, "Failed to create thread %d\n", i);
            goto cleanup;
        }
    }

    /* Wait for threads */
    for (int i = 0; i < g_num_threads; i++)
    {
        pthread_join(threads[i], NULL);
    }

    end_time = get_time();

    /* Aggregate results */
    int total_sign = 0, total_verify = 0, total_errors = 0;
    double total_sign_time = 0, total_verify_time = 0;

    printf("\nPer-thread Results:\n");
    printf("------------------------------------------------------------------------\n");
    printf("Thread  Signs   Verifies  Errors  Sign Avg (µs)  Verify Avg (µs)\n");
    printf("------------------------------------------------------------------------\n");

    for (int i = 0; i < g_num_threads; i++)
    {
        double sign_avg = stats[i].sign_count > 0 ? (stats[i].total_sign_time / stats[i].sign_count) * 1e6 : 0;
        double verify_avg = stats[i].verify_count > 0 ? (stats[i].total_verify_time / stats[i].verify_count) * 1e6 : 0;

        printf("  %3d   %5d    %5d     %3d     %10.2f     %10.2f\n",
               i, stats[i].sign_count, stats[i].verify_count,
               stats[i].error_count, sign_avg, verify_avg);

        total_sign += stats[i].sign_count;
        total_verify += stats[i].verify_count;
        total_errors += stats[i].error_count;
        total_sign_time += stats[i].total_sign_time;
        total_verify_time += stats[i].total_verify_time;
    }

    printf("------------------------------------------------------------------------\n\n");

    double elapsed = end_time - start_time;
    printf("Aggregate Results:\n");
    printf("  Total time: %.3f seconds\n", elapsed);
    printf("  Total signs: %d\n", total_sign);
    printf("  Total verifies: %d\n", total_verify);
    printf("  Total errors: %d\n", total_errors);
    printf("  Signs/second: %.2f\n", total_sign / elapsed);
    printf("  Verifies/second: %.2f\n", total_verify / elapsed);
    printf("  Avg sign time: %.2f µs\n",
           total_sign > 0 ? (total_sign_time / total_sign) * 1e6 : 0);
    printf("  Avg verify time: %.2f µs\n",
           total_verify > 0 ? (total_verify_time / total_verify) * 1e6 : 0);

    if (total_errors == 0)
    {
        printf("\n✓ All operations completed successfully!\n");
        ret = 0;
    }
    else
    {
        printf("\n✗ %d errors occurred\n", total_errors);
        ret = 1;
    }

cleanup:
    /* Delete test key */
    if (g_pub_key != CK_INVALID_HANDLE || g_priv_key != CK_INVALID_HANDLE)
    {
        rv = g_p11->C_OpenSession(g_slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                  NULL, NULL, &session);
        if (rv == CKR_OK)
        {
            if (g_pin)
            {
                g_p11->C_Login(session, CKU_USER, (CK_UTF8CHAR_PTR)g_pin, strlen(g_pin));
            }
            if (g_pub_key != CK_INVALID_HANDLE)
            {
                g_p11->C_DestroyObject(session, g_pub_key);
            }
            if (g_priv_key != CK_INVALID_HANDLE)
            {
                g_p11->C_DestroyObject(session, g_priv_key);
            }
            g_p11->C_Logout(session);
            g_p11->C_CloseSession(session);
        }
    }

    free(threads);
    free(stats);
    unload_module();
    return ret;
}