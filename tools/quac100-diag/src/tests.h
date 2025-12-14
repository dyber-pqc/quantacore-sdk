/**
 * @file tests.h
 * @brief QUAC 100 Diagnostics - Test Definitions
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#ifndef QUAC_DIAG_TESTS_H
#define QUAC_DIAG_TESTS_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "diag.h"

#ifdef __cplusplus
extern "C"
{
#endif

    /*=============================================================================
     * Test Status
     *=============================================================================*/

#define TEST_PASS 0
#define TEST_FAIL 1
#define TEST_SKIP 2

    /*=============================================================================
     * Test Result
     *=============================================================================*/

#define MAX_TEST_NAME 64
#define MAX_TEST_MESSAGE 256

    typedef struct
    {
        char name[MAX_TEST_NAME];
        int status;
        char message[MAX_TEST_MESSAGE];
        long duration_ms;
    } test_result_t;

    /*=============================================================================
     * Test List
     *=============================================================================*/

#define MAX_TESTS 128

    typedef struct
    {
        char *names[MAX_TESTS];
        int count;
    } test_list_t;

    /**
     * @brief Create empty test list
     */
    test_list_t *test_list_create(void);

    /**
     * @brief Destroy test list
     */
    void test_list_destroy(test_list_t *list);

    /**
     * @brief Add test to list
     */
    int test_list_add(test_list_t *list, const char *name);

    /**
     * @brief Check if test is in list
     */
    bool test_list_contains(test_list_t *list, const char *name);

    /*=============================================================================
     * Test Results Collection
     *=============================================================================*/

    typedef struct
    {
        test_result_t *results;
        int count;
        int capacity;
    } test_results_t;

    /**
     * @brief Create results container
     */
    test_results_t *test_results_create(void);

    /**
     * @brief Destroy results container
     */
    void test_results_destroy(test_results_t *results);

    /**
     * @brief Add result to container
     */
    int test_results_add(test_results_t *results, const test_result_t *result);

    /**
     * @brief Get pass count
     */
    int test_results_pass_count(test_results_t *results);

    /**
     * @brief Get fail count
     */
    int test_results_fail_count(test_results_t *results);

    /*=============================================================================
     * Test Execution
     *=============================================================================*/

    /**
     * @brief Print list of available tests
     */
    void tests_print_list(void);

    /**
     * @brief Run a single test by name
     */
    int tests_run_one(diag_context_t *ctx, const char *name, test_result_t *result);

    /**
     * @brief Check if test name is valid
     */
    bool tests_is_valid(const char *name);

    /*=============================================================================
     * Test Categories
     *=============================================================================*/

    typedef int (*test_func_t)(diag_context_t *ctx, test_result_t *result);

    typedef struct
    {
        const char *name;
        const char *description;
        test_func_t func;
    } test_entry_t;

    /* Hardware Tests */
    int test_hw_pcie(diag_context_t *ctx, test_result_t *result);
    int test_hw_registers(diag_context_t *ctx, test_result_t *result);
    int test_hw_memory(diag_context_t *ctx, test_result_t *result);
    int test_hw_dma(diag_context_t *ctx, test_result_t *result);
    int test_hw_interrupt(diag_context_t *ctx, test_result_t *result);
    int test_hw_temperature(diag_context_t *ctx, test_result_t *result);
    int test_hw_voltage(diag_context_t *ctx, test_result_t *result);
    int test_hw_clock(diag_context_t *ctx, test_result_t *result);

    /* KEM Tests */
    int test_kem_mlkem512_kat(diag_context_t *ctx, test_result_t *result);
    int test_kem_mlkem768_kat(diag_context_t *ctx, test_result_t *result);
    int test_kem_mlkem1024_kat(diag_context_t *ctx, test_result_t *result);
    int test_kem_roundtrip(diag_context_t *ctx, test_result_t *result);
    int test_kem_invalid(diag_context_t *ctx, test_result_t *result);

    /* Signature Tests */
    int test_sign_mldsa44_kat(diag_context_t *ctx, test_result_t *result);
    int test_sign_mldsa65_kat(diag_context_t *ctx, test_result_t *result);
    int test_sign_mldsa87_kat(diag_context_t *ctx, test_result_t *result);
    int test_sign_slhdsa_kat(diag_context_t *ctx, test_result_t *result);
    int test_sign_roundtrip(diag_context_t *ctx, test_result_t *result);
    int test_sign_invalid(diag_context_t *ctx, test_result_t *result);

    /* QRNG Tests */
    int test_random_basic(diag_context_t *ctx, test_result_t *result);
    int test_random_monobit(diag_context_t *ctx, test_result_t *result);
    int test_random_runs(diag_context_t *ctx, test_result_t *result);
    int test_random_entropy(diag_context_t *ctx, test_result_t *result);
    int test_random_repetition(diag_context_t *ctx, test_result_t *result);
    int test_random_adaptive(diag_context_t *ctx, test_result_t *result);

    /* Performance Tests */
    int test_perf_kem_throughput(diag_context_t *ctx, test_result_t *result);
    int test_perf_kem_latency(diag_context_t *ctx, test_result_t *result);
    int test_perf_sign_throughput(diag_context_t *ctx, test_result_t *result);
    int test_perf_sign_latency(diag_context_t *ctx, test_result_t *result);
    int test_perf_random_throughput(diag_context_t *ctx, test_result_t *result);
    int test_perf_batch(diag_context_t *ctx, test_result_t *result);

    /* Stress Tests */
    int test_stress_continuous(diag_context_t *ctx, test_result_t *result);
    int test_stress_thermal(diag_context_t *ctx, test_result_t *result);
    int test_stress_memory(diag_context_t *ctx, test_result_t *result);
    int test_stress_concurrent(diag_context_t *ctx, test_result_t *result);

#ifdef __cplusplus
}
#endif

#endif /* QUAC_DIAG_TESTS_H */