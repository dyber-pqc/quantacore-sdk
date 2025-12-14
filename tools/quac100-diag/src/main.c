/**
 * @file main.c
 * @brief QUAC 100 Diagnostics - Main Entry Point
 *
 * Comprehensive hardware diagnostics and testing utility.
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <getopt.h>

#include "diag.h"
#include "tests.h"
#include "hardware.h"
#include "report.h"
#include "utils.h"

/*=============================================================================
 * Version Information
 *=============================================================================*/

#define DIAG_VERSION_MAJOR 1
#define DIAG_VERSION_MINOR 0
#define DIAG_VERSION_PATCH 0

/*=============================================================================
 * Global State
 *=============================================================================*/

static volatile bool g_interrupted = false;

static diag_options_t g_options = {
    .device_index = 0,
    .use_simulator = false,
    .verbose = false,
    .continuous = false,
    .timeout_sec = 0,
    .output_file = NULL,
    .format = REPORT_TEXT};

/*=============================================================================
 * Signal Handler
 *=============================================================================*/

static void signal_handler(int sig)
{
    (void)sig;
    g_interrupted = true;
    printf("\nInterrupted. Finishing current test...\n");
}

/*=============================================================================
 * Command Line
 *=============================================================================*/

static const char *short_opts = "d:saqfSlo:F:vct:hV";

static struct option long_opts[] = {
    {"device", required_argument, NULL, 'd'},
    {"simulator", no_argument, NULL, 's'},
    {"all", no_argument, NULL, 'a'},
    {"quick", no_argument, NULL, 'q'},
    {"full", no_argument, NULL, 'f'},
    {"stress", no_argument, NULL, 'S'},
    {"list-tests", no_argument, NULL, 'l'},
    {"list-devices", no_argument, NULL, 'D'},
    {"output", required_argument, NULL, 'o'},
    {"format", required_argument, NULL, 'F'},
    {"verbose", no_argument, NULL, 'v'},
    {"continuous", no_argument, NULL, 'c'},
    {"timeout", required_argument, NULL, 't'},
    {"help", no_argument, NULL, 'h'},
    {"version", no_argument, NULL, 'V'},
    {NULL, 0, NULL, 0}};

static void print_usage(const char *prog)
{
    printf("Usage: %s [OPTIONS] [TEST...]\n", prog);
    printf("\n");
    printf("QUAC 100 Hardware Diagnostics Tool\n");
    printf("\n");
    printf("Options:\n");
    printf("  -d, --device <index>   Select device by index (default: 0)\n");
    printf("  -s, --simulator        Use software simulator\n");
    printf("  -a, --all              Run all tests\n");
    printf("  -q, --quick            Quick test suite (basic validation)\n");
    printf("  -f, --full             Full test suite (comprehensive)\n");
    printf("  -S, --stress           Stress test suite (extended)\n");
    printf("  -l, --list-tests       List available tests\n");
    printf("      --list-devices     List available devices\n");
    printf("  -o, --output <file>    Output report to file\n");
    printf("  -F, --format <fmt>     Report format: text, json, html\n");
    printf("  -v, --verbose          Verbose output\n");
    printf("  -c, --continuous       Run tests continuously\n");
    printf("  -t, --timeout <sec>    Test timeout in seconds\n");
    printf("  -h, --help             Show help\n");
    printf("  -V, --version          Show version\n");
    printf("\n");
    printf("Test Categories:\n");
    printf("  hw                     Hardware tests\n");
    printf("  kem                    KEM algorithm tests\n");
    printf("  sign                   Signature algorithm tests\n");
    printf("  random                 QRNG tests\n");
    printf("  perf                   Performance tests\n");
    printf("  stress                 Stress tests\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s -q                  Quick hardware check\n", prog);
    printf("  %s -f -o report.txt    Full test with report\n", prog);
    printf("  %s hw kem.roundtrip    Run specific tests\n", prog);
    printf("  %s -S -t 3600          1-hour stress test\n", prog);
}

static void print_version(void)
{
    printf("quac100-diag %d.%d.%d\n",
           DIAG_VERSION_MAJOR, DIAG_VERSION_MINOR, DIAG_VERSION_PATCH);
    printf("QUAC 100 Hardware Diagnostics Tool\n");
    printf("Copyright 2025 Dyber, Inc. All Rights Reserved.\n");
}

static report_format_t parse_format(const char *str)
{
    if (strcmp(str, "text") == 0)
        return REPORT_TEXT;
    if (strcmp(str, "json") == 0)
        return REPORT_JSON;
    if (strcmp(str, "html") == 0)
        return REPORT_HTML;
    return REPORT_TEXT;
}

/*=============================================================================
 * Test Selection
 *=============================================================================*/

typedef enum
{
    SUITE_NONE,
    SUITE_ALL,
    SUITE_QUICK,
    SUITE_FULL,
    SUITE_STRESS
} test_suite_t;

static void add_tests_for_suite(test_suite_t suite, test_list_t *list)
{
    switch (suite)
    {
    case SUITE_QUICK:
        test_list_add(list, "hw.pcie");
        test_list_add(list, "hw.registers");
        test_list_add(list, "hw.temperature");
        test_list_add(list, "kem.roundtrip");
        test_list_add(list, "sign.roundtrip");
        test_list_add(list, "random.basic");
        break;

    case SUITE_FULL:
        /* Hardware */
        test_list_add(list, "hw.pcie");
        test_list_add(list, "hw.registers");
        test_list_add(list, "hw.memory");
        test_list_add(list, "hw.dma");
        test_list_add(list, "hw.interrupt");
        test_list_add(list, "hw.temperature");
        test_list_add(list, "hw.voltage");
        test_list_add(list, "hw.clock");

        /* KEM */
        test_list_add(list, "kem.mlkem512.kat");
        test_list_add(list, "kem.mlkem768.kat");
        test_list_add(list, "kem.mlkem1024.kat");
        test_list_add(list, "kem.roundtrip");
        test_list_add(list, "kem.invalid");

        /* Signatures */
        test_list_add(list, "sign.mldsa44.kat");
        test_list_add(list, "sign.mldsa65.kat");
        test_list_add(list, "sign.mldsa87.kat");
        test_list_add(list, "sign.slhdsa.kat");
        test_list_add(list, "sign.roundtrip");
        test_list_add(list, "sign.invalid");

        /* Random */
        test_list_add(list, "random.basic");
        test_list_add(list, "random.monobit");
        test_list_add(list, "random.runs");
        test_list_add(list, "random.entropy");
        test_list_add(list, "random.repetition");
        test_list_add(list, "random.adaptive");

        /* Performance */
        test_list_add(list, "perf.kem.throughput");
        test_list_add(list, "perf.kem.latency");
        test_list_add(list, "perf.sign.throughput");
        test_list_add(list, "perf.sign.latency");
        test_list_add(list, "perf.random.throughput");
        test_list_add(list, "perf.batch");
        break;

    case SUITE_STRESS:
        test_list_add(list, "stress.continuous");
        test_list_add(list, "stress.thermal");
        test_list_add(list, "stress.memory");
        test_list_add(list, "stress.concurrent");
        break;

    case SUITE_ALL:
        add_tests_for_suite(SUITE_FULL, list);
        add_tests_for_suite(SUITE_STRESS, list);
        break;

    default:
        break;
    }
}

static void add_tests_by_category(const char *category, test_list_t *list)
{
    if (strcmp(category, "hw") == 0)
    {
        test_list_add(list, "hw.pcie");
        test_list_add(list, "hw.registers");
        test_list_add(list, "hw.memory");
        test_list_add(list, "hw.dma");
        test_list_add(list, "hw.interrupt");
        test_list_add(list, "hw.temperature");
        test_list_add(list, "hw.voltage");
        test_list_add(list, "hw.clock");
    }
    else if (strcmp(category, "kem") == 0)
    {
        test_list_add(list, "kem.mlkem512.kat");
        test_list_add(list, "kem.mlkem768.kat");
        test_list_add(list, "kem.mlkem1024.kat");
        test_list_add(list, "kem.roundtrip");
        test_list_add(list, "kem.invalid");
    }
    else if (strcmp(category, "sign") == 0)
    {
        test_list_add(list, "sign.mldsa44.kat");
        test_list_add(list, "sign.mldsa65.kat");
        test_list_add(list, "sign.mldsa87.kat");
        test_list_add(list, "sign.slhdsa.kat");
        test_list_add(list, "sign.roundtrip");
        test_list_add(list, "sign.invalid");
    }
    else if (strcmp(category, "random") == 0)
    {
        test_list_add(list, "random.basic");
        test_list_add(list, "random.monobit");
        test_list_add(list, "random.runs");
        test_list_add(list, "random.entropy");
        test_list_add(list, "random.repetition");
        test_list_add(list, "random.adaptive");
    }
    else if (strcmp(category, "perf") == 0)
    {
        test_list_add(list, "perf.kem.throughput");
        test_list_add(list, "perf.kem.latency");
        test_list_add(list, "perf.sign.throughput");
        test_list_add(list, "perf.sign.latency");
        test_list_add(list, "perf.random.throughput");
        test_list_add(list, "perf.batch");
    }
    else if (strcmp(category, "stress") == 0)
    {
        test_list_add(list, "stress.continuous");
        test_list_add(list, "stress.thermal");
        test_list_add(list, "stress.memory");
        test_list_add(list, "stress.concurrent");
    }
    else
    {
        /* Assume it's a specific test name */
        test_list_add(list, category);
    }
}

/*=============================================================================
 * Main
 *=============================================================================*/

int main(int argc, char *argv[])
{
    test_suite_t suite = SUITE_NONE;
    bool list_tests = false;
    bool list_devices = false;

    /* Parse options */
    int c;
    while ((c = getopt_long(argc, argv, short_opts, long_opts, NULL)) != -1)
    {
        switch (c)
        {
        case 'd':
            g_options.device_index = atoi(optarg);
            break;
        case 's':
            g_options.use_simulator = true;
            break;
        case 'a':
            suite = SUITE_ALL;
            break;
        case 'q':
            suite = SUITE_QUICK;
            break;
        case 'f':
            suite = SUITE_FULL;
            break;
        case 'S':
            suite = SUITE_STRESS;
            break;
        case 'l':
            list_tests = true;
            break;
        case 'D':
            list_devices = true;
            break;
        case 'o':
            g_options.output_file = optarg;
            break;
        case 'F':
            g_options.format = parse_format(optarg);
            break;
        case 'v':
            g_options.verbose = true;
            break;
        case 'c':
            g_options.continuous = true;
            break;
        case 't':
            g_options.timeout_sec = atoi(optarg);
            break;
        case 'h':
            print_usage(argv[0]);
            return 0;
        case 'V':
            print_version();
            return 0;
        case '?':
            return DIAG_ERR_ARGS;
        }
    }

    /* Handle special modes */
    if (list_tests)
    {
        tests_print_list();
        return 0;
    }

    if (list_devices)
    {
        hw_list_devices();
        return 0;
    }

    /* Setup signal handler */
    signal(SIGINT, signal_handler);
#ifndef _WIN32
    signal(SIGTERM, signal_handler);
#endif

    /* Initialize hardware */
    diag_context_t *ctx = diag_init(&g_options);
    if (!ctx)
    {
        fprintf(stderr, "Error: Failed to initialize diagnostics\n");
        return DIAG_ERR_DEVICE;
    }

    /* Build test list */
    test_list_t *tests = test_list_create();

    if (suite != SUITE_NONE)
    {
        add_tests_for_suite(suite, tests);
    }

    /* Add tests from command line */
    for (int i = optind; i < argc; i++)
    {
        add_tests_by_category(argv[i], tests);
    }

    /* Default to quick tests if nothing specified */
    if (tests->count == 0)
    {
        add_tests_for_suite(SUITE_QUICK, tests);
    }

    /* Create results container */
    test_results_t *results = test_results_create();

    /* Print header */
    if (!g_options.output_file)
    {
        printf("QUAC 100 Diagnostics\n");
        printf("====================\n");
        hw_info_t info;
        hw_get_info(ctx, &info);
        printf("Device: %s\n", info.name);
        printf("Serial: %s\n", info.serial);
        printf("Tests:  %d\n\n", tests->count);
    }

    /* Run tests */
    int pass_count = 0;
    int fail_count = 0;
    int skip_count = 0;

    do
    {
        for (int i = 0; i < tests->count && !g_interrupted; i++)
        {
            const char *test_name = tests->names[i];

            if (!g_options.output_file && g_options.verbose)
            {
                printf("Running: %s... ", test_name);
                fflush(stdout);
            }

            test_result_t result;
            int status = tests_run_one(ctx, test_name, &result);

            test_results_add(results, &result);

            if (status == TEST_PASS)
            {
                pass_count++;
                if (!g_options.output_file)
                {
                    if (g_options.verbose)
                    {
                        printf("PASS (%ldms)\n", result.duration_ms);
                    }
                    else
                    {
                        printf("[PASS] %-24s %s\n", test_name, result.message);
                    }
                }
            }
            else if (status == TEST_FAIL)
            {
                fail_count++;
                if (!g_options.output_file)
                {
                    if (g_options.verbose)
                    {
                        printf("FAIL\n");
                        printf("       %s\n", result.message);
                    }
                    else
                    {
                        printf("[FAIL] %-24s %s\n", test_name, result.message);
                    }
                }
            }
            else
            {
                skip_count++;
                if (!g_options.output_file)
                {
                    printf("[SKIP] %-24s %s\n", test_name, result.message);
                }
            }
        }
    } while (g_options.continuous && !g_interrupted);

    /* Print summary */
    if (!g_options.output_file)
    {
        printf("\n");
        printf("Summary: %d passed, %d failed, %d skipped\n",
               pass_count, fail_count, skip_count);
    }

    /* Generate report */
    if (g_options.output_file)
    {
        report_generate(g_options.output_file, g_options.format, ctx, results);
        printf("Report written to: %s\n", g_options.output_file);
    }

    /* Cleanup */
    test_results_destroy(results);
    test_list_destroy(tests);
    diag_cleanup(ctx);

    return (fail_count > 0) ? DIAG_ERR_FAILED : 0;
}