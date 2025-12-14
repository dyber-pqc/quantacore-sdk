/**
 * @file main.c
 * @brief QUAC 100 Benchmark Tool - Main Entry Point
 *
 * Command-line interface and main program logic for the
 * QUAC 100 performance benchmarking utility.
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <getopt.h>
#include <time.h>

#include "benchmark.h"
#include "stats.h"
#include "output.h"
#include "algorithms.h"

/*=============================================================================
 * Version Information
 *=============================================================================*/

#define BENCH_VERSION_MAJOR 1
#define BENCH_VERSION_MINOR 0
#define BENCH_VERSION_PATCH 0

/*=============================================================================
 * Global State
 *=============================================================================*/

static volatile sig_atomic_t g_interrupted = 0;

static void signal_handler(int sig)
{
    (void)sig;
    g_interrupted = 1;
    fprintf(stderr, "\nInterrupted. Finishing current operation...\n");
}

/*=============================================================================
 * Command Line Options
 *=============================================================================*/

typedef enum
{
    ALG_ALL = 0,
    ALG_ML_KEM_512,
    ALG_ML_KEM_768,
    ALG_ML_KEM_1024,
    ALG_ML_DSA_44,
    ALG_ML_DSA_65,
    ALG_ML_DSA_87,
    ALG_SLH_DSA_128F,
    ALG_SLH_DSA_128S,
    ALG_SLH_DSA_192F,
    ALG_SLH_DSA_192S,
    ALG_SLH_DSA_256F,
    ALG_SLH_DSA_256S,
    ALG_RANDOM,
    ALG_COUNT
} algorithm_select_t;

typedef enum
{
    OP_ALL = 0,
    OP_KEYGEN,
    OP_ENCAPS,
    OP_DECAPS,
    OP_SIGN,
    OP_VERIFY,
    OP_RANDOM,
    OP_COUNT
} operation_select_t;

typedef enum
{
    OUTPUT_TEXT = 0,
    OUTPUT_JSON,
    OUTPUT_CSV,
    OUTPUT_MARKDOWN
} output_format_t;

typedef struct
{
    /* Device selection */
    int device_index;
    bool use_simulator;

    /* Algorithm/operation selection */
    algorithm_select_t algorithm;
    operation_select_t operation;

    /* Benchmark parameters */
    int iterations;
    int warmup;
    int threads;
    int batch_size;

    /* Output options */
    char output_file[256];
    output_format_t format;
    bool verbose;
    bool quiet;

    /* Comparison mode */
    bool compare_mode;
    char baseline_file[256];

    /* Flags */
    bool list_devices;
    bool list_algorithms;
} bench_options_t;

static void init_options(bench_options_t *opts)
{
    memset(opts, 0, sizeof(*opts));
    opts->device_index = 0;
    opts->use_simulator = false;
    opts->algorithm = ALG_ALL;
    opts->operation = OP_ALL;
    opts->iterations = 1000;
    opts->warmup = 100;
    opts->threads = 1;
    opts->batch_size = 1;
    opts->format = OUTPUT_TEXT;
    opts->verbose = false;
    opts->quiet = false;
    opts->compare_mode = false;
    opts->list_devices = false;
    opts->list_algorithms = false;
}

/*=============================================================================
 * Argument Parsing
 *=============================================================================*/

static const char *short_opts = "d:sa:o:i:w:t:b:O:f:vqhV";

static struct option long_opts[] = {
    {"device", required_argument, NULL, 'd'},
    {"simulator", no_argument, NULL, 's'},
    {"algorithm", required_argument, NULL, 'a'},
    {"operation", required_argument, NULL, 'o'},
    {"iterations", required_argument, NULL, 'i'},
    {"warmup", required_argument, NULL, 'w'},
    {"threads", required_argument, NULL, 't'},
    {"batch-size", required_argument, NULL, 'b'},
    {"output", required_argument, NULL, 'O'},
    {"format", required_argument, NULL, 'f'},
    {"verbose", no_argument, NULL, 'v'},
    {"quiet", no_argument, NULL, 'q'},
    {"quick", no_argument, NULL, 'Q'},
    {"standard", no_argument, NULL, 'S'},
    {"extended", no_argument, NULL, 'E'},
    {"stress", no_argument, NULL, 'T'},
    {"compare", no_argument, NULL, 'C'},
    {"baseline", required_argument, NULL, 'B'},
    {"list-devices", no_argument, NULL, 'L'},
    {"list-algorithms", no_argument, NULL, 'A'},
    {"help", no_argument, NULL, 'h'},
    {"version", no_argument, NULL, 'V'},
    {NULL, 0, NULL, 0}};

static algorithm_select_t parse_algorithm(const char *str)
{
    if (!str)
        return ALG_ALL;

    if (strcmp(str, "all") == 0)
        return ALG_ALL;
    if (strcmp(str, "ml-kem-512") == 0)
        return ALG_ML_KEM_512;
    if (strcmp(str, "ml-kem-768") == 0)
        return ALG_ML_KEM_768;
    if (strcmp(str, "ml-kem-1024") == 0)
        return ALG_ML_KEM_1024;
    if (strcmp(str, "ml-dsa-44") == 0)
        return ALG_ML_DSA_44;
    if (strcmp(str, "ml-dsa-65") == 0)
        return ALG_ML_DSA_65;
    if (strcmp(str, "ml-dsa-87") == 0)
        return ALG_ML_DSA_87;
    if (strcmp(str, "slh-dsa-128f") == 0)
        return ALG_SLH_DSA_128F;
    if (strcmp(str, "slh-dsa-128s") == 0)
        return ALG_SLH_DSA_128S;
    if (strcmp(str, "slh-dsa-192f") == 0)
        return ALG_SLH_DSA_192F;
    if (strcmp(str, "slh-dsa-192s") == 0)
        return ALG_SLH_DSA_192S;
    if (strcmp(str, "slh-dsa-256f") == 0)
        return ALG_SLH_DSA_256F;
    if (strcmp(str, "slh-dsa-256s") == 0)
        return ALG_SLH_DSA_256S;
    if (strcmp(str, "random") == 0)
        return ALG_RANDOM;

    fprintf(stderr, "Unknown algorithm: %s\n", str);
    return ALG_ALL;
}

static operation_select_t parse_operation(const char *str)
{
    if (!str)
        return OP_ALL;

    if (strcmp(str, "all") == 0)
        return OP_ALL;
    if (strcmp(str, "keygen") == 0)
        return OP_KEYGEN;
    if (strcmp(str, "encaps") == 0)
        return OP_ENCAPS;
    if (strcmp(str, "decaps") == 0)
        return OP_DECAPS;
    if (strcmp(str, "sign") == 0)
        return OP_SIGN;
    if (strcmp(str, "verify") == 0)
        return OP_VERIFY;
    if (strcmp(str, "random") == 0)
        return OP_RANDOM;

    fprintf(stderr, "Unknown operation: %s\n", str);
    return OP_ALL;
}

static output_format_t parse_format(const char *str)
{
    if (!str)
        return OUTPUT_TEXT;

    if (strcmp(str, "text") == 0)
        return OUTPUT_TEXT;
    if (strcmp(str, "json") == 0)
        return OUTPUT_JSON;
    if (strcmp(str, "csv") == 0)
        return OUTPUT_CSV;
    if (strcmp(str, "markdown") == 0)
        return OUTPUT_MARKDOWN;
    if (strcmp(str, "md") == 0)
        return OUTPUT_MARKDOWN;

    fprintf(stderr, "Unknown format: %s\n", str);
    return OUTPUT_TEXT;
}

static void print_usage(const char *prog)
{
    printf("Usage: %s [OPTIONS]\n", prog);
    printf("\n");
    printf("QUAC 100 Performance Benchmark Tool\n");
    printf("\n");
    printf("Device Selection:\n");
    printf("  -d, --device <index>      Device index (default: 0)\n");
    printf("  -s, --simulator           Use software simulator\n");
    printf("\n");
    printf("Algorithm Selection:\n");
    printf("  -a, --algorithm <alg>     Algorithm to benchmark:\n");
    printf("                            ml-kem-512, ml-kem-768, ml-kem-1024\n");
    printf("                            ml-dsa-44, ml-dsa-65, ml-dsa-87\n");
    printf("                            slh-dsa-128f/s, slh-dsa-192f/s, slh-dsa-256f/s\n");
    printf("                            random, all (default)\n");
    printf("\n");
    printf("Operation Selection:\n");
    printf("  -o, --operation <op>      Operation to benchmark:\n");
    printf("                            keygen, encaps, decaps, sign, verify\n");
    printf("                            random, all (default)\n");
    printf("\n");
    printf("Benchmark Parameters:\n");
    printf("  -i, --iterations <n>      Number of iterations (default: 1000)\n");
    printf("  -w, --warmup <n>          Warmup iterations (default: 100)\n");
    printf("  -t, --threads <n>         Number of threads (default: 1)\n");
    printf("  -b, --batch-size <n>      Batch size (default: 1)\n");
    printf("\n");
    printf("Presets:\n");
    printf("  --quick                   Quick (100 iter, 10 warmup)\n");
    printf("  --standard                Standard (1000 iter, 100 warmup)\n");
    printf("  --extended                Extended (10000 iter, 1000 warmup)\n");
    printf("  --stress                  Stress (100000 iter, 10000 warmup)\n");
    printf("\n");
    printf("Output Options:\n");
    printf("  -O, --output <file>       Output file (default: stdout)\n");
    printf("  -f, --format <fmt>        Format: text, json, csv, markdown\n");
    printf("  -v, --verbose             Verbose output\n");
    printf("  -q, --quiet               Quiet mode\n");
    printf("\n");
    printf("Comparison:\n");
    printf("  --compare                 Compare hardware vs software\n");
    printf("  --baseline <file>         Load baseline for comparison\n");
    printf("\n");
    printf("Information:\n");
    printf("  -h, --help                Show this help\n");
    printf("  -V, --version             Show version\n");
    printf("  --list-devices            List available devices\n");
    printf("  --list-algorithms         List supported algorithms\n");
}

static void print_version(void)
{
    printf("quac100-bench %d.%d.%d\n",
           BENCH_VERSION_MAJOR, BENCH_VERSION_MINOR, BENCH_VERSION_PATCH);
    printf("QUAC 100 Performance Benchmark Tool\n");
    printf("Copyright 2025 Dyber, Inc. All Rights Reserved.\n");
}

static int parse_args(int argc, char *argv[], bench_options_t *opts)
{
    int c;

    while ((c = getopt_long(argc, argv, short_opts, long_opts, NULL)) != -1)
    {
        switch (c)
        {
        case 'd':
            opts->device_index = atoi(optarg);
            break;
        case 's':
            opts->use_simulator = true;
            break;
        case 'a':
            opts->algorithm = parse_algorithm(optarg);
            break;
        case 'o':
            opts->operation = parse_operation(optarg);
            break;
        case 'i':
            opts->iterations = atoi(optarg);
            if (opts->iterations < 1)
                opts->iterations = 1;
            break;
        case 'w':
            opts->warmup = atoi(optarg);
            if (opts->warmup < 0)
                opts->warmup = 0;
            break;
        case 't':
            opts->threads = atoi(optarg);
            if (opts->threads < 1)
                opts->threads = 1;
            break;
        case 'b':
            opts->batch_size = atoi(optarg);
            if (opts->batch_size < 1)
                opts->batch_size = 1;
            break;
        case 'O':
            strncpy(opts->output_file, optarg, sizeof(opts->output_file) - 1);
            break;
        case 'f':
            opts->format = parse_format(optarg);
            break;
        case 'v':
            opts->verbose = true;
            break;
        case 'q':
            opts->quiet = true;
            break;
        case 'Q': /* --quick */
            opts->iterations = 100;
            opts->warmup = 10;
            break;
        case 'S': /* --standard */
            opts->iterations = 1000;
            opts->warmup = 100;
            break;
        case 'E': /* --extended */
            opts->iterations = 10000;
            opts->warmup = 1000;
            break;
        case 'T': /* --stress */
            opts->iterations = 100000;
            opts->warmup = 10000;
            break;
        case 'C': /* --compare */
            opts->compare_mode = true;
            break;
        case 'B': /* --baseline */
            strncpy(opts->baseline_file, optarg, sizeof(opts->baseline_file) - 1);
            break;
        case 'L': /* --list-devices */
            opts->list_devices = true;
            break;
        case 'A': /* --list-algorithms */
            opts->list_algorithms = true;
            break;
        case 'h':
            print_usage(argv[0]);
            exit(0);
        case 'V':
            print_version();
            exit(0);
        case '?':
        default:
            return -1;
        }
    }

    return 0;
}

/*=============================================================================
 * Device Listing
 *=============================================================================*/

static int list_devices(void)
{
    printf("Available QUAC Devices:\n");
    printf("=======================\n\n");

    bench_context_t *ctx = bench_init();
    if (!ctx)
    {
        printf("  (SDK not initialized - using simulated device list)\n\n");
        printf("  Index  Name                    Status\n");
        printf("  -----  ----------------------  --------\n");
        printf("  0      QUAC 100 Simulator      Available\n");
        return 0;
    }

    int count = bench_get_device_count(ctx);

    if (count == 0)
    {
        printf("  No devices found.\n");
        printf("\n  Use -s/--simulator to use the software simulator.\n");
    }
    else
    {
        printf("  Index  Name                    FW Version  Status\n");
        printf("  -----  ----------------------  ----------  --------\n");

        for (int i = 0; i < count; i++)
        {
            device_info_t info;
            if (bench_get_device_info(ctx, i, &info) == 0)
            {
                printf("  %-5d  %-22s  %-10s  %s\n",
                       i, info.name, info.firmware_version,
                       info.available ? "Available" : "In Use");
            }
        }
    }

    bench_cleanup(ctx);
    return 0;
}

static int list_algorithms(void)
{
    printf("Supported Algorithms:\n");
    printf("=====================\n\n");

    printf("Key Encapsulation (KEM):\n");
    printf("  ml-kem-512       FIPS 203 ML-KEM-512\n");
    printf("  ml-kem-768       FIPS 203 ML-KEM-768 (recommended)\n");
    printf("  ml-kem-1024      FIPS 203 ML-KEM-1024\n");
    printf("\n");

    printf("Digital Signatures:\n");
    printf("  ml-dsa-44        FIPS 204 ML-DSA-44\n");
    printf("  ml-dsa-65        FIPS 204 ML-DSA-65 (recommended)\n");
    printf("  ml-dsa-87        FIPS 204 ML-DSA-87\n");
    printf("\n");

    printf("Hash-Based Signatures:\n");
    printf("  slh-dsa-128f     FIPS 205 SLH-DSA-SHA2-128f (fast)\n");
    printf("  slh-dsa-128s     FIPS 205 SLH-DSA-SHA2-128s (small)\n");
    printf("  slh-dsa-192f     FIPS 205 SLH-DSA-SHA2-192f (fast)\n");
    printf("  slh-dsa-192s     FIPS 205 SLH-DSA-SHA2-192s (small)\n");
    printf("  slh-dsa-256f     FIPS 205 SLH-DSA-SHA2-256f (fast)\n");
    printf("  slh-dsa-256s     FIPS 205 SLH-DSA-SHA2-256s (small)\n");
    printf("\n");

    printf("Random Number Generation:\n");
    printf("  random           Quantum Random Number Generator (QRNG)\n");
    printf("\n");

    return 0;
}

/*=============================================================================
 * Main Benchmark Logic
 *=============================================================================*/

static int run_benchmarks(bench_options_t *opts)
{
    bench_context_t *ctx = NULL;
    bench_device_t *device = NULL;
    bench_results_t *results = NULL;
    output_context_t *output = NULL;
    int ret = 0;

    /* Initialize */
    if (!opts->quiet)
    {
        printf("QUAC 100 Benchmark Tool v%d.%d.%d\n",
               BENCH_VERSION_MAJOR, BENCH_VERSION_MINOR, BENCH_VERSION_PATCH);
        printf("=====================================\n\n");
    }

    /* Initialize context */
    ctx = bench_init();
    if (!ctx)
    {
        fprintf(stderr, "Error: Failed to initialize benchmark context\n");
        return 1;
    }

    /* Open device */
    if (opts->use_simulator)
    {
        device = bench_open_simulator(ctx);
        if (!opts->quiet)
        {
            printf("Using software simulator\n\n");
        }
    }
    else
    {
        device = bench_open_device(ctx, opts->device_index);
    }

    if (!device)
    {
        fprintf(stderr, "Error: Failed to open device %d\n", opts->device_index);
        ret = 3;
        goto cleanup;
    }

    /* Print device info */
    if (!opts->quiet)
    {
        device_info_t info;
        if (bench_get_device_info_from_device(device, &info) == 0)
        {
            printf("Device: %s\n", info.name);
            printf("Firmware: %s\n", info.firmware_version);
            printf("Serial: %s\n\n", info.serial_number);
        }
    }

    /* Create results container */
    results = bench_results_create();
    if (!results)
    {
        fprintf(stderr, "Error: Failed to allocate results\n");
        ret = 1;
        goto cleanup;
    }

    /* Store benchmark parameters */
    results->iterations = opts->iterations;
    results->warmup = opts->warmup;
    results->threads = opts->threads;
    results->batch_size = opts->batch_size;
    time(&results->timestamp);

    /* Setup benchmark configuration */
    bench_config_t config = {
        .iterations = opts->iterations,
        .warmup = opts->warmup,
        .threads = opts->threads,
        .batch_size = opts->batch_size,
        .verbose = opts->verbose,
        .interrupted = &g_interrupted};

    /* Run benchmarks based on selection */
    if (!opts->quiet)
    {
        printf("Running benchmarks...\n");
        printf("  Iterations: %d\n", opts->iterations);
        printf("  Warmup: %d\n", opts->warmup);
        printf("  Threads: %d\n", opts->threads);
        printf("  Batch size: %d\n\n", opts->batch_size);
    }

    /* Run selected algorithms */
    if (opts->algorithm == ALG_ALL || opts->algorithm == ALG_ML_KEM_512)
    {
        run_kem_benchmark(device, BENCH_ALG_ML_KEM_512, opts->operation, &config, results);
    }
    if (g_interrupted)
        goto output_results;

    if (opts->algorithm == ALG_ALL || opts->algorithm == ALG_ML_KEM_768)
    {
        run_kem_benchmark(device, BENCH_ALG_ML_KEM_768, opts->operation, &config, results);
    }
    if (g_interrupted)
        goto output_results;

    if (opts->algorithm == ALG_ALL || opts->algorithm == ALG_ML_KEM_1024)
    {
        run_kem_benchmark(device, BENCH_ALG_ML_KEM_1024, opts->operation, &config, results);
    }
    if (g_interrupted)
        goto output_results;

    if (opts->algorithm == ALG_ALL || opts->algorithm == ALG_ML_DSA_44)
    {
        run_sign_benchmark(device, BENCH_ALG_ML_DSA_44, opts->operation, &config, results);
    }
    if (g_interrupted)
        goto output_results;

    if (opts->algorithm == ALG_ALL || opts->algorithm == ALG_ML_DSA_65)
    {
        run_sign_benchmark(device, BENCH_ALG_ML_DSA_65, opts->operation, &config, results);
    }
    if (g_interrupted)
        goto output_results;

    if (opts->algorithm == ALG_ALL || opts->algorithm == ALG_ML_DSA_87)
    {
        run_sign_benchmark(device, BENCH_ALG_ML_DSA_87, opts->operation, &config, results);
    }
    if (g_interrupted)
        goto output_results;

    /* SLH-DSA variants */
    if (opts->algorithm == ALG_SLH_DSA_128F)
    {
        run_sign_benchmark(device, BENCH_ALG_SLH_DSA_128F, opts->operation, &config, results);
    }
    if (opts->algorithm == ALG_SLH_DSA_128S)
    {
        run_sign_benchmark(device, BENCH_ALG_SLH_DSA_128S, opts->operation, &config, results);
    }
    if (opts->algorithm == ALG_SLH_DSA_192F)
    {
        run_sign_benchmark(device, BENCH_ALG_SLH_DSA_192F, opts->operation, &config, results);
    }
    if (opts->algorithm == ALG_SLH_DSA_192S)
    {
        run_sign_benchmark(device, BENCH_ALG_SLH_DSA_192S, opts->operation, &config, results);
    }
    if (opts->algorithm == ALG_SLH_DSA_256F)
    {
        run_sign_benchmark(device, BENCH_ALG_SLH_DSA_256F, opts->operation, &config, results);
    }
    if (opts->algorithm == ALG_SLH_DSA_256S)
    {
        run_sign_benchmark(device, BENCH_ALG_SLH_DSA_256S, opts->operation, &config, results);
    }
    if (g_interrupted)
        goto output_results;

    if (opts->algorithm == ALG_ALL || opts->algorithm == ALG_RANDOM)
    {
        run_random_benchmark(device, &config, results);
    }

output_results:
    /* Output results */
    output = output_create(opts->output_file[0] ? opts->output_file : NULL,
                           opts->format);
    if (!output)
    {
        fprintf(stderr, "Error: Failed to create output\n");
        ret = 6;
        goto cleanup;
    }

    /* Write results */
    output_write_results(output, results, device);

    /* Compare with baseline if specified */
    if (opts->baseline_file[0])
    {
        bench_results_t *baseline = bench_results_load(opts->baseline_file);
        if (baseline)
        {
            output_write_comparison(output, results, baseline);
            bench_results_destroy(baseline);
        }
        else
        {
            fprintf(stderr, "Warning: Failed to load baseline file\n");
        }
    }

cleanup:
    if (output)
        output_destroy(output);
    if (results)
        bench_results_destroy(results);
    if (device)
        bench_close_device(device);
    if (ctx)
        bench_cleanup(ctx);

    return ret;
}

/*=============================================================================
 * Main Entry Point
 *=============================================================================*/

int main(int argc, char *argv[])
{
    bench_options_t opts;
    init_options(&opts);

    /* Parse command line */
    if (parse_args(argc, argv, &opts) != 0)
    {
        fprintf(stderr, "Try '%s --help' for more information.\n", argv[0]);
        return 2;
    }

    /* Handle info commands */
    if (opts.list_devices)
    {
        return list_devices();
    }

    if (opts.list_algorithms)
    {
        return list_algorithms();
    }

    /* Install signal handler */
    signal(SIGINT, signal_handler);
#ifndef _WIN32
    signal(SIGTERM, signal_handler);
#endif

    /* Run benchmarks */
    return run_benchmarks(&opts);
}