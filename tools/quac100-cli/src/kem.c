/**
 * @file kem.c
 * @brief QUAC 100 CLI - KEM Operations
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include "commands.h"
#include "device.h"
#include "utils.h"

/*=============================================================================
 * KEM Key Sizes
 *=============================================================================*/

typedef struct
{
    cli_algorithm_t alg;
    size_t pk_size;
    size_t sk_size;
    size_t ct_size;
    size_t ss_size;
} kem_sizes_t;

static const kem_sizes_t kem_sizes[] = {
    {ALG_ML_KEM_512, 800, 1632, 768, 32},
    {ALG_ML_KEM_768, 1184, 2400, 1088, 32},
    {ALG_ML_KEM_1024, 1568, 3168, 1568, 32},
    {ALG_UNKNOWN, 0, 0, 0, 0}};

static const kem_sizes_t *get_kem_sizes(cli_algorithm_t alg)
{
    for (int i = 0; kem_sizes[i].alg != ALG_UNKNOWN; i++)
    {
        if (kem_sizes[i].alg == alg)
        {
            return &kem_sizes[i];
        }
    }
    return NULL;
}

/*=============================================================================
 * Simulated KEM Operations
 *=============================================================================*/

static int sim_kem_keygen(cli_algorithm_t alg, uint8_t *pk, size_t *pk_len,
                          uint8_t *sk, size_t *sk_len)
{
    const kem_sizes_t *sizes = get_kem_sizes(alg);
    if (!sizes)
        return -1;

    /* Generate random keys for simulation */
    for (size_t i = 0; i < sizes->pk_size; i++)
    {
        pk[i] = (uint8_t)(rand() & 0xFF);
    }
    for (size_t i = 0; i < sizes->sk_size; i++)
    {
        sk[i] = (uint8_t)(rand() & 0xFF);
    }

    *pk_len = sizes->pk_size;
    *sk_len = sizes->sk_size;

    return 0;
}

static int sim_kem_encaps(cli_algorithm_t alg, const uint8_t *pk, size_t pk_len,
                          uint8_t *ct, size_t *ct_len, uint8_t *ss, size_t *ss_len)
{
    (void)pk;
    (void)pk_len;

    const kem_sizes_t *sizes = get_kem_sizes(alg);
    if (!sizes)
        return -1;

    /* Generate random ciphertext and shared secret */
    for (size_t i = 0; i < sizes->ct_size; i++)
    {
        ct[i] = (uint8_t)(rand() & 0xFF);
    }
    for (size_t i = 0; i < sizes->ss_size; i++)
    {
        ss[i] = (uint8_t)(rand() & 0xFF);
    }

    *ct_len = sizes->ct_size;
    *ss_len = sizes->ss_size;

    return 0;
}

static int sim_kem_decaps(cli_algorithm_t alg, const uint8_t *ct, size_t ct_len,
                          const uint8_t *sk, size_t sk_len,
                          uint8_t *ss, size_t *ss_len)
{
    (void)ct;
    (void)ct_len;
    (void)sk;
    (void)sk_len;

    const kem_sizes_t *sizes = get_kem_sizes(alg);
    if (!sizes)
        return -1;

    /* Generate random shared secret (simulation) */
    for (size_t i = 0; i < sizes->ss_size; i++)
    {
        ss[i] = (uint8_t)(rand() & 0xFF);
    }

    *ss_len = sizes->ss_size;

    return 0;
}

/*=============================================================================
 * KEM Keygen Command
 *=============================================================================*/

static int kem_keygen(int argc, char *argv[])
{
    cli_algorithm_t alg = ALG_ML_KEM_768;
    char output_file[256] = "";
    char pk_file[256] = "";
    char sk_file[256] = "";

    static struct option opts[] = {
        {"algorithm", required_argument, NULL, 'a'},
        {"output", required_argument, NULL, 'o'},
        {"pk", required_argument, NULL, 'p'},
        {"sk", required_argument, NULL, 's'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}};

    optind = 1;
    int c;
    while ((c = getopt_long(argc, argv, "a:o:p:s:h", opts, NULL)) != -1)
    {
        switch (c)
        {
        case 'a':
            alg = parse_algorithm(optarg);
            if (!is_kem_algorithm(alg))
            {
                cli_error("Invalid KEM algorithm: %s", optarg);
                return CLI_ERR_ARGS;
            }
            break;
        case 'o':
            strncpy(output_file, optarg, sizeof(output_file) - 1);
            break;
        case 'p':
            strncpy(pk_file, optarg, sizeof(pk_file) - 1);
            break;
        case 's':
            strncpy(sk_file, optarg, sizeof(sk_file) - 1);
            break;
        case 'h':
            printf("Usage: quac100-cli kem keygen [options]\n\n");
            printf("Options:\n");
            printf("  -a, --algorithm <alg>  Algorithm (default: ml-kem-768)\n");
            printf("  -o, --output <file>    Combined output file\n");
            printf("  --pk <file>            Public key output file\n");
            printf("  --sk <file>            Secret key output file\n");
            return CLI_OK;
        default:
            return CLI_ERR_ARGS;
        }
    }

    const kem_sizes_t *sizes = get_kem_sizes(alg);
    if (!sizes)
    {
        cli_error("Invalid algorithm");
        return CLI_ERR_ARGS;
    }

    /* Allocate buffers */
    uint8_t *pk = malloc(sizes->pk_size);
    uint8_t *sk = malloc(sizes->sk_size);
    if (!pk || !sk)
    {
        free(pk);
        free(sk);
        cli_error("Memory allocation failed");
        return CLI_ERR_GENERAL;
    }

    size_t pk_len, sk_len;

    /* Get device and generate keys */
    cli_device_t *dev = cli_get_current_device();
    int result;

    if (!dev || cli_device_is_simulator(dev))
    {
        result = sim_kem_keygen(alg, pk, &pk_len, sk, &sk_len);
    }
    else
    {
#ifdef HAVE_QUAC_SDK
        /* Real SDK call would go here */
        result = sim_kem_keygen(alg, pk, &pk_len, sk, &sk_len);
#else
        result = sim_kem_keygen(alg, pk, &pk_len, sk, &sk_len);
#endif
    }

    if (result != 0)
    {
        free(pk);
        free(sk);
        cli_error("Key generation failed");
        return CLI_ERR_OPERATION;
    }

    /* Output keys */
    if (pk_file[0] && sk_file[0])
    {
        /* Separate files */
        if (write_binary_file(pk_file, pk, pk_len) != 0)
        {
            cli_error("Failed to write public key to %s", pk_file);
            free(pk);
            free(sk);
            return CLI_ERR_IO;
        }
        if (write_binary_file(sk_file, sk, sk_len) != 0)
        {
            cli_error("Failed to write secret key to %s", sk_file);
            free(pk);
            free(sk);
            return CLI_ERR_IO;
        }

        if (!g_options.quiet)
        {
            cli_info("Generated %s keypair", algorithm_name(alg));
            cli_info("Public key: %s (%zu bytes)", pk_file, pk_len);
            cli_info("Secret key: %s (%zu bytes)", sk_file, sk_len);
        }
    }
    else if (output_file[0])
    {
        /* Combined file: [4-byte pk_len][pk][sk] */
        FILE *f = fopen(output_file, "wb");
        if (!f)
        {
            cli_error("Failed to open %s for writing", output_file);
            free(pk);
            free(sk);
            return CLI_ERR_IO;
        }

        uint32_t pk_len32 = (uint32_t)pk_len;
        fwrite(&pk_len32, sizeof(pk_len32), 1, f);
        fwrite(pk, 1, pk_len, f);
        fwrite(sk, 1, sk_len, f);
        fclose(f);

        if (!g_options.quiet)
        {
            cli_info("Generated %s keypair", algorithm_name(alg));
            cli_info("Output: %s (%zu bytes)", output_file, 4 + pk_len + sk_len);
        }
    }
    else
    {
        /* Output to stdout as hex */
        if (g_options.json_output)
        {
            printf("{\n");
            printf("  \"algorithm\": \"%s\",\n", algorithm_name(alg));
            printf("  \"public_key\": \"");
            print_hex(pk, pk_len);
            printf("\",\n");
            printf("  \"secret_key\": \"");
            print_hex(sk, sk_len);
            printf("\"\n");
            printf("}\n");
        }
        else
        {
            printf("Algorithm: %s\n", algorithm_name(alg));
            printf("Public key (%zu bytes):\n", pk_len);
            print_hex_formatted(pk, pk_len, 32);
            printf("\nSecret key (%zu bytes):\n", sk_len);
            print_hex_formatted(sk, sk_len, 32);
        }
    }

    free(pk);
    free(sk);
    return CLI_OK;
}

/*=============================================================================
 * KEM Encaps Command
 *=============================================================================*/

static int kem_encaps(int argc, char *argv[])
{
    cli_algorithm_t alg = ALG_ML_KEM_768;
    char pk_file[256] = "";
    char output_file[256] = "";
    char ct_file[256] = "";
    char ss_file[256] = "";

    static struct option opts[] = {
        {"algorithm", required_argument, NULL, 'a'},
        {"pk", required_argument, NULL, 'p'},
        {"output", required_argument, NULL, 'o'},
        {"ct", required_argument, NULL, 'c'},
        {"ss", required_argument, NULL, 's'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}};

    optind = 1;
    int c;
    while ((c = getopt_long(argc, argv, "a:p:o:c:s:h", opts, NULL)) != -1)
    {
        switch (c)
        {
        case 'a':
            alg = parse_algorithm(optarg);
            break;
        case 'p':
            strncpy(pk_file, optarg, sizeof(pk_file) - 1);
            break;
        case 'o':
            strncpy(output_file, optarg, sizeof(output_file) - 1);
            break;
        case 'c':
            strncpy(ct_file, optarg, sizeof(ct_file) - 1);
            break;
        case 's':
            strncpy(ss_file, optarg, sizeof(ss_file) - 1);
            break;
        case 'h':
            printf("Usage: quac100-cli kem encaps [options]\n\n");
            printf("Options:\n");
            printf("  -a, --algorithm <alg>  Algorithm (default: ml-kem-768)\n");
            printf("  -p, --pk <file>        Public key file (required)\n");
            printf("  -o, --output <file>    Combined output file\n");
            printf("  --ct <file>            Ciphertext output file\n");
            printf("  --ss <file>            Shared secret output file\n");
            return CLI_OK;
        default:
            return CLI_ERR_ARGS;
        }
    }

    if (!pk_file[0])
    {
        cli_error("Public key file required (-p)");
        return CLI_ERR_ARGS;
    }

    const kem_sizes_t *sizes = get_kem_sizes(alg);
    if (!sizes)
    {
        cli_error("Invalid algorithm");
        return CLI_ERR_ARGS;
    }

    /* Read public key */
    size_t pk_len;
    uint8_t *pk = read_binary_file(pk_file, &pk_len);
    if (!pk)
    {
        cli_error("Failed to read public key from %s", pk_file);
        return CLI_ERR_IO;
    }

    /* Allocate output buffers */
    uint8_t *ct = malloc(sizes->ct_size);
    uint8_t *ss = malloc(sizes->ss_size);
    if (!ct || !ss)
    {
        free(pk);
        free(ct);
        free(ss);
        cli_error("Memory allocation failed");
        return CLI_ERR_GENERAL;
    }

    size_t ct_len, ss_len;

    /* Perform encapsulation */
    cli_device_t *dev = cli_get_current_device();
    int result;

    if (!dev || cli_device_is_simulator(dev))
    {
        result = sim_kem_encaps(alg, pk, pk_len, ct, &ct_len, ss, &ss_len);
    }
    else
    {
        result = sim_kem_encaps(alg, pk, pk_len, ct, &ct_len, ss, &ss_len);
    }

    free(pk);

    if (result != 0)
    {
        free(ct);
        free(ss);
        cli_error("Encapsulation failed");
        return CLI_ERR_OPERATION;
    }

    /* Output results */
    if (ct_file[0] && ss_file[0])
    {
        if (write_binary_file(ct_file, ct, ct_len) != 0 ||
            write_binary_file(ss_file, ss, ss_len) != 0)
        {
            cli_error("Failed to write output files");
            free(ct);
            free(ss);
            return CLI_ERR_IO;
        }

        if (!g_options.quiet)
        {
            cli_info("Encapsulation complete");
            cli_info("Ciphertext: %s (%zu bytes)", ct_file, ct_len);
            cli_info("Shared secret: %s (%zu bytes)", ss_file, ss_len);
        }
    }
    else if (output_file[0])
    {
        FILE *f = fopen(output_file, "wb");
        if (!f)
        {
            cli_error("Failed to open %s", output_file);
            free(ct);
            free(ss);
            return CLI_ERR_IO;
        }

        uint32_t ct_len32 = (uint32_t)ct_len;
        fwrite(&ct_len32, sizeof(ct_len32), 1, f);
        fwrite(ct, 1, ct_len, f);
        fwrite(ss, 1, ss_len, f);
        fclose(f);

        if (!g_options.quiet)
        {
            cli_info("Encapsulation complete: %s", output_file);
        }
    }
    else
    {
        if (g_options.json_output)
        {
            printf("{\n");
            printf("  \"ciphertext\": \"");
            print_hex(ct, ct_len);
            printf("\",\n");
            printf("  \"shared_secret\": \"");
            print_hex(ss, ss_len);
            printf("\"\n");
            printf("}\n");
        }
        else
        {
            printf("Ciphertext (%zu bytes):\n", ct_len);
            print_hex_formatted(ct, ct_len, 32);
            printf("\nShared secret (%zu bytes):\n", ss_len);
            print_hex_formatted(ss, ss_len, 32);
        }
    }

    free(ct);
    free(ss);
    return CLI_OK;
}

/*=============================================================================
 * KEM Decaps Command
 *=============================================================================*/

static int kem_decaps(int argc, char *argv[])
{
    cli_algorithm_t alg = ALG_ML_KEM_768;
    char ct_file[256] = "";
    char sk_file[256] = "";
    char output_file[256] = "";

    static struct option opts[] = {
        {"algorithm", required_argument, NULL, 'a'},
        {"ct", required_argument, NULL, 'c'},
        {"sk", required_argument, NULL, 's'},
        {"output", required_argument, NULL, 'o'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}};

    optind = 1;
    int c;
    while ((c = getopt_long(argc, argv, "a:c:s:o:h", opts, NULL)) != -1)
    {
        switch (c)
        {
        case 'a':
            alg = parse_algorithm(optarg);
            break;
        case 'c':
            strncpy(ct_file, optarg, sizeof(ct_file) - 1);
            break;
        case 's':
            strncpy(sk_file, optarg, sizeof(sk_file) - 1);
            break;
        case 'o':
            strncpy(output_file, optarg, sizeof(output_file) - 1);
            break;
        case 'h':
            printf("Usage: quac100-cli kem decaps [options]\n\n");
            printf("Options:\n");
            printf("  -a, --algorithm <alg>  Algorithm (default: ml-kem-768)\n");
            printf("  -c, --ct <file>        Ciphertext file (required)\n");
            printf("  -s, --sk <file>        Secret key file (required)\n");
            printf("  -o, --output <file>    Output file for shared secret\n");
            return CLI_OK;
        default:
            return CLI_ERR_ARGS;
        }
    }

    if (!ct_file[0] || !sk_file[0])
    {
        cli_error("Ciphertext (-c) and secret key (-s) required");
        return CLI_ERR_ARGS;
    }

    const kem_sizes_t *sizes = get_kem_sizes(alg);
    if (!sizes)
    {
        cli_error("Invalid algorithm");
        return CLI_ERR_ARGS;
    }

    /* Read inputs */
    size_t ct_len, sk_len;
    uint8_t *ct = read_binary_file(ct_file, &ct_len);
    uint8_t *sk = read_binary_file(sk_file, &sk_len);

    if (!ct || !sk)
    {
        free(ct);
        free(sk);
        cli_error("Failed to read input files");
        return CLI_ERR_IO;
    }

    /* Allocate output */
    uint8_t *ss = malloc(sizes->ss_size);
    if (!ss)
    {
        free(ct);
        free(sk);
        cli_error("Memory allocation failed");
        return CLI_ERR_GENERAL;
    }

    size_t ss_len;

    /* Perform decapsulation */
    cli_device_t *dev = cli_get_current_device();
    int result;

    if (!dev || cli_device_is_simulator(dev))
    {
        result = sim_kem_decaps(alg, ct, ct_len, sk, sk_len, ss, &ss_len);
    }
    else
    {
        result = sim_kem_decaps(alg, ct, ct_len, sk, sk_len, ss, &ss_len);
    }

    free(ct);
    free(sk);

    if (result != 0)
    {
        free(ss);
        cli_error("Decapsulation failed");
        return CLI_ERR_OPERATION;
    }

    /* Output shared secret */
    if (output_file[0])
    {
        if (write_binary_file(output_file, ss, ss_len) != 0)
        {
            cli_error("Failed to write shared secret");
            free(ss);
            return CLI_ERR_IO;
        }

        if (!g_options.quiet)
        {
            cli_info("Decapsulation complete");
            cli_info("Shared secret: %s (%zu bytes)", output_file, ss_len);
        }
    }
    else
    {
        if (g_options.json_output)
        {
            printf("{\n");
            printf("  \"shared_secret\": \"");
            print_hex(ss, ss_len);
            printf("\"\n");
            printf("}\n");
        }
        else
        {
            printf("Shared secret (%zu bytes):\n", ss_len);
            print_hex_formatted(ss, ss_len, 32);
        }
    }

    free(ss);
    return CLI_OK;
}

/*=============================================================================
 * KEM Demo Command
 *=============================================================================*/

static int kem_demo(int argc, char *argv[])
{
    cli_algorithm_t alg = ALG_ML_KEM_768;

    static struct option opts[] = {
        {"algorithm", required_argument, NULL, 'a'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}};

    optind = 1;
    int c;
    while ((c = getopt_long(argc, argv, "a:h", opts, NULL)) != -1)
    {
        switch (c)
        {
        case 'a':
            alg = parse_algorithm(optarg);
            break;
        case 'h':
            printf("Usage: quac100-cli kem demo [-a algorithm]\n");
            return CLI_OK;
        default:
            return CLI_ERR_ARGS;
        }
    }

    const kem_sizes_t *sizes = get_kem_sizes(alg);
    if (!sizes)
    {
        cli_error("Invalid algorithm");
        return CLI_ERR_ARGS;
    }

    printf("KEM Demonstration: %s\n", algorithm_name(alg));
    printf("================================\n\n");

    /* Keygen */
    printf("1. Generating keypair...\n");
    uint8_t *pk = malloc(sizes->pk_size);
    uint8_t *sk = malloc(sizes->sk_size);
    size_t pk_len, sk_len;

    sim_kem_keygen(alg, pk, &pk_len, sk, &sk_len);
    printf("   Public key: %zu bytes\n", pk_len);
    printf("   Secret key: %zu bytes\n\n", sk_len);

    /* Encaps */
    printf("2. Encapsulating...\n");
    uint8_t *ct = malloc(sizes->ct_size);
    uint8_t *ss1 = malloc(sizes->ss_size);
    size_t ct_len, ss1_len;

    sim_kem_encaps(alg, pk, pk_len, ct, &ct_len, ss1, &ss1_len);
    printf("   Ciphertext: %zu bytes\n", ct_len);
    printf("   Shared secret (sender): ");
    print_hex(ss1, ss1_len < 16 ? ss1_len : 16);
    printf("...\n\n");

    /* Decaps */
    printf("3. Decapsulating...\n");
    uint8_t *ss2 = malloc(sizes->ss_size);
    size_t ss2_len;

    sim_kem_decaps(alg, ct, ct_len, sk, sk_len, ss2, &ss2_len);
    printf("   Shared secret (receiver): ");
    print_hex(ss2, ss2_len < 16 ? ss2_len : 16);
    printf("...\n\n");

    /* Note: In simulation, secrets won't match */
    printf("Note: This is a simulation - shared secrets are randomly generated.\n");
    printf("In actual hardware, both shared secrets would be identical.\n");

    free(pk);
    free(sk);
    free(ct);
    free(ss1);
    free(ss2);

    return CLI_OK;
}

/*=============================================================================
 * KEM Command Entry Point
 *=============================================================================*/

int cmd_kem(int argc, char *argv[])
{
    if (argc < 2)
    {
        printf("Usage: quac100-cli kem <subcommand> [options]\n\n");
        printf("Subcommands:\n");
        printf("  keygen    Generate KEM keypair\n");
        printf("  encaps    Encapsulate (generate ciphertext and shared secret)\n");
        printf("  decaps    Decapsulate (recover shared secret)\n");
        printf("  demo      Run full KEM demonstration\n");
        return CLI_ERR_ARGS;
    }

    const char *subcmd = argv[1];

    if (strcmp(subcmd, "keygen") == 0)
    {
        return kem_keygen(argc - 1, &argv[1]);
    }
    else if (strcmp(subcmd, "encaps") == 0)
    {
        return kem_encaps(argc - 1, &argv[1]);
    }
    else if (strcmp(subcmd, "decaps") == 0)
    {
        return kem_decaps(argc - 1, &argv[1]);
    }
    else if (strcmp(subcmd, "demo") == 0)
    {
        return kem_demo(argc - 1, &argv[1]);
    }
    else
    {
        cli_error("Unknown KEM subcommand: %s", subcmd);
        return CLI_ERR_ARGS;
    }
}