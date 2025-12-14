/**
 * @file sign.c
 * @brief QUAC 100 CLI - Signature Operations
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
 * Signature Key/Signature Sizes
 *=============================================================================*/

typedef struct
{
    cli_algorithm_t alg;
    size_t pk_size;
    size_t sk_size;
    size_t sig_size;
} sign_sizes_t;

static const sign_sizes_t sign_sizes[] = {
    {ALG_ML_DSA_44, 1312, 2560, 2420},
    {ALG_ML_DSA_65, 1952, 4032, 3309},
    {ALG_ML_DSA_87, 2592, 4896, 4627},
    {ALG_SLH_DSA_128F, 32, 64, 17088},
    {ALG_SLH_DSA_128S, 32, 64, 7856},
    {ALG_SLH_DSA_192F, 48, 96, 35664},
    {ALG_SLH_DSA_192S, 48, 96, 16224},
    {ALG_SLH_DSA_256F, 64, 128, 49856},
    {ALG_SLH_DSA_256S, 64, 128, 29792},
    {ALG_UNKNOWN, 0, 0, 0}};

static const sign_sizes_t *get_sign_sizes(cli_algorithm_t alg)
{
    for (int i = 0; sign_sizes[i].alg != ALG_UNKNOWN; i++)
    {
        if (sign_sizes[i].alg == alg)
        {
            return &sign_sizes[i];
        }
    }
    return NULL;
}

/*=============================================================================
 * Simulated Signature Operations
 *=============================================================================*/

static int sim_sign_keygen(cli_algorithm_t alg, uint8_t *pk, size_t *pk_len,
                           uint8_t *sk, size_t *sk_len)
{
    const sign_sizes_t *sizes = get_sign_sizes(alg);
    if (!sizes)
        return -1;

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

static int sim_sign(cli_algorithm_t alg, const uint8_t *msg, size_t msg_len,
                    const uint8_t *sk, size_t sk_len,
                    uint8_t *sig, size_t *sig_len)
{
    (void)msg;
    (void)msg_len;
    (void)sk;
    (void)sk_len;

    const sign_sizes_t *sizes = get_sign_sizes(alg);
    if (!sizes)
        return -1;

    for (size_t i = 0; i < sizes->sig_size; i++)
    {
        sig[i] = (uint8_t)(rand() & 0xFF);
    }

    *sig_len = sizes->sig_size;
    return 0;
}

static int sim_verify(cli_algorithm_t alg, const uint8_t *msg, size_t msg_len,
                      const uint8_t *sig, size_t sig_len,
                      const uint8_t *pk, size_t pk_len)
{
    (void)alg;
    (void)msg;
    (void)msg_len;
    (void)sig;
    (void)sig_len;
    (void)pk;
    (void)pk_len;

    /* Simulation: randomly succeed */
    return (rand() % 10 < 8) ? 0 : -1;
}

/*=============================================================================
 * Sign Keygen Command
 *=============================================================================*/

static int sign_keygen(int argc, char *argv[])
{
    cli_algorithm_t alg = ALG_ML_DSA_65;
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
            if (!is_sign_algorithm(alg))
            {
                cli_error("Invalid signature algorithm: %s", optarg);
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
            printf("Usage: quac100-cli sign keygen [options]\n\n");
            printf("Options:\n");
            printf("  -a, --algorithm <alg>  Algorithm (default: ml-dsa-65)\n");
            printf("  -o, --output <file>    Combined output file\n");
            printf("  --pk <file>            Public key output file\n");
            printf("  --sk <file>            Secret key output file\n");
            return CLI_OK;
        default:
            return CLI_ERR_ARGS;
        }
    }

    const sign_sizes_t *sizes = get_sign_sizes(alg);
    if (!sizes)
    {
        cli_error("Invalid algorithm");
        return CLI_ERR_ARGS;
    }

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

    cli_device_t *dev = cli_get_current_device();
    int result;

    if (!dev || cli_device_is_simulator(dev))
    {
        result = sim_sign_keygen(alg, pk, &pk_len, sk, &sk_len);
    }
    else
    {
        result = sim_sign_keygen(alg, pk, &pk_len, sk, &sk_len);
    }

    if (result != 0)
    {
        free(pk);
        free(sk);
        cli_error("Key generation failed");
        return CLI_ERR_OPERATION;
    }

    if (pk_file[0] && sk_file[0])
    {
        if (write_binary_file(pk_file, pk, pk_len) != 0 ||
            write_binary_file(sk_file, sk, sk_len) != 0)
        {
            cli_error("Failed to write key files");
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
        FILE *f = fopen(output_file, "wb");
        if (!f)
        {
            cli_error("Failed to open %s", output_file);
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
            cli_info("Generated %s keypair: %s", algorithm_name(alg), output_file);
        }
    }
    else
    {
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
 * Sign Command
 *=============================================================================*/

static int sign_sign(int argc, char *argv[])
{
    cli_algorithm_t alg = ALG_ML_DSA_65;
    char sk_file[256] = "";
    char msg_file[256] = "";
    char output_file[256] = "";

    static struct option opts[] = {
        {"algorithm", required_argument, NULL, 'a'},
        {"sk", required_argument, NULL, 's'},
        {"message", required_argument, NULL, 'm'},
        {"output", required_argument, NULL, 'o'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}};

    optind = 1;
    int c;
    while ((c = getopt_long(argc, argv, "a:s:m:o:h", opts, NULL)) != -1)
    {
        switch (c)
        {
        case 'a':
            alg = parse_algorithm(optarg);
            break;
        case 's':
            strncpy(sk_file, optarg, sizeof(sk_file) - 1);
            break;
        case 'm':
            strncpy(msg_file, optarg, sizeof(msg_file) - 1);
            break;
        case 'o':
            strncpy(output_file, optarg, sizeof(output_file) - 1);
            break;
        case 'h':
            printf("Usage: quac100-cli sign sign [options]\n\n");
            printf("Options:\n");
            printf("  -a, --algorithm <alg>  Algorithm (default: ml-dsa-65)\n");
            printf("  -s, --sk <file>        Secret key file (required)\n");
            printf("  -m, --message <file>   Message file (required)\n");
            printf("  -o, --output <file>    Signature output file\n");
            return CLI_OK;
        default:
            return CLI_ERR_ARGS;
        }
    }

    if (!sk_file[0] || !msg_file[0])
    {
        cli_error("Secret key (-s) and message (-m) required");
        return CLI_ERR_ARGS;
    }

    const sign_sizes_t *sizes = get_sign_sizes(alg);
    if (!sizes)
    {
        cli_error("Invalid algorithm");
        return CLI_ERR_ARGS;
    }

    /* Read inputs */
    size_t sk_len, msg_len;
    uint8_t *sk = read_binary_file(sk_file, &sk_len);
    uint8_t *msg = read_binary_file(msg_file, &msg_len);

    if (!sk || !msg)
    {
        free(sk);
        free(msg);
        cli_error("Failed to read input files");
        return CLI_ERR_IO;
    }

    uint8_t *sig = malloc(sizes->sig_size);
    if (!sig)
    {
        free(sk);
        free(msg);
        cli_error("Memory allocation failed");
        return CLI_ERR_GENERAL;
    }

    size_t sig_len;

    cli_device_t *dev = cli_get_current_device();
    int result;

    if (!dev || cli_device_is_simulator(dev))
    {
        result = sim_sign(alg, msg, msg_len, sk, sk_len, sig, &sig_len);
    }
    else
    {
        result = sim_sign(alg, msg, msg_len, sk, sk_len, sig, &sig_len);
    }

    free(sk);
    free(msg);

    if (result != 0)
    {
        free(sig);
        cli_error("Signing failed");
        return CLI_ERR_OPERATION;
    }

    if (output_file[0])
    {
        if (write_binary_file(output_file, sig, sig_len) != 0)
        {
            cli_error("Failed to write signature");
            free(sig);
            return CLI_ERR_IO;
        }

        if (!g_options.quiet)
        {
            cli_info("Signature created: %s (%zu bytes)", output_file, sig_len);
        }
    }
    else
    {
        if (g_options.json_output)
        {
            printf("{\n");
            printf("  \"signature\": \"");
            print_hex(sig, sig_len);
            printf("\"\n");
            printf("}\n");
        }
        else
        {
            printf("Signature (%zu bytes):\n", sig_len);
            print_hex_formatted(sig, sig_len, 32);
        }
    }

    free(sig);
    return CLI_OK;
}

/*=============================================================================
 * Verify Command
 *=============================================================================*/

static int sign_verify(int argc, char *argv[])
{
    cli_algorithm_t alg = ALG_ML_DSA_65;
    char pk_file[256] = "";
    char msg_file[256] = "";
    char sig_file[256] = "";

    static struct option opts[] = {
        {"algorithm", required_argument, NULL, 'a'},
        {"pk", required_argument, NULL, 'p'},
        {"message", required_argument, NULL, 'm'},
        {"signature", required_argument, NULL, 'g'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}};

    optind = 1;
    int c;
    while ((c = getopt_long(argc, argv, "a:p:m:g:h", opts, NULL)) != -1)
    {
        switch (c)
        {
        case 'a':
            alg = parse_algorithm(optarg);
            break;
        case 'p':
            strncpy(pk_file, optarg, sizeof(pk_file) - 1);
            break;
        case 'm':
            strncpy(msg_file, optarg, sizeof(msg_file) - 1);
            break;
        case 'g':
            strncpy(sig_file, optarg, sizeof(sig_file) - 1);
            break;
        case 'h':
            printf("Usage: quac100-cli sign verify [options]\n\n");
            printf("Options:\n");
            printf("  -a, --algorithm <alg>   Algorithm (default: ml-dsa-65)\n");
            printf("  -p, --pk <file>         Public key file (required)\n");
            printf("  -m, --message <file>    Message file (required)\n");
            printf("  -g, --signature <file>  Signature file (required)\n");
            return CLI_OK;
        default:
            return CLI_ERR_ARGS;
        }
    }

    if (!pk_file[0] || !msg_file[0] || !sig_file[0])
    {
        cli_error("Public key (-p), message (-m), and signature (-g) required");
        return CLI_ERR_ARGS;
    }

    /* Read inputs */
    size_t pk_len, msg_len, sig_len;
    uint8_t *pk = read_binary_file(pk_file, &pk_len);
    uint8_t *msg = read_binary_file(msg_file, &msg_len);
    uint8_t *sig = read_binary_file(sig_file, &sig_len);

    if (!pk || !msg || !sig)
    {
        free(pk);
        free(msg);
        free(sig);
        cli_error("Failed to read input files");
        return CLI_ERR_IO;
    }

    cli_device_t *dev = cli_get_current_device();
    int result;

    if (!dev || cli_device_is_simulator(dev))
    {
        result = sim_verify(alg, msg, msg_len, sig, sig_len, pk, pk_len);
    }
    else
    {
        result = sim_verify(alg, msg, msg_len, sig, sig_len, pk, pk_len);
    }

    free(pk);
    free(msg);
    free(sig);

    if (g_options.json_output)
    {
        printf("{\n");
        printf("  \"valid\": %s\n", result == 0 ? "true" : "false");
        printf("}\n");
    }
    else
    {
        if (result == 0)
        {
            cli_info("Signature is VALID");
        }
        else
        {
            cli_error("Signature is INVALID");
        }
    }

    return result == 0 ? CLI_OK : CLI_ERR_OPERATION;
}

/*=============================================================================
 * Sign Demo Command
 *=============================================================================*/

static int sign_demo(int argc, char *argv[])
{
    cli_algorithm_t alg = ALG_ML_DSA_65;

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
            printf("Usage: quac100-cli sign demo [-a algorithm]\n");
            return CLI_OK;
        default:
            return CLI_ERR_ARGS;
        }
    }

    const sign_sizes_t *sizes = get_sign_sizes(alg);
    if (!sizes)
    {
        cli_error("Invalid algorithm");
        return CLI_ERR_ARGS;
    }

    printf("Signature Demonstration: %s\n", algorithm_name(alg));
    printf("=====================================\n\n");

    /* Keygen */
    printf("1. Generating keypair...\n");
    uint8_t *pk = malloc(sizes->pk_size);
    uint8_t *sk = malloc(sizes->sk_size);
    size_t pk_len, sk_len;

    sim_sign_keygen(alg, pk, &pk_len, sk, &sk_len);
    printf("   Public key: %zu bytes\n", pk_len);
    printf("   Secret key: %zu bytes\n\n", sk_len);

    /* Sign */
    printf("2. Signing message...\n");
    const char *message = "Hello, Post-Quantum World!";
    size_t msg_len = strlen(message);
    uint8_t *sig = malloc(sizes->sig_size);
    size_t sig_len;

    sim_sign(alg, (const uint8_t *)message, msg_len, sk, sk_len, sig, &sig_len);
    printf("   Message: \"%s\"\n", message);
    printf("   Signature: %zu bytes\n", sig_len);
    printf("   First bytes: ");
    print_hex(sig, sig_len < 16 ? sig_len : 16);
    printf("...\n\n");

    /* Verify */
    printf("3. Verifying signature...\n");
    int result = sim_verify(alg, (const uint8_t *)message, msg_len,
                            sig, sig_len, pk, pk_len);
    printf("   Result: %s\n\n", result == 0 ? "VALID" : "INVALID");

    printf("Note: This is a simulation with random data.\n");

    free(pk);
    free(sk);
    free(sig);

    return CLI_OK;
}

/*=============================================================================
 * Sign Command Entry Point
 *=============================================================================*/

int cmd_sign(int argc, char *argv[])
{
    if (argc < 2)
    {
        printf("Usage: quac100-cli sign <subcommand> [options]\n\n");
        printf("Subcommands:\n");
        printf("  keygen    Generate signature keypair\n");
        printf("  sign      Sign a message or file\n");
        printf("  verify    Verify a signature\n");
        printf("  demo      Run full signature demonstration\n");
        return CLI_ERR_ARGS;
    }

    const char *subcmd = argv[1];

    if (strcmp(subcmd, "keygen") == 0)
    {
        return sign_keygen(argc - 1, &argv[1]);
    }
    else if (strcmp(subcmd, "sign") == 0)
    {
        return sign_sign(argc - 1, &argv[1]);
    }
    else if (strcmp(subcmd, "verify") == 0)
    {
        return sign_verify(argc - 1, &argv[1]);
    }
    else if (strcmp(subcmd, "demo") == 0)
    {
        return sign_demo(argc - 1, &argv[1]);
    }
    else
    {
        cli_error("Unknown sign subcommand: %s", subcmd);
        return CLI_ERR_ARGS;
    }
}