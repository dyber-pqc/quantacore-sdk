/**
 * @file kyber_demo.c
 * @brief QUAC 100 ML-KEM (Kyber) Key Exchange Demo
 *
 * Demonstrates complete key encapsulation mechanism workflow:
 * - Key generation
 * - Encapsulation (sender side)
 * - Decapsulation (receiver side)
 * - Shared secret verification
 *
 * Build:
 *   gcc -o kyber_demo kyber_demo.c -lquac100
 *
 * Run:
 *   ./kyber_demo [512|768|1024]
 *
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <quac100.h>

/*=============================================================================
 * Utility Functions
 *=============================================================================*/

static void print_hex(const char *label, const uint8_t *data, size_t len)
{
    printf("%s (%zu bytes):\n  ", label, len);
    for (size_t i = 0; i < len && i < 48; i++)
    {
        printf("%02x", data[i]);
        if ((i + 1) % 32 == 0 && i + 1 < len)
            printf("\n  ");
    }
    if (len > 48)
        printf("...");
    printf("\n");
}

static int compare_bytes(const uint8_t *a, const uint8_t *b, size_t len)
{
    for (size_t i = 0; i < len; i++)
    {
        if (a[i] != b[i])
            return 0;
    }
    return 1;
}

/*=============================================================================
 * KEM Parameter Selection
 *=============================================================================*/

typedef struct
{
    quac_algorithm_t alg;
    const char *name;
    size_t pk_size;
    size_t sk_size;
    size_t ct_size;
    size_t ss_size;
} kem_params_t;

static const kem_params_t kem_variants[] = {
    {QUAC_ALG_ML_KEM_512, "ML-KEM-512",
     QUAC_ML_KEM_512_PUBLIC_KEY_SIZE,
     QUAC_ML_KEM_512_SECRET_KEY_SIZE,
     QUAC_ML_KEM_512_CIPHERTEXT_SIZE,
     QUAC_ML_KEM_512_SHARED_SECRET_SIZE},
    {QUAC_ALG_ML_KEM_768, "ML-KEM-768",
     QUAC_ML_KEM_768_PUBLIC_KEY_SIZE,
     QUAC_ML_KEM_768_SECRET_KEY_SIZE,
     QUAC_ML_KEM_768_CIPHERTEXT_SIZE,
     QUAC_ML_KEM_768_SHARED_SECRET_SIZE},
    {QUAC_ALG_ML_KEM_1024, "ML-KEM-1024",
     QUAC_ML_KEM_1024_PUBLIC_KEY_SIZE,
     QUAC_ML_KEM_1024_SECRET_KEY_SIZE,
     QUAC_ML_KEM_1024_CIPHERTEXT_SIZE,
     QUAC_ML_KEM_1024_SHARED_SECRET_SIZE}};

static const kem_params_t *get_kem_params(int level)
{
    switch (level)
    {
    case 512:
        return &kem_variants[0];
    case 768:
        return &kem_variants[1];
    case 1024:
        return &kem_variants[2];
    default:
        return &kem_variants[1]; /* Default to 768 */
    }
}

/*=============================================================================
 * Main Demo
 *=============================================================================*/

int main(int argc, char *argv[])
{
    quac_context_t *ctx = NULL;
    quac_device_t *device = NULL;
    quac_result_t result;
    int exit_code = 0;

    /* Parse command line */
    int level = 768;
    if (argc > 1)
    {
        level = atoi(argv[1]);
        if (level != 512 && level != 768 && level != 1024)
        {
            fprintf(stderr, "Usage: %s [512|768|1024]\n", argv[0]);
            return 1;
        }
    }

    const kem_params_t *params = get_kem_params(level);

    printf("================================================================\n");
    printf("  QUAC 100 ML-KEM Key Exchange Demo\n");
    printf("  Algorithm: %s (FIPS 203)\n", params->name);
    printf("================================================================\n\n");

    /*-------------------------------------------------------------------------
     * Initialize
     *-------------------------------------------------------------------------*/
    printf("Initializing...\n");

    result = quac_init(&ctx);
    if (result != QUAC_SUCCESS)
    {
        fprintf(stderr, "Error: SDK initialization failed\n");
        return 1;
    }

    /* Try hardware first, fall back to simulator */
    uint32_t count = 0;
    quac_get_device_count(ctx, &count);

    if (count > 0)
    {
        result = quac_open_device(ctx, 0, &device);
        printf("Using hardware accelerator.\n\n");
    }
    else
    {
        result = quac_open_simulator(ctx, &device);
        printf("Using software simulator.\n\n");
    }

    if (result != QUAC_SUCCESS)
    {
        fprintf(stderr, "Error: Failed to open device\n");
        quac_shutdown(ctx);
        return 1;
    }

    /*-------------------------------------------------------------------------
     * Allocate Buffers
     *-------------------------------------------------------------------------*/
    uint8_t *pk = malloc(params->pk_size);
    uint8_t *sk = malloc(params->sk_size);
    uint8_t *ct = malloc(params->ct_size);
    uint8_t *ss_sender = malloc(params->ss_size);
    uint8_t *ss_receiver = malloc(params->ss_size);

    if (!pk || !sk || !ct || !ss_sender || !ss_receiver)
    {
        fprintf(stderr, "Error: Memory allocation failed\n");
        exit_code = 1;
        goto cleanup;
    }

    size_t pk_len = params->pk_size;
    size_t sk_len = params->sk_size;
    size_t ct_len = params->ct_size;
    size_t ss_sender_len = params->ss_size;
    size_t ss_receiver_len = params->ss_size;

    /*-------------------------------------------------------------------------
     * Step 1: Key Generation (Receiver)
     *-------------------------------------------------------------------------*/
    printf("Step 1: Key Generation (Receiver - Alice)\n");
    printf("------------------------------------------\n");
    printf("Alice generates a keypair to receive encrypted messages.\n\n");

    result = quac_kem_keygen(device, params->alg, pk, &pk_len, sk, &sk_len);
    if (result != QUAC_SUCCESS)
    {
        fprintf(stderr, "Error: Key generation failed (code: %d)\n", result);
        exit_code = 1;
        goto cleanup;
    }

    print_hex("Alice's Public Key", pk, pk_len);
    printf("Alice's Secret Key: %zu bytes (kept private)\n\n", sk_len);

    printf("Alice sends her public key to Bob...\n\n");

    /*-------------------------------------------------------------------------
     * Step 2: Encapsulation (Sender)
     *-------------------------------------------------------------------------*/
    printf("Step 2: Encapsulation (Sender - Bob)\n");
    printf("------------------------------------\n");
    printf("Bob uses Alice's public key to create:\n");
    printf("  - A ciphertext (to send to Alice)\n");
    printf("  - A shared secret (kept by Bob)\n\n");

    result = quac_kem_encaps(device, params->alg, pk, pk_len,
                             ct, &ct_len, ss_sender, &ss_sender_len);
    if (result != QUAC_SUCCESS)
    {
        fprintf(stderr, "Error: Encapsulation failed (code: %d)\n", result);
        exit_code = 1;
        goto cleanup;
    }

    print_hex("Ciphertext", ct, ct_len);
    print_hex("Bob's Shared Secret", ss_sender, ss_sender_len);
    printf("\nBob sends the ciphertext to Alice...\n\n");

    /*-------------------------------------------------------------------------
     * Step 3: Decapsulation (Receiver)
     *-------------------------------------------------------------------------*/
    printf("Step 3: Decapsulation (Receiver - Alice)\n");
    printf("-----------------------------------------\n");
    printf("Alice uses her secret key to recover the shared secret.\n\n");

    result = quac_kem_decaps(device, params->alg, ct, ct_len, sk, sk_len,
                             ss_receiver, &ss_receiver_len);
    if (result != QUAC_SUCCESS)
    {
        fprintf(stderr, "Error: Decapsulation failed (code: %d)\n", result);
        exit_code = 1;
        goto cleanup;
    }

    print_hex("Alice's Shared Secret", ss_receiver, ss_receiver_len);
    printf("\n");

    /*-------------------------------------------------------------------------
     * Step 4: Verification
     *-------------------------------------------------------------------------*/
    printf("Step 4: Verification\n");
    printf("--------------------\n");

    if (ss_sender_len == ss_receiver_len &&
        compare_bytes(ss_sender, ss_receiver, ss_sender_len))
    {
        printf("SUCCESS! Both parties have the same shared secret.\n");
        printf("This secret can now be used as a symmetric encryption key.\n\n");
    }
    else
    {
        printf("FAILURE! Shared secrets do not match.\n");
        exit_code = 1;
    }

    /*-------------------------------------------------------------------------
     * Summary
     *-------------------------------------------------------------------------*/
    printf("================================================================\n");
    printf("  Key Exchange Complete\n");
    printf("================================================================\n");
    printf("Algorithm:      %s\n", params->name);
    printf("Public Key:     %zu bytes\n", pk_len);
    printf("Secret Key:     %zu bytes\n", sk_len);
    printf("Ciphertext:     %zu bytes\n", ct_len);
    printf("Shared Secret:  %zu bytes (256 bits)\n", ss_sender_len);
    printf("\nThis shared secret provides:\n");
    printf("  - Post-quantum security against Shor's algorithm\n");
    printf("  - IND-CCA2 security (chosen ciphertext attack resistance)\n");
    printf("  - Perfect forward secrecy when used with ephemeral keys\n");
    printf("================================================================\n");

cleanup:
    /* Secure cleanup - zero sensitive data */
    if (sk)
    {
        memset(sk, 0, params->sk_size);
        free(sk);
    }
    if (ss_sender)
    {
        memset(ss_sender, 0, params->ss_size);
        free(ss_sender);
    }
    if (ss_receiver)
    {
        memset(ss_receiver, 0, params->ss_size);
        free(ss_receiver);
    }
    free(pk);
    free(ct);

    if (device)
        quac_close_device(device);
    if (ctx)
        quac_shutdown(ctx);

    return exit_code;
}