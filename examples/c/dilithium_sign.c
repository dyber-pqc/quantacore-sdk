/**
 * @file dilithium_sign.c
 * @brief QUAC 100 ML-DSA (Dilithium) Digital Signature Demo
 *
 * Demonstrates complete digital signature workflow:
 * - Key generation
 * - Message signing
 * - Signature verification
 * - Tamper detection
 *
 * Build:
 *   gcc -o dilithium_sign dilithium_sign.c -lquac100
 *
 * Run:
 *   ./dilithium_sign [44|65|87]
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

static void print_hex_short(const char *label, const uint8_t *data, size_t len)
{
    printf("%s (%zu bytes): ", label, len);
    size_t show = (len < 32) ? len : 32;
    for (size_t i = 0; i < show; i++)
    {
        printf("%02x", data[i]);
    }
    if (len > 32)
        printf("...");
    printf("\n");
}

/*=============================================================================
 * Signature Parameter Selection
 *=============================================================================*/

typedef struct
{
    quac_algorithm_t alg;
    const char *name;
    const char *security;
    size_t pk_size;
    size_t sk_size;
    size_t sig_size;
} sign_params_t;

static const sign_params_t sign_variants[] = {
    {QUAC_ALG_ML_DSA_44, "ML-DSA-44",
     "NIST Level 2 (128-bit)",
     QUAC_ML_DSA_44_PUBLIC_KEY_SIZE,
     QUAC_ML_DSA_44_SECRET_KEY_SIZE,
     QUAC_ML_DSA_44_SIGNATURE_SIZE},
    {QUAC_ALG_ML_DSA_65, "ML-DSA-65",
     "NIST Level 3 (192-bit)",
     QUAC_ML_DSA_65_PUBLIC_KEY_SIZE,
     QUAC_ML_DSA_65_SECRET_KEY_SIZE,
     QUAC_ML_DSA_65_SIGNATURE_SIZE},
    {QUAC_ALG_ML_DSA_87, "ML-DSA-87",
     "NIST Level 5 (256-bit)",
     QUAC_ML_DSA_87_PUBLIC_KEY_SIZE,
     QUAC_ML_DSA_87_SECRET_KEY_SIZE,
     QUAC_ML_DSA_87_SIGNATURE_SIZE}};

static const sign_params_t *get_sign_params(int level)
{
    switch (level)
    {
    case 44:
        return &sign_variants[0];
    case 65:
        return &sign_variants[1];
    case 87:
        return &sign_variants[2];
    default:
        return &sign_variants[1]; /* Default to 65 */
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
    int level = 65;
    if (argc > 1)
    {
        level = atoi(argv[1]);
        if (level != 44 && level != 65 && level != 87)
        {
            fprintf(stderr, "Usage: %s [44|65|87]\n", argv[0]);
            return 1;
        }
    }

    const sign_params_t *params = get_sign_params(level);

    printf("================================================================\n");
    printf("  QUAC 100 ML-DSA Digital Signature Demo\n");
    printf("  Algorithm: %s (FIPS 204)\n", params->name);
    printf("  Security:  %s\n", params->security);
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
    uint8_t *sig = malloc(params->sig_size);

    if (!pk || !sk || !sig)
    {
        fprintf(stderr, "Error: Memory allocation failed\n");
        exit_code = 1;
        goto cleanup;
    }

    size_t pk_len = params->pk_size;
    size_t sk_len = params->sk_size;
    size_t sig_len = params->sig_size;

    /* Sample message */
    const char *message = "This is a critical financial transaction: "
                          "Transfer $1,000,000 from Account A to Account B. "
                          "Transaction ID: TXN-2025-001-PQC";
    size_t msg_len = strlen(message);

    /*-------------------------------------------------------------------------
     * Step 1: Key Generation
     *-------------------------------------------------------------------------*/
    printf("Step 1: Key Generation\n");
    printf("----------------------\n");
    printf("Generating a signing keypair...\n\n");

    result = quac_sign_keygen(device, params->alg, pk, &pk_len, sk, &sk_len);
    if (result != QUAC_SUCCESS)
    {
        fprintf(stderr, "Error: Key generation failed (code: %d)\n", result);
        exit_code = 1;
        goto cleanup;
    }

    print_hex_short("Public Key (verification key)", pk, pk_len);
    printf("Secret Key (signing key): %zu bytes (kept private)\n\n", sk_len);

    /*-------------------------------------------------------------------------
     * Step 2: Sign Message
     *-------------------------------------------------------------------------*/
    printf("Step 2: Sign Message\n");
    printf("--------------------\n");
    printf("Message to sign:\n  \"%s\"\n\n", message);

    result = quac_sign(device, params->alg,
                       (const uint8_t *)message, msg_len,
                       sk, sk_len,
                       sig, &sig_len);
    if (result != QUAC_SUCCESS)
    {
        fprintf(stderr, "Error: Signing failed (code: %d)\n", result);
        exit_code = 1;
        goto cleanup;
    }

    print_hex_short("Signature", sig, sig_len);
    printf("\n");

    /*-------------------------------------------------------------------------
     * Step 3: Verify Signature (Valid)
     *-------------------------------------------------------------------------*/
    printf("Step 3: Verify Original Signature\n");
    printf("----------------------------------\n");

    result = quac_verify(device, params->alg,
                         (const uint8_t *)message, msg_len,
                         sig, sig_len,
                         pk, pk_len);

    if (result == QUAC_SUCCESS)
    {
        printf("VALID: Signature verification succeeded.\n");
        printf("  -> The message is authentic and unmodified.\n");
        printf("  -> It was signed by the holder of the corresponding secret key.\n\n");
    }
    else
    {
        printf("INVALID: Signature verification failed.\n");
        exit_code = 1;
        goto cleanup;
    }

    /*-------------------------------------------------------------------------
     * Step 4: Detect Tampering
     *-------------------------------------------------------------------------*/
    printf("Step 4: Tamper Detection Test\n");
    printf("-----------------------------\n");
    printf("Simulating message tampering (changing amount to $10,000,000)...\n\n");

    const char *tampered_message = "This is a critical financial transaction: "
                                   "Transfer $10,000,000 from Account A to Account B. "
                                   "Transaction ID: TXN-2025-001-PQC";
    size_t tampered_len = strlen(tampered_message);

    result = quac_verify(device, params->alg,
                         (const uint8_t *)tampered_message, tampered_len,
                         sig, sig_len,
                         pk, pk_len);

    if (result != QUAC_SUCCESS)
    {
        printf("DETECTED: Signature verification FAILED for tampered message.\n");
        printf("  -> The tampering was successfully detected!\n");
        printf("  -> Any modification to the message invalidates the signature.\n\n");
    }
    else
    {
        printf("ERROR: Tampered message was incorrectly accepted!\n");
        exit_code = 1;
        goto cleanup;
    }

    /*-------------------------------------------------------------------------
     * Step 5: Wrong Key Test
     *-------------------------------------------------------------------------*/
    printf("Step 5: Wrong Key Detection Test\n");
    printf("---------------------------------\n");
    printf("Generating a different keypair and trying to verify...\n\n");

    uint8_t *wrong_pk = malloc(params->pk_size);
    uint8_t *wrong_sk = malloc(params->sk_size);
    size_t wrong_pk_len = params->pk_size;
    size_t wrong_sk_len = params->sk_size;

    if (wrong_pk && wrong_sk)
    {
        quac_sign_keygen(device, params->alg, wrong_pk, &wrong_pk_len,
                         wrong_sk, &wrong_sk_len);

        result = quac_verify(device, params->alg,
                             (const uint8_t *)message, msg_len,
                             sig, sig_len,
                             wrong_pk, wrong_pk_len);

        if (result != QUAC_SUCCESS)
        {
            printf("DETECTED: Signature verification FAILED with wrong key.\n");
            printf("  -> Only the correct public key can verify the signature.\n\n");
        }
        else
        {
            printf("ERROR: Wrong key was incorrectly accepted!\n");
        }

        memset(wrong_sk, 0, params->sk_size);
        free(wrong_pk);
        free(wrong_sk);
    }

    /*-------------------------------------------------------------------------
     * Summary
     *-------------------------------------------------------------------------*/
    printf("================================================================\n");
    printf("  Digital Signature Demo Complete\n");
    printf("================================================================\n");
    printf("Algorithm:      %s\n", params->name);
    printf("Security Level: %s\n", params->security);
    printf("Public Key:     %zu bytes\n", pk_len);
    printf("Secret Key:     %zu bytes\n", sk_len);
    printf("Signature:      %zu bytes\n", sig_len);
    printf("\nML-DSA provides:\n");
    printf("  - Post-quantum security (resistant to Shor's algorithm)\n");
    printf("  - EUF-CMA security (existential unforgeability)\n");
    printf("  - Deterministic signatures (no random number needed)\n");
    printf("  - Fast verification suitable for certificate checking\n");
    printf("================================================================\n");

cleanup:
    /* Secure cleanup - zero sensitive data */
    if (sk)
    {
        memset(sk, 0, params->sk_size);
        free(sk);
    }
    free(pk);
    free(sig);

    if (device)
        quac_close_device(device);
    if (ctx)
        quac_shutdown(ctx);

    return exit_code;
}