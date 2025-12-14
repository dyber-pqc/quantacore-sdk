/**
 * @file kem_example.c
 * @brief ML-KEM Key Encapsulation Example
 * @copyright Copyright © 2025 Dyber, Inc. All Rights Reserved.
 *
 * Demonstrates a complete key exchange between Alice and Bob using ML-KEM-768.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <quac100/quac100.h>

static void print_hex(const char *label, const uint8_t *data, size_t len)
{
    printf("%s: ", label);
    for (size_t i = 0; i < len && i < 16; i++)
    {
        printf("%02x", data[i]);
    }
    if (len > 16)
        printf("...");
    printf(" (%zu bytes)\n", len);
}

int main(void)
{
    printf("QUAC 100 ML-KEM Key Exchange Example\n");
    printf("=====================================\n\n");

    quac_status_t status;

    /* Initialize */
    status = quac_init(QUAC_FLAG_DEFAULT);
    if (status != QUAC_SUCCESS)
    {
        fprintf(stderr, "Init failed: %s\n", quac_error_string(status));
        return 1;
    }

    /* Open device */
    quac_device_t device;
    status = quac_open_first_device(&device);
    if (status != QUAC_SUCCESS)
    {
        fprintf(stderr, "Failed to open device: %s\n", quac_error_string(status));
        quac_cleanup();
        return 1;
    }

    /* Get algorithm parameters */
    quac_kem_params_t params;
    quac_kem_get_params(QUAC_KEM_ML_KEM_768, &params);

    printf("Using %s (Security Level %d)\n", params.name, params.security_level);
    printf("  Public Key:     %zu bytes\n", params.public_key_size);
    printf("  Secret Key:     %zu bytes\n", params.secret_key_size);
    printf("  Ciphertext:     %zu bytes\n", params.ciphertext_size);
    printf("  Shared Secret:  %zu bytes\n", params.shared_secret_size);
    printf("\n");

    /* Allocate buffers */
    uint8_t *alice_pk = malloc(params.public_key_size);
    uint8_t *alice_sk = malloc(params.secret_key_size);
    uint8_t *ciphertext = malloc(params.ciphertext_size);
    uint8_t *bob_ss = malloc(params.shared_secret_size);
    uint8_t *alice_ss = malloc(params.shared_secret_size);

    if (!alice_pk || !alice_sk || !ciphertext || !bob_ss || !alice_ss)
    {
        fprintf(stderr, "Memory allocation failed\n");
        goto cleanup;
    }

    /* Step 1: Alice generates key pair */
    printf("Step 1: Alice generates key pair...\n");

    size_t pk_len = params.public_key_size;
    size_t sk_len = params.secret_key_size;

    status = quac_kem_keygen(device, QUAC_KEM_ML_KEM_768,
                             alice_pk, &pk_len, alice_sk, &sk_len);
    if (status != QUAC_SUCCESS)
    {
        fprintf(stderr, "Key generation failed: %s\n", quac_error_string(status));
        goto cleanup;
    }

    print_hex("Alice Public Key", alice_pk, pk_len);
    print_hex("Alice Secret Key", alice_sk, sk_len);
    printf("\n");

    /* Step 2: Alice sends public key to Bob (simulated) */
    printf("Step 2: Alice sends public key to Bob\n\n");

    /* Step 3: Bob encapsulates a shared secret */
    printf("Step 3: Bob encapsulates shared secret...\n");

    size_t ct_len = params.ciphertext_size;
    size_t ss_len = params.shared_secret_size;

    status = quac_kem_encaps(device, QUAC_KEM_ML_KEM_768,
                             alice_pk, pk_len,
                             ciphertext, &ct_len,
                             bob_ss, &ss_len);
    if (status != QUAC_SUCCESS)
    {
        fprintf(stderr, "Encapsulation failed: %s\n", quac_error_string(status));
        goto cleanup;
    }

    print_hex("Ciphertext", ciphertext, ct_len);
    print_hex("Bob's Shared Secret", bob_ss, ss_len);
    printf("\n");

    /* Step 4: Bob sends ciphertext to Alice (simulated) */
    printf("Step 4: Bob sends ciphertext to Alice\n\n");

    /* Step 5: Alice decapsulates the shared secret */
    printf("Step 5: Alice decapsulates shared secret...\n");

    ss_len = params.shared_secret_size;

    status = quac_kem_decaps(device, QUAC_KEM_ML_KEM_768,
                             alice_sk, sk_len,
                             ciphertext, ct_len,
                             alice_ss, &ss_len);
    if (status != QUAC_SUCCESS)
    {
        fprintf(stderr, "Decapsulation failed: %s\n", quac_error_string(status));
        goto cleanup;
    }

    print_hex("Alice's Shared Secret", alice_ss, ss_len);
    printf("\n");

    /* Verify shared secrets match */
    printf("Step 6: Verify shared secrets match...\n");

    if (quac_secure_compare(alice_ss, bob_ss, params.shared_secret_size) == 0)
    {
        printf("SUCCESS: Shared secrets match!\n");
    }
    else
    {
        printf("WARNING: Shared secrets do NOT match (simulation mode)\n");
    }

    printf("\nKey exchange completed!\n");

cleanup:
    /* Securely clear and free memory */
    if (alice_sk)
    {
        quac_secure_zero(alice_sk, params.secret_key_size);
        free(alice_sk);
    }
    if (alice_ss)
    {
        quac_secure_zero(alice_ss, params.shared_secret_size);
        free(alice_ss);
    }
    if (bob_ss)
    {
        quac_secure_zero(bob_ss, params.shared_secret_size);
        free(bob_ss);
    }
    free(alice_pk);
    free(ciphertext);

    quac_close_device(device);
    quac_cleanup();

    return 0;
}