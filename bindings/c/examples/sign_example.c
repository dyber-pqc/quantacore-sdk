/**
 * @file sign_example.c
 * @brief ML-DSA Digital Signature Example
 * @copyright Copyright © 2025 Dyber, Inc. All Rights Reserved.
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
    printf("QUAC 100 ML-DSA Digital Signature Example\n");
    printf("==========================================\n\n");

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
    quac_sign_params_t params;
    quac_sign_get_params(QUAC_SIGN_ML_DSA_65, &params);

    printf("Using %s (Security Level %d)\n", params.name, params.security_level);
    printf("  Public Key:  %zu bytes\n", params.public_key_size);
    printf("  Secret Key:  %zu bytes\n", params.secret_key_size);
    printf("  Signature:   %zu bytes\n", params.signature_size);
    printf("\n");

    /* Allocate buffers */
    uint8_t *public_key = malloc(params.public_key_size);
    uint8_t *secret_key = malloc(params.secret_key_size);
    uint8_t *signature = malloc(params.signature_size);

    if (!public_key || !secret_key || !signature)
    {
        fprintf(stderr, "Memory allocation failed\n");
        goto cleanup;
    }

    /* Generate key pair */
    printf("Generating key pair...\n");

    size_t pk_len = params.public_key_size;
    size_t sk_len = params.secret_key_size;

    status = quac_sign_keygen(device, QUAC_SIGN_ML_DSA_65,
                              public_key, &pk_len, secret_key, &sk_len);
    if (status != QUAC_SUCCESS)
    {
        fprintf(stderr, "Key generation failed: %s\n", quac_error_string(status));
        goto cleanup;
    }

    print_hex("Public Key", public_key, pk_len);
    print_hex("Secret Key", secret_key, sk_len);
    printf("\n");

    /* Sign a message */
    const char *message = "Hello, Post-Quantum World! This message is protected by ML-DSA-65.";
    size_t message_len = strlen(message);

    printf("Signing message: \"%s\"\n", message);

    size_t sig_len = params.signature_size;

    status = quac_sign(device, QUAC_SIGN_ML_DSA_65,
                       secret_key, sk_len,
                       (const uint8_t *)message, message_len,
                       signature, &sig_len);
    if (status != QUAC_SUCCESS)
    {
        fprintf(stderr, "Signing failed: %s\n", quac_error_string(status));
        goto cleanup;
    }

    print_hex("Signature", signature, sig_len);
    printf("\n");

    /* Verify the signature */
    printf("Verifying signature...\n");

    status = quac_verify(device, QUAC_SIGN_ML_DSA_65,
                         public_key, pk_len,
                         (const uint8_t *)message, message_len,
                         signature, sig_len);
    if (status == QUAC_SUCCESS)
    {
        printf("Signature VALID ✓\n\n");
    }
    else if (status == QUAC_ERROR_VERIFY_FAILED)
    {
        printf("Signature INVALID ✗\n\n");
    }
    else
    {
        fprintf(stderr, "Verification error: %s\n", quac_error_string(status));
        goto cleanup;
    }

    /* Test tamper detection */
    printf("Testing tamper detection...\n");

    /* Modify the message */
    char tampered_message[] = "Hello, Post-Quantum World! This message is protected by ML-DSA-65!";
    size_t tampered_len = strlen(tampered_message);

    printf("Verifying with tampered message: \"%s\"\n", tampered_message);

    status = quac_verify(device, QUAC_SIGN_ML_DSA_65,
                         public_key, pk_len,
                         (const uint8_t *)tampered_message, tampered_len,
                         signature, sig_len);
    if (status == QUAC_SUCCESS)
    {
        printf("Signature VALID (unexpected in real hardware)\n");
    }
    else if (status == QUAC_ERROR_VERIFY_FAILED)
    {
        printf("Signature INVALID ✓ (tamper detected)\n");
    }
    else
    {
        fprintf(stderr, "Verification error: %s\n", quac_error_string(status));
    }

    printf("\nSignature example completed!\n");

cleanup:
    /* Securely clear and free memory */
    if (secret_key)
    {
        quac_secure_zero(secret_key, params.secret_key_size);
        free(secret_key);
    }
    free(public_key);
    free(signature);

    quac_close_device(device);
    quac_cleanup();

    return 0;
}