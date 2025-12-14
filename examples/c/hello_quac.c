/**
 * @file hello_quac.c
 * @brief QUAC 100 Hello World Example
 *
 * Basic example demonstrating device initialization and random number generation.
 *
 * Build:
 *   gcc -o hello_quac hello_quac.c -lquac100
 *
 * Run:
 *   ./hello_quac
 *
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <quac100.h>

/* Print bytes as hex */
static void print_hex(const char *label, const uint8_t *data, size_t len)
{
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++)
    {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main(int argc, char *argv[])
{
    quac_context_t *ctx = NULL;
    quac_device_t *device = NULL;
    quac_result_t result;

    (void)argc;
    (void)argv;

    printf("===========================================\n");
    printf("  QUAC 100 Hello World Example\n");
    printf("===========================================\n\n");

    /*-------------------------------------------------------------------------
     * Step 1: Initialize the SDK
     *-------------------------------------------------------------------------*/
    printf("1. Initializing QUAC SDK...\n");

    result = quac_init(&ctx);
    if (result != QUAC_SUCCESS)
    {
        fprintf(stderr, "   Error: Failed to initialize SDK (code: %d)\n", result);
        return 1;
    }
    printf("   SDK initialized successfully.\n\n");

    /*-------------------------------------------------------------------------
     * Step 2: Query available devices
     *-------------------------------------------------------------------------*/
    printf("2. Querying devices...\n");

    uint32_t device_count = 0;
    result = quac_get_device_count(ctx, &device_count);
    if (result != QUAC_SUCCESS)
    {
        fprintf(stderr, "   Error: Failed to get device count\n");
        quac_shutdown(ctx);
        return 1;
    }
    printf("   Found %u device(s)\n\n", device_count);

    /*-------------------------------------------------------------------------
     * Step 3: Open a device
     *-------------------------------------------------------------------------*/
    printf("3. Opening device 0...\n");

    if (device_count > 0)
    {
        result = quac_open_device(ctx, 0, &device);
    }
    else
    {
        /* Use simulator if no hardware available */
        printf("   No hardware found, using simulator...\n");
        result = quac_open_simulator(ctx, &device);
    }

    if (result != QUAC_SUCCESS)
    {
        fprintf(stderr, "   Error: Failed to open device\n");
        quac_shutdown(ctx);
        return 1;
    }
    printf("   Device opened successfully.\n\n");

    /*-------------------------------------------------------------------------
     * Step 4: Get device information
     *-------------------------------------------------------------------------*/
    printf("4. Device Information:\n");

    quac_device_info_t info;
    result = quac_device_get_info(device, &info);
    if (result == QUAC_SUCCESS)
    {
        printf("   Name:     %s\n", info.name);
        printf("   Serial:   %s\n", info.serial_number);
        printf("   Firmware: %s\n", info.firmware_version);
    }
    printf("\n");

    /*-------------------------------------------------------------------------
     * Step 5: Generate random numbers
     *-------------------------------------------------------------------------*/
    printf("5. Generating random numbers with QRNG...\n");

    uint8_t random_bytes[32];
    size_t random_len = sizeof(random_bytes);

    result = quac_random(device, random_bytes, random_len);
    if (result != QUAC_SUCCESS)
    {
        fprintf(stderr, "   Error: Failed to generate random bytes\n");
    }
    else
    {
        print_hex("   Random", random_bytes, random_len);
    }
    printf("\n");

    /*-------------------------------------------------------------------------
     * Step 6: Quick ML-KEM-768 demo
     *-------------------------------------------------------------------------*/
    printf("6. Quick ML-KEM-768 demonstration...\n");

    /* Allocate key buffers */
    uint8_t pk[QUAC_ML_KEM_768_PUBLIC_KEY_SIZE];
    uint8_t sk[QUAC_ML_KEM_768_SECRET_KEY_SIZE];
    size_t pk_len = sizeof(pk);
    size_t sk_len = sizeof(sk);

    /* Generate keypair */
    result = quac_kem_keygen(device, QUAC_ALG_ML_KEM_768, pk, &pk_len, sk, &sk_len);
    if (result != QUAC_SUCCESS)
    {
        fprintf(stderr, "   Error: Keygen failed\n");
    }
    else
    {
        printf("   Generated keypair:\n");
        printf("     Public key:  %zu bytes\n", pk_len);
        printf("     Secret key:  %zu bytes\n", sk_len);

        /* Show first 16 bytes of public key */
        printf("     PK (first 16 bytes): ");
        for (int i = 0; i < 16; i++)
            printf("%02x", pk[i]);
        printf("...\n");
    }
    printf("\n");

    /*-------------------------------------------------------------------------
     * Step 7: Cleanup
     *-------------------------------------------------------------------------*/
    printf("7. Cleaning up...\n");

    quac_close_device(device);
    quac_shutdown(ctx);

    printf("   Done!\n\n");
    printf("===========================================\n");
    printf("  Hello World Complete!\n");
    printf("===========================================\n");

    return 0;
}