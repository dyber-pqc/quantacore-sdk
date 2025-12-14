/**
 * @file random_example.c
 * @brief QUAC 100 SDK - Random Number Generation Example
 * @copyright Copyright © 2025 Dyber, Inc. All Rights Reserved.
 *
 * Demonstrates quantum random number generation features.
 */

#include <quac100/quac100.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Print bytes as hex */
static void print_hex(const char *label, const uint8_t *data, size_t len)
{
    printf("%s: ", label);
    for (size_t i = 0; i < len && i < 32; i++)
    {
        printf("%02x", data[i]);
    }
    if (len > 32)
        printf("...");
    printf("\n");
}

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    printf("========================================\n");
    printf("QUAC 100 Random Number Generation Example\n");
    printf("========================================\n\n");

    /* Initialize */
    quac_status_t status = quac_init(QUAC_FLAG_DEFAULT);
    if (status != QUAC_SUCCESS)
    {
        fprintf(stderr, "Init failed: %s\n", quac_error_string(status));
        return 1;
    }

    quac_device_t device;
    status = quac_open_first_device(&device);
    if (status != QUAC_SUCCESS)
    {
        fprintf(stderr, "Open device failed: %s\n", quac_error_string(status));
        quac_cleanup();
        return 1;
    }

    /* 1. Basic random bytes */
    printf("--- Random Bytes ---\n");
    uint8_t bytes[32];
    status = quac_random_bytes(device, bytes, sizeof(bytes));
    if (status == QUAC_SUCCESS)
    {
        print_hex("32 random bytes", bytes, sizeof(bytes));
    }

    /* 2. Random bytes with different entropy sources */
    printf("\n--- Entropy Sources ---\n");

    status = quac_random_bytes_ex(device, bytes, 16, QUAC_ENTROPY_QRNG);
    if (status == QUAC_SUCCESS)
    {
        print_hex("QRNG (16 bytes)", bytes, 16);
    }

    status = quac_random_bytes_ex(device, bytes, 16, QUAC_ENTROPY_HYBRID);
    if (status == QUAC_SUCCESS)
    {
        print_hex("Hybrid (16 bytes)", bytes, 16);
    }

    /* 3. Random integers */
    printf("\n--- Random Integers ---\n");

    uint32_t u32;
    status = quac_random_uint32(device, &u32);
    if (status == QUAC_SUCCESS)
    {
        printf("uint32: %u\n", u32);
    }

    uint64_t u64;
    status = quac_random_uint64(device, &u64);
    if (status == QUAC_SUCCESS)
    {
        printf("uint64: %llu\n", (unsigned long long)u64);
    }

    /* 4. Random range */
    printf("\n--- Random Range ---\n");

    printf("10 random dice rolls: ");
    for (int i = 0; i < 10; i++)
    {
        uint32_t dice;
        status = quac_random_range(device, 6, &dice);
        if (status == QUAC_SUCCESS)
        {
            printf("%u ", dice + 1);
        }
    }
    printf("\n");

    printf("10 random numbers [50, 100): ");
    for (int i = 0; i < 10; i++)
    {
        int64_t val;
        status = quac_random_range_ex(device, 50, 100, &val);
        if (status == QUAC_SUCCESS)
        {
            printf("%lld ", (long long)val);
        }
    }
    printf("\n");

    /* 5. Random floating point */
    printf("\n--- Random Floats ---\n");

    printf("10 random doubles [0, 1): ");
    for (int i = 0; i < 10; i++)
    {
        double d;
        status = quac_random_double(device, &d);
        if (status == QUAC_SUCCESS)
        {
            printf("%.4f ", d);
        }
    }
    printf("\n");

    printf("10 random floats [0, 1): ");
    for (int i = 0; i < 10; i++)
    {
        float f;
        status = quac_random_float(device, &f);
        if (status == QUAC_SUCCESS)
        {
            printf("%.4f ", f);
        }
    }
    printf("\n");

    /* 6. Random UUID */
    printf("\n--- Random UUID ---\n");

    char uuid_str[37];
    status = quac_random_uuid_string(device, uuid_str, sizeof(uuid_str));
    if (status == QUAC_SUCCESS)
    {
        printf("UUID v4: %s\n", uuid_str);
    }

    /* Generate a few more */
    printf("More UUIDs:\n");
    for (int i = 0; i < 3; i++)
    {
        status = quac_random_uuid_string(device, uuid_str, sizeof(uuid_str));
        if (status == QUAC_SUCCESS)
        {
            printf("  %s\n", uuid_str);
        }
    }

    /* 7. Shuffle array */
    printf("\n--- Array Shuffle ---\n");

    int values[10] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    printf("Original: ");
    for (int i = 0; i < 10; i++)
        printf("%d ", values[i]);
    printf("\n");

    status = quac_random_shuffle(device, values, 10, sizeof(int));
    if (status == QUAC_SUCCESS)
    {
        printf("Shuffled: ");
        for (int i = 0; i < 10; i++)
            printf("%d ", values[i]);
        printf("\n");
    }

    /* 8. Random selection */
    printf("\n--- Random Selection ---\n");

    const char *options[] = {"Apple", "Banana", "Cherry", "Date", "Elderberry"};
    const char *selected[3];

    status = quac_random_select(device, options, 5, sizeof(const char *), 3, selected);
    if (status == QUAC_SUCCESS)
    {
        printf("Selected 3 from 5 fruits: ");
        for (int i = 0; i < 3; i++)
        {
            printf("%s ", selected[i]);
        }
        printf("\n");
    }

    /* 9. Entropy status */
    printf("\n--- Entropy Status ---\n");

    quac_entropy_status_t entropy;
    status = quac_entropy_status(device, &entropy);
    if (status == QUAC_SUCCESS)
    {
        printf("Entropy level: %d%%\n", entropy.level);
        printf("Entropy source: %s\n",
               entropy.source == QUAC_ENTROPY_QRNG ? "QRNG" : entropy.source == QUAC_ENTROPY_TRNG ? "TRNG"
                                                          : entropy.source == QUAC_ENTROPY_HYBRID ? "Hybrid"
                                                                                                  : "Software");
        printf("Health check: %s\n", entropy.health_ok ? "OK" : "FAIL");
        printf("Bytes generated: %llu\n", (unsigned long long)entropy.bytes_generated);
    }

    /* 10. Entropy estimation */
    printf("\n--- Entropy Estimation ---\n");

    double entropy_bits;
    status = quac_random_estimate_entropy(device, 10000, &entropy_bits);
    if (status == QUAC_SUCCESS)
    {
        printf("Estimated entropy: %.4f bits/byte (max 8.0)\n", entropy_bits);
    }

    /* 11. Benchmark */
    printf("\n--- Benchmark ---\n");

    double mbps;
    status = quac_random_benchmark(device, 10 * 1024 * 1024, &mbps); /* 10 MB */
    if (status == QUAC_SUCCESS)
    {
        printf("Throughput: %.2f MB/s\n", mbps);
    }

    /* 12. Cryptographic key generation */
    printf("\n--- Cryptographic Key Generation ---\n");

    /* Generate AES-256 key */
    uint8_t aes_key[32];
    status = quac_random_bytes(device, aes_key, sizeof(aes_key));
    if (status == QUAC_SUCCESS)
    {
        print_hex("AES-256 key", aes_key, sizeof(aes_key));
        quac_secure_zero(aes_key, sizeof(aes_key)); /* Secure cleanup */
    }

    /* Generate nonce */
    uint8_t nonce[12];
    status = quac_random_bytes(device, nonce, sizeof(nonce));
    if (status == QUAC_SUCCESS)
    {
        print_hex("96-bit nonce", nonce, sizeof(nonce));
    }

    /* Generate IV */
    uint8_t iv[16];
    status = quac_random_bytes(device, iv, sizeof(iv));
    if (status == QUAC_SUCCESS)
    {
        print_hex("128-bit IV", iv, sizeof(iv));
    }

    /* Cleanup */
    printf("\n========================================\n");
    printf("Example completed successfully!\n");
    printf("========================================\n");

    quac_close_device(device);
    quac_cleanup();

    return 0;
}