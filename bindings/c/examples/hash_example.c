/**
 * @file hash_example.c
 * @brief QUAC 100 SDK - Hash Operations Example
 * @copyright Copyright © 2025 Dyber, Inc. All Rights Reserved.
 *
 * Demonstrates hardware-accelerated hash functions.
 */

#include <quac100/quac100.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Print bytes as hex */
static void print_hash(const char *label, const uint8_t *hash, size_t len)
{
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++)
    {
        printf("%02x", hash[i]);
    }
    printf("\n");
}

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    printf("========================================\n");
    printf("QUAC 100 Hash Operations Example\n");
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

    const char *test_data = "Hello, QUAC 100!";
    printf("Test data: \"%s\"\n\n", test_data);

    /* 1. SHA-256 */
    printf("--- SHA-2 Family ---\n");

    uint8_t sha256[QUAC_SHA256_SIZE];
    status = quac_sha256(device, (const uint8_t *)test_data, strlen(test_data), sha256);
    if (status == QUAC_SUCCESS)
    {
        print_hash("SHA-256", sha256, sizeof(sha256));
    }

    uint8_t sha384[QUAC_SHA384_SIZE];
    status = quac_sha384(device, (const uint8_t *)test_data, strlen(test_data), sha384);
    if (status == QUAC_SUCCESS)
    {
        print_hash("SHA-384", sha384, sizeof(sha384));
    }

    uint8_t sha512[QUAC_SHA512_SIZE];
    status = quac_sha512(device, (const uint8_t *)test_data, strlen(test_data), sha512);
    if (status == QUAC_SUCCESS)
    {
        print_hash("SHA-512", sha512, sizeof(sha512));
    }

    /* 2. SHA-3 */
    printf("\n--- SHA-3 Family ---\n");

    uint8_t sha3_256[QUAC_SHA3_256_SIZE];
    status = quac_sha3_256(device, (const uint8_t *)test_data, strlen(test_data), sha3_256);
    if (status == QUAC_SUCCESS)
    {
        print_hash("SHA3-256", sha3_256, sizeof(sha3_256));
    }

    uint8_t sha3_512[QUAC_SHA3_512_SIZE];
    status = quac_sha3_512(device, (const uint8_t *)test_data, strlen(test_data), sha3_512);
    if (status == QUAC_SUCCESS)
    {
        print_hash("SHA3-512", sha3_512, sizeof(sha3_512));
    }

    /* 3. SHAKE extendable output */
    printf("\n--- SHAKE (XOF) ---\n");

    uint8_t shake128_out[64];
    status = quac_shake128(device, (const uint8_t *)test_data, strlen(test_data),
                           shake128_out, sizeof(shake128_out));
    if (status == QUAC_SUCCESS)
    {
        print_hash("SHAKE128 (64 bytes)", shake128_out, sizeof(shake128_out));
    }

    uint8_t shake256_out[128];
    status = quac_shake256(device, (const uint8_t *)test_data, strlen(test_data),
                           shake256_out, sizeof(shake256_out));
    if (status == QUAC_SUCCESS)
    {
        printf("SHAKE256 (128 bytes): ");
        for (size_t i = 0; i < 32; i++)
            printf("%02x", shake256_out[i]);
        printf("...\n");
    }

    /* 4. Generic hash function */
    printf("\n--- Generic Hash API ---\n");

    uint8_t hash[64];
    size_t hash_len;

    hash_len = sizeof(hash);
    status = quac_hash(device, QUAC_HASH_SHA256,
                       (const uint8_t *)test_data, strlen(test_data),
                       hash, &hash_len);
    if (status == QUAC_SUCCESS)
    {
        printf("quac_hash(SHA256), len=%zu\n", hash_len);
    }

    hash_len = sizeof(hash);
    status = quac_hash(device, QUAC_HASH_SHA3_384,
                       (const uint8_t *)test_data, strlen(test_data),
                       hash, &hash_len);
    if (status == QUAC_SUCCESS)
    {
        printf("quac_hash(SHA3-384), len=%zu\n", hash_len);
    }

    /* 5. Incremental hashing */
    printf("\n--- Incremental Hashing ---\n");

    quac_hash_ctx_t ctx;
    status = quac_hash_init(device, QUAC_HASH_SHA256, &ctx);
    if (status == QUAC_SUCCESS)
    {
        /* Feed data in parts */
        quac_hash_update(ctx, (const uint8_t *)"Hello, ", 7);
        quac_hash_update(ctx, (const uint8_t *)"QUAC ", 5);
        quac_hash_update(ctx, (const uint8_t *)"100!", 4);

        hash_len = sizeof(hash);
        status = quac_hash_final(ctx, hash, &hash_len);
        if (status == QUAC_SUCCESS)
        {
            print_hash("Incremental SHA-256", hash, hash_len);

            /* Should match one-shot */
            printf("Matches one-shot: %s\n",
                   memcmp(hash, sha256, hash_len) == 0 ? "YES" : "NO");
        }

        quac_hash_free(ctx);
    }

    /* 6. HMAC */
    printf("\n--- HMAC ---\n");

    const char *hmac_key = "secret-key-123";
    uint8_t mac[QUAC_SHA256_SIZE];
    size_t mac_len = sizeof(mac);

    status = quac_hmac(device, QUAC_HASH_SHA256,
                       (const uint8_t *)hmac_key, strlen(hmac_key),
                       (const uint8_t *)test_data, strlen(test_data),
                       mac, &mac_len);
    if (status == QUAC_SUCCESS)
    {
        print_hash("HMAC-SHA256", mac, mac_len);
    }

    /* 7. HKDF key derivation */
    printf("\n--- HKDF Key Derivation ---\n");

    const char *ikm = "input-key-material";
    const char *salt = "random-salt";
    const char *info = "application-context";
    uint8_t derived[32];

    status = quac_hkdf(device, QUAC_HASH_SHA256,
                       (const uint8_t *)salt, strlen(salt),
                       (const uint8_t *)ikm, strlen(ikm),
                       (const uint8_t *)info, strlen(info),
                       derived, sizeof(derived));
    if (status == QUAC_SUCCESS)
    {
        print_hash("HKDF derived key", derived, sizeof(derived));
    }

    /* 8. Hash size lookup */
    printf("\n--- Hash Sizes ---\n");

    size_t size;
    quac_hash_size(QUAC_HASH_SHA256, &size);
    printf("SHA-256: %zu bytes\n", size);

    quac_hash_size(QUAC_HASH_SHA384, &size);
    printf("SHA-384: %zu bytes\n", size);

    quac_hash_size(QUAC_HASH_SHA512, &size);
    printf("SHA-512: %zu bytes\n", size);

    quac_hash_size(QUAC_HASH_SHA3_256, &size);
    printf("SHA3-256: %zu bytes\n", size);

    quac_hash_size(QUAC_HASH_SHA3_512, &size);
    printf("SHA3-512: %zu bytes\n", size);

    /* 9. Hash empty data */
    printf("\n--- Empty Data Hashes ---\n");

    status = quac_sha256(device, (const uint8_t *)"", 0, sha256);
    if (status == QUAC_SUCCESS)
    {
        print_hash("SHA-256(\"\")", sha256, sizeof(sha256));
    }

    /* 10. Large data hash benchmark */
    printf("\n--- Large Data Benchmark ---\n");

    const size_t large_size = 10 * 1024 * 1024; /* 10 MB */
    uint8_t *large_data = (uint8_t *)malloc(large_size);
    if (large_data)
    {
        memset(large_data, 'A', large_size);

        clock_t start = clock();
        hash_len = sizeof(hash);
        status = quac_hash(device, QUAC_HASH_SHA256,
                           large_data, large_size, hash, &hash_len);
        clock_t end = clock();

        if (status == QUAC_SUCCESS)
        {
            double elapsed = (double)(end - start) / CLOCKS_PER_SEC;
            double mbps = (large_size / (1024.0 * 1024.0)) / elapsed;
            printf("SHA-256 of 10 MB: %.3f seconds (%.2f MB/s)\n", elapsed, mbps);
        }

        free(large_data);
    }

    /* 11. Hash verification example */
    printf("\n--- Hash Verification Example ---\n");

    const char *password = "my-secret-password";
    uint8_t stored_hash[QUAC_SHA256_SIZE];
    uint8_t verify_hash[QUAC_SHA256_SIZE];

    /* Store hash (in real application, use proper password hashing like Argon2) */
    quac_sha256(device, (const uint8_t *)password, strlen(password), stored_hash);

    /* Later, verify password */
    const char *attempt = "my-secret-password";
    quac_sha256(device, (const uint8_t *)attempt, strlen(attempt), verify_hash);

    if (quac_secure_compare(stored_hash, verify_hash, sizeof(stored_hash)) == 0)
    {
        printf("Password verification: SUCCESS\n");
    }
    else
    {
        printf("Password verification: FAILED\n");
    }

    /* Wrong password */
    const char *wrong = "wrong-password";
    quac_sha256(device, (const uint8_t *)wrong, strlen(wrong), verify_hash);

    if (quac_secure_compare(stored_hash, verify_hash, sizeof(stored_hash)) == 0)
    {
        printf("Wrong password check: FAILED (should not match)\n");
    }
    else
    {
        printf("Wrong password check: CORRECTLY REJECTED\n");
    }

    /* Cleanup */
    printf("\n========================================\n");
    printf("Example completed successfully!\n");
    printf("========================================\n");

    quac_close_device(device);
    quac_cleanup();

    return 0;
}