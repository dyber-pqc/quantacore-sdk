/*
 * QUAC 100 Userspace Test Program
 *
 * Copyright 2025 Dyber, Inc. All Rights Reserved.
 *
 * This program tests the QUAC 100 driver (real or mock) by performing
 * actual ioctl calls and verifying the results.
 *
 * BUILD:
 *   gcc -o test_quac100 test_userspace.c -Wall -Wextra
 *
 * USAGE:
 *   ./test_quac100 [device]
 *   ./test_quac100              # Uses /dev/quac100_0
 *   ./test_quac100 /dev/quac100_1
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <time.h>

/*----------------------------------------------------------------------------
 * IOCTL Definitions (must match driver)
 *---------------------------------------------------------------------------*/

#define QUAC_IOCTL_MAGIC 'Q'

#define QUAC_IOC_GET_VERSION _IOR(QUAC_IOCTL_MAGIC, 0x00, uint32_t)
#define QUAC_IOC_GET_INFO _IOR(QUAC_IOCTL_MAGIC, 0x01, struct quac_device_info)
#define QUAC_IOC_RESET _IOW(QUAC_IOCTL_MAGIC, 0x04, uint32_t)
#define QUAC_IOC_KEM_KEYGEN _IOWR(QUAC_IOCTL_MAGIC, 0x40, struct quac_kem_keygen)
#define QUAC_IOC_RANDOM _IOWR(QUAC_IOCTL_MAGIC, 0x46, struct quac_random)
#define QUAC_IOC_SELF_TEST _IOWR(QUAC_IOCTL_MAGIC, 0xE0, struct quac_self_test)

/* Algorithm IDs */
#define QUAC_ALGORITHM_KYBER512 0x1100
#define QUAC_ALGORITHM_KYBER768 0x1101
#define QUAC_ALGORITHM_KYBER1024 0x1102

/* Key sizes */
#define KYBER768_PK_SIZE 1184
#define KYBER768_SK_SIZE 2400

/*----------------------------------------------------------------------------
 * Data Structures
 *---------------------------------------------------------------------------*/

struct quac_device_info
{
    uint32_t version;
    uint32_t device_index;
    char serial[32];
    uint32_t capabilities;
    uint32_t status;
    int32_t temperature;
    uint32_t entropy_available;
};

struct quac_kem_keygen
{
    uint32_t algorithm;
    uint32_t flags;
    uint64_t pk_addr;
    uint32_t pk_size;
    uint64_t sk_addr;
    uint32_t sk_size;
    int32_t result;
    uint32_t reserved;
};

struct quac_random
{
    uint64_t buf_addr;
    uint32_t length;
    uint32_t quality;
    int32_t result;
    uint32_t reserved;
};

struct quac_self_test
{
    uint32_t tests;
    uint32_t flags;
    uint32_t tests_passed;
    uint32_t tests_failed;
    uint32_t duration_us;
    int32_t result;
};

/*----------------------------------------------------------------------------
 * Test Framework
 *---------------------------------------------------------------------------*/

static int tests_passed = 0;
static int tests_failed = 0;

#define COLOR_GREEN "\033[0;32m"
#define COLOR_RED "\033[0;31m"
#define COLOR_YELLOW "\033[1;33m"
#define COLOR_RESET "\033[0m"

#define TEST_PASS(name)                                         \
    do                                                          \
    {                                                           \
        printf(COLOR_GREEN "[PASS]" COLOR_RESET " %s\n", name); \
        tests_passed++;                                         \
    } while (0)

#define TEST_FAIL(name, reason)                                           \
    do                                                                    \
    {                                                                     \
        printf(COLOR_RED "[FAIL]" COLOR_RESET " %s: %s\n", name, reason); \
        tests_failed++;                                                   \
    } while (0)

#define TEST_INFO(fmt, ...) printf("       " fmt "\n", ##__VA_ARGS__)

/*----------------------------------------------------------------------------
 * Test Functions
 *---------------------------------------------------------------------------*/

static int test_open_device(const char *device_path, int *fd)
{
    printf("\n=== Test: Open Device ===\n");

    *fd = open(device_path, O_RDWR);
    if (*fd < 0)
    {
        char reason[256];
        snprintf(reason, sizeof(reason), "open() failed: %s", strerror(errno));
        TEST_FAIL("Open device", reason);
        return -1;
    }

    TEST_PASS("Open device");
    TEST_INFO("Opened %s (fd=%d)", device_path, *fd);
    return 0;
}

static int test_get_version(int fd)
{
    printf("\n=== Test: Get Version ===\n");

    uint32_t version;
    if (ioctl(fd, QUAC_IOC_GET_VERSION, &version) < 0)
    {
        char reason[256];
        snprintf(reason, sizeof(reason), "ioctl failed: %s", strerror(errno));
        TEST_FAIL("Get version", reason);
        return -1;
    }

    TEST_PASS("Get version");
    TEST_INFO("Version: %d.%d.%d (0x%08x)",
              (version >> 16) & 0xFF,
              (version >> 8) & 0xFF,
              version & 0xFF,
              version);
    return 0;
}

static int test_get_info(int fd)
{
    printf("\n=== Test: Get Device Info ===\n");

    struct quac_device_info info;
    memset(&info, 0, sizeof(info));

    if (ioctl(fd, QUAC_IOC_GET_INFO, &info) < 0)
    {
        char reason[256];
        snprintf(reason, sizeof(reason), "ioctl failed: %s", strerror(errno));
        TEST_FAIL("Get device info", reason);
        return -1;
    }

    TEST_PASS("Get device info");
    TEST_INFO("Device index: %u", info.device_index);
    TEST_INFO("Serial: %s", info.serial);
    TEST_INFO("Capabilities: 0x%08x", info.capabilities);
    TEST_INFO("Status: 0x%08x", info.status);
    TEST_INFO("Temperature: %d°C", info.temperature);
    TEST_INFO("Entropy: %u bits", info.entropy_available);

    /* Check if simulator */
    if (info.capabilities & 0x80000000)
    {
        TEST_INFO("Mode: SIMULATOR");
    }
    else
    {
        TEST_INFO("Mode: HARDWARE");
    }

    return 0;
}

static int test_random_generation(int fd)
{
    printf("\n=== Test: Random Number Generation ===\n");

    uint8_t buffer[256];
    struct quac_random rnd = {
        .buf_addr = (uint64_t)buffer,
        .length = sizeof(buffer),
        .quality = 0, /* Standard quality */
        .result = -1,
    };

    memset(buffer, 0, sizeof(buffer));

    if (ioctl(fd, QUAC_IOC_RANDOM, &rnd) < 0)
    {
        char reason[256];
        snprintf(reason, sizeof(reason), "ioctl failed: %s", strerror(errno));
        TEST_FAIL("Random generation (ioctl)", reason);
        return -1;
    }

    if (rnd.result != 0)
    {
        char reason[256];
        snprintf(reason, sizeof(reason), "Device returned error: %d", rnd.result);
        TEST_FAIL("Random generation (result)", reason);
        return -1;
    }

    /* Verify we got some random data (not all zeros) */
    int nonzero = 0;
    for (size_t i = 0; i < sizeof(buffer); i++)
    {
        if (buffer[i] != 0)
            nonzero++;
    }

    if (nonzero < 200)
    { /* At least ~78% non-zero */
        TEST_FAIL("Random generation (quality)", "Too many zero bytes");
        return -1;
    }

    TEST_PASS("Random generation");
    TEST_INFO("Generated %zu bytes, %d non-zero", sizeof(buffer), nonzero);
    TEST_INFO("First 16 bytes: %02x %02x %02x %02x %02x %02x %02x %02x "
              "%02x %02x %02x %02x %02x %02x %02x %02x",
              buffer[0], buffer[1], buffer[2], buffer[3],
              buffer[4], buffer[5], buffer[6], buffer[7],
              buffer[8], buffer[9], buffer[10], buffer[11],
              buffer[12], buffer[13], buffer[14], buffer[15]);

    return 0;
}

static int test_kem_keygen(int fd)
{
    printf("\n=== Test: KEM Key Generation (Kyber-768) ===\n");

    uint8_t *pk = malloc(KYBER768_PK_SIZE);
    uint8_t *sk = malloc(KYBER768_SK_SIZE);

    if (!pk || !sk)
    {
        TEST_FAIL("KEM keygen", "Memory allocation failed");
        free(pk);
        free(sk);
        return -1;
    }

    memset(pk, 0, KYBER768_PK_SIZE);
    memset(sk, 0, KYBER768_SK_SIZE);

    struct quac_kem_keygen keygen = {
        .algorithm = QUAC_ALGORITHM_KYBER768,
        .flags = 0,
        .pk_addr = (uint64_t)pk,
        .pk_size = KYBER768_PK_SIZE,
        .sk_addr = (uint64_t)sk,
        .sk_size = KYBER768_SK_SIZE,
        .result = -1,
    };

    clock_t start = clock();

    if (ioctl(fd, QUAC_IOC_KEM_KEYGEN, &keygen) < 0)
    {
        char reason[256];
        snprintf(reason, sizeof(reason), "ioctl failed: %s", strerror(errno));
        TEST_FAIL("KEM keygen (ioctl)", reason);
        free(pk);
        free(sk);
        return -1;
    }

    clock_t end = clock();
    double elapsed_ms = ((double)(end - start) / CLOCKS_PER_SEC) * 1000;

    if (keygen.result != 0)
    {
        char reason[256];
        snprintf(reason, sizeof(reason), "Device returned error: %d", keygen.result);
        TEST_FAIL("KEM keygen (result)", reason);
        free(pk);
        free(sk);
        return -1;
    }

    /* Verify keys are not all zeros */
    int pk_nonzero = 0, sk_nonzero = 0;
    for (int i = 0; i < KYBER768_PK_SIZE; i++)
    {
        if (pk[i] != 0)
            pk_nonzero++;
    }
    for (int i = 0; i < KYBER768_SK_SIZE; i++)
    {
        if (sk[i] != 0)
            sk_nonzero++;
    }

    if (pk_nonzero < KYBER768_PK_SIZE / 2 || sk_nonzero < KYBER768_SK_SIZE / 2)
    {
        TEST_FAIL("KEM keygen (quality)", "Keys appear to be mostly zeros");
        free(pk);
        free(sk);
        return -1;
    }

    TEST_PASS("KEM keygen");
    TEST_INFO("Algorithm: Kyber-768 (0x%04x)", keygen.algorithm);
    TEST_INFO("Public key: %d bytes (%d non-zero)", KYBER768_PK_SIZE, pk_nonzero);
    TEST_INFO("Secret key: %d bytes (%d non-zero)", KYBER768_SK_SIZE, sk_nonzero);
    TEST_INFO("Time: %.2f ms", elapsed_ms);
    TEST_INFO("PK preview: %02x %02x %02x %02x ... %02x %02x %02x %02x",
              pk[0], pk[1], pk[2], pk[3],
              pk[KYBER768_PK_SIZE - 4], pk[KYBER768_PK_SIZE - 3],
              pk[KYBER768_PK_SIZE - 2], pk[KYBER768_PK_SIZE - 1]);

    /* Securely clear secret key */
    memset(sk, 0, KYBER768_SK_SIZE);

    free(pk);
    free(sk);
    return 0;
}

static int test_self_test(int fd)
{
    printf("\n=== Test: Device Self-Test ===\n");

    struct quac_self_test selftest = {
        .tests = 0x003F, /* All KAT tests */
        .flags = 0,
        .tests_passed = 0,
        .tests_failed = 0,
        .result = -1,
    };

    clock_t start = clock();

    if (ioctl(fd, QUAC_IOC_SELF_TEST, &selftest) < 0)
    {
        char reason[256];
        snprintf(reason, sizeof(reason), "ioctl failed: %s", strerror(errno));
        TEST_FAIL("Self-test (ioctl)", reason);
        return -1;
    }

    clock_t end = clock();
    double elapsed_ms = ((double)(end - start) / CLOCKS_PER_SEC) * 1000;

    TEST_INFO("Tests requested: 0x%04x", selftest.tests);
    TEST_INFO("Tests passed: 0x%04x", selftest.tests_passed);
    TEST_INFO("Tests failed: 0x%04x", selftest.tests_failed);
    TEST_INFO("Time: %.2f ms", elapsed_ms);

    if (selftest.result != 0 || selftest.tests_failed != 0)
    {
        TEST_FAIL("Self-test", "Some tests failed");
        return -1;
    }

    TEST_PASS("Self-test");
    return 0;
}

static int test_reset(int fd)
{
    printf("\n=== Test: Device Reset ===\n");

    uint32_t reset_type = 0; /* Soft reset */

    if (ioctl(fd, QUAC_IOC_RESET, &reset_type) < 0)
    {
        char reason[256];
        snprintf(reason, sizeof(reason), "ioctl failed: %s", strerror(errno));
        TEST_FAIL("Device reset", reason);
        return -1;
    }

    TEST_PASS("Device reset");
    return 0;
}

static int test_stress_random(int fd, int iterations)
{
    printf("\n=== Test: Stress Test (Random Generation) ===\n");

    uint8_t buffer[1024];
    uint64_t total_bytes = 0;
    int failures = 0;

    clock_t start = clock();

    for (int i = 0; i < iterations; i++)
    {
        struct quac_random rnd = {
            .buf_addr = (uint64_t)buffer,
            .length = sizeof(buffer),
            .quality = 0,
            .result = -1,
        };

        if (ioctl(fd, QUAC_IOC_RANDOM, &rnd) < 0 || rnd.result != 0)
        {
            failures++;
        }
        else
        {
            total_bytes += sizeof(buffer);
        }
    }

    clock_t end = clock();
    double elapsed_sec = (double)(end - start) / CLOCKS_PER_SEC;
    double throughput_mbps = (total_bytes / (1024.0 * 1024.0)) / elapsed_sec;

    if (failures > iterations / 100)
    { /* Allow 1% failure rate */
        char reason[256];
        snprintf(reason, sizeof(reason), "%d/%d operations failed", failures, iterations);
        TEST_FAIL("Stress test", reason);
        return -1;
    }

    TEST_PASS("Stress test");
    TEST_INFO("Iterations: %d", iterations);
    TEST_INFO("Failures: %d", failures);
    TEST_INFO("Total data: %lu bytes", total_bytes);
    TEST_INFO("Time: %.2f seconds", elapsed_sec);
    TEST_INFO("Throughput: %.2f MB/s", throughput_mbps);

    return 0;
}

/*----------------------------------------------------------------------------
 * Main
 *---------------------------------------------------------------------------*/

static void print_usage(const char *prog)
{
    printf("QUAC 100 Userspace Test Program\n");
    printf("\n");
    printf("Usage: %s [options] [device]\n", prog);
    printf("\n");
    printf("Options:\n");
    printf("  -h, --help     Show this help\n");
    printf("  -s, --stress   Run stress tests\n");
    printf("  -q, --quiet    Quiet mode (less output)\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s                      # Test /dev/quac100_0\n", prog);
    printf("  %s /dev/quac100_1       # Test specific device\n", prog);
    printf("  %s -s                   # Include stress tests\n", prog);
}

int main(int argc, char *argv[])
{
    const char *device_path = "/dev/quac100_0";
    int run_stress = 0;
    int fd;

    /* Parse arguments */
    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0)
        {
            print_usage(argv[0]);
            return 0;
        }
        else if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--stress") == 0)
        {
            run_stress = 1;
        }
        else if (argv[i][0] != '-')
        {
            device_path = argv[i];
        }
    }

    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║  QUAC 100 Userspace Driver Test                          ║\n");
    printf("║  Copyright 2025 Dyber, Inc.                              ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n");
    printf("\nDevice: %s\n", device_path);

    /* Run tests */
    if (test_open_device(device_path, &fd) != 0)
    {
        printf("\n" COLOR_RED "Cannot open device. Is the driver loaded?\n" COLOR_RESET);
        printf("Try: sudo insmod quac100_mock.ko\n");
        return 1;
    }

    test_get_version(fd);
    test_get_info(fd);
    test_random_generation(fd);
    test_kem_keygen(fd);
    test_self_test(fd);

    if (run_stress)
    {
        test_stress_random(fd, 1000);
    }

    test_reset(fd);

    close(fd);

    /* Summary */
    printf("\n");
    printf("════════════════════════════════════════════════════════════\n");
    printf("  RESULTS: " COLOR_GREEN "%d passed" COLOR_RESET ", " COLOR_RED "%d failed" COLOR_RESET "\n",
           tests_passed, tests_failed);
    printf("════════════════════════════════════════════════════════════\n");

    return tests_failed > 0 ? 1 : 0;
}