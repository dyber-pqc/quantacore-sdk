/*
 * QUAC 100 Test Application - Common Definitions
 * Copyright (c) 2024 Dyber, Inc. All rights reserved.
 *
 * Common test utilities and macros for the QUAC 100 test suite.
 */

#ifndef QUAC100_TEST_COMMON_H
#define QUAC100_TEST_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include "quac100lib.h"

/* Test result codes */
typedef enum {
    TEST_PASS = 0,
    TEST_FAIL = 1,
    TEST_SKIP = 2
} TestResult;

/* Test context structure */
typedef struct {
    QUAC_HANDLE Handle;
    QUAC_DEVICE_INFO DeviceInfo;
    BOOL Verbose;
    UINT32 TestCount;
    UINT32 PassCount;
    UINT32 FailCount;
    UINT32 SkipCount;
} TestContext;

/* Color output */
#define COLOR_GREEN     10
#define COLOR_RED       12
#define COLOR_YELLOW    14
#define COLOR_WHITE     15

static inline void SetConsoleColor(WORD color)
{
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, color);
}

static inline void ResetConsoleColor(void)
{
    SetConsoleColor(COLOR_WHITE);
}

/* Test macros */
#define TEST_BEGIN(name) \
    do { \
        printf("\n[TEST] %s\n", name); \
        ctx->TestCount++; \
    } while (0)

#define TEST_PASS_MSG(msg) \
    do { \
        SetConsoleColor(COLOR_GREEN); \
        printf("  [PASS] %s\n", msg); \
        ResetConsoleColor(); \
        ctx->PassCount++; \
        return TEST_PASS; \
    } while (0)

#define TEST_FAIL_MSG(msg) \
    do { \
        SetConsoleColor(COLOR_RED); \
        printf("  [FAIL] %s\n", msg); \
        ResetConsoleColor(); \
        ctx->FailCount++; \
        return TEST_FAIL; \
    } while (0)

#define TEST_SKIP_MSG(msg) \
    do { \
        SetConsoleColor(COLOR_YELLOW); \
        printf("  [SKIP] %s\n", msg); \
        ResetConsoleColor(); \
        ctx->SkipCount++; \
        return TEST_SKIP; \
    } while (0)

#define TEST_ASSERT(cond, msg) \
    do { \
        if (!(cond)) { \
            TEST_FAIL_MSG(msg); \
        } \
    } while (0)

#define TEST_ASSERT_EQ(actual, expected, msg) \
    do { \
        if ((actual) != (expected)) { \
            printf("  Expected: %d, Actual: %d\n", (int)(expected), (int)(actual)); \
            TEST_FAIL_MSG(msg); \
        } \
    } while (0)

#define TEST_ASSERT_QUAC_OK(err, msg) \
    do { \
        if ((err) != QUAC_SUCCESS) { \
            printf("  Error: %s\n", QuacGetErrorString(err)); \
            TEST_FAIL_MSG(msg); \
        } \
    } while (0)

/* Hex dump utility */
static inline void HexDump(const char* prefix, const BYTE* data, size_t len)
{
    printf("  %s (%zu bytes): ", prefix, len);
    size_t displayLen = (len > 32) ? 32 : len;
    for (size_t i = 0; i < displayLen; i++) {
        printf("%02X", data[i]);
    }
    if (len > 32) {
        printf("...");
    }
    printf("\n");
}

/* Performance timing */
typedef struct {
    LARGE_INTEGER Start;
    LARGE_INTEGER End;
    LARGE_INTEGER Frequency;
} PerfTimer;

static inline void PerfTimerStart(PerfTimer* timer)
{
    QueryPerformanceFrequency(&timer->Frequency);
    QueryPerformanceCounter(&timer->Start);
}

static inline double PerfTimerStop(PerfTimer* timer)
{
    QueryPerformanceCounter(&timer->End);
    return (double)(timer->End.QuadPart - timer->Start.QuadPart) * 1000.0 /
           (double)timer->Frequency.QuadPart;
}

/* Test function declarations */
TestResult TestKemKeyGen(TestContext* ctx, QUAC_KEM_ALG alg);
TestResult TestKemEncapsDecaps(TestContext* ctx, QUAC_KEM_ALG alg);
TestResult TestKemAllAlgorithms(TestContext* ctx);

TestResult TestSignKeyGen(TestContext* ctx, QUAC_SIGN_ALG alg);
TestResult TestSignVerify(TestContext* ctx, QUAC_SIGN_ALG alg);
TestResult TestSignAllAlgorithms(TestContext* ctx);

TestResult TestQrngBasic(TestContext* ctx);
TestResult TestQrngQuality(TestContext* ctx);
TestResult TestQrngHealth(TestContext* ctx);

TestResult TestPerfKem(TestContext* ctx);
TestResult TestPerfSign(TestContext* ctx);
TestResult TestPerfQrng(TestContext* ctx);

#endif /* QUAC100_TEST_COMMON_H */
