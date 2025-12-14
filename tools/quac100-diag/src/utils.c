/**
 * @file utils.c
 * @brief QUAC 100 Diagnostics - Utility Functions Implementation
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <time.h>
#include <unistd.h>
#endif

#include "utils.h"

/*=============================================================================
 * Timing Utilities
 *=============================================================================*/

uint64_t diag_timestamp_ms(void)
{
#ifdef _WIN32
    LARGE_INTEGER freq, count;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&count);
    return (uint64_t)(count.QuadPart * 1000 / freq.QuadPart);
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
#endif
}

uint64_t diag_timestamp_us(void)
{
#ifdef _WIN32
    LARGE_INTEGER freq, count;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&count);
    return (uint64_t)(count.QuadPart * 1000000 / freq.QuadPart);
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000 + (uint64_t)ts.tv_nsec / 1000;
#endif
}

void diag_sleep_ms(unsigned int ms)
{
#ifdef _WIN32
    Sleep(ms);
#else
    usleep(ms * 1000);
#endif
}

/*=============================================================================
 * Memory Utilities
 *=============================================================================*/

void *diag_alloc(size_t size)
{
    return calloc(1, size);
}

void diag_free(void *ptr)
{
    free(ptr);
}

char *diag_strdup(const char *str)
{
    if (!str)
        return NULL;

    size_t len = strlen(str) + 1;
    char *dup = malloc(len);
    if (dup)
    {
        memcpy(dup, str, len);
    }
    return dup;
}

/*=============================================================================
 * Random Utilities
 *=============================================================================*/

static bool random_seeded = false;

static void ensure_random_seeded(void)
{
    if (!random_seeded)
    {
        srand((unsigned int)diag_timestamp_us());
        random_seeded = true;
    }
}

void diag_random_bytes(uint8_t *buf, size_t len)
{
    ensure_random_seeded();

    for (size_t i = 0; i < len; i++)
    {
        buf[i] = (uint8_t)(rand() & 0xFF);
    }
}

uint32_t diag_random_u32(void)
{
    ensure_random_seeded();

    return ((uint32_t)rand() << 16) | ((uint32_t)rand() & 0xFFFF);
}

/*=============================================================================
 * Hex Utilities
 *=============================================================================*/

void diag_hex_dump(const uint8_t *data, size_t len)
{
    if (!data || len == 0)
        return;

    for (size_t i = 0; i < len; i++)
    {
        if (i > 0 && i % 16 == 0)
        {
            printf("\n");
        }
        else if (i > 0 && i % 8 == 0)
        {
            printf(" ");
        }
        printf("%02x ", data[i]);
    }
    printf("\n");
}

char *diag_bytes_to_hex(const uint8_t *data, size_t len, char *out, size_t out_size)
{
    if (!data || !out || out_size < len * 2 + 1)
    {
        if (out && out_size > 0)
            out[0] = '\0';
        return out;
    }

    for (size_t i = 0; i < len; i++)
    {
        snprintf(out + i * 2, out_size - i * 2, "%02x", data[i]);
    }

    return out;
}