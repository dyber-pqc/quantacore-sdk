/**
 * @file utils.c
 * @brief QUAC 100 SDK - Utility Functions Implementation
 * @copyright Copyright © 2025 Dyber, Inc. All Rights Reserved.
 */

#include "quac100/quac100.h"
#include "internal.h"

#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/*============================================================================
 * Secure Memory Functions
 *============================================================================*/

QUAC_API void quac_secure_zero(void *buffer, size_t length)
{
    if (!buffer || length == 0)
        return;

    volatile uint8_t *p = (volatile uint8_t *)buffer;
    while (length--)
    {
        *p++ = 0;
    }

    /* Memory barrier to prevent optimization */
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" : : "r"(buffer) : "memory");
#elif defined(_MSC_VER)
    _ReadWriteBarrier();
#endif
}

QUAC_API int quac_secure_compare(
    const void *a,
    const void *b,
    size_t length)
{
    const volatile uint8_t *pa = (const volatile uint8_t *)a;
    const volatile uint8_t *pb = (const volatile uint8_t *)b;

    volatile uint8_t result = 0;

    for (size_t i = 0; i < length; i++)
    {
        result |= pa[i] ^ pb[i];
    }

    return result;
}

QUAC_API void *quac_secure_alloc(size_t size)
{
    if (size == 0)
        return NULL;

    void *ptr = malloc(size);
    if (ptr)
    {
        memset(ptr, 0, size);
    }

    return ptr;
}

QUAC_API void quac_secure_free(void *ptr, size_t size)
{
    if (!ptr)
        return;

    quac_secure_zero(ptr, size);
    free(ptr);
}

QUAC_API void *quac_secure_realloc(void *ptr, size_t old_size, size_t new_size)
{
    if (new_size == 0)
    {
        quac_secure_free(ptr, old_size);
        return NULL;
    }

    void *new_ptr = quac_secure_alloc(new_size);
    if (!new_ptr)
        return NULL;

    if (ptr)
    {
        size_t copy_size = (old_size < new_size) ? old_size : new_size;
        memcpy(new_ptr, ptr, copy_size);
        quac_secure_free(ptr, old_size);
    }

    return new_ptr;
}

/*============================================================================
 * Encoding Functions
 *============================================================================*/

static const char hex_upper[] = "0123456789ABCDEF";
static const char hex_lower[] = "0123456789abcdef";

QUAC_API quac_status_t quac_hex_encode(
    const uint8_t *data,
    size_t data_len,
    char *hex_str,
    size_t buffer_size,
    bool uppercase)
{
    QUAC_CHECK_PARAM(data != NULL || data_len == 0);
    QUAC_CHECK_PARAM(hex_str != NULL);

    size_t required = data_len * 2 + 1;
    if (buffer_size < required)
    {
        return QUAC_ERROR_BUFFER_SMALL;
    }

    const char *hex_chars = uppercase ? hex_upper : hex_lower;

    for (size_t i = 0; i < data_len; i++)
    {
        hex_str[i * 2] = hex_chars[(data[i] >> 4) & 0x0F];
        hex_str[i * 2 + 1] = hex_chars[data[i] & 0x0F];
    }
    hex_str[data_len * 2] = '\0';

    return QUAC_SUCCESS;
}

static int hex_value(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    return -1;
}

QUAC_API quac_status_t quac_hex_decode(
    const char *hex_str,
    uint8_t *data,
    size_t *data_len)
{
    QUAC_CHECK_PARAM(hex_str != NULL);
    QUAC_CHECK_PARAM(data != NULL);
    QUAC_CHECK_PARAM(data_len != NULL);

    size_t hex_len = strlen(hex_str);
    if (hex_len % 2 != 0)
    {
        return QUAC_ERROR_INVALID_PARAM;
    }

    size_t out_len = hex_len / 2;
    if (*data_len < out_len)
    {
        *data_len = out_len;
        return QUAC_ERROR_BUFFER_SMALL;
    }

    for (size_t i = 0; i < out_len; i++)
    {
        int hi = hex_value(hex_str[i * 2]);
        int lo = hex_value(hex_str[i * 2 + 1]);

        if (hi < 0 || lo < 0)
        {
            return QUAC_ERROR_INVALID_PARAM;
        }

        data[i] = (uint8_t)((hi << 4) | lo);
    }

    *data_len = out_len;
    return QUAC_SUCCESS;
}

static const char base64_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

QUAC_API quac_status_t quac_base64_encode(
    const uint8_t *data,
    size_t data_len,
    char *b64_str,
    size_t buffer_size)
{
    QUAC_CHECK_PARAM(data != NULL || data_len == 0);
    QUAC_CHECK_PARAM(b64_str != NULL);

    size_t out_len = ((data_len + 2) / 3) * 4 + 1;
    if (buffer_size < out_len)
    {
        return QUAC_ERROR_BUFFER_SMALL;
    }

    size_t i = 0, j = 0;

    while (i < data_len)
    {
        uint32_t octet_a = i < data_len ? data[i++] : 0;
        uint32_t octet_b = i < data_len ? data[i++] : 0;
        uint32_t octet_c = i < data_len ? data[i++] : 0;

        uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;

        b64_str[j++] = base64_chars[(triple >> 18) & 0x3F];
        b64_str[j++] = base64_chars[(triple >> 12) & 0x3F];
        b64_str[j++] = base64_chars[(triple >> 6) & 0x3F];
        b64_str[j++] = base64_chars[triple & 0x3F];
    }

    /* Add padding */
    size_t mod = data_len % 3;
    if (mod == 1)
    {
        b64_str[j - 1] = '=';
        b64_str[j - 2] = '=';
    }
    else if (mod == 2)
    {
        b64_str[j - 1] = '=';
    }

    b64_str[j] = '\0';
    return QUAC_SUCCESS;
}

static int base64_value(char c)
{
    if (c >= 'A' && c <= 'Z')
        return c - 'A';
    if (c >= 'a' && c <= 'z')
        return c - 'a' + 26;
    if (c >= '0' && c <= '9')
        return c - '0' + 52;
    if (c == '+')
        return 62;
    if (c == '/')
        return 63;
    if (c == '=')
        return 0;
    return -1;
}

QUAC_API quac_status_t quac_base64_decode(
    const char *b64_str,
    uint8_t *data,
    size_t *data_len)
{
    QUAC_CHECK_PARAM(b64_str != NULL);
    QUAC_CHECK_PARAM(data != NULL);
    QUAC_CHECK_PARAM(data_len != NULL);

    size_t b64_len = strlen(b64_str);
    if (b64_len % 4 != 0)
    {
        return QUAC_ERROR_INVALID_PARAM;
    }

    size_t out_len = (b64_len / 4) * 3;
    if (b64_len > 0 && b64_str[b64_len - 1] == '=')
        out_len--;
    if (b64_len > 1 && b64_str[b64_len - 2] == '=')
        out_len--;

    if (*data_len < out_len)
    {
        *data_len = out_len;
        return QUAC_ERROR_BUFFER_SMALL;
    }

    size_t i = 0, j = 0;

    while (i < b64_len)
    {
        int a = base64_value(b64_str[i++]);
        int b = base64_value(b64_str[i++]);
        int c = base64_value(b64_str[i++]);
        int d = base64_value(b64_str[i++]);

        if (a < 0 || b < 0 || c < 0 || d < 0)
        {
            return QUAC_ERROR_INVALID_PARAM;
        }

        uint32_t triple = (a << 18) | (b << 12) | (c << 6) | d;

        if (j < out_len)
            data[j++] = (triple >> 16) & 0xFF;
        if (j < out_len)
            data[j++] = (triple >> 8) & 0xFF;
        if (j < out_len)
            data[j++] = triple & 0xFF;
    }

    *data_len = out_len;
    return QUAC_SUCCESS;
}

/*============================================================================
 * Async Operations
 *============================================================================*/

QUAC_API quac_status_t quac_async_wait(
    quac_async_t handle,
    uint32_t timeout_ms)
{
    QUAC_CHECK_PARAM(handle != NULL);

    quac_async_op_impl *op = (quac_async_op_impl *)handle;

#ifdef QUAC_PLATFORM_WINDOWS
    DWORD result = WaitForSingleObject(op->event, timeout_ms ? timeout_ms : INFINITE);
    if (result == WAIT_TIMEOUT)
    {
        return QUAC_ERROR_TIMEOUT;
    }
#else
    if (timeout_ms == 0)
    {
        pthread_mutex_lock(&op->mutex);
        while (!op->complete)
        {
            pthread_cond_wait(&op->cond, &op->mutex);
        }
        pthread_mutex_unlock(&op->mutex);
    }
    else
    {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += timeout_ms / 1000;
        ts.tv_nsec += (timeout_ms % 1000) * 1000000;
        if (ts.tv_nsec >= 1000000000)
        {
            ts.tv_sec++;
            ts.tv_nsec -= 1000000000;
        }

        pthread_mutex_lock(&op->mutex);
        int result = 0;
        while (!op->complete && result == 0)
        {
            result = pthread_cond_timedwait(&op->cond, &op->mutex, &ts);
        }
        pthread_mutex_unlock(&op->mutex);

        if (result != 0)
        {
            return QUAC_ERROR_TIMEOUT;
        }
    }
#endif

    return op->status;
}

QUAC_API quac_status_t quac_async_cancel(quac_async_t handle)
{
    QUAC_CHECK_PARAM(handle != NULL);

    quac_async_op_impl *op = (quac_async_op_impl *)handle;
    op->cancelled = true;

    return QUAC_SUCCESS;
}

QUAC_API int quac_async_is_complete(quac_async_t handle)
{
    if (!handle)
        return 1;
    quac_async_op_impl *op = (quac_async_op_impl *)handle;
    return op->complete ? 1 : 0;
}

QUAC_API quac_status_t quac_async_get_result(quac_async_t handle)
{
    if (!handle)
        return QUAC_ERROR_INVALID_HANDLE;
    quac_async_op_impl *op = (quac_async_op_impl *)handle;
    return op->status;
}

QUAC_API void quac_async_free(quac_async_t handle)
{
    if (!handle)
        return;

    quac_async_op_impl *op = (quac_async_op_impl *)handle;

#ifdef QUAC_PLATFORM_WINDOWS
    if (op->event)
        CloseHandle(op->event);
    if (op->thread)
        CloseHandle(op->thread);
#else
    pthread_mutex_destroy(&op->mutex);
    pthread_cond_destroy(&op->cond);
#endif

    free(op);
}