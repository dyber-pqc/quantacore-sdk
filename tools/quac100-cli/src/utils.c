/**
 * @file utils.c
 * @brief QUAC 100 CLI - Utility Functions Implementation
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>

#include "utils.h"
#include "commands.h"

/*=============================================================================
 * Output Functions
 *=============================================================================*/

void cli_info(const char *fmt, ...)
{
    if (g_options.quiet)
        return;

    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    printf("\n");
}

void cli_error(const char *fmt, ...)
{
    fprintf(stderr, "Error: ");

    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fprintf(stderr, "\n");
}

void cli_warn(const char *fmt, ...)
{
    if (g_options.quiet)
        return;

    fprintf(stderr, "Warning: ");

    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fprintf(stderr, "\n");
}

void cli_debug(const char *fmt, ...)
{
    if (!g_options.verbose)
        return;

    printf("[DEBUG] ");

    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    printf("\n");
}

/*=============================================================================
 * Hex Output
 *=============================================================================*/

void print_hex(const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i++)
    {
        printf("%02x", data[i]);
    }
}

void print_hex_formatted(const uint8_t *data, size_t len, int bytes_per_line)
{
    for (size_t i = 0; i < len; i++)
    {
        printf("%02x", data[i]);

        if ((i + 1) % bytes_per_line == 0 && i + 1 < len)
        {
            printf("\n");
        }
        else if ((i + 1) % 4 == 0 && i + 1 < len)
        {
            printf(" ");
        }
    }
    printf("\n");
}

static int hex_digit(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

int hex_to_bytes(const char *hex, uint8_t *out, size_t out_size)
{
    if (!hex || !out)
        return -1;

    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0)
        return -1;

    size_t bytes = hex_len / 2;
    if (bytes > out_size)
        return -1;

    for (size_t i = 0; i < bytes; i++)
    {
        int high = hex_digit(hex[i * 2]);
        int low = hex_digit(hex[i * 2 + 1]);

        if (high < 0 || low < 0)
            return -1;

        out[i] = (uint8_t)((high << 4) | low);
    }

    return (int)bytes;
}

char *bytes_to_hex(const uint8_t *data, size_t len, char *out, size_t out_size)
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

/*=============================================================================
 * File I/O
 *=============================================================================*/

uint8_t *read_binary_file(const char *filename, size_t *size)
{
    if (!filename || !size)
        return NULL;

    FILE *f = fopen(filename, "rb");
    if (!f)
        return NULL;

    /* Get file size */
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (fsize < 0)
    {
        fclose(f);
        return NULL;
    }

    /* Allocate buffer */
    uint8_t *data = malloc((size_t)fsize);
    if (!data)
    {
        fclose(f);
        return NULL;
    }

    /* Read file */
    size_t read = fread(data, 1, (size_t)fsize, f);
    fclose(f);

    if (read != (size_t)fsize)
    {
        free(data);
        return NULL;
    }

    *size = (size_t)fsize;
    return data;
}

int write_binary_file(const char *filename, const uint8_t *data, size_t size)
{
    if (!filename || !data)
        return -1;

    FILE *f = fopen(filename, "wb");
    if (!f)
        return -1;

    size_t written = fwrite(data, 1, size, f);
    fclose(f);

    return (written == size) ? 0 : -1;
}

bool file_exists(const char *filename)
{
    if (!filename)
        return false;

    FILE *f = fopen(filename, "r");
    if (f)
    {
        fclose(f);
        return true;
    }
    return false;
}

long file_size(const char *filename)
{
    if (!filename)
        return -1;

    FILE *f = fopen(filename, "rb");
    if (!f)
        return -1;

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fclose(f);

    return size;
}

/*=============================================================================
 * String Utilities
 *=============================================================================*/

char *str_trim(char *str)
{
    if (!str)
        return str;

    /* Trim leading */
    while (*str && isspace(*str))
        str++;

    if (*str == '\0')
        return str;

    /* Trim trailing */
    char *end = str + strlen(str) - 1;
    while (end > str && isspace(*end))
        end--;
    end[1] = '\0';

    return str;
}

char *str_lower(char *str)
{
    if (!str)
        return str;

    for (char *p = str; *p; p++)
    {
        *p = (char)tolower(*p);
    }

    return str;
}

char *str_dup(const char *str)
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

void str_copy(char *dst, const char *src, size_t size)
{
    if (!dst || !src || size == 0)
        return;

    size_t len = strlen(src);
    if (len >= size)
    {
        len = size - 1;
    }

    memcpy(dst, src, len);
    dst[len] = '\0';
}