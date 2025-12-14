/**
 * @file generator.c
 * @brief QUAC Binding Generator - Base Generator Implementation
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <time.h>

#include "generator.h"

/*=============================================================================
 * Constants
 *=============================================================================*/

#define INITIAL_BUFFER_SIZE 4096
#define MAX_LINE_LENGTH 1024

/*=============================================================================
 * Generator Registry
 *=============================================================================*/

static generator_func_t g_generators[TARGET_COUNT] = {NULL};

void gen_register(target_language_t target, generator_func_t func)
{
    if (target < TARGET_COUNT)
    {
        g_generators[target] = func;
    }
}

generator_func_t gen_get(target_language_t target)
{
    if (target < TARGET_COUNT)
    {
        return g_generators[target];
    }
    return NULL;
}

/*=============================================================================
 * Output Context Implementation
 *=============================================================================*/

gen_output_t *gen_output_create_file(const char *path)
{
    FILE *f = fopen(path, "w");
    if (!f)
    {
        return NULL;
    }

    gen_output_t *out = calloc(1, sizeof(gen_output_t));
    if (!out)
    {
        fclose(f);
        return NULL;
    }

    out->file = f;
    out->indent_size = 4;
    out->indent_char = " ";
    out->at_line_start = true;

    return out;
}

gen_output_t *gen_output_create_buffer(size_t initial_size)
{
    if (initial_size == 0)
    {
        initial_size = INITIAL_BUFFER_SIZE;
    }

    gen_output_t *out = calloc(1, sizeof(gen_output_t));
    if (!out)
        return NULL;

    out->buffer = malloc(initial_size);
    if (!out->buffer)
    {
        free(out);
        return NULL;
    }

    out->buffer_size = initial_size;
    out->buffer_pos = 0;
    out->buffer[0] = '\0';
    out->indent_size = 4;
    out->indent_char = " ";
    out->at_line_start = true;

    return out;
}

void gen_output_destroy(gen_output_t *out)
{
    if (!out)
        return;

    if (out->file)
    {
        fclose(out->file);
    }
    free(out->buffer);
    free(out);
}

const char *gen_output_get_buffer(gen_output_t *out)
{
    return out ? out->buffer : NULL;
}

static void ensure_buffer_space(gen_output_t *out, size_t needed)
{
    if (!out->buffer)
        return;

    size_t required = out->buffer_pos + needed + 1;
    if (required > out->buffer_size)
    {
        size_t new_size = out->buffer_size * 2;
        while (new_size < required)
            new_size *= 2;

        char *new_buf = realloc(out->buffer, new_size);
        if (new_buf)
        {
            out->buffer = new_buf;
            out->buffer_size = new_size;
        }
    }
}

static void write_indent(gen_output_t *out)
{
    if (!out->at_line_start || out->indent_level <= 0)
        return;

    int spaces = out->indent_level * out->indent_size;

    if (out->file)
    {
        for (int i = 0; i < spaces; i++)
        {
            fputc(out->indent_char[0], out->file);
        }
    }
    else if (out->buffer)
    {
        ensure_buffer_space(out, spaces);
        for (int i = 0; i < spaces && out->buffer_pos < out->buffer_size - 1; i++)
        {
            out->buffer[out->buffer_pos++] = out->indent_char[0];
        }
        out->buffer[out->buffer_pos] = '\0';
    }

    out->at_line_start = false;
}

void gen_write(gen_output_t *out, const char *fmt, ...)
{
    if (!out || !fmt)
        return;

    write_indent(out);

    va_list args;
    va_start(args, fmt);

    char line[MAX_LINE_LENGTH];
    int len = vsnprintf(line, sizeof(line), fmt, args);

    va_end(args);

    if (len <= 0)
        return;

    if (out->file)
    {
        fputs(line, out->file);
    }
    else if (out->buffer)
    {
        ensure_buffer_space(out, len);
        if (out->buffer_pos + len < out->buffer_size)
        {
            memcpy(out->buffer + out->buffer_pos, line, len);
            out->buffer_pos += len;
            out->buffer[out->buffer_pos] = '\0';
        }
    }

    /* Check if we ended with newline */
    if (len > 0 && line[len - 1] == '\n')
    {
        out->at_line_start = true;
    }
}

void gen_writeln(gen_output_t *out, const char *fmt, ...)
{
    if (!out)
        return;

    write_indent(out);

    if (fmt && *fmt)
    {
        va_list args;
        va_start(args, fmt);

        char line[MAX_LINE_LENGTH];
        int len = vsnprintf(line, sizeof(line), fmt, args);

        va_end(args);

        if (len > 0)
        {
            if (out->file)
            {
                fputs(line, out->file);
            }
            else if (out->buffer)
            {
                ensure_buffer_space(out, len);
                if (out->buffer_pos + len < out->buffer_size)
                {
                    memcpy(out->buffer + out->buffer_pos, line, len);
                    out->buffer_pos += len;
                }
            }
        }
    }

    if (out->file)
    {
        fputc('\n', out->file);
    }
    else if (out->buffer)
    {
        ensure_buffer_space(out, 1);
        if (out->buffer_pos < out->buffer_size - 1)
        {
            out->buffer[out->buffer_pos++] = '\n';
            out->buffer[out->buffer_pos] = '\0';
        }
    }

    out->at_line_start = true;
}

void gen_newline(gen_output_t *out)
{
    gen_writeln(out, "");
}

void gen_indent(gen_output_t *out)
{
    if (out)
        out->indent_level++;
}

void gen_dedent(gen_output_t *out)
{
    if (out && out->indent_level > 0)
        out->indent_level--;
}

void gen_set_indent(gen_output_t *out, int size, const char *ch)
{
    if (!out)
        return;
    out->indent_size = size > 0 ? size : 4;
    out->indent_char = ch ? ch : " ";
}

/*=============================================================================
 * String Conversion Utilities
 *=============================================================================*/

void gen_to_pascal_case(const char *input, char *output, size_t size)
{
    if (!input || !output || size == 0)
        return;

    char *dst = output;
    const char *end = output + size - 1;
    bool cap = true;

    for (const char *src = input; *src && dst < end; src++)
    {
        if (*src == '_' || *src == ' ' || *src == '-')
        {
            cap = true;
        }
        else
        {
            *dst++ = cap ? toupper(*src) : *src;
            cap = false;
        }
    }
    *dst = '\0';
}

void gen_to_camel_case(const char *input, char *output, size_t size)
{
    if (!input || !output || size == 0)
        return;

    char *dst = output;
    const char *end = output + size - 1;
    bool cap = false;
    bool first = true;

    for (const char *src = input; *src && dst < end; src++)
    {
        if (*src == '_' || *src == ' ' || *src == '-')
        {
            cap = true;
        }
        else
        {
            if (first)
            {
                *dst++ = tolower(*src);
                first = false;
            }
            else
            {
                *dst++ = cap ? toupper(*src) : *src;
            }
            cap = false;
        }
    }
    *dst = '\0';
}

void gen_to_snake_case(const char *input, char *output, size_t size)
{
    if (!input || !output || size == 0)
        return;

    char *dst = output;
    const char *end = output + size - 1;

    for (const char *src = input; *src && dst < end; src++)
    {
        if (isupper(*src))
        {
            if (src != input && dst < end - 1)
            {
                *dst++ = '_';
            }
            *dst++ = tolower(*src);
        }
        else if (*src == ' ' || *src == '-')
        {
            *dst++ = '_';
        }
        else
        {
            *dst++ = *src;
        }
    }
    *dst = '\0';
}

void gen_to_screaming_case(const char *input, char *output, size_t size)
{
    if (!input || !output || size == 0)
        return;

    char *dst = output;
    const char *end = output + size - 1;

    for (const char *src = input; *src && dst < end; src++)
    {
        if (isupper(*src) && src != input)
        {
            if (dst < end - 1)
            {
                *dst++ = '_';
            }
            *dst++ = *src;
        }
        else if (*src == ' ' || *src == '-')
        {
            *dst++ = '_';
        }
        else
        {
            *dst++ = toupper(*src);
        }
    }
    *dst = '\0';
}

const char *gen_strip_prefix(const char *name, const char *prefix)
{
    if (!name || !prefix)
        return name;

    size_t prefix_len = strlen(prefix);
    if (strncmp(name, prefix, prefix_len) == 0)
    {
        return name + prefix_len;
    }
    return name;
}

void gen_strip_suffix(const char *name, const char *suffix, char *output, size_t size)
{
    if (!name || !output || size == 0)
        return;

    strncpy(output, name, size - 1);
    output[size - 1] = '\0';

    if (!suffix)
        return;

    size_t name_len = strlen(output);
    size_t suffix_len = strlen(suffix);

    if (name_len >= suffix_len && strcmp(output + name_len - suffix_len, suffix) == 0)
    {
        output[name_len - suffix_len] = '\0';
    }
}

void gen_escape_string(const char *input, char *output, size_t size,
                       target_language_t target)
{
    if (!input || !output || size == 0)
        return;

    char *dst = output;
    const char *end = output + size - 1;

    for (const char *src = input; *src && dst < end; src++)
    {
        if (*src == '\\' || *src == '"')
        {
            if (dst < end - 1)
            {
                *dst++ = '\\';
                *dst++ = *src;
            }
        }
        else if (*src == '\n')
        {
            if (dst < end - 1)
            {
                *dst++ = '\\';
                *dst++ = 'n';
            }
        }
        else if (*src == '\t')
        {
            if (dst < end - 1)
            {
                *dst++ = '\\';
                *dst++ = 't';
            }
        }
        else
        {
            *dst++ = *src;
        }
    }
    *dst = '\0';
}

/*=============================================================================
 * Documentation Generation
 *=============================================================================*/

void gen_write_doc_comment(gen_output_t *out, const char *doc,
                           target_language_t target)
{
    if (!out || !doc || !*doc)
        return;

    /* Split into lines */
    char *doc_copy = strdup(doc);
    if (!doc_copy)
        return;

    char *line = strtok(doc_copy, "\n");
    bool first = true;

    switch (target)
    {
    case TARGET_PYTHON:
        gen_writeln(out, "\"\"\"");
        while (line)
        {
            gen_writeln(out, "%s", line);
            line = strtok(NULL, "\n");
        }
        gen_writeln(out, "\"\"\"");
        break;

    case TARGET_RUST:
        while (line)
        {
            gen_writeln(out, "/// %s", line);
            line = strtok(NULL, "\n");
        }
        break;

    case TARGET_GO:
        while (line)
        {
            gen_writeln(out, "// %s", line);
            line = strtok(NULL, "\n");
        }
        break;

    case TARGET_JAVA:
    case TARGET_CSHARP:
        gen_writeln(out, "/**");
        while (line)
        {
            gen_writeln(out, " * %s", line);
            line = strtok(NULL, "\n");
        }
        gen_writeln(out, " */");
        break;

    case TARGET_NODEJS:
        gen_writeln(out, "/**");
        while (line)
        {
            gen_writeln(out, " * %s", line);
            line = strtok(NULL, "\n");
        }
        gen_writeln(out, " */");
        break;

    default:
        break;
    }

    free(doc_copy);
}

void gen_write_file_header(gen_output_t *out, const char *filename,
                           const char *description, target_language_t target)
{
    if (!out)
        return;

    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    char date[32];
    strftime(date, sizeof(date), "%Y-%m-%d", tm);

    switch (target)
    {
    case TARGET_PYTHON:
        gen_writeln(out, "\"\"\"%s", filename ? filename : "");
        if (description)
        {
            gen_writeln(out, "");
            gen_writeln(out, "%s", description);
        }
        gen_writeln(out, "");
        gen_writeln(out, "Auto-generated by quac-bindgen on %s", date);
        gen_writeln(out, "DO NOT EDIT MANUALLY");
        gen_writeln(out, "");
        gen_writeln(out, "Copyright 2025 Dyber, Inc. All Rights Reserved.");
        gen_writeln(out, "\"\"\"");
        gen_newline(out);
        break;

    case TARGET_RUST:
        gen_writeln(out, "//! %s", filename ? filename : "");
        if (description)
        {
            gen_writeln(out, "//!");
            gen_writeln(out, "//! %s", description);
        }
        gen_writeln(out, "//!");
        gen_writeln(out, "//! Auto-generated by quac-bindgen on %s", date);
        gen_writeln(out, "//! DO NOT EDIT MANUALLY");
        gen_writeln(out, "//!");
        gen_writeln(out, "//! Copyright 2025 Dyber, Inc. All Rights Reserved.");
        gen_newline(out);
        break;

    case TARGET_GO:
    case TARGET_JAVA:
    case TARGET_CSHARP:
    case TARGET_NODEJS:
        gen_writeln(out, "/*");
        gen_writeln(out, " * %s", filename ? filename : "");
        if (description)
        {
            gen_writeln(out, " *");
            gen_writeln(out, " * %s", description);
        }
        gen_writeln(out, " *");
        gen_writeln(out, " * Auto-generated by quac-bindgen on %s", date);
        gen_writeln(out, " * DO NOT EDIT MANUALLY");
        gen_writeln(out, " *");
        gen_writeln(out, " * Copyright 2025 Dyber, Inc. All Rights Reserved.");
        gen_writeln(out, " */");
        gen_newline(out);
        break;
    }
}