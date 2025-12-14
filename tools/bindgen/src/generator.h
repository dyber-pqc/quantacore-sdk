/**
 * @file generator.h
 * @brief QUAC Binding Generator - Base Generator Framework
 *
 * Provides common infrastructure for code generators and defines
 * the generator interface that language-specific generators implement.
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#ifndef QUAC_BINDGEN_GENERATOR_H
#define QUAC_BINDGEN_GENERATOR_H

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "parser.h"
#include "types.h"

/*=============================================================================
 * Generator Configuration
 *=============================================================================*/

typedef struct
{
    const char *output_dir;
    const char *namespace;
    const char *prefix;
    bool gen_async;
    bool gen_docs;
    const char *doc_format;
    bool dry_run;
    bool force;
    bool verbose;
} generator_config_t;

/*=============================================================================
 * Output Utilities
 *=============================================================================*/

/** Output context for code generation */
typedef struct
{
    FILE *file;
    char *buffer;
    size_t buffer_size;
    size_t buffer_pos;
    int indent_level;
    int indent_size;
    const char *indent_char;
    bool at_line_start;
} gen_output_t;

/**
 * @brief Create output context for file
 */
gen_output_t *gen_output_create_file(const char *path);

/**
 * @brief Create output context for buffer
 */
gen_output_t *gen_output_create_buffer(size_t initial_size);

/**
 * @brief Close and free output context
 */
void gen_output_destroy(gen_output_t *out);

/**
 * @brief Get buffer content (for buffer outputs)
 */
const char *gen_output_get_buffer(gen_output_t *out);

/**
 * @brief Write formatted output
 */
void gen_write(gen_output_t *out, const char *fmt, ...);

/**
 * @brief Write line with automatic indentation
 */
void gen_writeln(gen_output_t *out, const char *fmt, ...);

/**
 * @brief Write empty line
 */
void gen_newline(gen_output_t *out);

/**
 * @brief Increase indentation
 */
void gen_indent(gen_output_t *out);

/**
 * @brief Decrease indentation
 */
void gen_dedent(gen_output_t *out);

/**
 * @brief Set indentation style
 */
void gen_set_indent(gen_output_t *out, int size, const char *ch);

/*=============================================================================
 * Code Generation Helpers
 *=============================================================================*/

/**
 * @brief Convert snake_case to PascalCase
 */
void gen_to_pascal_case(const char *input, char *output, size_t size);

/**
 * @brief Convert snake_case to camelCase
 */
void gen_to_camel_case(const char *input, char *output, size_t size);

/**
 * @brief Convert PascalCase to snake_case
 */
void gen_to_snake_case(const char *input, char *output, size_t size);

/**
 * @brief Convert to SCREAMING_SNAKE_CASE
 */
void gen_to_screaming_case(const char *input, char *output, size_t size);

/**
 * @brief Strip prefix from name
 */
const char *gen_strip_prefix(const char *name, const char *prefix);

/**
 * @brief Strip suffix from name
 */
void gen_strip_suffix(const char *name, const char *suffix, char *output, size_t size);

/**
 * @brief Escape string for target language
 */
void gen_escape_string(const char *input, char *output, size_t size,
                       target_language_t target);

/**
 * @brief Format documentation comment
 */
void gen_write_doc_comment(gen_output_t *out, const char *doc,
                           target_language_t target);

/**
 * @brief Generate file header comment
 */
void gen_write_file_header(gen_output_t *out, const char *filename,
                           const char *description, target_language_t target);

/*=============================================================================
 * Generator Interface
 *=============================================================================*/

/**
 * @brief Generator function type
 */
typedef int (*generator_func_t)(const parsed_api_t *api,
                                const generator_config_t *config);

/**
 * @brief Register a generator
 */
void gen_register(target_language_t target, generator_func_t func);

/**
 * @brief Get generator for target
 */
generator_func_t gen_get(target_language_t target);

#endif /* QUAC_BINDGEN_GENERATOR_H */