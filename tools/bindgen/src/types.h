/**
 * @file types.h
 * @brief QUAC Binding Generator - Type System and Mappings
 *
 * Defines type mappings from C to target languages and provides
 * utilities for type conversion and formatting.
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#ifndef QUAC_BINDGEN_TYPES_H
#define QUAC_BINDGEN_TYPES_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "parser.h"

/*=============================================================================
 * Target Languages
 *=============================================================================*/

typedef enum
{
    TARGET_PYTHON,
    TARGET_RUST,
    TARGET_GO,
    TARGET_JAVA,
    TARGET_CSHARP,
    TARGET_NODEJS,
    TARGET_COUNT
} target_language_t;

/*=============================================================================
 * Type Mapping
 *=============================================================================*/

/** Type mapping entry */
typedef struct
{
    c_type_kind_t c_kind;
    const char *c_name;
    const char *python_type;
    const char *python_ctypes;
    const char *rust_type;
    const char *rust_ffi;
    const char *go_type;
    const char *go_cgo;
    const char *java_type;
    const char *java_jni;
    const char *csharp_type;
    const char *csharp_marshal;
    const char *nodejs_type;
    const char *nodejs_napi;
} type_mapping_t;

/*=============================================================================
 * API
 *=============================================================================*/

/**
 * @brief Initialize type system
 */
void types_init(void);

/**
 * @brief Shutdown type system
 */
void types_shutdown(void);

/**
 * @brief Get type mapping for C type kind
 */
const type_mapping_t *types_get_mapping(c_type_kind_t kind);

/**
 * @brief Get type mapping by C type name
 */
const type_mapping_t *types_get_mapping_by_name(const char *c_name);

/**
 * @brief Convert parsed type to target language string
 */
const char *types_convert(const parsed_type_t *type, target_language_t target);

/**
 * @brief Convert parsed type to FFI/interop string
 */
const char *types_convert_ffi(const parsed_type_t *type, target_language_t target);

/**
 * @brief Get default value for type in target language
 */
const char *types_default_value(const parsed_type_t *type, target_language_t target);

/**
 * @brief Check if type needs special handling (e.g., string, buffer)
 */
bool types_needs_conversion(const parsed_type_t *type, target_language_t target);

/**
 * @brief Get conversion code for type (input direction: lang -> C)
 */
const char *types_get_input_conversion(const parsed_type_t *type,
                                       target_language_t target,
                                       const char *var_name);

/**
 * @brief Get conversion code for type (output direction: C -> lang)
 */
const char *types_get_output_conversion(const parsed_type_t *type,
                                        target_language_t target,
                                        const char *var_name);

/**
 * @brief Format type for target language declaration
 */
void types_format(const parsed_type_t *type, target_language_t target,
                  char *buffer, size_t size);

/**
 * @brief Format type for FFI declaration
 */
void types_format_ffi(const parsed_type_t *type, target_language_t target,
                      char *buffer, size_t size);

/*=============================================================================
 * QUAC-Specific Type Handling
 *=============================================================================*/

/**
 * @brief Check if type is a QUAC handle type (e.g., quac_context_t)
 */
bool types_is_quac_handle(const char *type_name);

/**
 * @brief Check if type is a QUAC result type
 */
bool types_is_quac_result(const char *type_name);

/**
 * @brief Check if type is a QUAC enum
 */
bool types_is_quac_enum(const char *type_name);

/**
 * @brief Get wrapper class name for QUAC handle
 */
const char *types_get_wrapper_class(const char *type_name, target_language_t target);

/**
 * @brief Get exception/error type name
 */
const char *types_get_error_type(target_language_t target);

#endif /* QUAC_BINDGEN_TYPES_H */