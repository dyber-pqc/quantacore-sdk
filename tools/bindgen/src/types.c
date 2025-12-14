/**
 * @file types.c
 * @brief QUAC Binding Generator - Type System Implementation
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "types.h"

/*=============================================================================
 * Type Mapping Table
 *=============================================================================*/

static const type_mapping_t g_type_mappings[] = {
    /* Void */
    {TYPE_VOID, "void",
     "None", "None",
     "()", "c_void",
     "", "C.void",
     "void", "void",
     "void", "",
     "void", "napi_undefined"},

    /* Boolean */
    {TYPE_BOOL, "bool",
     "bool", "c_bool",
     "bool", "c_bool",
     "bool", "C.bool",
     "boolean", "jboolean",
     "bool", "MarshalAs(UnmanagedType.I1)",
     "boolean", "napi_boolean"},

    /* Character */
    {TYPE_CHAR, "char",
     "str", "c_char",
     "i8", "c_char",
     "byte", "C.char",
     "byte", "jbyte",
     "sbyte", "",
     "number", "napi_number"},

    /* Signed integers */
    {TYPE_INT8, "int8_t",
     "int", "c_int8",
     "i8", "i8",
     "int8", "C.int8_t",
     "byte", "jbyte",
     "sbyte", "",
     "number", "napi_number"},
    {TYPE_INT16, "int16_t",
     "int", "c_int16",
     "i16", "i16",
     "int16", "C.int16_t",
     "short", "jshort",
     "short", "",
     "number", "napi_number"},
    {TYPE_INT32, "int32_t",
     "int", "c_int32",
     "i32", "i32",
     "int32", "C.int32_t",
     "int", "jint",
     "int", "",
     "number", "napi_number"},
    {TYPE_INT64, "int64_t",
     "int", "c_int64",
     "i64", "i64",
     "int64", "C.int64_t",
     "long", "jlong",
     "long", "",
     "bigint", "napi_bigint_int64"},

    /* Unsigned integers */
    {TYPE_UINT8, "uint8_t",
     "int", "c_uint8",
     "u8", "u8",
     "uint8", "C.uint8_t",
     "int", "jint", /* Java has no unsigned */
     "byte", "",
     "number", "napi_number"},
    {TYPE_UINT16, "uint16_t",
     "int", "c_uint16",
     "u16", "u16",
     "uint16", "C.uint16_t",
     "int", "jint",
     "ushort", "",
     "number", "napi_number"},
    {TYPE_UINT32, "uint32_t",
     "int", "c_uint32",
     "u32", "u32",
     "uint32", "C.uint32_t",
     "int", "jint",
     "uint", "",
     "number", "napi_number"},
    {TYPE_UINT64, "uint64_t",
     "int", "c_uint64",
     "u64", "u64",
     "uint64", "C.uint64_t",
     "long", "jlong",
     "ulong", "",
     "bigint", "napi_bigint_uint64"},

    /* Size type */
    {TYPE_SIZE, "size_t",
     "int", "c_size_t",
     "usize", "usize",
     "uintptr", "C.size_t",
     "long", "jlong",
     "UIntPtr", "MarshalAs(UnmanagedType.SysUInt)",
     "number", "napi_number"},

    /* Floating point */
    {TYPE_FLOAT, "float",
     "float", "c_float",
     "f32", "f32",
     "float32", "C.float",
     "float", "jfloat",
     "float", "",
     "number", "napi_number"},
    {TYPE_DOUBLE, "double",
     "float", "c_double",
     "f64", "f64",
     "float64", "C.double",
     "double", "jdouble",
     "double", "",
     "number", "napi_number"},

    /* Pointer (void*) */
    {TYPE_POINTER, "void*",
     "Any", "c_void_p",
     "*mut c_void", "*mut c_void",
     "unsafe.Pointer", "unsafe.Pointer",
     "long", "jlong",
     "IntPtr", "",
     "Buffer", "napi_external"},

    /* Terminator */
    {TYPE_UNKNOWN, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL}};

/*=============================================================================
 * QUAC-Specific Types
 *=============================================================================*/

static const char *g_quac_handles[] = {
    "quac_context_t",
    "quac_device_t",
    "quac_async_handle_t",
    "quac_batch_t",
    "quac_key_handle_t",
    NULL};

static const char *g_quac_enums[] = {
    "quac_result_t",
    "quac_kem_algorithm_t",
    "quac_sign_algorithm_t",
    "quac_device_state_t",
    "quac_key_type_t",
    "quac_random_quality_t",
    NULL};

/*=============================================================================
 * Thread-Local Buffer
 *=============================================================================*/

#define TYPE_BUFFER_SIZE 256
#define TYPE_BUFFER_COUNT 8

static __thread char g_buffers[TYPE_BUFFER_COUNT][TYPE_BUFFER_SIZE];
static __thread int g_buffer_index = 0;

static char *get_buffer(void)
{
    char *buf = g_buffers[g_buffer_index];
    g_buffer_index = (g_buffer_index + 1) % TYPE_BUFFER_COUNT;
    return buf;
}

/*=============================================================================
 * API Implementation
 *=============================================================================*/

void types_init(void)
{
    /* Nothing to initialize currently */
}

void types_shutdown(void)
{
    /* Nothing to cleanup currently */
}

const type_mapping_t *types_get_mapping(c_type_kind_t kind)
{
    for (const type_mapping_t *m = g_type_mappings; m->c_name; m++)
    {
        if (m->c_kind == kind)
        {
            return m;
        }
    }
    return NULL;
}

const type_mapping_t *types_get_mapping_by_name(const char *c_name)
{
    if (!c_name)
        return NULL;

    for (const type_mapping_t *m = g_type_mappings; m->c_name; m++)
    {
        if (strcmp(m->c_name, c_name) == 0)
        {
            return m;
        }
    }
    return NULL;
}

const char *types_convert(const parsed_type_t *type, target_language_t target)
{
    if (!type)
        return "???";

    char *buf = get_buffer();
    types_format(type, target, buf, TYPE_BUFFER_SIZE);
    return buf;
}

const char *types_convert_ffi(const parsed_type_t *type, target_language_t target)
{
    if (!type)
        return "???";

    char *buf = get_buffer();
    types_format_ffi(type, target, buf, TYPE_BUFFER_SIZE);
    return buf;
}

const char *types_default_value(const parsed_type_t *type, target_language_t target)
{
    if (!type)
        return "null";

    /* Pointers */
    if (type->pointer_depth > 0)
    {
        switch (target)
        {
        case TARGET_PYTHON:
            return "None";
        case TARGET_RUST:
            return "std::ptr::null_mut()";
        case TARGET_GO:
            return "nil";
        case TARGET_JAVA:
            return "0L";
        case TARGET_CSHARP:
            return "IntPtr.Zero";
        case TARGET_NODEJS:
            return "null";
        default:
            return "null";
        }
    }

    /* Primitives */
    switch (type->kind)
    {
    case TYPE_BOOL:
        return (target == TARGET_PYTHON) ? "False" : "false";

    case TYPE_FLOAT:
    case TYPE_DOUBLE:
        return "0.0";

    case TYPE_VOID:
        switch (target)
        {
        case TARGET_PYTHON:
            return "None";
        case TARGET_RUST:
            return "()";
        case TARGET_CSHARP:
        case TARGET_JAVA:
            return "";
        default:
            return "undefined";
        }

    default:
        return "0";
    }
}

bool types_needs_conversion(const parsed_type_t *type, target_language_t target)
{
    if (!type)
        return false;

    /* String types need conversion */
    if (type->kind == TYPE_CHAR && type->pointer_depth == 1)
    {
        return true;
    }

    /* Buffer types */
    if (type->kind == TYPE_UINT8 && type->pointer_depth == 1)
    {
        return true;
    }

    /* QUAC handles */
    if (types_is_quac_handle(type->name))
    {
        return true;
    }

    return false;
}

const char *types_get_input_conversion(const parsed_type_t *type,
                                       target_language_t target,
                                       const char *var_name)
{
    char *buf = get_buffer();

    /* String conversion */
    if (type->kind == TYPE_CHAR && type->pointer_depth == 1)
    {
        switch (target)
        {
        case TARGET_PYTHON:
            snprintf(buf, TYPE_BUFFER_SIZE, "%s.encode('utf-8')", var_name);
            break;
        case TARGET_RUST:
            snprintf(buf, TYPE_BUFFER_SIZE, "CString::new(%s)?.as_ptr()", var_name);
            break;
        case TARGET_GO:
            snprintf(buf, TYPE_BUFFER_SIZE, "C.CString(%s)", var_name);
            break;
        default:
            snprintf(buf, TYPE_BUFFER_SIZE, "%s", var_name);
        }
        return buf;
    }

    snprintf(buf, TYPE_BUFFER_SIZE, "%s", var_name);
    return buf;
}

const char *types_get_output_conversion(const parsed_type_t *type,
                                        target_language_t target,
                                        const char *var_name)
{
    char *buf = get_buffer();

    /* String conversion */
    if (type->kind == TYPE_CHAR && type->pointer_depth == 1)
    {
        switch (target)
        {
        case TARGET_PYTHON:
            snprintf(buf, TYPE_BUFFER_SIZE, "%s.decode('utf-8')", var_name);
            break;
        case TARGET_RUST:
            snprintf(buf, TYPE_BUFFER_SIZE, "CStr::from_ptr(%s).to_string_lossy()", var_name);
            break;
        case TARGET_GO:
            snprintf(buf, TYPE_BUFFER_SIZE, "C.GoString(%s)", var_name);
            break;
        default:
            snprintf(buf, TYPE_BUFFER_SIZE, "%s", var_name);
        }
        return buf;
    }

    snprintf(buf, TYPE_BUFFER_SIZE, "%s", var_name);
    return buf;
}

void types_format(const parsed_type_t *type, target_language_t target,
                  char *buffer, size_t size)
{
    if (!type || !buffer || size == 0)
        return;

    const type_mapping_t *mapping = types_get_mapping(type->kind);

    /* Handle pointers */
    if (type->pointer_depth > 0)
    {
        /* String type (char*) */
        if (type->kind == TYPE_CHAR && type->pointer_depth == 1)
        {
            switch (target)
            {
            case TARGET_PYTHON:
                strncpy(buffer, "str", size);
                break;
            case TARGET_RUST:
                strncpy(buffer, "&str", size);
                break;
            case TARGET_GO:
                strncpy(buffer, "string", size);
                break;
            case TARGET_JAVA:
                strncpy(buffer, "String", size);
                break;
            case TARGET_CSHARP:
                strncpy(buffer, "string", size);
                break;
            case TARGET_NODEJS:
                strncpy(buffer, "string", size);
                break;
            default:
                strncpy(buffer, "string", size);
            }
            return;
        }

        /* Buffer type (uint8_t*) */
        if (type->kind == TYPE_UINT8 && type->pointer_depth == 1)
        {
            switch (target)
            {
            case TARGET_PYTHON:
                strncpy(buffer, "bytes", size);
                break;
            case TARGET_RUST:
                strncpy(buffer, "&[u8]", size);
                break;
            case TARGET_GO:
                strncpy(buffer, "[]byte", size);
                break;
            case TARGET_JAVA:
                strncpy(buffer, "byte[]", size);
                break;
            case TARGET_CSHARP:
                strncpy(buffer, "byte[]", size);
                break;
            case TARGET_NODEJS:
                strncpy(buffer, "Buffer", size);
                break;
            default:
                strncpy(buffer, "Buffer", size);
            }
            return;
        }

        /* Generic pointer */
        switch (target)
        {
        case TARGET_PYTHON:
            strncpy(buffer, "Any", size);
            break;
        case TARGET_RUST:
            strncpy(buffer, "*mut c_void", size);
            break;
        case TARGET_GO:
            strncpy(buffer, "unsafe.Pointer", size);
            break;
        case TARGET_JAVA:
            strncpy(buffer, "long", size);
            break;
        case TARGET_CSHARP:
            strncpy(buffer, "IntPtr", size);
            break;
        case TARGET_NODEJS:
            strncpy(buffer, "Buffer", size);
            break;
        default:
            strncpy(buffer, "pointer", size);
        }
        return;
    }

    /* Check for QUAC types */
    if (types_is_quac_handle(type->name))
    {
        const char *wrapper = types_get_wrapper_class(type->name, target);
        strncpy(buffer, wrapper, size);
        return;
    }

    if (types_is_quac_enum(type->name) || types_is_quac_result(type->name))
    {
        /* Strip quac_ prefix and _t suffix for enum name */
        char enum_name[128];
        const char *name = type->name;
        if (strncmp(name, "quac_", 5) == 0)
            name += 5;
        strncpy(enum_name, name, sizeof(enum_name) - 1);
        size_t len = strlen(enum_name);
        if (len > 2 && strcmp(enum_name + len - 2, "_t") == 0)
        {
            enum_name[len - 2] = '\0';
        }

        /* Convert to PascalCase */
        char pascal[128];
        char *dst = pascal;
        bool cap = true;
        for (const char *src = enum_name; *src && dst < pascal + sizeof(pascal) - 1; src++)
        {
            if (*src == '_')
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

        strncpy(buffer, pascal, size);
        return;
    }

    /* Use mapping */
    if (mapping)
    {
        const char *type_str = NULL;
        switch (target)
        {
        case TARGET_PYTHON:
            type_str = mapping->python_type;
            break;
        case TARGET_RUST:
            type_str = mapping->rust_type;
            break;
        case TARGET_GO:
            type_str = mapping->go_type;
            break;
        case TARGET_JAVA:
            type_str = mapping->java_type;
            break;
        case TARGET_CSHARP:
            type_str = mapping->csharp_type;
            break;
        case TARGET_NODEJS:
            type_str = mapping->nodejs_type;
            break;
        default:
            type_str = type->name;
        }
        strncpy(buffer, type_str ? type_str : type->name, size);
    }
    else
    {
        strncpy(buffer, type->name, size);
    }

    buffer[size - 1] = '\0';
}

void types_format_ffi(const parsed_type_t *type, target_language_t target,
                      char *buffer, size_t size)
{
    if (!type || !buffer || size == 0)
        return;

    const type_mapping_t *mapping = types_get_mapping(type->kind);

    /* Handle pointers */
    if (type->pointer_depth > 0)
    {
        switch (target)
        {
        case TARGET_PYTHON:
            strncpy(buffer, "c_void_p", size);
            break;
        case TARGET_RUST:
            snprintf(buffer, size, "*mut c_void");
            break;
        case TARGET_GO:
            strncpy(buffer, "unsafe.Pointer", size);
            break;
        case TARGET_JAVA:
            strncpy(buffer, "jlong", size);
            break;
        case TARGET_CSHARP:
            strncpy(buffer, "IntPtr", size);
            break;
        case TARGET_NODEJS:
            strncpy(buffer, "napi_external", size);
            break;
        default:
            strncpy(buffer, "void*", size);
        }
        return;
    }

    /* Use FFI mapping */
    if (mapping)
    {
        const char *type_str = NULL;
        switch (target)
        {
        case TARGET_PYTHON:
            type_str = mapping->python_ctypes;
            break;
        case TARGET_RUST:
            type_str = mapping->rust_ffi;
            break;
        case TARGET_GO:
            type_str = mapping->go_cgo;
            break;
        case TARGET_JAVA:
            type_str = mapping->java_jni;
            break;
        case TARGET_CSHARP:
            type_str = mapping->csharp_type;
            break;
        case TARGET_NODEJS:
            type_str = mapping->nodejs_napi;
            break;
        default:
            type_str = type->name;
        }
        strncpy(buffer, type_str ? type_str : type->name, size);
    }
    else
    {
        strncpy(buffer, type->name, size);
    }

    buffer[size - 1] = '\0';
}

/*=============================================================================
 * QUAC-Specific Type Handling
 *=============================================================================*/

bool types_is_quac_handle(const char *type_name)
{
    if (!type_name)
        return false;

    for (const char **p = g_quac_handles; *p; p++)
    {
        if (strcmp(type_name, *p) == 0)
            return true;
    }
    return false;
}

bool types_is_quac_result(const char *type_name)
{
    return type_name && strcmp(type_name, "quac_result_t") == 0;
}

bool types_is_quac_enum(const char *type_name)
{
    if (!type_name)
        return false;

    for (const char **p = g_quac_enums; *p; p++)
    {
        if (strcmp(type_name, *p) == 0)
            return true;
    }
    return false;
}

const char *types_get_wrapper_class(const char *type_name, target_language_t target)
{
    static char buffer[128];

    if (!type_name)
        return "Unknown";

    /* Map QUAC types to wrapper class names */
    if (strcmp(type_name, "quac_context_t") == 0)
    {
        return "Context";
    }
    else if (strcmp(type_name, "quac_device_t") == 0)
    {
        return "Device";
    }
    else if (strcmp(type_name, "quac_async_handle_t") == 0)
    {
        return "AsyncHandle";
    }
    else if (strcmp(type_name, "quac_batch_t") == 0)
    {
        return "Batch";
    }
    else if (strcmp(type_name, "quac_key_handle_t") == 0)
    {
        return "KeyHandle";
    }

    /* Generic conversion */
    const char *name = type_name;
    if (strncmp(name, "quac_", 5) == 0)
        name += 5;

    char *dst = buffer;
    bool cap = true;
    for (const char *src = name; *src && dst < buffer + sizeof(buffer) - 1; src++)
    {
        if (*src == '_')
        {
            cap = true;
        }
        else if (*src != 't' || src[1] != '\0')
        { /* Skip trailing _t */
            *dst++ = cap ? toupper(*src) : *src;
            cap = false;
        }
    }
    *dst = '\0';

    return buffer;
}

const char *types_get_error_type(target_language_t target)
{
    switch (target)
    {
    case TARGET_PYTHON:
        return "QUACError";
    case TARGET_RUST:
        return "Error";
    case TARGET_GO:
        return "error";
    case TARGET_JAVA:
        return "QUACException";
    case TARGET_CSHARP:
        return "QUACException";
    case TARGET_NODEJS:
        return "QUACError";
    default:
        return "Error";
    }
}