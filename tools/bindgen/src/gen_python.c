/**
 * @file gen_python.c
 * @brief QUAC Binding Generator - Python Generator
 *
 * Generates Python bindings using ctypes for FFI.
 * Produces:
 * - quac100.py: Main module with classes and functions
 * - _quac100.pyi: Type stub file for IDE support
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "parser.h"
#include "types.h"
#include "generator.h"

/*=============================================================================
 * Python-Specific Helpers
 *=============================================================================*/

static void python_name(const char *c_name, const char *prefix, char *out, size_t size)
{
    const char *name = gen_strip_prefix(c_name, prefix);
    gen_strip_suffix(name, "_t", out, size);
}

static void python_class_name(const char *c_name, char *out, size_t size)
{
    char stripped[128];
    python_name(c_name, "quac_", stripped, sizeof(stripped));
    gen_to_pascal_case(stripped, out, size);
}

static void python_func_name(const char *c_name, char *out, size_t size)
{
    const char *name = gen_strip_prefix(c_name, "quac_");
    strncpy(out, name, size - 1);
    out[size - 1] = '\0';
}

static const char *python_ctypes_type(const parsed_type_t *type)
{
    if (type->pointer_depth > 0)
    {
        if (type->kind == TYPE_CHAR)
            return "c_char_p";
        if (type->kind == TYPE_VOID)
            return "c_void_p";
        return "c_void_p";
    }

    switch (type->kind)
    {
    case TYPE_VOID:
        return "None";
    case TYPE_BOOL:
        return "c_bool";
    case TYPE_CHAR:
        return "c_char";
    case TYPE_INT8:
        return "c_int8";
    case TYPE_UINT8:
        return "c_uint8";
    case TYPE_INT16:
        return "c_int16";
    case TYPE_UINT16:
        return "c_uint16";
    case TYPE_INT32:
        return "c_int32";
    case TYPE_UINT32:
        return "c_uint32";
    case TYPE_INT64:
        return "c_int64";
    case TYPE_UINT64:
        return "c_uint64";
    case TYPE_SIZE:
        return "c_size_t";
    case TYPE_FLOAT:
        return "c_float";
    case TYPE_DOUBLE:
        return "c_double";
    default:
        return "c_void_p";
    }
}

/*=============================================================================
 * Code Generation
 *=============================================================================*/

static void generate_imports(gen_output_t *out)
{
    gen_writeln(out, "from __future__ import annotations");
    gen_writeln(out, "import ctypes");
    gen_writeln(out, "from ctypes import (");
    gen_indent(out);
    gen_writeln(out, "c_void_p, c_char_p, c_bool, c_int, c_uint,");
    gen_writeln(out, "c_int8, c_uint8, c_int16, c_uint16,");
    gen_writeln(out, "c_int32, c_uint32, c_int64, c_uint64,");
    gen_writeln(out, "c_size_t, c_float, c_double, c_char,");
    gen_writeln(out, "Structure, POINTER, byref, create_string_buffer");
    gen_dedent(out);
    gen_writeln(out, ")");
    gen_writeln(out, "from enum import IntEnum, IntFlag");
    gen_writeln(out, "from typing import Optional, Union, List, Tuple, Any");
    gen_writeln(out, "from pathlib import Path");
    gen_writeln(out, "import sys");
    gen_writeln(out, "import os");
    gen_newline(out);
}

static void generate_library_loading(gen_output_t *out)
{
    gen_writeln(out, "# Library loading");
    gen_writeln(out, "_lib_name = 'quac100'");
    gen_writeln(out, "if sys.platform == 'win32':");
    gen_indent(out);
    gen_writeln(out, "_lib_name = 'quac100.dll'");
    gen_dedent(out);
    gen_writeln(out, "elif sys.platform == 'darwin':");
    gen_indent(out);
    gen_writeln(out, "_lib_name = 'libquac100.dylib'");
    gen_dedent(out);
    gen_writeln(out, "else:");
    gen_indent(out);
    gen_writeln(out, "_lib_name = 'libquac100.so'");
    gen_dedent(out);
    gen_newline(out);
    gen_writeln(out, "_lib_path = os.environ.get('QUAC_LIB_PATH', '')");
    gen_writeln(out, "if _lib_path:");
    gen_indent(out);
    gen_writeln(out, "_lib_name = os.path.join(_lib_path, _lib_name)");
    gen_dedent(out);
    gen_newline(out);
    gen_writeln(out, "try:");
    gen_indent(out);
    gen_writeln(out, "_lib = ctypes.CDLL(_lib_name)");
    gen_dedent(out);
    gen_writeln(out, "except OSError as e:");
    gen_indent(out);
    gen_writeln(out, "raise ImportError(f'Failed to load QUAC library: {e}') from e");
    gen_dedent(out);
    gen_newline(out);
}

static void generate_error_class(gen_output_t *out)
{
    gen_writeln(out, "class QUACError(Exception):");
    gen_indent(out);
    gen_writeln(out, "\"\"\"QUAC SDK error.\"\"\"");
    gen_newline(out);
    gen_writeln(out, "def __init__(self, code: int, message: str = ''):");
    gen_indent(out);
    gen_writeln(out, "self.code = code");
    gen_writeln(out, "self.message = message or f'Error code {code}'");
    gen_writeln(out, "super().__init__(self.message)");
    gen_dedent(out);
    gen_dedent(out);
    gen_newline(out);
}

static void generate_enum(gen_output_t *out, const parsed_enum_t *e)
{
    char class_name[128];
    python_class_name(e->name, class_name, sizeof(class_name));

    if (e->doc[0])
    {
        gen_write_doc_comment(out, e->doc, TARGET_PYTHON);
    }

    gen_writeln(out, "class %s(%s):", class_name, e->is_flags ? "IntFlag" : "IntEnum");
    gen_indent(out);

    if (e->value_count == 0)
    {
        gen_writeln(out, "pass");
    }
    else
    {
        for (int i = 0; i < e->value_count; i++)
        {
            const parsed_enum_value_t *v = &e->values[i];

            /* Convert name to SCREAMING_CASE */
            char value_name[128];
            const char *name = gen_strip_prefix(v->name, "QUAC_");
            strncpy(value_name, name, sizeof(value_name) - 1);

            gen_writeln(out, "%s = %lld", value_name, (long long)v->value);
        }
    }

    gen_dedent(out);
    gen_newline(out);
}

static void generate_struct(gen_output_t *out, const parsed_struct_t *s)
{
    if (s->is_opaque)
        return;

    char class_name[128];
    python_class_name(s->name, class_name, sizeof(class_name));

    if (s->doc[0])
    {
        gen_write_doc_comment(out, s->doc, TARGET_PYTHON);
    }

    gen_writeln(out, "class %s(Structure):", class_name);
    gen_indent(out);

    if (s->field_count == 0)
    {
        gen_writeln(out, "pass");
    }
    else
    {
        gen_writeln(out, "_fields_ = [");
        gen_indent(out);

        for (int i = 0; i < s->field_count; i++)
        {
            const parsed_field_t *f = &s->fields[i];
            const char *ctype = python_ctypes_type(&f->type);

            gen_writeln(out, "('%s', %s),", f->name, ctype);
        }

        gen_dedent(out);
        gen_writeln(out, "]");
    }

    gen_dedent(out);
    gen_newline(out);
}

static void generate_function_wrapper(gen_output_t *out, const parsed_function_t *f,
                                      const char *prefix)
{
    char func_name[128];
    python_func_name(f->name, func_name, sizeof(func_name));

    /* Build parameter list */
    char params[1024] = "";
    char *p = params;

    for (int i = 0; i < f->param_count; i++)
    {
        const parsed_param_t *param = &f->params[i];
        const char *py_type = types_convert(&param->type, TARGET_PYTHON);

        if (i > 0)
        {
            p += sprintf(p, ", ");
        }
        p += sprintf(p, "%s: %s", param->name, py_type);
    }

    /* Return type */
    const char *return_type = types_convert(&f->return_type, TARGET_PYTHON);

    /* Write docstring */
    if (f->doc[0])
    {
        gen_write_doc_comment(out, f->doc, TARGET_PYTHON);
    }

    /* Write function */
    gen_writeln(out, "def %s(%s) -> %s:", func_name, params, return_type);
    gen_indent(out);

    /* Call native function */
    gen_writeln(out, "result = _lib.%s(", f->name);
    gen_indent(out);

    for (int i = 0; i < f->param_count; i++)
    {
        const parsed_param_t *param = &f->params[i];
        gen_writeln(out, "%s%s", param->name, i < f->param_count - 1 ? "," : "");
    }

    gen_dedent(out);
    gen_writeln(out, ")");

    /* Check result if it's a QUAC result type */
    if (types_is_quac_result(f->return_type.name))
    {
        gen_writeln(out, "if result != 0:");
        gen_indent(out);
        gen_writeln(out, "raise QUACError(result)");
        gen_dedent(out);
        gen_writeln(out, "return result");
    }
    else
    {
        gen_writeln(out, "return result");
    }

    gen_dedent(out);
    gen_newline(out);
}

static void generate_ffi_declarations(gen_output_t *out, const parsed_api_t *api)
{
    gen_writeln(out, "# FFI function declarations");

    for (int i = 0; i < api->function_count; i++)
    {
        const parsed_function_t *f = &api->functions[i];

        gen_writeln(out, "_lib.%s.argtypes = [", f->name);
        gen_indent(out);

        for (int j = 0; j < f->param_count; j++)
        {
            const parsed_param_t *param = &f->params[j];
            const char *ctype = python_ctypes_type(&param->type);
            gen_writeln(out, "%s,", ctype);
        }

        gen_dedent(out);
        gen_writeln(out, "]");

        const char *ret_ctype = python_ctypes_type(&f->return_type);
        gen_writeln(out, "_lib.%s.restype = %s", f->name, ret_ctype);
        gen_newline(out);
    }
}

/*=============================================================================
 * Main Generator Entry Point
 *=============================================================================*/

int generate_python(const parsed_api_t *api, const generator_config_t *config)
{
    if (!api || !config)
        return -1;

    char path[1024];
    snprintf(path, sizeof(path), "%s/quac100.py", config->output_dir);

    if (config->verbose)
    {
        printf("  Generating: %s\n", path);
    }

    if (config->dry_run)
    {
        return 0;
    }

    gen_output_t *out = gen_output_create_file(path);
    if (!out)
    {
        fprintf(stderr, "Error: Cannot create %s\n", path);
        return -1;
    }

    /* File header */
    gen_write_file_header(out, "quac100.py",
                          "Python bindings for QUAC 100 SDK", TARGET_PYTHON);

    /* Imports */
    generate_imports(out);

    /* Library loading */
    generate_library_loading(out);

    /* Error class */
    generate_error_class(out);

    /* Constants */
    gen_writeln(out, "# Constants");
    for (int i = 0; i < api->constant_count; i++)
    {
        const parsed_constant_t *c = &api->constants[i];
        if (strncmp(c->name, "QUAC_", 5) == 0)
        {
            if (c->is_string)
            {
                gen_writeln(out, "%s = '%s'", c->name, c->value_str);
            }
            else
            {
                gen_writeln(out, "%s = %s", c->name, c->value_str);
            }
        }
    }
    gen_newline(out);

    /* Enums */
    gen_writeln(out, "# Enumerations");
    for (int i = 0; i < api->enum_count; i++)
    {
        generate_enum(out, &api->enums[i]);
    }

    /* Structures */
    gen_writeln(out, "# Structures");
    for (int i = 0; i < api->struct_count; i++)
    {
        generate_struct(out, &api->structs[i]);
    }

    /* FFI declarations */
    generate_ffi_declarations(out, api);

    /* Function wrappers */
    gen_writeln(out, "# API Functions");
    for (int i = 0; i < api->function_count; i++)
    {
        generate_function_wrapper(out, &api->functions[i], config->prefix);
    }

    gen_output_destroy(out);

    /* Generate type stubs */
    snprintf(path, sizeof(path), "%s/_quac100.pyi", config->output_dir);

    if (config->verbose)
    {
        printf("  Generating: %s\n", path);
    }

    out = gen_output_create_file(path);
    if (out)
    {
        gen_write_file_header(out, "_quac100.pyi",
                              "Type stubs for QUAC 100 Python bindings", TARGET_PYTHON);

        gen_writeln(out, "from typing import Optional, Union, List, Tuple, Any");
        gen_writeln(out, "from enum import IntEnum, IntFlag");
        gen_newline(out);

        /* Enum stubs */
        for (int i = 0; i < api->enum_count; i++)
        {
            char class_name[128];
            python_class_name(api->enums[i].name, class_name, sizeof(class_name));
            gen_writeln(out, "class %s(%s): ...", class_name,
                        api->enums[i].is_flags ? "IntFlag" : "IntEnum");
        }
        gen_newline(out);

        /* Function stubs */
        for (int i = 0; i < api->function_count; i++)
        {
            const parsed_function_t *f = &api->functions[i];
            char func_name[128];
            python_func_name(f->name, func_name, sizeof(func_name));

            gen_write(out, "def %s(", func_name);
            for (int j = 0; j < f->param_count; j++)
            {
                if (j > 0)
                    gen_write(out, ", ");
                gen_write(out, "%s: %s", f->params[j].name,
                          types_convert(&f->params[j].type, TARGET_PYTHON));
            }
            gen_writeln(out, ") -> %s: ...",
                        types_convert(&f->return_type, TARGET_PYTHON));
        }

        gen_output_destroy(out);
    }

    return 0;
}