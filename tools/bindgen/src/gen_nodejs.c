/**
 * @file gen_nodejs.c
 * @brief QUAC Binding Generator - Node.js Generator
 *
 * Generates Node.js bindings using N-API for native addons.
 * Produces:
 * - quac100.js: JavaScript wrapper module
 * - quac100.d.ts: TypeScript declarations
 * - binding.gyp: Build configuration
 * - quac100_napi.c: N-API native addon source
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
 * Node.js-Specific Helpers
 *=============================================================================*/

static void js_class_name(const char *c_name, char *out, size_t size)
{
    const char *name = gen_strip_prefix(c_name, "quac_");
    char stripped[128];
    gen_strip_suffix(name, "_t", stripped, sizeof(stripped));
    gen_to_pascal_case(stripped, out, size);
}

static void js_func_name(const char *c_name, char *out, size_t size)
{
    const char *name = gen_strip_prefix(c_name, "quac_");
    gen_to_camel_case(name, out, size);
}

static void js_const_name(const char *c_name, char *out, size_t size)
{
    const char *name = gen_strip_prefix(c_name, "QUAC_");
    strncpy(out, name, size - 1);
    out[size - 1] = '\0';
}

static const char *ts_type(const parsed_type_t *type)
{
    if (type->pointer_depth > 0)
    {
        if (type->kind == TYPE_CHAR)
            return "string";
        if (type->kind == TYPE_UINT8)
            return "Buffer";
        return "Buffer";
    }

    switch (type->kind)
    {
    case TYPE_VOID:
        return "void";
    case TYPE_BOOL:
        return "boolean";
    case TYPE_INT64:
    case TYPE_UINT64:
        return "bigint";
    default:
        return "number";
    }
}

/*=============================================================================
 * JavaScript Module Generation
 *=============================================================================*/

static void generate_js_imports(gen_output_t *out)
{
    gen_writeln(out, "'use strict';");
    gen_newline(out);
    gen_writeln(out, "const path = require('path');");
    gen_writeln(out, "const { promisify } = require('util');");
    gen_newline(out);
}

static void generate_js_native_loading(gen_output_t *out)
{
    gen_writeln(out, "// Load native addon");
    gen_writeln(out, "let native;");
    gen_writeln(out, "try {");
    gen_indent(out);
    gen_writeln(out, "native = require('./build/Release/quac100_napi.node');");
    gen_dedent(out);
    gen_writeln(out, "} catch (e) {");
    gen_indent(out);
    gen_writeln(out, "try {");
    gen_indent(out);
    gen_writeln(out, "native = require('./build/Debug/quac100_napi.node');");
    gen_dedent(out);
    gen_writeln(out, "} catch (e2) {");
    gen_indent(out);
    gen_writeln(out, "throw new Error('Failed to load QUAC native addon: ' + e.message);");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);
}

static void generate_js_error_class(gen_output_t *out)
{
    gen_writeln(out, "/**");
    gen_writeln(out, " * QUAC SDK Error");
    gen_writeln(out, " */");
    gen_writeln(out, "class QUACError extends Error {");
    gen_indent(out);
    gen_writeln(out, "constructor(code, message) {");
    gen_indent(out);
    gen_writeln(out, "super(message || `QUAC error code ${code}`);");
    gen_writeln(out, "this.name = 'QUACError';");
    gen_writeln(out, "this.code = code;");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);
}

static void generate_js_enum(gen_output_t *out, const parsed_enum_t *e)
{
    char class_name[128];
    js_class_name(e->name, class_name, sizeof(class_name));

    gen_writeln(out, "/**");
    if (e->doc[0])
    {
        gen_writeln(out, " * %s", e->doc);
    }
    else
    {
        gen_writeln(out, " * %s enumeration", class_name);
    }
    gen_writeln(out, " * @enum {number}");
    gen_writeln(out, " */");
    gen_writeln(out, "const %s = Object.freeze({", class_name);
    gen_indent(out);

    for (int i = 0; i < e->value_count; i++)
    {
        const parsed_enum_value_t *v = &e->values[i];
        char value_name[128];
        js_const_name(v->name, value_name, sizeof(value_name));

        gen_writeln(out, "%s: %lld,", value_name, (long long)v->value);
    }

    gen_dedent(out);
    gen_writeln(out, "});");
    gen_newline(out);
}

static void generate_js_context_class(gen_output_t *out)
{
    gen_writeln(out, "/**");
    gen_writeln(out, " * QUAC Context - Main SDK entry point");
    gen_writeln(out, " */");
    gen_writeln(out, "class Context {");
    gen_indent(out);

    gen_writeln(out, "/**");
    gen_writeln(out, " * Create a new QUAC context");
    gen_writeln(out, " */");
    gen_writeln(out, "constructor() {");
    gen_indent(out);
    gen_writeln(out, "this._handle = native.quac_init();");
    gen_writeln(out, "if (!this._handle) {");
    gen_indent(out);
    gen_writeln(out, "throw new QUACError(-1, 'Failed to initialize QUAC context');");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);

    gen_writeln(out, "/**");
    gen_writeln(out, " * Close the context and release resources");
    gen_writeln(out, " */");
    gen_writeln(out, "close() {");
    gen_indent(out);
    gen_writeln(out, "if (this._handle) {");
    gen_indent(out);
    gen_writeln(out, "native.quac_shutdown(this._handle);");
    gen_writeln(out, "this._handle = null;");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);

    gen_writeln(out, "/**");
    gen_writeln(out, " * Get the number of available devices");
    gen_writeln(out, " * @returns {number}");
    gen_writeln(out, " */");
    gen_writeln(out, "getDeviceCount() {");
    gen_indent(out);
    gen_writeln(out, "return native.quac_get_device_count(this._handle);");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);

    gen_writeln(out, "/**");
    gen_writeln(out, " * Open a device by index");
    gen_writeln(out, " * @param {number} index - Device index");
    gen_writeln(out, " * @returns {Device}");
    gen_writeln(out, " */");
    gen_writeln(out, "openDevice(index) {");
    gen_indent(out);
    gen_writeln(out, "const handle = native.quac_open_device(this._handle, index);");
    gen_writeln(out, "if (!handle) {");
    gen_indent(out);
    gen_writeln(out, "throw new QUACError(-1, `Failed to open device ${index}`);");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_writeln(out, "return new Device(handle);");
    gen_dedent(out);
    gen_writeln(out, "}");

    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);
}

static void generate_js_device_class(gen_output_t *out)
{
    gen_writeln(out, "/**");
    gen_writeln(out, " * QUAC Device - Hardware accelerator interface");
    gen_writeln(out, " */");
    gen_writeln(out, "class Device {");
    gen_indent(out);

    gen_writeln(out, "/**");
    gen_writeln(out, " * @param {*} handle - Native device handle");
    gen_writeln(out, " * @private");
    gen_writeln(out, " */");
    gen_writeln(out, "constructor(handle) {");
    gen_indent(out);
    gen_writeln(out, "this._handle = handle;");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);

    gen_writeln(out, "/**");
    gen_writeln(out, " * Close the device");
    gen_writeln(out, " */");
    gen_writeln(out, "close() {");
    gen_indent(out);
    gen_writeln(out, "if (this._handle) {");
    gen_indent(out);
    gen_writeln(out, "native.quac_close_device(this._handle);");
    gen_writeln(out, "this._handle = null;");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);

    gen_writeln(out, "/**");
    gen_writeln(out, " * Generate a KEM keypair");
    gen_writeln(out, " * @param {number} algorithm - KEM algorithm");
    gen_writeln(out, " * @returns {Promise<{publicKey: Buffer, secretKey: Buffer}>}");
    gen_writeln(out, " */");
    gen_writeln(out, "async kemKeygen(algorithm) {");
    gen_indent(out);
    gen_writeln(out, "return new Promise((resolve, reject) => {");
    gen_indent(out);
    gen_writeln(out, "native.quac_kem_keygen(this._handle, algorithm, (err, pk, sk) => {");
    gen_indent(out);
    gen_writeln(out, "if (err) reject(new QUACError(err));");
    gen_writeln(out, "else resolve({ publicKey: pk, secretKey: sk });");
    gen_dedent(out);
    gen_writeln(out, "});");
    gen_dedent(out);
    gen_writeln(out, "});");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);

    gen_writeln(out, "/**");
    gen_writeln(out, " * Encapsulate using a public key");
    gen_writeln(out, " * @param {number} algorithm - KEM algorithm");
    gen_writeln(out, " * @param {Buffer} publicKey - Public key");
    gen_writeln(out, " * @returns {Promise<{ciphertext: Buffer, sharedSecret: Buffer}>}");
    gen_writeln(out, " */");
    gen_writeln(out, "async kemEncaps(algorithm, publicKey) {");
    gen_indent(out);
    gen_writeln(out, "return new Promise((resolve, reject) => {");
    gen_indent(out);
    gen_writeln(out, "native.quac_kem_encaps(this._handle, algorithm, publicKey, (err, ct, ss) => {");
    gen_indent(out);
    gen_writeln(out, "if (err) reject(new QUACError(err));");
    gen_writeln(out, "else resolve({ ciphertext: ct, sharedSecret: ss });");
    gen_dedent(out);
    gen_writeln(out, "});");
    gen_dedent(out);
    gen_writeln(out, "});");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);

    gen_writeln(out, "/**");
    gen_writeln(out, " * Decapsulate to recover shared secret");
    gen_writeln(out, " * @param {number} algorithm - KEM algorithm");
    gen_writeln(out, " * @param {Buffer} ciphertext - Ciphertext");
    gen_writeln(out, " * @param {Buffer} secretKey - Secret key");
    gen_writeln(out, " * @returns {Promise<Buffer>} Shared secret");
    gen_writeln(out, " */");
    gen_writeln(out, "async kemDecaps(algorithm, ciphertext, secretKey) {");
    gen_indent(out);
    gen_writeln(out, "return new Promise((resolve, reject) => {");
    gen_indent(out);
    gen_writeln(out, "native.quac_kem_decaps(this._handle, algorithm, ciphertext, secretKey, (err, ss) => {");
    gen_indent(out);
    gen_writeln(out, "if (err) reject(new QUACError(err));");
    gen_writeln(out, "else resolve(ss);");
    gen_dedent(out);
    gen_writeln(out, "});");
    gen_dedent(out);
    gen_writeln(out, "});");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);

    gen_writeln(out, "/**");
    gen_writeln(out, " * Generate random bytes");
    gen_writeln(out, " * @param {number} length - Number of bytes");
    gen_writeln(out, " * @returns {Promise<Buffer>}");
    gen_writeln(out, " */");
    gen_writeln(out, "async random(length) {");
    gen_indent(out);
    gen_writeln(out, "return new Promise((resolve, reject) => {");
    gen_indent(out);
    gen_writeln(out, "native.quac_random(this._handle, length, (err, buf) => {");
    gen_indent(out);
    gen_writeln(out, "if (err) reject(new QUACError(err));");
    gen_writeln(out, "else resolve(buf);");
    gen_dedent(out);
    gen_writeln(out, "});");
    gen_dedent(out);
    gen_writeln(out, "});");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);

    gen_writeln(out, "/**");
    gen_writeln(out, " * Generate random bytes (synchronous)");
    gen_writeln(out, " * @param {number} length - Number of bytes");
    gen_writeln(out, " * @returns {Buffer}");
    gen_writeln(out, " */");
    gen_writeln(out, "randomSync(length) {");
    gen_indent(out);
    gen_writeln(out, "return native.quac_random_sync(this._handle, length);");
    gen_dedent(out);
    gen_writeln(out, "}");

    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);
}

static void generate_js_exports(gen_output_t *out, const parsed_api_t *api)
{
    gen_writeln(out, "// Exports");
    gen_writeln(out, "module.exports = {");
    gen_indent(out);
    gen_writeln(out, "QUACError,");
    gen_writeln(out, "Context,");
    gen_writeln(out, "Device,");

    /* Export enums */
    for (int i = 0; i < api->enum_count; i++)
    {
        char class_name[128];
        js_class_name(api->enums[i].name, class_name, sizeof(class_name));
        gen_writeln(out, "%s,", class_name);
    }

    gen_dedent(out);
    gen_writeln(out, "};");
}

/*=============================================================================
 * TypeScript Declarations Generation
 *=============================================================================*/

static void generate_ts_declarations(gen_output_t *out, const parsed_api_t *api)
{
    gen_writeln(out, "/**");
    gen_writeln(out, " * QUAC SDK Error");
    gen_writeln(out, " */");
    gen_writeln(out, "export class QUACError extends Error {");
    gen_indent(out);
    gen_writeln(out, "code: number;");
    gen_writeln(out, "constructor(code: number, message?: string);");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);

    /* Enums */
    for (int i = 0; i < api->enum_count; i++)
    {
        const parsed_enum_t *e = &api->enums[i];
        char class_name[128];
        js_class_name(e->name, class_name, sizeof(class_name));

        gen_writeln(out, "export const %s: {", class_name);
        gen_indent(out);

        for (int j = 0; j < e->value_count; j++)
        {
            const parsed_enum_value_t *v = &e->values[j];
            char value_name[128];
            js_const_name(v->name, value_name, sizeof(value_name));
            gen_writeln(out, "readonly %s: %lld;", value_name, (long long)v->value);
        }

        gen_dedent(out);
        gen_writeln(out, "};");
        gen_newline(out);
    }

    /* Context class */
    gen_writeln(out, "/**");
    gen_writeln(out, " * QUAC Context - Main SDK entry point");
    gen_writeln(out, " */");
    gen_writeln(out, "export class Context {");
    gen_indent(out);
    gen_writeln(out, "constructor();");
    gen_writeln(out, "close(): void;");
    gen_writeln(out, "getDeviceCount(): number;");
    gen_writeln(out, "openDevice(index: number): Device;");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);

    /* Device class */
    gen_writeln(out, "/**");
    gen_writeln(out, " * QUAC Device - Hardware accelerator interface");
    gen_writeln(out, " */");
    gen_writeln(out, "export class Device {");
    gen_indent(out);
    gen_writeln(out, "close(): void;");
    gen_writeln(out, "kemKeygen(algorithm: number): Promise<{ publicKey: Buffer; secretKey: Buffer }>;");
    gen_writeln(out, "kemEncaps(algorithm: number, publicKey: Buffer): Promise<{ ciphertext: Buffer; sharedSecret: Buffer }>;");
    gen_writeln(out, "kemDecaps(algorithm: number, ciphertext: Buffer, secretKey: Buffer): Promise<Buffer>;");
    gen_writeln(out, "random(length: number): Promise<Buffer>;");
    gen_writeln(out, "randomSync(length: number): Buffer;");
    gen_dedent(out);
    gen_writeln(out, "}");
}

/*=============================================================================
 * binding.gyp Generation
 *=============================================================================*/

static void generate_binding_gyp(gen_output_t *out)
{
    gen_writeln(out, "{");
    gen_indent(out);
    gen_writeln(out, "\"targets\": [");
    gen_indent(out);
    gen_writeln(out, "{");
    gen_indent(out);
    gen_writeln(out, "\"target_name\": \"quac100_napi\",");
    gen_writeln(out, "\"sources\": [\"quac100_napi.c\"],");
    gen_writeln(out, "\"include_dirs\": [");
    gen_indent(out);
    gen_writeln(out, "\"<!@(node -p \\\"require('node-addon-api').include\\\")\",");
    gen_writeln(out, "\"../../include\"");
    gen_dedent(out);
    gen_writeln(out, "],");
    gen_writeln(out, "\"libraries\": [\"-lquac100\"],");
    gen_writeln(out, "\"cflags!\": [\"-fno-exceptions\"],");
    gen_writeln(out, "\"cflags_cc!\": [\"-fno-exceptions\"],");
    gen_writeln(out, "\"defines\": [\"NAPI_DISABLE_CPP_EXCEPTIONS\"],");
    gen_writeln(out, "\"conditions\": [");
    gen_indent(out);
    gen_writeln(out, "[\"OS=='win'\", {");
    gen_indent(out);
    gen_writeln(out, "\"libraries\": [\"quac100.lib\"]");
    gen_dedent(out);
    gen_writeln(out, "}],");
    gen_writeln(out, "[\"OS=='mac'\", {");
    gen_indent(out);
    gen_writeln(out, "\"xcode_settings\": {");
    gen_indent(out);
    gen_writeln(out, "\"GCC_ENABLE_CPP_EXCEPTIONS\": \"YES\"");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_dedent(out);
    gen_writeln(out, "}]");
    gen_dedent(out);
    gen_writeln(out, "]");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_dedent(out);
    gen_writeln(out, "]");
    gen_dedent(out);
    gen_writeln(out, "}");
}

/*=============================================================================
 * Main Generator Entry Point
 *=============================================================================*/

int generate_nodejs(const parsed_api_t *api, const generator_config_t *config)
{
    if (!api || !config)
        return -1;

    /* Generate quac100.js */
    char path[1024];
    snprintf(path, sizeof(path), "%s/quac100.js", config->output_dir);

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

    gen_write_file_header(out, "quac100.js",
                          "Node.js bindings for QUAC 100 SDK", TARGET_NODEJS);

    generate_js_imports(out);
    generate_js_native_loading(out);
    generate_js_error_class(out);

    /* Enums */
    for (int i = 0; i < api->enum_count; i++)
    {
        generate_js_enum(out, &api->enums[i]);
    }

    generate_js_context_class(out);
    generate_js_device_class(out);
    generate_js_exports(out, api);

    gen_output_destroy(out);

    /* Generate TypeScript declarations */
    snprintf(path, sizeof(path), "%s/quac100.d.ts", config->output_dir);

    if (config->verbose)
    {
        printf("  Generating: %s\n", path);
    }

    out = gen_output_create_file(path);
    if (out)
    {
        gen_write_file_header(out, "quac100.d.ts",
                              "TypeScript declarations for QUAC 100 SDK", TARGET_NODEJS);
        generate_ts_declarations(out, api);
        gen_output_destroy(out);
    }

    /* Generate binding.gyp */
    snprintf(path, sizeof(path), "%s/binding.gyp", config->output_dir);

    if (config->verbose)
    {
        printf("  Generating: %s\n", path);
    }

    out = gen_output_create_file(path);
    if (out)
    {
        generate_binding_gyp(out);
        gen_output_destroy(out);
    }

    return 0;
}