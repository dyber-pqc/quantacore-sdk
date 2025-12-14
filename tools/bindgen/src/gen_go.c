/**
 * @file gen_go.c
 * @brief QUAC Binding Generator - Go Generator
 *
 * Generates Go bindings using cgo for FFI.
 * Produces:
 * - quac100.go: Main Go package with cgo bindings
 * - types.go: Type definitions and conversions
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
 * Go-Specific Helpers
 *=============================================================================*/

static void go_type_name(const char *c_name, char *out, size_t size)
{
    const char *name = gen_strip_prefix(c_name, "quac_");
    char stripped[128];
    gen_strip_suffix(name, "_t", stripped, sizeof(stripped));
    gen_to_pascal_case(stripped, out, size);
}

static void go_func_name(const char *c_name, char *out, size_t size)
{
    const char *name = gen_strip_prefix(c_name, "quac_");
    gen_to_pascal_case(name, out, size);
}

static void go_const_name(const char *c_name, char *out, size_t size)
{
    const char *name = gen_strip_prefix(c_name, "QUAC_");
    gen_to_pascal_case(name, out, size);
}

static const char *go_cgo_type(const parsed_type_t *type)
{
    if (type->pointer_depth > 0)
    {
        if (type->kind == TYPE_CHAR)
            return "*C.char";
        if (type->kind == TYPE_VOID)
            return "unsafe.Pointer";
        if (type->kind == TYPE_UINT8)
            return "*C.uint8_t";
        return "unsafe.Pointer";
    }

    switch (type->kind)
    {
    case TYPE_VOID:
        return "";
    case TYPE_BOOL:
        return "C.bool";
    case TYPE_CHAR:
        return "C.char";
    case TYPE_INT8:
        return "C.int8_t";
    case TYPE_UINT8:
        return "C.uint8_t";
    case TYPE_INT16:
        return "C.int16_t";
    case TYPE_UINT16:
        return "C.uint16_t";
    case TYPE_INT32:
        return "C.int32_t";
    case TYPE_UINT32:
        return "C.uint32_t";
    case TYPE_INT64:
        return "C.int64_t";
    case TYPE_UINT64:
        return "C.uint64_t";
    case TYPE_SIZE:
        return "C.size_t";
    case TYPE_FLOAT:
        return "C.float";
    case TYPE_DOUBLE:
        return "C.double";
    default:
        return "unsafe.Pointer";
    }
}

static const char *go_native_type(const parsed_type_t *type)
{
    if (type->pointer_depth > 0)
    {
        if (type->kind == TYPE_CHAR)
            return "string";
        if (type->kind == TYPE_UINT8)
            return "[]byte";
        return "unsafe.Pointer";
    }

    switch (type->kind)
    {
    case TYPE_VOID:
        return "";
    case TYPE_BOOL:
        return "bool";
    case TYPE_CHAR:
        return "byte";
    case TYPE_INT8:
        return "int8";
    case TYPE_UINT8:
        return "uint8";
    case TYPE_INT16:
        return "int16";
    case TYPE_UINT16:
        return "uint16";
    case TYPE_INT32:
        return "int32";
    case TYPE_UINT32:
        return "uint32";
    case TYPE_INT64:
        return "int64";
    case TYPE_UINT64:
        return "uint64";
    case TYPE_SIZE:
        return "uintptr";
    case TYPE_FLOAT:
        return "float32";
    case TYPE_DOUBLE:
        return "float64";
    default:
        return "interface{}";
    }
}

/*=============================================================================
 * Code Generation
 *=============================================================================*/

static void generate_go_header(gen_output_t *out, const char *pkg_name)
{
    gen_writeln(out, "package %s", pkg_name);
    gen_newline(out);
    gen_writeln(out, "/*");
    gen_writeln(out, "#cgo LDFLAGS: -lquac100");
    gen_writeln(out, "#cgo CFLAGS: -I${SRCDIR}/../../include");
    gen_writeln(out, "#include <quac100.h>");
    gen_writeln(out, "#include <quac100_kem.h>");
    gen_writeln(out, "#include <quac100_sign.h>");
    gen_writeln(out, "#include <quac100_random.h>");
    gen_writeln(out, "#include <stdlib.h>");
    gen_writeln(out, "*/");
    gen_writeln(out, "import \"C\"");
    gen_newline(out);
    gen_writeln(out, "import (");
    gen_indent(out);
    gen_writeln(out, "\"fmt\"");
    gen_writeln(out, "\"unsafe\"");
    gen_dedent(out);
    gen_writeln(out, ")");
    gen_newline(out);
}

static void generate_go_error(gen_output_t *out)
{
    gen_writeln(out, "// Error represents a QUAC SDK error");
    gen_writeln(out, "type Error struct {");
    gen_indent(out);
    gen_writeln(out, "Code    int32");
    gen_writeln(out, "Message string");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);

    gen_writeln(out, "func (e *Error) Error() string {");
    gen_indent(out);
    gen_writeln(out, "return fmt.Sprintf(\"QUAC error %%d: %%s\", e.Code, e.Message)");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);

    gen_writeln(out, "func checkResult(code C.int) error {");
    gen_indent(out);
    gen_writeln(out, "if code != 0 {");
    gen_indent(out);
    gen_writeln(out, "return &Error{");
    gen_indent(out);
    gen_writeln(out, "Code:    int32(code),");
    gen_writeln(out, "Message: errorMessage(int32(code)),");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_writeln(out, "return nil");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);

    gen_writeln(out, "func errorMessage(code int32) string {");
    gen_indent(out);
    gen_writeln(out, "switch code {");
    gen_writeln(out, "case -1:");
    gen_indent(out);
    gen_writeln(out, "return \"Invalid argument\"");
    gen_dedent(out);
    gen_writeln(out, "case -2:");
    gen_indent(out);
    gen_writeln(out, "return \"Device not found\"");
    gen_dedent(out);
    gen_writeln(out, "case -3:");
    gen_indent(out);
    gen_writeln(out, "return \"Operation failed\"");
    gen_dedent(out);
    gen_writeln(out, "case -4:");
    gen_indent(out);
    gen_writeln(out, "return \"Out of memory\"");
    gen_dedent(out);
    gen_writeln(out, "case -5:");
    gen_indent(out);
    gen_writeln(out, "return \"Timeout\"");
    gen_dedent(out);
    gen_writeln(out, "case -6:");
    gen_indent(out);
    gen_writeln(out, "return \"Not initialized\"");
    gen_dedent(out);
    gen_writeln(out, "default:");
    gen_indent(out);
    gen_writeln(out, "return fmt.Sprintf(\"Unknown error (%%d)\", code)");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);
}

static void generate_go_enum(gen_output_t *out, const parsed_enum_t *e)
{
    char type_name[128];
    go_type_name(e->name, type_name, sizeof(type_name));

    if (e->doc[0])
    {
        gen_writeln(out, "// %s %s", type_name, e->doc);
    }
    else
    {
        gen_writeln(out, "// %s enumeration", type_name);
    }
    gen_writeln(out, "type %s int32", type_name);
    gen_newline(out);

    gen_writeln(out, "// %s values", type_name);
    gen_writeln(out, "const (");
    gen_indent(out);

    for (int i = 0; i < e->value_count; i++)
    {
        const parsed_enum_value_t *v = &e->values[i];
        char value_name[128];
        go_const_name(v->name, value_name, sizeof(value_name));

        if (v->doc[0])
        {
            gen_writeln(out, "// %s %s", value_name, v->doc);
        }
        gen_writeln(out, "%s %s = %lld", value_name, type_name, (long long)v->value);
    }

    gen_dedent(out);
    gen_writeln(out, ")");
    gen_newline(out);

    /* String method */
    gen_writeln(out, "func (v %s) String() string {", type_name);
    gen_indent(out);
    gen_writeln(out, "switch v {");
    for (int i = 0; i < e->value_count; i++)
    {
        const parsed_enum_value_t *v = &e->values[i];
        char value_name[128];
        go_const_name(v->name, value_name, sizeof(value_name));
        gen_writeln(out, "case %s:", value_name);
        gen_indent(out);
        gen_writeln(out, "return \"%s\"", value_name);
        gen_dedent(out);
    }
    gen_writeln(out, "default:");
    gen_indent(out);
    gen_writeln(out, "return fmt.Sprintf(\"%s(%%d)\", int32(v))", type_name);
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);
}

static void generate_go_struct(gen_output_t *out, const parsed_struct_t *s)
{
    if (s->is_opaque)
        return;

    char type_name[128];
    go_type_name(s->name, type_name, sizeof(type_name));

    if (s->doc[0])
    {
        gen_writeln(out, "// %s %s", type_name, s->doc);
    }
    gen_writeln(out, "type %s struct {", type_name);
    gen_indent(out);

    for (int i = 0; i < s->field_count; i++)
    {
        const parsed_field_t *f = &s->fields[i];
        char field_name[128];
        gen_to_pascal_case(f->name, field_name, sizeof(field_name));

        const char *go_type = go_native_type(&f->type);

        if (f->doc[0])
        {
            gen_writeln(out, "// %s", f->doc);
        }

        if (f->type.array_size > 0)
        {
            gen_writeln(out, "%s [%d]%s", field_name, f->type.array_size, go_type);
        }
        else
        {
            gen_writeln(out, "%s %s", field_name, go_type);
        }
    }

    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);
}

static void generate_go_context(gen_output_t *out)
{
    gen_writeln(out, "// Context represents a QUAC SDK context");
    gen_writeln(out, "type Context struct {");
    gen_indent(out);
    gen_writeln(out, "handle unsafe.Pointer");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);

    gen_writeln(out, "// NewContext creates a new QUAC context");
    gen_writeln(out, "func NewContext() (*Context, error) {");
    gen_indent(out);
    gen_writeln(out, "var handle unsafe.Pointer");
    gen_writeln(out, "result := C.quac_init(&handle)");
    gen_writeln(out, "if err := checkResult(result); err != nil {");
    gen_indent(out);
    gen_writeln(out, "return nil, err");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_writeln(out, "return &Context{handle: handle}, nil");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);

    gen_writeln(out, "// Close releases the context resources");
    gen_writeln(out, "func (ctx *Context) Close() error {");
    gen_indent(out);
    gen_writeln(out, "if ctx.handle != nil {");
    gen_indent(out);
    gen_writeln(out, "result := C.quac_shutdown(ctx.handle)");
    gen_writeln(out, "ctx.handle = nil");
    gen_writeln(out, "return checkResult(result)");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_writeln(out, "return nil");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);

    gen_writeln(out, "// DeviceCount returns the number of available devices");
    gen_writeln(out, "func (ctx *Context) DeviceCount() (uint32, error) {");
    gen_indent(out);
    gen_writeln(out, "var count C.uint32_t");
    gen_writeln(out, "result := C.quac_get_device_count(ctx.handle, &count)");
    gen_writeln(out, "if err := checkResult(result); err != nil {");
    gen_indent(out);
    gen_writeln(out, "return 0, err");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_writeln(out, "return uint32(count), nil");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);

    gen_writeln(out, "// OpenDevice opens a device by index");
    gen_writeln(out, "func (ctx *Context) OpenDevice(index uint32) (*Device, error) {");
    gen_indent(out);
    gen_writeln(out, "var handle unsafe.Pointer");
    gen_writeln(out, "result := C.quac_open_device(ctx.handle, C.uint32_t(index), &handle)");
    gen_writeln(out, "if err := checkResult(result); err != nil {");
    gen_indent(out);
    gen_writeln(out, "return nil, err");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_writeln(out, "return &Device{handle: handle}, nil");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);
}

static void generate_go_device(gen_output_t *out)
{
    gen_writeln(out, "// Device represents a QUAC hardware device");
    gen_writeln(out, "type Device struct {");
    gen_indent(out);
    gen_writeln(out, "handle unsafe.Pointer");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);

    gen_writeln(out, "// Close releases the device");
    gen_writeln(out, "func (dev *Device) Close() error {");
    gen_indent(out);
    gen_writeln(out, "if dev.handle != nil {");
    gen_indent(out);
    gen_writeln(out, "result := C.quac_close_device(dev.handle)");
    gen_writeln(out, "dev.handle = nil");
    gen_writeln(out, "return checkResult(result)");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_writeln(out, "return nil");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);

    /* KEM Keygen */
    gen_writeln(out, "// KEMKeygen generates a KEM keypair");
    gen_writeln(out, "func (dev *Device) KEMKeygen(algorithm KemAlgorithm) (publicKey, secretKey []byte, err error) {");
    gen_indent(out);
    gen_writeln(out, "pk := make([]byte, 2048)");
    gen_writeln(out, "sk := make([]byte, 4096)");
    gen_writeln(out, "var pkLen, skLen C.size_t = C.size_t(len(pk)), C.size_t(len(sk))");
    gen_newline(out);
    gen_writeln(out, "result := C.quac_kem_keygen(");
    gen_indent(out);
    gen_writeln(out, "dev.handle,");
    gen_writeln(out, "C.int(algorithm),");
    gen_writeln(out, "(*C.uint8_t)(unsafe.Pointer(&pk[0])),");
    gen_writeln(out, "&pkLen,");
    gen_writeln(out, "(*C.uint8_t)(unsafe.Pointer(&sk[0])),");
    gen_writeln(out, "&skLen,");
    gen_dedent(out);
    gen_writeln(out, ")");
    gen_newline(out);
    gen_writeln(out, "if err = checkResult(result); err != nil {");
    gen_indent(out);
    gen_writeln(out, "return nil, nil, err");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_writeln(out, "return pk[:pkLen], sk[:skLen], nil");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);

    /* KEM Encaps */
    gen_writeln(out, "// KEMEncaps performs KEM encapsulation");
    gen_writeln(out, "func (dev *Device) KEMEncaps(algorithm KemAlgorithm, publicKey []byte) (ciphertext, sharedSecret []byte, err error) {");
    gen_indent(out);
    gen_writeln(out, "ct := make([]byte, 2048)");
    gen_writeln(out, "ss := make([]byte, 64)");
    gen_writeln(out, "var ctLen, ssLen C.size_t = C.size_t(len(ct)), C.size_t(len(ss))");
    gen_newline(out);
    gen_writeln(out, "result := C.quac_kem_encaps(");
    gen_indent(out);
    gen_writeln(out, "dev.handle,");
    gen_writeln(out, "C.int(algorithm),");
    gen_writeln(out, "(*C.uint8_t)(unsafe.Pointer(&publicKey[0])),");
    gen_writeln(out, "C.size_t(len(publicKey)),");
    gen_writeln(out, "(*C.uint8_t)(unsafe.Pointer(&ct[0])),");
    gen_writeln(out, "&ctLen,");
    gen_writeln(out, "(*C.uint8_t)(unsafe.Pointer(&ss[0])),");
    gen_writeln(out, "&ssLen,");
    gen_dedent(out);
    gen_writeln(out, ")");
    gen_newline(out);
    gen_writeln(out, "if err = checkResult(result); err != nil {");
    gen_indent(out);
    gen_writeln(out, "return nil, nil, err");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_writeln(out, "return ct[:ctLen], ss[:ssLen], nil");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);

    /* KEM Decaps */
    gen_writeln(out, "// KEMDecaps performs KEM decapsulation");
    gen_writeln(out, "func (dev *Device) KEMDecaps(algorithm KemAlgorithm, ciphertext, secretKey []byte) (sharedSecret []byte, err error) {");
    gen_indent(out);
    gen_writeln(out, "ss := make([]byte, 64)");
    gen_writeln(out, "var ssLen C.size_t = C.size_t(len(ss))");
    gen_newline(out);
    gen_writeln(out, "result := C.quac_kem_decaps(");
    gen_indent(out);
    gen_writeln(out, "dev.handle,");
    gen_writeln(out, "C.int(algorithm),");
    gen_writeln(out, "(*C.uint8_t)(unsafe.Pointer(&ciphertext[0])),");
    gen_writeln(out, "C.size_t(len(ciphertext)),");
    gen_writeln(out, "(*C.uint8_t)(unsafe.Pointer(&secretKey[0])),");
    gen_writeln(out, "C.size_t(len(secretKey)),");
    gen_writeln(out, "(*C.uint8_t)(unsafe.Pointer(&ss[0])),");
    gen_writeln(out, "&ssLen,");
    gen_dedent(out);
    gen_writeln(out, ")");
    gen_newline(out);
    gen_writeln(out, "if err = checkResult(result); err != nil {");
    gen_indent(out);
    gen_writeln(out, "return nil, err");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_writeln(out, "return ss[:ssLen], nil");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);

    /* SignKeygen */
    gen_writeln(out, "// SignKeygen generates a signature keypair");
    gen_writeln(out, "func (dev *Device) SignKeygen(algorithm SignAlgorithm) (publicKey, secretKey []byte, err error) {");
    gen_indent(out);
    gen_writeln(out, "pk := make([]byte, 4096)");
    gen_writeln(out, "sk := make([]byte, 8192)");
    gen_writeln(out, "var pkLen, skLen C.size_t = C.size_t(len(pk)), C.size_t(len(sk))");
    gen_newline(out);
    gen_writeln(out, "result := C.quac_sign_keygen(");
    gen_indent(out);
    gen_writeln(out, "dev.handle,");
    gen_writeln(out, "C.int(algorithm),");
    gen_writeln(out, "(*C.uint8_t)(unsafe.Pointer(&pk[0])),");
    gen_writeln(out, "&pkLen,");
    gen_writeln(out, "(*C.uint8_t)(unsafe.Pointer(&sk[0])),");
    gen_writeln(out, "&skLen,");
    gen_dedent(out);
    gen_writeln(out, ")");
    gen_newline(out);
    gen_writeln(out, "if err = checkResult(result); err != nil {");
    gen_indent(out);
    gen_writeln(out, "return nil, nil, err");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_writeln(out, "return pk[:pkLen], sk[:skLen], nil");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);

    /* Sign */
    gen_writeln(out, "// Sign creates a signature");
    gen_writeln(out, "func (dev *Device) Sign(algorithm SignAlgorithm, message, secretKey []byte) (signature []byte, err error) {");
    gen_indent(out);
    gen_writeln(out, "sig := make([]byte, 8192)");
    gen_writeln(out, "var sigLen C.size_t = C.size_t(len(sig))");
    gen_newline(out);
    gen_writeln(out, "result := C.quac_sign(");
    gen_indent(out);
    gen_writeln(out, "dev.handle,");
    gen_writeln(out, "C.int(algorithm),");
    gen_writeln(out, "(*C.uint8_t)(unsafe.Pointer(&message[0])),");
    gen_writeln(out, "C.size_t(len(message)),");
    gen_writeln(out, "(*C.uint8_t)(unsafe.Pointer(&secretKey[0])),");
    gen_writeln(out, "C.size_t(len(secretKey)),");
    gen_writeln(out, "(*C.uint8_t)(unsafe.Pointer(&sig[0])),");
    gen_writeln(out, "&sigLen,");
    gen_dedent(out);
    gen_writeln(out, ")");
    gen_newline(out);
    gen_writeln(out, "if err = checkResult(result); err != nil {");
    gen_indent(out);
    gen_writeln(out, "return nil, err");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_writeln(out, "return sig[:sigLen], nil");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);

    /* Verify */
    gen_writeln(out, "// Verify checks a signature");
    gen_writeln(out, "func (dev *Device) Verify(algorithm SignAlgorithm, message, signature, publicKey []byte) (valid bool, err error) {");
    gen_indent(out);
    gen_writeln(out, "result := C.quac_verify(");
    gen_indent(out);
    gen_writeln(out, "dev.handle,");
    gen_writeln(out, "C.int(algorithm),");
    gen_writeln(out, "(*C.uint8_t)(unsafe.Pointer(&message[0])),");
    gen_writeln(out, "C.size_t(len(message)),");
    gen_writeln(out, "(*C.uint8_t)(unsafe.Pointer(&signature[0])),");
    gen_writeln(out, "C.size_t(len(signature)),");
    gen_writeln(out, "(*C.uint8_t)(unsafe.Pointer(&publicKey[0])),");
    gen_writeln(out, "C.size_t(len(publicKey)),");
    gen_dedent(out);
    gen_writeln(out, ")");
    gen_newline(out);
    gen_writeln(out, "if result < 0 {");
    gen_indent(out);
    gen_writeln(out, "return false, checkResult(result)");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_writeln(out, "return result == 0, nil");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);

    /* Random */
    gen_writeln(out, "// Random generates random bytes using QRNG");
    gen_writeln(out, "func (dev *Device) Random(length int) ([]byte, error) {");
    gen_indent(out);
    gen_writeln(out, "if length <= 0 {");
    gen_indent(out);
    gen_writeln(out, "return nil, &Error{Code: -1, Message: \"Invalid length\"}");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_writeln(out, "buf := make([]byte, length)");
    gen_writeln(out, "result := C.quac_random(");
    gen_indent(out);
    gen_writeln(out, "dev.handle,");
    gen_writeln(out, "(*C.uint8_t)(unsafe.Pointer(&buf[0])),");
    gen_writeln(out, "C.size_t(length),");
    gen_dedent(out);
    gen_writeln(out, ")");
    gen_newline(out);
    gen_writeln(out, "if err := checkResult(result); err != nil {");
    gen_indent(out);
    gen_writeln(out, "return nil, err");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_writeln(out, "return buf, nil");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);
}

/*=============================================================================
 * Main Generator Entry Point
 *=============================================================================*/

int generate_go(const parsed_api_t *api, const generator_config_t *config)
{
    if (!api || !config)
        return -1;

    char path[1024];
    snprintf(path, sizeof(path), "%s/quac100.go", config->output_dir);

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

    gen_write_file_header(out, "quac100.go",
                          "Go bindings for QUAC 100 SDK", TARGET_GO);

    generate_go_header(out, "quac100");
    generate_go_error(out);

    /* Enums */
    for (int i = 0; i < api->enum_count; i++)
    {
        generate_go_enum(out, &api->enums[i]);
    }

    /* Structs */
    for (int i = 0; i < api->struct_count; i++)
    {
        generate_go_struct(out, &api->structs[i]);
    }

    generate_go_context(out);
    generate_go_device(out);

    gen_output_destroy(out);

    /* Generate go.mod */
    snprintf(path, sizeof(path), "%s/go.mod", config->output_dir);

    if (config->verbose)
    {
        printf("  Generating: %s\n", path);
    }

    out = gen_output_create_file(path);
    if (out)
    {
        gen_writeln(out, "module github.com/dyber/quac100");
        gen_newline(out);
        gen_writeln(out, "go 1.21");
        gen_output_destroy(out);
    }

    return 0;
}